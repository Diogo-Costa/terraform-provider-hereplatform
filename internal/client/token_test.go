package client

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// tokenServer issues tok-1, tok-2, ... and verifies every request it receives.
type tokenServer struct {
	t         *testing.T
	url       string
	requests  atomic.Int32
	body      func(n int) (int, string)
	onRequest func(r *http.Request)
	secret    string
}

func (s *tokenServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := int(s.requests.Add(1))
	if s.onRequest != nil {
		s.onRequest(r)
	}
	if r.Method != http.MethodPost {
		s.t.Errorf("token request method = %s", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		s.t.Errorf("token request content type = %q", ct)
	}
	if err := r.ParseForm(); err != nil {
		s.t.Errorf("parsing token form: %v", err)
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		s.t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
	}
	if r.PostForm.Has("scope") {
		s.t.Error("token request must be unscoped")
	}
	if s.secret != "" {
		s.verifyOAuth1(r)
	}
	status, body := http.StatusOK, fmt.Sprintf(`{"access_token":"tok-%d","token_type":"bearer","expires_in":86399}`, n)
	if s.body != nil {
		status, body = s.body(n)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// verifyOAuth1 recomputes the signature over what the server received, which catches any
// drift between the signed and the transmitted parameters.
func (s *tokenServer) verifyOAuth1(r *http.Request) {
	params := parseOAuthHeader(s.t, r.Header.Get("Authorization"))
	signature := params["oauth_signature"]
	delete(params, "oauth_signature")
	all := url.Values{}
	for k, vs := range r.PostForm {
		all[k] = vs
	}
	for k, v := range params {
		all.Set(k, v)
	}
	u, err := url.Parse(s.url)
	if err != nil {
		s.t.Fatal(err)
	}
	want := hmacSignature(sha256.New, s.secret, "", signatureBaseString(r.Method, u, all))
	if signature != want {
		s.t.Errorf("OAuth signature does not verify")
	}
	if params["oauth_signature_method"] != "HMAC-SHA256" || params["oauth_version"] != "1.0" {
		s.t.Errorf("unexpected OAuth parameters %v", params)
	}
}

func newTokenSourceForTest(t *testing.T, ts *tokenServer, clock *fakeClock) *cachingTokenSource {
	t.Helper()
	ts.t = t
	srv := httptest.NewServer(ts)
	t.Cleanup(srv.Close)
	ts.url = srv.URL + "/oauth2/token"
	ts.secret = "s3cr3t/value+="
	auth, err := NewOAuth1Auth("access-key-id", ts.secret)
	if err != nil {
		t.Fatal(err)
	}
	tr := &transport{
		http:      srv.Client(),
		userAgent: "test",
		retry:     RetryPolicy{MaxAttempts: 3}.withDefaults(),
		now:       clock.Now,
		sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
	}
	return newCachingTokenSource(auth, ts.url, tr)
}

func TestTokenIsCachedUnderConcurrency(t *testing.T) {
	ts := &tokenServer{}
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	src := newTokenSourceForTest(t, ts, clock)

	var wg sync.WaitGroup
	tokens := make([]string, 64)
	errs := make([]error, len(tokens))
	for i := range tokens {
		wg.Go(func() { tokens[i], errs[i] = src.Token(t.Context()) })
	}
	wg.Wait()
	for i := range tokens {
		if errs[i] != nil || tokens[i] != "tok-1" {
			t.Fatalf("caller %d got %q, %v", i, tokens[i], errs[i])
		}
	}
	if got := ts.requests.Load(); got != 1 {
		t.Fatalf("token endpoint called %d times, want 1", got)
	}
}

func TestTokenRefreshWindow(t *testing.T) {
	ts := &tokenServer{}
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	src := newTokenSourceForTest(t, ts, clock)

	mustToken := func(want string) {
		t.Helper()
		got, err := src.Token(t.Context())
		if err != nil || got != want {
			t.Fatalf("Token() = %q, %v; want %q", got, err, want)
		}
	}
	mustToken("tok-1")
	clock.Advance(86399*time.Second - 5*time.Minute - time.Second)
	mustToken("tok-1")
	clock.Advance(2 * time.Second)
	mustToken("tok-2")

	src.Invalidate("stale-token")
	mustToken("tok-2")
	src.Invalidate("tok-2")
	mustToken("tok-3")
}

func TestTokenResponseFormats(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		lifetime time.Duration
	}{
		{name: "snake case", body: `{"access_token":"abc","expires_in":3600}`, lifetime: 3600 * time.Second},
		{name: "camel case", body: `{"accessToken":"abc","expiresIn":"600"}`, lifetime: 600 * time.Second},
		{name: "no lifetime", body: `{"access_token":"abc"}`, lifetime: fallbackTokenLifetime},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &tokenServer{body: func(int) (int, string) { return http.StatusOK, tt.body }}
			clock := &fakeClock{now: time.Unix(1700000000, 0)}
			src := newTokenSourceForTest(t, ts, clock)
			tok, err := src.Token(t.Context())
			if err != nil || tok != "abc" {
				t.Fatalf("Token() = %q, %v", tok, err)
			}
			margin := min(maxRefreshMargin, tt.lifetime/2)
			if want := clock.Now().Add(tt.lifetime - margin); !src.refreshAt.Equal(want) {
				t.Fatalf("refreshAt = %v, want %v", src.refreshAt, want)
			}
		})
	}
}

func TestTokenErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   []string
	}{
		{
			name:   "legacy error",
			status: http.StatusUnauthorized,
			body:   `{"errorId":"x","httpStatus":401,"errorCode":401300,"message":"Signature mismatch for s3cr3t/value+=","correlationId":"corr-1"}`,
			want:   []string{"requesting HERE access token", "HTTP 401", "code 401300", "corr-1", "[REDACTED]"},
		},
		{
			name:   "OAuth error",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_request","error_description":"bad"}`,
			want:   []string{"HTTP 400", "invalid_request"},
		},
		{
			name:   "clock skew hint",
			status: http.StatusUnauthorized,
			body:   `{"errorCode":401204,"message":"Time stamp is outside the valid period."}`,
			want:   []string{"system clock"},
		},
		{name: "missing token", status: http.StatusOK, body: `{"token_type":"bearer"}`, want: []string{"no access token"}},
		{name: "not JSON", status: http.StatusOK, body: `<html>`, want: []string{"not valid JSON"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &tokenServer{body: func(int) (int, string) { return tt.status, tt.body }}
			src := newTokenSourceForTest(t, ts, &fakeClock{now: time.Now()})
			_, err := src.Token(t.Context())
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			for _, w := range tt.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q does not contain %q", msg, w)
				}
			}
			if strings.Contains(msg, ts.secret) {
				t.Errorf("error leaks the access key secret: %q", msg)
			}
		})
	}
}

func TestTokenRequestRetriesServerErrorsWithFreshSignature(t *testing.T) {
	var nonces sync.Map
	ts := &tokenServer{
		body: func(n int) (int, string) {
			if n == 1 {
				return http.StatusBadGateway, `{"message":"upstream"}`
			}
			return http.StatusOK, `{"access_token":"ok","expires_in":3600}`
		},
		onRequest: func(r *http.Request) {
			nonce := parseOAuthHeader(t, r.Header.Get("Authorization"))["oauth_nonce"]
			if _, dup := nonces.LoadOrStore(nonce, true); dup {
				t.Errorf("nonce %q replayed", nonce)
			}
		},
	}
	src := newTokenSourceForTest(t, ts, &fakeClock{now: time.Now()})
	if tok, err := src.Token(t.Context()); err != nil || tok != "ok" {
		t.Fatalf("Token() = %q, %v", tok, err)
	}
	if got := ts.requests.Load(); got != 2 {
		t.Fatalf("token endpoint called %d times, want 2", got)
	}
}

func TestTokenWaitsForContext(t *testing.T) {
	ts := &tokenServer{}
	src := newTokenSourceForTest(t, ts, &fakeClock{now: time.Now()})
	src.lock <- struct{}{}
	defer func() { <-src.lock }()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := src.Token(ctx); err == nil {
		t.Fatal("expected the context error while another fetch holds the lock")
	}
}

func TestStaticTokenSource(t *testing.T) {
	src := StaticTokenSource("fixed")
	src.Invalidate("fixed")
	if tok, err := src.Token(t.Context()); err != nil || tok != "fixed" {
		t.Fatalf("Token() = %q, %v", tok, err)
	}
}
