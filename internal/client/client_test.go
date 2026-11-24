package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	testAppHRN = "hrn:here:account::realm1:app/abc123"
	testKeyHRN = "hrn:here:account::realm1:apikey/obfuscated-xyz"

	encodedAppHRN = "hrn%3Ahere%3Aaccount%3A%3Arealm1%3Aapp%2Fabc123"
	encodedKeyHRN = "hrn%3Ahere%3Aaccount%3A%3Arealm1%3Aapikey%2Fobfuscated-xyz"
	apiPrefix     = "/authentication/v1.1"
)

type sleepRecorder struct {
	mu     sync.Mutex
	sleeps []time.Duration
}

func (s *sleepRecorder) Sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.sleeps = append(s.sleeps, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleepRecorder) Durations() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.sleeps...)
}

type recordedRequest struct {
	Method     string
	RequestURI string
	Header     http.Header
	Body       string
}

type apiServer struct {
	mu       sync.Mutex
	requests []recordedRequest
}

func (s *apiServer) record(r *http.Request) int {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, recordedRequest{Method: r.Method, RequestURI: r.RequestURI, Header: r.Header.Clone(), Body: string(body)})
	return len(s.requests)
}

func (s *apiServer) Requests() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.requests...)
}

// newTestClient serves handler on a loopback server; n counts API requests from 1.
func newTestClient(t *testing.T, handler func(n int, w http.ResponseWriter, r *http.Request), opts ...func(*Config)) (*Client, *apiServer, *sleepRecorder) {
	t.Helper()
	rec := &apiServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(rec.record(r), w, r)
	}))
	t.Cleanup(srv.Close)
	sleeps := &sleepRecorder{}
	cfg := Config{
		APIURL:      srv.URL + apiPrefix,
		TokenSource: StaticTokenSource("test-token"),
		HTTPClient:  srv.Client(),
		UserAgent:   "terraform-provider-hereplatform/test",
		Retry:       RetryPolicy{MaxAttempts: 4},
		Poll:        PollPolicy{MinInterval: time.Millisecond, MaxInterval: time.Millisecond},
		Sleep:       sleeps.Sleep,
	}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, rec, sleeps
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

const appJSON = `{"hrn":"hrn:here:account::realm1:app/abc123","clientId":"abc123","name":"demo","description":"d",` +
	`"realm":"realm1","status":"ACTIVE","appCreationEnabled":false,"createdTime":1700000000000}`

func TestHRNPathParametersStayEncoded(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.RequestURI, "/apiKeys/"):
			writeJSON(w, http.StatusOK, `{"apiKeyId":"plain","apiKey":"`+testKeyHRN+`","name":"k"}`)
		default:
			writeJSON(w, http.StatusOK, appJSON)
		}
	})
	if _, err := c.GetApp(t.Context(), testAppHRN); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetAPIKey(t.Context(), testAppHRN, testKeyHRN); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAPIKeyEnabled(t.Context(), testAppHRN, testKeyHRN, false); err != nil {
		t.Fatal(err)
	}

	want := []string{
		apiPrefix + "/apps/" + encodedAppHRN,
		apiPrefix + "/apps/" + encodedAppHRN + "/apiKeys/" + encodedKeyHRN,
		apiPrefix + "/apps/" + encodedAppHRN + "/apiKeys/" + encodedKeyHRN + "/disable",
	}
	got := rec.Requests()
	for i, w := range want {
		if got[i].RequestURI != w {
			t.Errorf("request %d RequestURI = %q, want %q", i, got[i].RequestURI, w)
		}
	}
}

func TestRequestHeaders(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, appJSON)
	})
	if _, err := c.CreateApp(t.Context(), CreateAppInput{Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	r := rec.Requests()[0]
	checks := map[string]string{
		"Authorization": "Bearer test-token",
		"User-Agent":    "terraform-provider-hereplatform/test",
		"Content-Type":  "application/json",
		"Accept":        "application/json",
	}
	for h, want := range checks {
		if got := r.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if r.Body != `{"name":"demo"}` {
		t.Errorf("body = %s", r.Body)
	}
}

func TestUnauthorizedRefreshesTokenOnce(t *testing.T) {
	var tokenRequests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		n := tokenRequests.Add(1)
		writeJSON(w, http.StatusOK, fmt.Sprintf(`{"access_token":"tok-%d","expires_in":86399}`, n))
	})
	var apiCalls atomic.Int32
	rejectAll := atomic.Bool{}
	mux.HandleFunc(apiPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		auth := r.Header.Get("Authorization")
		if rejectAll.Load() || auth == "Bearer tok-1" {
			writeJSON(w, http.StatusUnauthorized, `{"title":"","message":"token `+strings.TrimPrefix(auth, "Bearer ")+` expired"}`)
			return
		}
		writeJSON(w, http.StatusOK, appJSON)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	auth, err := NewOAuth1Auth("id", "secret")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{APIURL: srv.URL + apiPrefix, TokenURL: srv.URL + "/oauth2/token", Auth: auth, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.GetApp(t.Context(), testAppHRN); err != nil {
		t.Fatalf("expected the refreshed token to succeed: %v", err)
	}
	if tokenRequests.Load() != 2 || apiCalls.Load() != 2 {
		t.Fatalf("token requests = %d, API calls = %d; want 2 and 2", tokenRequests.Load(), apiCalls.Load())
	}

	rejectAll.Store(true)
	_, err = c.GetApp(t.Context(), testAppHRN)
	if !HasStatus(err, http.StatusUnauthorized) {
		t.Fatalf("expected a 401, got %v", err)
	}
	if tokenRequests.Load() != 3 || apiCalls.Load() != 4 {
		t.Fatalf("token requests = %d, API calls = %d; want one refresh only", tokenRequests.Load(), apiCalls.Load())
	}
	if strings.Contains(err.Error(), "tok-") {
		t.Fatalf("error leaks a bearer token: %v", err)
	}
}

func TestTooManyRequestsHonoursRetryAfter(t *testing.T) {
	c, rec, sleeps := newTestClient(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			w.Header().Set("Retry-After", "7")
			writeJSON(w, http.StatusTooManyRequests, `{"errorCode":429003,"message":"Too many requests"}`)
			return
		}
		writeJSON(w, http.StatusOK, appJSON)
	})
	if _, err := c.GetApp(t.Context(), testAppHRN); err != nil {
		t.Fatal(err)
	}
	if got := sleeps.Durations(); len(got) != 1 || got[0] != 7*time.Second {
		t.Fatalf("sleeps = %v, want [7s]", got)
	}
	if len(rec.Requests()) != 2 {
		t.Fatalf("requests = %d, want 2", len(rec.Requests()))
	}
}

func TestRetryAfterBeyondLimitFailsFast(t *testing.T) {
	// Without clamping, the largest values overflow time.Duration into an immediate retry.
	for _, retryAfter := range []string{"3600", "9223372036854775807", "99999999999999999999", "Fri, 31 Dec 9999 23:59:59 GMT"} {
		t.Run(retryAfter, func(t *testing.T) {
			c, rec, sleeps := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", retryAfter)
				writeJSON(w, http.StatusTooManyRequests, `{"title":"Too Many Requests"}`)
			})
			_, err := c.GetApp(t.Context(), testAppHRN)
			if !HasStatus(err, http.StatusTooManyRequests) {
				t.Fatalf("expected a 429, got %v", err)
			}
			if len(rec.Requests()) != 1 || len(sleeps.Durations()) != 0 {
				t.Fatalf("requests = %d, sleeps = %v", len(rec.Requests()), sleeps.Durations())
			}
		})
	}
}

func TestServerErrorRetries(t *testing.T) {
	createKey := func(ctx context.Context, c *Client) error {
		_, err := c.CreateAPIKey(ctx, testAppHRN, CreateAPIKeyInput{Name: "x"})
		return err
	}
	tests := []struct {
		name        string
		status      int
		call        func(context.Context, *Client) error
		attempts    int
		unconfirmed bool
	}{
		{name: "GET 500 is retried", status: 500, call: func(ctx context.Context, c *Client) error { _, err := c.GetApp(ctx, testAppHRN); return err }, attempts: 4},
		{name: "create 500 is not replayed", status: 500, call: func(ctx context.Context, c *Client) error {
			_, err := c.CreateApp(ctx, CreateAppInput{Name: "x"})
			return err
		}, attempts: 1, unconfirmed: true},
		{name: "create 503 is not replayed", status: 503, call: createKey, attempts: 1, unconfirmed: true},
		{name: "create 429 is retried", status: 429, call: createKey, attempts: 4},
		{name: "create 501 is definite", status: 501, call: createKey, attempts: 1},
		{name: "501 is not retried", status: 501, call: func(ctx context.Context, c *Client) error { return c.DeleteApp(ctx, testAppHRN) }, attempts: 1},
		{name: "404 is not retried", status: 404, call: func(ctx context.Context, c *Client) error { _, err := c.GetApp(ctx, testAppHRN); return err }, attempts: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec, sleeps := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, tt.status, `{"title":"boom"}`)
			})
			err := tt.call(t.Context(), c)
			if !HasStatus(err, tt.status) {
				t.Fatalf("expected HTTP %d, got %v", tt.status, err)
			}
			if got := len(rec.Requests()); got != tt.attempts {
				t.Fatalf("attempts = %d, want %d", got, tt.attempts)
			}
			if IsUnconfirmed(err) != tt.unconfirmed {
				t.Fatalf("IsUnconfirmed = %t, want %t", !tt.unconfirmed, tt.unconfirmed)
			}
			for _, d := range sleeps.Durations() {
				if d <= 0 || d > DefaultRetryPolicy().MaxBackoff {
					t.Fatalf("backoff %v out of bounds", d)
				}
			}
		})
	}
}

type flakyTransport struct {
	failures int
	err      error
	calls    atomic.Int32
	next     http.RoundTripper
}

func (f *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if int(f.calls.Add(1)) <= f.failures {
		return nil, f.err
	}
	return f.next.RoundTrip(r)
}

func TestNetworkErrorRetries(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	resetErr := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	tests := []struct {
		name  string
		err   error
		call  func(context.Context, *Client) error
		calls int32
	}{
		{name: "dial error on create is retried", err: dialErr, call: func(ctx context.Context, c *Client) error {
			_, err := c.CreateApp(ctx, CreateAppInput{Name: "x"})
			return err
		}, calls: 3},
		{name: "reset on GET is retried", err: resetErr, call: func(ctx context.Context, c *Client) error { _, err := c.GetApp(ctx, testAppHRN); return err }, calls: 3},
		{name: "reset on create is not replayed", err: resetErr, call: func(ctx context.Context, c *Client) error {
			_, err := c.CreateApp(ctx, CreateAppInput{Name: "x"})
			return err
		}, calls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flaky := &flakyTransport{failures: 2, err: tt.err}
			c, _, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, appJSON)
			}, func(cfg *Config) {
				flaky.next = cfg.HTTPClient.Transport
				cfg.HTTPClient = &http.Client{Transport: flaky}
			})
			err := tt.call(t.Context(), c)
			if got := flaky.calls.Load(); got != tt.calls {
				t.Fatalf("round trips = %d, want %d (err %v)", got, tt.calls, err)
			}
			if tt.calls == 3 && err != nil {
				t.Fatalf("expected success after retries: %v", err)
			}
			if tt.calls == 1 && err == nil {
				t.Fatal("expected the network error")
			}
		})
	}
}

func TestUnconfirmedCreates(t *testing.T) {
	createApp := func(ctx context.Context, c *Client) error {
		_, err := c.CreateApp(ctx, CreateAppInput{Name: "x"})
		return err
	}
	createKey := func(ctx context.Context, c *Client) error {
		_, err := c.CreateAPIKey(ctx, testAppHRN, CreateAPIKeyInput{Name: "x"})
		return err
	}
	getApp := func(ctx context.Context, c *Client) error { _, err := c.GetApp(ctx, testAppHRN); return err }
	hangUp := func(_ int, w http.ResponseWriter, _ *http.Request) {
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = conn.Close()
		}
	}
	reply := func(status int, body string) func(int, http.ResponseWriter, *http.Request) {
		return func(_ int, w http.ResponseWriter, _ *http.Request) { writeJSON(w, status, body) }
	}
	tests := []struct {
		name        string
		handler     func(int, http.ResponseWriter, *http.Request)
		call        func(context.Context, *Client) error
		unconfirmed bool
	}{
		{"connection lost after a create", hangUp, createApp, true},
		{"connection lost after a GET", hangUp, getApp, false},
		{"unreadable create response", reply(http.StatusOK, "{not json"), createKey, true},
		{"unreadable GET response", reply(http.StatusOK, "{not json"), getApp, false},
		{"app create response without an HRN", reply(http.StatusOK, "{}"), createApp, true},
		{"API key create response without an HRN", reply(http.StatusCreated, `{"name":"x"}`), createKey, true},
		{"create rejected", reply(http.StatusBadRequest, `{"title":"bad"}`), createApp, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec, _ := newTestClient(t, tt.handler)
			err := tt.call(t.Context(), c)
			if err == nil {
				t.Fatal("expected an error")
			}
			if IsUnconfirmed(err) != tt.unconfirmed {
				t.Fatalf("IsUnconfirmed = %t, want %t: %v", !tt.unconfirmed, tt.unconfirmed, err)
			}
			if tt.unconfirmed && len(rec.Requests()) != 1 {
				t.Fatalf("%d requests; an unconfirmed create must not be replayed", len(rec.Requests()))
			}
		})
	}
}

func TestCreateTimeoutAfterSendIsUnconfirmed(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, _ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := c.CreateApp(ctx, CreateAppInput{Name: "x"})
	if !IsUnconfirmed(err) || !errors.Is(err, context.DeadlineExceeded) || len(rec.Requests()) != 1 {
		t.Fatalf("got %v after %d request(s), want an unconfirmed deadline error after 1", err, len(rec.Requests()))
	}

	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if _, err := c.CreateApp(ctx, CreateAppInput{Name: "x"}); err == nil || IsUnconfirmed(err) {
		t.Fatalf("a create cancelled before it was sent must fail definitely, got %v", err)
	}
}

func TestCreateThatNeverReachedHEREIsDefinite(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	c, _, sleeps := newTestClient(t, func(int, http.ResponseWriter, *http.Request) {}, func(cfg *Config) {
		cfg.APIURL = closed.URL + apiPrefix
	})
	_, err := c.CreateApp(t.Context(), CreateAppInput{Name: "x"})
	if err == nil || IsUnconfirmed(err) {
		t.Fatalf("a refused connection must fail definitely, got %v", err)
	}
	if n := len(sleeps.Durations()); n != 3 {
		t.Fatalf("%d retries of a create that never reached HERE, want 3", n)
	}
}

func TestContextCancellationStopsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		cancel()
		writeJSON(w, http.StatusServiceUnavailable, `{}`)
	})
	_, err := c.GetApp(ctx, testAppHRN)
	if err == nil || len(rec.Requests()) != 1 {
		t.Fatalf("err = %v, requests = %d", err, len(rec.Requests()))
	}
}

func TestErrorParsing(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		header  map[string]string
		body    string
		want    []string
		notWant []string
		code    int
	}{
		{
			name:   "current format",
			status: http.StatusForbidden,
			body: `{"title":"Forbidden","errorId":"ERROR-1","status":403,"code":"E202101",` +
				`"cause":"identity hrn:here:account::realm1:user/secret-user lacks access","action":"ask an admin","correlationId":"corr-403"}`,
			want:    []string{"HTTP 403", "code E202101", "Forbidden", "corr-403"},
			notWant: []string{"secret-user", "ask an admin", "ERROR-1"},
		},
		{
			name:   "legacy format with hint",
			status: http.StatusConflict,
			body:   `{"errorId":"x","httpStatus":409,"errorCode":409303,"message":"Reached allowed maximum number of active API keys","errorFields":[]}`,
			want:   []string{"HTTP 409", "code 409303", "Reached allowed maximum", "at most 2 API keys"},
			code:   409303,
		},
		{
			name:   "correlation ID from header",
			status: http.StatusNotFound,
			header: map[string]string{"X-Correlation-ID": "hdr-corr"},
			body:   ``,
			want:   []string{"HTTP 404: Not Found", "hdr-corr"},
		},
		{
			name:    "non-JSON body",
			status:  http.StatusBadGateway,
			body:    `<html>proxy error</html>`,
			want:    []string{"HTTP 502: Bad Gateway"},
			notWant: []string{"<html>"},
		},
		{
			name:    "long title is truncated",
			status:  http.StatusBadRequest,
			body:    `{"title":"` + strings.Repeat("x", 1000) + `"}`,
			want:    []string{strings.Repeat("x", maxTitleLength) + "..."},
			notWant: []string{strings.Repeat("x", maxTitleLength+1)},
		},
		{
			name:    "bearer token echoed in any field is redacted",
			status:  http.StatusBadRequest,
			body:    `{"title":"bad token test-token","code":"test-token","correlationId":"test-token"}`,
			want:    []string{"bad token [REDACTED]", "code [REDACTED]", "correlation ID: [REDACTED]"},
			notWant: []string{"test-token"},
		},
		{
			name:    "secret cut by the truncation is redacted first",
			status:  http.StatusBadRequest,
			body:    `{"title":"` + strings.Repeat("x", maxTitleLength-4) + `test-token"}`,
			want:    []string{strings.Repeat("x", maxTitleLength-4) + "[RED..."},
			notWant: []string{"test"},
		},
		{
			name:    "JWT echoed by the server is redacted even if this client did not send it",
			status:  http.StatusBadRequest,
			body:    `{"title":"token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl expired","correlationId":"eyJhbGciOiJSUzI1NiJ9"}`,
			want:    []string{"token [REDACTED] expired", "correlation ID: [REDACTED]"},
			notWant: []string{"eyJ"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				for k, v := range tt.header {
					w.Header().Set(k, v)
				}
				writeJSON(w, tt.status, tt.body)
			}, func(cfg *Config) { cfg.Retry = RetryPolicy{MaxAttempts: 1} })
			_, err := c.GetApp(t.Context(), testAppHRN)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tt.status {
				t.Fatalf("expected an APIError with status %d, got %v", tt.status, err)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(err.Error(), nw) {
					t.Errorf("error %q must not contain %q", err, nw)
				}
			}
			if tt.code != 0 && !HasCode(err, tt.code) {
				t.Errorf("HasCode(%d) = false for %v", tt.code, err)
			}
		})
	}
}

func TestErrorHelpers(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &APIError{StatusCode: http.StatusNotFound, Code: "404660"})
	if !IsNotFound(err) || !HasStatus(err, 500, 404) || HasStatus(err, 500) || !HasCode(err, 404660) || StatusCode(err) != 404 {
		t.Fatal("helpers do not see through wrapping")
	}
	plain := errors.New("plain")
	if IsNotFound(plain) || HasCode(plain, 404660) || StatusCode(plain) != 0 || HasStatus(nil, 0) {
		t.Fatal("helpers must be false for non-API errors")
	}
}
