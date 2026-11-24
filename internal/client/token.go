package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	grantTypeClientCredentials = "client_credentials"
	// Used only when HERE omits expires_in; a premature expiry is recovered by the 401 refresh.
	fallbackTokenLifetime = time.Hour
	maxRefreshMargin      = 5 * time.Minute
)

// TokenSource supplies bearer tokens for the HERE IAM API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	// Invalidate drops token if it is still cached, so the next call fetches a new one.
	Invalidate(token string)
}

// Auth authenticates a single token request. Implementations must produce fresh
// credentials on every call: HERE rejects replayed OAuth nonces and JWT assertions.
type Auth interface {
	authenticate(form url.Values, header http.Header, tokenURL string, now time.Time) error
	secrets() []string
}

type tokenResponse struct {
	AccessToken      string     `json:"access_token"`
	AccessTokenCamel string     `json:"accessToken"`
	ExpiresIn        flexString `json:"expires_in"`
	ExpiresInCamel   flexString `json:"expiresIn"`
}

// cachingTokenSource shares one token across concurrent Terraform operations. The
// channel acts as a context-aware mutex held during fetches, so a burst of callers with
// an expired token triggers a single request against the 25,000/15 min token quota.
type cachingTokenSource struct {
	auth     Auth
	tokenURL string
	t        *transport

	lock      chan struct{}
	token     string
	refreshAt time.Time
}

func newCachingTokenSource(auth Auth, tokenURL string, t *transport) *cachingTokenSource {
	return &cachingTokenSource{
		auth:     auth,
		tokenURL: tokenURL,
		t:        t,
		lock:     make(chan struct{}, 1),
	}
}

func (s *cachingTokenSource) Token(ctx context.Context) (string, error) {
	select {
	case s.lock <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-s.lock }()

	if s.token != "" && s.t.now().Before(s.refreshAt) {
		return s.token, nil
	}
	token, lifetime, obtainedAt, err := s.fetch(ctx)
	if err != nil {
		return "", err
	}
	margin := min(maxRefreshMargin, lifetime/2) //nolint:mnd // short-lived tokens are reused for half their life.
	s.token = token
	s.refreshAt = obtainedAt.Add(lifetime - margin)
	return token, nil
}

func (s *cachingTokenSource) Invalidate(token string) {
	s.lock <- struct{}{}
	defer func() { <-s.lock }()
	if s.token == token {
		s.token = ""
		s.refreshAt = time.Time{}
	}
}

func (s *cachingTokenSource) fetch(ctx context.Context) (string, time.Duration, time.Time, error) {
	var obtainedAt time.Time
	build := func(ctx context.Context) (*http.Request, error) {
		obtainedAt = s.t.now()
		form := url.Values{"grant_type": {grantTypeClientCredentials}}
		header := http.Header{}
		if err := s.auth.authenticate(form, header, s.tokenURL, obtainedAt); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, nil
	}

	resp, err := s.t.send(ctx, "token", build, true, s.auth.secrets()...)
	if err != nil {
		return "", 0, time.Time{}, fmt.Errorf("requesting HERE access token: %w", err)
	}
	var body tokenResponse
	if json.Unmarshal(resp.body, &body) != nil {
		return "", 0, time.Time{}, fmt.Errorf("requesting HERE access token: response is not valid JSON")
	}
	token := firstNonEmpty(body.AccessToken, body.AccessTokenCamel)
	if token == "" {
		return "", 0, time.Time{}, fmt.Errorf("requesting HERE access token: response has no access token")
	}
	lifetime := fallbackTokenLifetime
	if secs := parsePositiveSeconds(string(body.ExpiresIn), string(body.ExpiresInCamel)); secs > 0 {
		lifetime = secs
	}
	return token, lifetime, obtainedAt, nil
}

func parsePositiveSeconds(values ...string) time.Duration {
	for _, v := range values {
		var secs int64
		if _, err := fmt.Sscan(v, &secs); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// staticTokenSource serves a fixed token; for tests and pre-issued tokens.
type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) { return string(s), nil }
func (staticTokenSource) Invalidate(string)                       {}

// StaticTokenSource returns a TokenSource that always yields token.
func StaticTokenSource(token string) TokenSource {
	return staticTokenSource(token)
}
