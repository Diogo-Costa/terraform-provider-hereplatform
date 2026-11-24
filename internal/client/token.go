package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	grantTypeClientCredentials = "client_credentials"
	// tokenLifetime is requested because a token can manage every app the provider reaches:
	// an hour bounds a leak, where the app default is up to 24 h. Also assumed when HERE
	// omits expires_in; a premature expiry is recovered by the 401 refresh.
	tokenLifetime = time.Hour
	// maxTokenLifetime is HERE's ceiling; larger expires_in values are clamped before they
	// can overflow time.Duration.
	maxTokenLifetime = 24 * time.Hour
	maxRefreshMargin = 5 * time.Minute
)

// TokenSource supplies bearer tokens for the HERE IAM API.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	// Invalidate drops token if it is still cached, so the next call fetches a new one. It
	// gives up when ctx ends first.
	Invalidate(ctx context.Context, token string)
}

// Auth authenticates a single token request. Implementations must produce fresh
// credentials on every call: HERE rejects replayed OAuth nonces and JWT assertions.
type Auth interface {
	// authenticate returns the secrets the request carries or is signed with, which errors
	// must never echo.
	authenticate(form url.Values, header http.Header, tokenURL string, now time.Time) ([]string, error)
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

func (s *cachingTokenSource) Invalidate(ctx context.Context, token string) {
	select {
	case s.lock <- struct{}{}:
	case <-ctx.Done():
		// The caller is giving up and will not use a new token.
		return
	}
	defer func() { <-s.lock }()
	if s.token == token {
		s.token = ""
		s.refreshAt = time.Time{}
	}
}

func (s *cachingTokenSource) fetch(ctx context.Context) (string, time.Duration, time.Time, error) {
	var obtainedAt time.Time
	build := func(ctx context.Context) (*http.Request, []string, error) {
		obtainedAt = s.t.now()
		form := url.Values{
			"grant_type": {grantTypeClientCredentials},
			"expires_in": {strconv.FormatInt(int64(tokenLifetime/time.Second), 10)},
		}
		header := http.Header{}
		secrets, err := s.auth.authenticate(form, header, s.tokenURL, obtainedAt)
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req, secrets, nil
	}

	resp, err := s.t.send(ctx, "token", build, true)
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
	lifetime := tokenLifetime
	if d := parsePositiveSeconds(maxTokenLifetime, string(body.ExpiresIn), string(body.ExpiresInCamel)); d > 0 {
		lifetime = d
	}
	return token, lifetime, obtainedAt, nil
}

// parsePositiveSeconds returns the first positive number of seconds in values, at most limit.
func parsePositiveSeconds(limit time.Duration, values ...string) time.Duration {
	for _, v := range values {
		var secs int64
		if _, err := fmt.Sscan(v, &secs); err == nil && secs > 0 {
			return time.Duration(min(secs, int64(limit/time.Second))) * time.Second
		}
	}
	return 0
}

// staticTokenSource serves a fixed token; for tests and pre-issued tokens.
type staticTokenSource string

func (s staticTokenSource) Token(context.Context) (string, error) { return string(s), nil }
func (staticTokenSource) Invalidate(context.Context, string)      {}

// StaticTokenSource returns a TokenSource that always yields token.
func StaticTokenSource(token string) TokenSource {
	return staticTokenSource(token)
}
