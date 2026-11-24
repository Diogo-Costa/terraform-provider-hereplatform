package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	// DefaultTokenURL is the HERE OAuth 2.0 token endpoint.
	DefaultTokenURL = "https://account.api.here.com/oauth2/token" //nolint:gosec // a public endpoint, not a credential.
	// DefaultAPIURL is the base URL of the HERE Authentication API v1.1.
	DefaultAPIURL = "https://account.api.here.com/authentication/v1.1"

	schemeHTTP  = "http"
	schemeHTTPS = "https"
	hereHost    = "account.api.here.com"

	logKeyOperation = "operation"

	defaultHTTPTimeout = 60 * time.Second
	maxResponseBytes   = 8 << 20
)

// Config configures a Client. Zero values select production defaults.
type Config struct {
	APIURL   string
	TokenURL string
	// Auth authenticates token requests; ignored when TokenSource is set.
	Auth        Auth
	TokenSource TokenSource
	HTTPClient  *http.Client
	UserAgent   string
	Retry       RetryPolicy
	Poll        PollPolicy
	Now         func() time.Time
	Sleep       func(context.Context, time.Duration) error
	// AllowCustomEndpoints accepts HTTPS hosts other than HERE's; see ValidateEndpoint.
	AllowCustomEndpoints bool
}

// Client calls the HERE Authentication API v1.1. It is safe for concurrent use.
type Client struct {
	apiURL string
	tokens TokenSource
	t      *transport
	poll   PollPolicy
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	apiURL := strings.TrimRight(firstNonEmpty(cfg.APIURL, DefaultAPIURL), "/")
	if err := checkEndpoint(apiURL, cfg.AllowCustomEndpoints); err != nil {
		return nil, fmt.Errorf("invalid API URL: %w", err)
	}
	tokenURL := firstNonEmpty(cfg.TokenURL, DefaultTokenURL)
	if err := checkEndpoint(tokenURL, cfg.AllowCustomEndpoints); err != nil {
		return nil, fmt.Errorf("invalid token URL: %w", err)
	}

	t := &transport{
		http:      cfg.HTTPClient,
		userAgent: firstNonEmpty(cfg.UserAgent, "terraform-provider-hereplatform/dev"),
		retry:     cfg.Retry.withDefaults(),
		now:       cfg.Now,
		sleep:     cfg.Sleep,
	}
	if t.http == nil {
		t.http = &http.Client{
			Timeout: defaultHTTPTimeout,
			// Never forward bearer tokens or signed requests to another location.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	if t.now == nil {
		t.now = time.Now
	}
	if t.sleep == nil {
		t.sleep = sleepContext
	}

	tokens := cfg.TokenSource
	if tokens == nil {
		if cfg.Auth == nil {
			return nil, errors.New("no client authentication configured")
		}
		tokens = newCachingTokenSource(cfg.Auth, tokenURL, t)
	}
	return &Client{apiURL: apiURL, tokens: tokens, t: t, poll: cfg.Poll.withDefaults()}, nil
}

// ErrCustomEndpoint marks a well-formed HTTPS URL outside HERE. Both endpoints receive
// credentials that can manage every app the provider reaches, so other hosts need an
// explicit opt-in.
var ErrCustomEndpoint = errors.New("not a HERE endpoint")

// ValidateEndpoint accepts HTTPS URLs of account.api.here.com, and HTTP or HTTPS URLs of
// literal loopback IP addresses for test servers; host names such as localhost can resolve
// elsewhere. Other HTTPS hosts get ErrCustomEndpoint.
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("not a valid URL")
	}
	switch {
	case u.Host == "":
		return errors.New("an absolute URL with a host is required")
	case u.User != nil:
		return errors.New("user information is not allowed in the URL")
	case u.RawQuery != "" || u.Fragment != "":
		return errors.New("query strings and fragments are not allowed")
	case u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	case isLoopbackIP(u.Hostname()):
		return nil
	case u.Scheme == schemeHTTP:
		return errors.New("HTTPS is required (plain HTTP is accepted only for literal loopback IP addresses)")
	case strings.EqualFold(u.Hostname(), hereHost) && (u.Port() == "" || u.Port() == "443"):
		return nil
	default:
		return fmt.Errorf("%w: %s is neither %s nor a literal loopback IP address", ErrCustomEndpoint, u.Host, hereHost)
	}
}

func checkEndpoint(raw string, allowCustom bool) error {
	if err := ValidateEndpoint(raw); err != nil && (!allowCustom || !errors.Is(err, ErrCustomEndpoint)) {
		return err
	}
	return nil
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type response struct {
	status int
	header http.Header
	body   []byte
}

type transport struct {
	http      *http.Client
	userAgent string
	retry     RetryPolicy
	now       func() time.Time
	sleep     func(context.Context, time.Duration) error
}

// send runs build once per attempt so each retry carries fresh signatures and tokens.
// Bodies are never logged: they can contain tokens, assertions or API key values.
func (t *transport) send(
	ctx context.Context,
	op string,
	build func(context.Context) (*http.Request, error),
	idempotent bool,
	secrets ...string,
) (*response, error) {
	for attempt := 1; ; attempt++ {
		req, err := build(ctx)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", t.userAgent)
		req.Header.Set("Accept", "application/json")
		tflog.Debug(ctx, "HERE API request", map[string]any{
			logKeyOperation: op, "method": req.Method, "path": req.URL.EscapedPath(), "attempt": attempt,
		})

		httpResp, err := t.http.Do(req)
		var resp *response
		if err == nil {
			resp, err = readResponse(httpResp)
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, fmt.Errorf("%s: %w", op, ctxErr)
			}
			if attempt < t.retry.MaxAttempts && isRetryableNetError(err, idempotent) {
				wait := expBackoff(attempt, t.retry.MinBackoff, t.retry.MaxBackoff)
				if t.wait(ctx, op, wait, "network error") {
					continue
				}
			}
			return nil, err
		}

		tflog.Debug(ctx, "HERE API response", map[string]any{
			logKeyOperation: op, "status": resp.status, "correlation_id": resp.header.Get("X-Correlation-ID"),
		})
		if resp.status >= 200 && resp.status < 300 {
			return resp, nil
		}
		apiErr := newAPIError(resp, secrets...)
		if attempt < t.retry.MaxAttempts && isRetryableStatus(resp.status, idempotent) {
			wait, ok := parseRetryAfter(resp.header.Get("Retry-After"), t.now())
			if !ok {
				wait = expBackoff(attempt, t.retry.MinBackoff, t.retry.MaxBackoff)
			}
			if wait <= t.retry.MaxRetryAfter && t.wait(ctx, op, wait, fmt.Sprintf("HTTP %d", resp.status)) {
				continue
			}
		}
		return nil, apiErr
	}
}

func (t *transport) wait(ctx context.Context, op string, d time.Duration, reason string) bool {
	if exceedsDeadline(ctx, d) {
		return false
	}
	tflog.Debug(ctx, "Retrying HERE API request", map[string]any{logKeyOperation: op, "reason": reason, "wait": d.String()})
	return t.sleep(ctx, d) == nil
}

func readResponse(r *http.Response) (*response, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	return &response{status: r.StatusCode, header: r.Header, body: body}, nil
}

type request struct {
	method string
	// path is relative to the API URL and already percent-encoded.
	path  string
	query string
	body  any
	// idempotent is false for creates, which are only replayed when HERE cannot have applied them.
	idempotent bool
}

func (c *Client) do(ctx context.Context, r request, out any) (*response, error) {
	var payload []byte
	if r.body != nil {
		b, err := json.Marshal(r.body)
		if err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
		payload = b
	}
	target := c.apiURL + r.path
	if r.query != "" {
		target += "?" + r.query
	}
	op := r.method + " " + r.path

	var token string
	var usedTokens []string
	build := func(ctx context.Context) (*http.Request, error) {
		tok, err := c.tokens.Token(ctx)
		if err != nil {
			return nil, err
		}
		token = tok
		usedTokens = append(usedTokens, tok)
		var body io.Reader
		if payload != nil {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, r.method, target, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, nil
	}

	resp, err := c.t.send(ctx, op, build, r.idempotent)
	// token is empty when the token endpoint itself failed; only an API 401 warrants a refresh.
	if token != "" && HasStatus(err, http.StatusUnauthorized) {
		c.tokens.Invalidate(token)
		resp, err = c.t.send(ctx, op, build, r.idempotent)
	}
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			apiErr.Title = redact(apiErr.Title, usedTokens...)
		}
		return nil, err
	}
	if out != nil && len(bytes.TrimSpace(resp.body)) > 0 {
		if json.Unmarshal(resp.body, out) != nil {
			return nil, fmt.Errorf("%s: response is not valid JSON", op)
		}
	}
	return resp, nil
}
