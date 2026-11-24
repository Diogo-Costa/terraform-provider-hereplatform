package client

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Sized for IAM: five retries spanning up to ~30 s of backoff (longer when Retry-After
// asks for it), and polling that covers the documented five-minute convergence window.
const (
	defaultMaxAttempts   = 6
	defaultMinBackoff    = time.Second
	defaultMaxBackoff    = 30 * time.Second
	defaultMaxRetryAfter = 2 * time.Minute
	defaultPollMin       = 2 * time.Second
	defaultPollMax       = 15 * time.Second
	defaultPollTimeout   = 5 * time.Minute
	// maxRetryAfter caps Retry-After before conversion, which could overflow time.Duration;
	// any value above RetryPolicy.MaxRetryAfter fails the request anyway.
	maxRetryAfter = 24 * time.Hour
)

// RetryPolicy bounds transport-level retries of throttled, failed or unreachable requests.
type RetryPolicy struct {
	MaxAttempts   int
	MinBackoff    time.Duration
	MaxBackoff    time.Duration
	MaxRetryAfter time.Duration
}

// DefaultRetryPolicy returns the policy used when none is configured.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:   defaultMaxAttempts,
		MinBackoff:    defaultMinBackoff,
		MaxBackoff:    defaultMaxBackoff,
		MaxRetryAfter: defaultMaxRetryAfter,
	}
}

func (p RetryPolicy) withDefaults() RetryPolicy {
	d := DefaultRetryPolicy()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = d.MaxAttempts
	}
	if p.MinBackoff <= 0 {
		p.MinBackoff = d.MinBackoff
	}
	if p.MaxBackoff < p.MinBackoff {
		p.MaxBackoff = max(d.MaxBackoff, p.MinBackoff)
	}
	if p.MaxRetryAfter <= 0 {
		p.MaxRetryAfter = d.MaxRetryAfter
	}
	return p
}

// PollPolicy paces read-after-write polling while IAM converges (up to ~5 minutes).
type PollPolicy struct {
	MinInterval time.Duration
	MaxInterval time.Duration
	// DefaultTimeout bounds polling when the caller's context has no deadline.
	DefaultTimeout time.Duration
}

// DefaultPollPolicy returns the policy used when none is configured.
func DefaultPollPolicy() PollPolicy {
	return PollPolicy{
		MinInterval:    defaultPollMin,
		MaxInterval:    defaultPollMax,
		DefaultTimeout: defaultPollTimeout,
	}
}

func (p PollPolicy) withDefaults() PollPolicy {
	d := DefaultPollPolicy()
	if p.MinInterval <= 0 {
		p.MinInterval = d.MinInterval
	}
	if p.MaxInterval < p.MinInterval {
		p.MaxInterval = max(d.MaxInterval, p.MinInterval)
	}
	if p.DefaultTimeout <= 0 {
		p.DefaultTimeout = d.DefaultTimeout
	}
	return p
}

// expBackoff returns an exponentially growing delay with equal jitter, so concurrent
// Terraform operations hitting the same rate limit do not retry in lockstep.
func expBackoff(attempt int, minDelay, maxDelay time.Duration) time.Duration {
	d := minDelay
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	half := d / 2                //nolint:mnd // equal jitter splits the delay in two halves.
	return half + rand.N(half+1) //nolint:gosec // jitter does not need a CSPRNG.
}

// parseRetryAfter supports both delay-seconds and HTTP-date forms (RFC 9110 10.2.3).
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	// ParseInt returns the extreme value with ErrRange, which the clamp handles.
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second, true
	}
	if t, err := http.ParseTime(value); err == nil {
		return min(max(t.Sub(now), 0), maxRetryAfter), true
	}
	return 0, false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// exceedsDeadline avoids sleeping when the context would expire before the next attempt.
func exceedsDeadline(ctx context.Context, wait time.Duration) bool {
	deadline, ok := ctx.Deadline()
	return ok && time.Until(deadline) < wait
}

// isRetryableStatus retries throttled requests, which HERE did not process, and server
// failures of idempotent ones: a server failure, 503 included, may arrive after HERE applied
// a create, and replaying it could duplicate an app or take one of the two API key slots.
func isRetryableStatus(status int, idempotent bool) bool {
	return status == http.StatusTooManyRequests || idempotent && isServerFailure(status)
}

// isServerFailure matches 5xx responses other than those that fail every attempt.
func isServerFailure(status int) bool {
	return status >= http.StatusInternalServerError && status != http.StatusNotImplemented &&
		status != http.StatusHTTPVersionNotSupported
}

func isRetryableNetError(err error, idempotent bool) bool {
	if !idempotent {
		return isPreSendError(err)
	}
	if isPreSendError(err) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

// isPreSendError matches failures that happen before any byte reaches the server.
func isPreSendError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTimeout || dnsErr.IsTemporary
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
