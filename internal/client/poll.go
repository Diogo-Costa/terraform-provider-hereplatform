package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Retry runs op until it succeeds or fails with an error retryable rejects. It backs off
// per the poll policy and gives up when ctx ends, or after the default poll timeout when
// ctx has no deadline; the last retryable error is then wrapped.
func (c *Client) Retry(ctx context.Context, what string, retryable func(error) bool, op func(context.Context) error) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.poll.DefaultTimeout)
		defer cancel()
	}
	var last error
	for attempt := 1; ; attempt++ {
		err := op(ctx)
		switch {
		case err == nil:
			return nil
		// The create may have succeeded, which outranks the errors that led to it.
		case IsUnconfirmed(err):
			return err
		case ctx.Err() != nil && last != nil:
			return fmt.Errorf("timed out waiting for %s: %w", what, last)
		case !retryable(err):
			return err
		}
		last = err
		wait := expBackoff(attempt, c.poll.MinInterval, c.poll.MaxInterval)
		if exceedsDeadline(ctx, wait) || c.t.sleep(ctx, wait) != nil {
			return fmt.Errorf("timed out waiting for %s: %w", what, last)
		}
		tflog.Debug(ctx, "Retrying while HERE IAM converges", map[string]any{
			"target": what, "attempt": attempt, "status": StatusCode(err),
		})
	}
}

// WaitForApp polls until a newly created app is readable. A 403 is tolerated too: the
// creator's permissions on the new app propagate like any other IAM change.
func (c *Client) WaitForApp(ctx context.Context, appHRN string) (*App, error) {
	var app *App
	err := c.Retry(ctx, "app "+appHRN+" to become visible", func(err error) bool {
		return HasStatus(err, http.StatusNotFound, http.StatusForbidden)
	}, func(ctx context.Context) error {
		var err error
		app, err = c.GetApp(ctx, appHRN)
		return err
	})
	return app, err
}

// WaitForAPIKey polls until a newly created API key is readable.
func (c *Client) WaitForAPIKey(ctx context.Context, appHRN, keyHRN string) (*APIKey, error) {
	var key *APIKey
	err := c.Retry(ctx, "API key "+keyHRN+" to become visible", IsNotFound, func(ctx context.Context) error {
		var err error
		key, err = c.GetAPIKey(ctx, appHRN, keyHRN)
		return err
	})
	return key, err
}
