package client

import (
	"context"
	"fmt"
	"net/http"
)

// NeverExpires is the HERE sentinel for API keys without an expiry.
const NeverExpires int64 = -1

// APIKey is a HERE API key. Value is the plaintext credential (apiKeyId); HRN carries
// only an obfuscated form.
type APIKey struct {
	Value       string `json:"apiKeyId"`
	HRN         string `json:"apiKey"`
	Identity    string `json:"identity"`
	Realm       string `json:"realm"`
	Name        string `json:"name"`
	Enabled     *bool  `json:"enabled"`
	CreatedTime int64  `json:"createdTime"`
	ExpiresAt   *int64 `json:"expiresAt"`
}

// String keeps the plaintext key out of accidental %v / %+v formatting.
func (k APIKey) String() string {
	return fmt.Sprintf("APIKey{HRN: %s, Name: %q, Value: %s}", k.HRN, k.Name, redacted)
}

// GoString keeps the plaintext key out of %#v formatting.
func (k APIKey) GoString() string { return k.String() }

// IsEnabled applies the documented default (true) when the field is omitted.
func (k *APIKey) IsEnabled() bool {
	return k.Enabled == nil || *k.Enabled
}

// Expiry returns the expiry in Unix milliseconds, or NeverExpires.
func (k *APIKey) Expiry() int64 {
	if k.ExpiresAt == nil || *k.ExpiresAt <= 0 {
		return NeverExpires
	}
	return *k.ExpiresAt
}

// CreateAPIKeyInput is the body of POST /apps/{app}/apiKeys.
type CreateAPIKeyInput struct {
	Name      string `json:"name"`
	ExpiresAt *int64 `json:"expiresAt,omitempty"`
	Enabled   *bool  `json:"enabled,omitempty"`
}

// UpdateAPIKeyInput is the body of PATCH /apps/{app}/apiKeys/{apiKey}.
type UpdateAPIKeyInput struct {
	Name      string `json:"name"`
	ExpiresAt int64  `json:"expiresAt"`
}

type apiKeyPage struct {
	Items     []APIKey `json:"items"`
	PageToken string   `json:"pageToken"`
}

func apiKeyPath(appHRN, keyHRN string) string {
	return appPath(appHRN) + "/apiKeys/" + PercentEncode(keyHRN)
}

// CreateAPIKey generates a key. HERE caps apps at two keys (HTTP 409, code 409303).
func (c *Client) CreateAPIKey(ctx context.Context, appHRN string, in CreateAPIKeyInput) (*APIKey, error) {
	var key APIKey
	if _, err := c.do(ctx, request{method: http.MethodPost, path: appPath(appHRN) + "/apiKeys", body: in}, &key); err != nil {
		return nil, err
	}
	if key.HRN == "" {
		return nil, fmt.Errorf("POST /apps/{app}/apiKeys: response has no API key HRN")
	}
	return &key, nil
}

// GetAPIKey fetches a key, including its plaintext value.
func (c *Client) GetAPIKey(ctx context.Context, appHRN, keyHRN string) (*APIKey, error) {
	var key APIKey
	if _, err := c.do(ctx, request{method: http.MethodGet, path: apiKeyPath(appHRN, keyHRN), idempotent: true}, &key); err != nil {
		return nil, err
	}
	if key.HRN == "" {
		key.HRN = keyHRN
	}
	return &key, nil
}

// ListAPIKeys returns every key of an app.
func (c *Client) ListAPIKeys(ctx context.Context, appHRN string) ([]APIKey, error) {
	var keys []APIKey
	err := paginate(func(pageToken string) (string, error) {
		var page apiKeyPage
		r := request{method: http.MethodGet, path: appPath(appHRN) + "/apiKeys", query: pageQuery(pageToken), idempotent: true}
		if _, err := c.do(ctx, r, &page); err != nil {
			return "", err
		}
		keys = append(keys, page.Items...)
		return page.PageToken, nil
	})
	return keys, err
}

// UpdateAPIKey sets a key's name and expiry (NeverExpires clears it).
func (c *Client) UpdateAPIKey(ctx context.Context, appHRN, keyHRN string, in UpdateAPIKeyInput) (*APIKey, error) {
	var key APIKey
	r := request{method: http.MethodPatch, path: apiKeyPath(appHRN, keyHRN), body: in, idempotent: true}
	if _, err := c.do(ctx, r, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// SetAPIKeyEnabled enables or disables a key.
func (c *Client) SetAPIKeyEnabled(ctx context.Context, appHRN, keyHRN string, enabled bool) error {
	action := "/disable"
	if enabled {
		action = "/enable"
	}
	_, err := c.do(ctx, request{method: http.MethodPost, path: apiKeyPath(appHRN, keyHRN) + action, idempotent: true}, nil)
	return err
}

// DeleteAPIKey permanently deletes a key.
func (c *Client) DeleteAPIKey(ctx context.Context, appHRN, keyHRN string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: apiKeyPath(appHRN, keyHRN), idempotent: true}, nil)
	return err
}
