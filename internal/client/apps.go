package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

const maxPageSize = 100

// App is a HERE app as returned by the Authentication API.
type App struct {
	HRN      string `json:"hrn"`
	ClientID string `json:"clientId"`
	// ID is the app ID in list responses, which omit clientId.
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Realm              string `json:"realm"`
	Status             string `json:"status"`
	AppCreationEnabled bool   `json:"appCreationEnabled"`
	CreatedTime        int64  `json:"createdTime"`
}

// AppClientID returns the client ID, falling back to the list-response ID.
func (a *App) AppClientID() string {
	return firstNonEmpty(a.ClientID, a.ID)
}

// CreateAppInput is the body of POST /apps.
type CreateAppInput struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// UpdateAppInput is the body of PATCH /apps/{app}; nil fields are left unchanged.
type UpdateAppInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type appPage struct {
	Items     []App  `json:"items"`
	PageToken string `json:"pageToken"`
}

// pageQuery asks for the largest page; list endpoints default to as few as 10 entries.
func pageQuery(pageToken string) string {
	q := url.Values{"limit": {strconv.Itoa(maxPageSize)}}
	if pageToken != "" {
		q.Set("pageToken", pageToken)
	}
	return q.Encode()
}

func appPath(appHRN string) string {
	return "/apps/" + PercentEncode(appHRN)
}

// CreateApp registers a new app. HERE answers 200 with the full app.
func (c *Client) CreateApp(ctx context.Context, in CreateAppInput) (*App, error) {
	var app App
	if _, err := c.do(ctx, request{method: http.MethodPost, path: "/apps", body: in}, &app); err != nil {
		return nil, err
	}
	if app.HRN == "" {
		return nil, fmt.Errorf("POST /apps: response has no app HRN")
	}
	return &app, nil
}

// GetApp fetches an app by HRN.
func (c *Client) GetApp(ctx context.Context, appHRN string) (*App, error) {
	var app App
	if _, err := c.do(ctx, request{method: http.MethodGet, path: appPath(appHRN), idempotent: true}, &app); err != nil {
		return nil, err
	}
	if app.HRN == "" {
		app.HRN = appHRN
	}
	return &app, nil
}

// UpdateApp patches an app's name and/or description.
func (c *Client) UpdateApp(ctx context.Context, appHRN string, in UpdateAppInput) (*App, error) {
	var app App
	r := request{method: http.MethodPatch, path: appPath(appHRN), body: in, idempotent: true}
	if _, err := c.do(ctx, r, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

// DeleteApp permanently deletes an app and its credentials.
func (c *Client) DeleteApp(ctx context.Context, appHRN string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: appPath(appHRN), idempotent: true}, nil)
	return err
}

// SetAppCreationEnabled toggles whether the app may create other apps.
func (c *Client) SetAppCreationEnabled(ctx context.Context, appHRN string, enabled bool) error {
	method := http.MethodDelete
	if enabled {
		method = http.MethodPut
	}
	_, err := c.do(ctx, request{method: method, path: appPath(appHRN) + "/appCreationEnabled", idempotent: true}, nil)
	return err
}

// ListApps walks every page of GET /apps. HERE filters the result by the caller's
// permissions, so apps the provider identity cannot read are silently absent.
func (c *Client) ListApps(ctx context.Context) ([]App, error) {
	var apps []App
	err := paginate(func(pageToken string) (string, error) {
		var page appPage
		r := request{method: http.MethodGet, path: "/apps", query: pageQuery(pageToken), idempotent: true}
		if _, err := c.do(ctx, r, &page); err != nil {
			return "", err
		}
		apps = append(apps, page.Items...)
		return page.PageToken, nil
	})
	return apps, err
}

// FindAppsByName returns the visible apps whose name matches exactly.
func (c *Client) FindAppsByName(ctx context.Context, name string) ([]App, error) {
	apps, err := c.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	var matches []App
	for _, app := range apps {
		if app.Name == name {
			matches = append(matches, app)
		}
	}
	return matches, nil
}

// paginate guards against a server echoing the same page token forever.
func paginate(fetch func(pageToken string) (string, error)) error {
	seen := map[string]bool{}
	token := ""
	for {
		next, err := fetch(token)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		if seen[next] {
			return fmt.Errorf("pagination did not advance")
		}
		seen[next] = true
		token = next
	}
}
