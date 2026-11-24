package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// MaxTrustedDomainsPerRequest is the HERE batch limit for bulk add and delete.
const MaxTrustedDomainsPerRequest = 10

// DomainFailure is one rejected entry of a 207 Multi-Status response. Status is either
// an HTTP status or a six-digit HERE error code such as 400367.
type DomainFailure struct {
	Domain string
	Status int
}

// PartialFailureError reports entries HERE rejected while accepting the rest.
type PartialFailureError struct {
	Operation string
	Failures  []DomainFailure
}

func (e *PartialFailureError) Error() string {
	parts := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		parts[i] = fmt.Sprintf("%q (status %d)", f.Domain, f.Status)
	}
	return fmt.Sprintf("HERE rejected %d trusted domain(s) while %s: %s", len(e.Failures), e.Operation, strings.Join(parts, ", "))
}

type domainResult struct {
	TrustedDomain string `json:"trustedDomain"`
	Status        int    `json:"status"`
}

type domainResultPage struct {
	Items []domainResult `json:"items"`
}

type domainPage struct {
	Items     []string `json:"items"`
	PageToken string   `json:"pageToken"`
}

type trustedDomainsEnabled struct {
	TrustedDomainsEnabled bool `json:"trustedDomainsEnabled"`
}

// ListTrustedDomains returns every trusted domain of an app.
func (c *Client) ListTrustedDomains(ctx context.Context, appHRN string) ([]string, error) {
	var domains []string
	err := paginate(func(pageToken string) (string, error) {
		var page domainPage
		r := request{method: http.MethodGet, path: appPath(appHRN) + "/trustedDomains", query: pageQuery(pageToken), idempotent: true}
		if _, err := c.do(ctx, r, &page); err != nil {
			return "", err
		}
		domains = append(domains, page.Items...)
		return page.PageToken, nil
	})
	return domains, err
}

// AddTrustedDomains adds domains in batches. Rejected entries are collected into a
// *PartialFailureError after all batches ran.
func (c *Client) AddTrustedDomains(ctx context.Context, appHRN string, domains []string) error {
	return c.domainBatches(ctx, domains, "adding", func(batch []string) (*response, error) {
		r := request{
			method: http.MethodPost, path: appPath(appHRN) + "/trustedDomains",
			body: map[string][]string{"data": batch}, idempotent: true,
		}
		return c.do(ctx, r, nil)
	})
}

// RemoveTrustedDomains deletes domains in batches; entries already absent count as removed.
func (c *Client) RemoveTrustedDomains(ctx context.Context, appHRN string, domains []string) error {
	return c.domainBatches(ctx, domains, "removing", func(batch []string) (*response, error) {
		encoded := make([]string, len(batch))
		for i, d := range batch {
			encoded[i] = PercentEncode(d)
		}
		// Commas stay literal: they separate entries, so each entry is encoded on its own.
		r := request{
			method: http.MethodDelete, path: appPath(appHRN) + "/trustedDomains",
			query: "list=" + strings.Join(encoded, ","), idempotent: true,
		}
		return c.do(ctx, r, nil)
	})
}

func (c *Client) domainBatches(ctx context.Context, domains []string, op string, send func([]string) (*response, error)) error {
	var failures []DomainFailure
	for start := 0; start < len(domains); start += MaxTrustedDomainsPerRequest {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch := domains[start:min(start+MaxTrustedDomainsPerRequest, len(domains))]
		resp, err := send(batch)
		if err != nil {
			return err
		}
		if resp.status != http.StatusMultiStatus {
			continue
		}
		failures = append(failures, multiStatusFailures(resp.body, batch, op == "removing")...)
	}
	if len(failures) > 0 {
		return &PartialFailureError{Operation: op, Failures: failures}
	}
	return nil
}

func multiStatusFailures(body []byte, batch []string, removing bool) []DomainFailure {
	var page domainResultPage
	if err := json.Unmarshal(body, &page); err != nil || len(page.Items) == 0 {
		failures := make([]DomainFailure, len(batch))
		for i, d := range batch {
			failures[i] = DomainFailure{Domain: d, Status: http.StatusMultiStatus}
		}
		return failures
	}
	var failures []DomainFailure
	for _, item := range page.Items {
		if domainResultOK(item.Status, removing) {
			continue
		}
		failures = append(failures, DomainFailure{Domain: item.TrustedDomain, Status: item.Status})
	}
	return failures
}

func domainResultOK(status int, removing bool) bool {
	if status >= 200 && status < 300 {
		return true
	}
	// HERE codes are the HTTP status followed by three digits (404660). Absent entries count
	// as removed and, as an undocumented assumption, conflicting ones as already added.
	expected := http.StatusConflict
	if removing {
		expected = http.StatusNotFound
	}
	return status == expected || status/1000 == expected
}

// TrustedDomainsEnabled reports whether trusted-domain enforcement is on.
func (c *Client) TrustedDomainsEnabled(ctx context.Context, appHRN string) (bool, error) {
	var out trustedDomainsEnabled
	r := request{method: http.MethodGet, path: appPath(appHRN) + "/trustedDomainsEnabled", idempotent: true}
	if _, err := c.do(ctx, r, &out); err != nil {
		return false, err
	}
	return out.TrustedDomainsEnabled, nil
}

// SetTrustedDomainsEnabled toggles trusted-domain enforcement.
func (c *Client) SetTrustedDomainsEnabled(ctx context.Context, appHRN string, enabled bool) error {
	method := http.MethodDelete
	if enabled {
		method = http.MethodPut
	}
	_, err := c.do(ctx, request{method: method, path: appPath(appHRN) + "/trustedDomainsEnabled", idempotent: true}, nil)
	return err
}
