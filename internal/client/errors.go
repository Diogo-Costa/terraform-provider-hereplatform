package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxTitleLength = 300
	redacted       = "[REDACTED]"
)

// APIError carries only fields that are safe to surface: HERE error bodies may echo
// request details, so cause, action, details and raw bodies are deliberately dropped.
type APIError struct {
	StatusCode    int
	Code          string
	Title         string
	CorrelationID string
	Hint          string
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HERE API returned HTTP %d", e.StatusCode)
	if e.Code != "" {
		fmt.Fprintf(&b, " (code %s)", e.Code)
	}
	if e.Title != "" {
		fmt.Fprintf(&b, ": %s", e.Title)
	}
	if e.CorrelationID != "" {
		fmt.Fprintf(&b, " [correlation ID: %s]", e.CorrelationID)
	}
	if e.Hint != "" {
		fmt.Fprintf(&b, ". %s", e.Hint)
	}
	return b.String()
}

// flexString accepts JSON strings and numbers: HERE mixes legacy numeric errorCode
// values with string codes in the newer error format.
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

type errorBody struct {
	Title         string     `json:"title"`
	Message       string     `json:"message"`
	OAuthError    string     `json:"error"`
	Code          flexString `json:"code"`
	ErrorCode     flexString `json:"errorCode"`
	CorrelationID string     `json:"correlationId"`
}

var errorHints = map[string]string{
	"401204": "The request timestamp was rejected: check that the system clock is synchronized",
	"401207": "The OAuth nonce was rejected as already used: retry the operation",
	"401310": "Use the access key ID, not the client ID, as access_key_id",
	"409303": "HERE allows at most 2 API keys per app",
}

func newAPIError(resp *response, secrets ...string) *APIError {
	e := &APIError{StatusCode: resp.status}
	var body errorBody
	if json.Unmarshal(resp.body, &body) == nil {
		e.Code = string(body.Code)
		if e.Code == "" {
			e.Code = string(body.ErrorCode)
		}
		e.Title = firstNonEmpty(body.Title, body.Message, body.OAuthError)
		e.CorrelationID = body.CorrelationID
	}
	if e.Title == "" {
		e.Title = http.StatusText(resp.status)
	}
	if e.CorrelationID == "" {
		e.CorrelationID = resp.header.Get("X-Correlation-ID")
	}
	// Redacted before truncation, which could otherwise cut a secret beyond recognition.
	e.Title = truncate(redact(e.Title, secrets...), maxTitleLength)
	e.Code = truncate(redact(e.Code, secrets...), maxTitleLength)
	e.CorrelationID = truncate(redact(e.CorrelationID, secrets...), maxTitleLength)
	e.Hint = errorHints[e.Code]
	return e
}

// jwsPattern matches JWS compact serializations, the form of HERE access tokens and client
// assertions, so that an echoed token is redacted even when it is not one this client sent.
var jwsPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*){0,2}`)

func redact(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, redacted)
		}
	}
	return jwsPattern.ReplaceAllString(s, redacted)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// StatusCode returns the HTTP status of an *APIError in the chain, or 0.
func StatusCode(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// HasStatus reports whether err wraps an *APIError with one of the given statuses.
func HasStatus(err error, statuses ...int) bool {
	status := StatusCode(err)
	for _, s := range statuses {
		if status != 0 && status == s {
			return true
		}
	}
	return false
}

// IsNotFound reports whether err is an HTTP 404 from the HERE API.
func IsNotFound(err error) bool {
	return HasStatus(err, http.StatusNotFound)
}

// HasCode reports whether err wraps an *APIError with the given HERE error code.
func HasCode(err error, code int) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == strconv.Itoa(code)
}
