package provider

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-log/tflogtest"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

// CI logs of this public repository are public (W-10). The fake echoes credentials back in
// error bodies; none may reach diagnostics or logs, so failures name only the kind of secret.

var (
	// Allows "Bearer [REDACTED]".
	bearerCredential = regexp.MustCompile(`(?i)bearer\s+[^\s\[]`)
	// Logs carry no bodies or headers, so none of these words may appear in them.
	logOnlyForbidden = regexp.MustCompile(`(?i)bearer|authorization|client_assertion|access_token|apikeyid|private`)
)

type secretKind struct {
	kind   string
	values []string
}

func knownSecrets(f *fakeHERE) []secretKind {
	tokens, assertions, keyValues := f.secrets()
	var signatures []string
	for _, a := range assertions {
		if i := strings.LastIndexByte(a, '.'); i >= 0 {
			signatures = append(signatures, a[i+1:])
		}
	}
	var pemLines []string
	for line := range strings.Lines(f.pem) {
		// Short lines could match by chance; the full-length ones cover the key.
		if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") {
			pemLines = append(pemLines, line)
		}
	}
	return []secretKind{
		{"an access token", tokens},
		{"a client assertion", assertions},
		{"a client assertion signature", signatures},
		{"an API key value", keyValues},
		{"private key material", pemLines},
	}
}

func requireNoSecrets(t *testing.T, f *fakeHERE, where, text string) {
	t.Helper()
	var leaks []string
	for _, s := range knownSecrets(f) {
		if len(s.values) == 0 && s.kind != "a client assertion signature" {
			t.Errorf("the fake recorded no %s: the scan of %s would be vacuous", strings.TrimPrefix(s.kind, "a "), where)
		}
		if slices.ContainsFunc(s.values, func(v string) bool { return v != "" && strings.Contains(text, v) }) {
			leaks = append(leaks, s.kind)
		}
	}
	if strings.Contains(text, "PRIVATE KEY") {
		leaks = append(leaks, "a PEM header")
	}
	if bearerCredential.MatchString(text) {
		leaks = append(leaks, "a bearer credential")
	}
	if len(leaks) > 0 {
		t.Errorf("%s contain %s", where, strings.Join(leaks, ", "))
	}
}

// scrub replaces every known secret, so that unexpected errors stay printable.
func scrub(f *fakeHERE, text string) string {
	for _, s := range knownSecrets(f) {
		for _, v := range s.values {
			if v != "" {
				text = strings.ReplaceAll(text, v, "<"+s.kind+">")
			}
		}
	}
	return text
}

// echoAssertion rejects token requests, repeating the client assertion in every field.
func echoAssertion(field string) fakeHook {
	return func(c fakeCall) (fakeReply, bool) {
		if c.Route != routeToken {
			return fakeReply{}, false
		}
		form, _ := url.ParseQuery(string(c.Body))
		a := form.Get("client_assertion")
		body := map[string]any{"error": "invalid_client", "error_description": "Rejected client_assertion=" + a}
		body[field] = "Rejected " + a
		return fakeReply{status: http.StatusUnauthorized, body: body}, true
	}
}

// echoCredentials answers the next calls of route, one per status, with errors that repeat
// the caller's bearer token and, for key routes, the key value.
func (f *fakeHERE) echoCredentials(route string, statuses ...int) fakeHook {
	return func(c fakeCall) (fakeReply, bool) {
		if c.Route != route || len(statuses) == 0 {
			return fakeReply{}, false
		}
		status := statuses[0]
		statuses = statuses[1:]
		echoed := "Authorization: Bearer " + c.Token
		// Hooks run under the fake's lock, so the store is read directly.
		if a := f.find(c.App); a != nil && c.Key != "" {
			k := a.findKey(c.Key)
			if k == nil {
				return fakeReply{}, false
			}
			echoed += " apiKeyId=" + k.Value
		}
		r := hereError(status, "400200", "Rejected Bearer "+c.Token)
		body, _ := r.body.(map[string]any)
		body["cause"], body["action"] = echoed, echoed
		body["details"] = []any{map[string]any{"request": echoed}}
		return r, true
	}
}

func TestSecretHygieneDiagnostics(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var want *regexp.Regexp
	var captured []string
	fails := func(pattern string, hooks ...fakeHook) func() {
		return func() {
			f.clearHooks()
			f.hook(hooks...)
			want = regexp.MustCompile(pattern)
		}
	}
	succeeds := func() {
		f.clearHooks()
		want = nil
	}
	const redactedBearer = `[\s\S]*Rejected\s+Bearer\s+\[REDACTED\]`

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		// ExpectError prints an unmatched error verbatim; this prints it scrubbed.
		ErrorCheck: func(err error) error {
			if want == nil || !want.MatchString(err.Error()) {
				return errors.New("unexpected error: " + scrub(f, err.Error()))
			}
			captured = append(captured, err.Error())
			return nil
		},
		Steps: []tfresource.TestStep{
			{
				PreConfig: fails(`Unable\s+to\s+create\s+HERE\s+app[\s\S]*requesting\s+HERE\s+access\s+token[\s\S]*HTTP\s+401`,
					echoAssertion("message")),
				Config: appConfig("tfacc-hygiene", unprotected),
			},
			{
				PreConfig: fails(`Unable\s+to\s+create\s+HERE\s+app`+redactedBearer, f.echoCredentials(routeCreateApp, http.StatusForbidden)),
				Config:    appConfig("tfacc-hygiene", unprotected),
			},
			{
				PreConfig: succeeds,
				Config:    keyConfig(`name = "primary"`),
			},
			{
				PreConfig: fails(`Unable\s+to\s+update\s+HERE\s+API\s+key`+redactedBearer, f.echoCredentials(routePatchKey, http.StatusBadRequest)),
				Config:    keyConfig(`name = "renamed"`),
			},
			{
				PreConfig: fails(`Unable\s+to\s+read\s+HERE\s+API\s+key`+redactedBearer, f.echoCredentials(routeGetKey, http.StatusBadRequest)),
				Config:    keyConfig(`name = "renamed"`),
			},
			{
				PreConfig: succeeds,
				Config:    keyConfig(`name = "renamed"`),
			},
		},
	})

	if len(captured) != 4 {
		t.Fatalf("%d steps failed as designed, want 4", len(captured))
	}
	requireNoSecrets(t, f, "diagnostics", strings.Join(captured, "\n"))
}

func TestSecretHygieneLogs(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.pageSize = 1 })
	f.seedApp("tfacc-other")
	var logs bytes.Buffer
	ctx := tflogtest.RootLogger(t.Context(), &logs)
	c := f.client(t)
	var failures []string
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected client error: %s", scrub(f, err.Error()))
		}
	}
	mustFail := func(err error) {
		t.Helper()
		if err == nil {
			t.Fatal("want an error")
		}
		failures = append(failures, err.Error())
	}

	// A 404 then a 429 exercise the convergence and transport retry logs.
	f.hook(sequence(routeGetApp, notFound(), fakeReply{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "0"}}))
	app, err := c.CreateApp(ctx, client.CreateAppInput{Name: "tfacc-logs", Description: "Logged."})
	must(err)
	_, err = c.WaitForApp(ctx, app.HRN)
	must(err)
	name := "tfacc-logs-renamed"
	_, err = c.UpdateApp(ctx, app.HRN, client.UpdateAppInput{Name: &name})
	must(err)
	must(c.SetAppCreationEnabled(ctx, app.HRN, true))
	_, err = c.FindAppsByName(ctx, name)
	must(err)

	key, err := c.CreateAPIKey(ctx, app.HRN, client.CreateAPIKeyInput{Name: "primary"})
	must(err)
	_, err = c.WaitForAPIKey(ctx, app.HRN, key.HRN)
	must(err)
	_, err = c.UpdateAPIKey(ctx, app.HRN, key.HRN, client.UpdateAPIKeyInput{Name: "renamed", ExpiresAt: client.NeverExpires})
	must(err)
	must(c.SetAPIKeyEnabled(ctx, app.HRN, key.HRN, false))

	domains := numberedDomains("logs", 12)
	must(c.AddTrustedDomains(ctx, app.HRN, domains))
	must(c.SetTrustedDomainsEnabled(ctx, app.HRN, true))
	_, err = c.ListTrustedDomains(ctx, app.HRN)
	must(err)
	_, err = c.TrustedDomainsEnabled(ctx, app.HRN)
	must(err)
	must(c.RemoveTrustedDomains(ctx, app.HRN, domains))

	// The 401 makes the client fetch a second token, which the redaction must cover too.
	f.hook(f.echoCredentials(routeDeleteKey, http.StatusUnauthorized, http.StatusConflict))
	mustFail(c.DeleteAPIKey(ctx, app.HRN, key.HRN))
	f.clearHooks()
	must(c.DeleteAPIKey(ctx, app.HRN, key.HRN))
	must(c.DeleteApp(ctx, app.HRN))

	f.hook(echoAssertion("error"))
	_, err = f.client(t).ListApps(ctx)
	mustFail(err)

	entries, err := tflogtest.MultilineJSONDecode(bytes.NewReader(logs.Bytes()))
	if err != nil {
		t.Fatalf("logs are not JSON lines: %v", err)
	}
	messages := map[string]int{}
	var fields []string
	for _, e := range entries {
		m, _ := e["@message"].(string)
		messages[m]++
		for k, v := range e {
			// The caller is a source path, which varies with the checkout location.
			if k != "@caller" {
				s, _ := v.(string)
				fields = append(fields, k, s)
			}
		}
	}
	for _, m := range []string{"HERE API request", "HERE API response", "Retrying HERE API request", "Retrying while HERE IAM converges"} {
		if messages[m] == 0 {
			t.Errorf("no %q log entry: the scan would be vacuous", m)
		}
	}
	if n := len(f.callsOf(routeToken)); n != 3 {
		t.Errorf("%d token requests, want 3: the first, the refresh after the 401 and the rejected one", n)
	}
	requireNoSecrets(t, f, "logs", logs.String())
	if w := logOnlyForbidden.FindString(strings.Join(fields, " ")); w != "" {
		t.Errorf("logs mention %q", w)
	}
	requireNoSecrets(t, f, "client errors", strings.Join(failures, "\n"))
	if n := strings.Count(strings.Join(failures, "\n"), "Rejected Bearer [REDACTED]"); n != 1 {
		t.Errorf("%d redacted bearer tokens in client errors, want 1", n)
	}
}
