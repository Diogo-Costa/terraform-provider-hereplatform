package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestListAppsPaginates(t *testing.T) {
	c, rec, _ := newTestClient(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 1 {
			writeJSON(w, http.StatusOK, `{"items":[{"hrn":"hrn:a","id":"a","name":"dup"},{"hrn":"hrn:b","id":"b","name":"other"}],"pageToken":"p2","total":3}`)
			return
		}
		writeJSON(w, http.StatusOK, `{"items":[{"hrn":"hrn:c","id":"c","name":"dup"}],"total":3}`)
	})
	apps, err := c.FindAppsByName(t.Context(), "dup")
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 2 || apps[0].AppClientID() != "a" || apps[1].HRN != "hrn:c" {
		t.Fatalf("unexpected matches %+v", apps)
	}
	reqs := rec.Requests()
	if len(reqs) != 2 || reqs[0].RequestURI != apiPrefix+"/apps?limit=100" ||
		reqs[1].RequestURI != apiPrefix+"/apps?limit=100&pageToken=p2" {
		t.Fatalf("unexpected requests %+v", reqs)
	}
}

func TestPaginationMustAdvance(t *testing.T) {
	c, _, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"items":[],"pageToken":"same"}`)
	})
	if _, err := c.ListApps(t.Context()); err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("expected a pagination error, got %v", err)
	}
}

func TestCreateAppRequiresHRN(t *testing.T) {
	c, _, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, `{"name":"x"}`)
	})
	if _, err := c.CreateApp(t.Context(), CreateAppInput{Name: "x"}); err == nil {
		t.Fatal("expected an error for a response without an HRN")
	}
}

func TestAppRequests(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			writeJSON(w, http.StatusOK, appJSON)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	desc := ""
	if _, err := c.UpdateApp(t.Context(), testAppHRN, UpdateAppInput{Description: &desc}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAppCreationEnabled(t.Context(), testAppHRN, true); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAppCreationEnabled(t.Context(), testAppHRN, false); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteApp(t.Context(), testAppHRN); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PATCH " + apiPrefix + "/apps/" + encodedAppHRN + ` {"description":""}`,
		"PUT " + apiPrefix + "/apps/" + encodedAppHRN + "/appCreationEnabled ",
		"DELETE " + apiPrefix + "/apps/" + encodedAppHRN + "/appCreationEnabled ",
		"DELETE " + apiPrefix + "/apps/" + encodedAppHRN + " ",
	}
	for i, r := range rec.Requests() {
		if got := r.Method + " " + r.RequestURI + " " + r.Body; got != want[i] {
			t.Errorf("request %d = %q, want %q", i, got, want[i])
		}
	}
}

const apiKeyJSON = `{"apiKeyId":"PLAINTEXT-KEY-VALUE","apiKey":"` + testKeyHRN + `","identity":"` + testAppHRN + `",` +
	`"realm":"hrn:here:account::realm1:realm/realm1","name":"k1","enabled":true,"createdTime":1700000000000,"expiresAt":-1}`

func TestAPIKeyRequests(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if strings.HasSuffix(r.URL.EscapedPath(), "/apiKeys") {
				writeJSON(w, http.StatusCreated, apiKeyJSON)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			writeJSON(w, http.StatusOK, `{"items":[`+apiKeyJSON+`]}`)
		case http.MethodPatch:
			writeJSON(w, http.StatusOK, apiKeyJSON)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	expiry := int64(1900000000000)
	key, err := c.CreateAPIKey(t.Context(), testAppHRN, CreateAPIKeyInput{Name: "k1", ExpiresAt: &expiry})
	if err != nil {
		t.Fatal(err)
	}
	if key.Value != "PLAINTEXT-KEY-VALUE" || key.HRN != testKeyHRN || !key.IsEnabled() || key.Expiry() != NeverExpires {
		t.Fatalf("unexpected key %v", key)
	}
	keys, err := c.ListAPIKeys(t.Context(), testAppHRN)
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListAPIKeys = %v, %v", keys, err)
	}
	if _, err := c.UpdateAPIKey(t.Context(), testAppHRN, testKeyHRN, UpdateAPIKeyInput{Name: "k2", ExpiresAt: NeverExpires}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAPIKeyEnabled(t.Context(), testAppHRN, testKeyHRN, true); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteAPIKey(t.Context(), testAppHRN, testKeyHRN); err != nil {
		t.Fatal(err)
	}
	keyPath := apiPrefix + "/apps/" + encodedAppHRN + "/apiKeys"
	want := []string{
		"POST " + keyPath + ` {"name":"k1","expiresAt":1900000000000}`,
		"GET " + keyPath + "?limit=100 ",
		"PATCH " + keyPath + "/" + encodedKeyHRN + ` {"name":"k2","expiresAt":-1}`,
		"POST " + keyPath + "/" + encodedKeyHRN + "/enable ",
		"DELETE " + keyPath + "/" + encodedKeyHRN + " ",
	}
	for i, r := range rec.Requests() {
		if got := r.Method + " " + r.RequestURI + " " + r.Body; got != want[i] {
			t.Errorf("request %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestAPIKeyValueIsNeverFormatted(t *testing.T) {
	var key APIKey
	if err := json.Unmarshal([]byte(apiKeyJSON), &key); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{key, &key} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, "PLAINTEXT-KEY-VALUE") {
				t.Errorf("%s leaks the key value: %s", verb, out)
			}
		}
	}
}

func TestAPIKeyDefaults(t *testing.T) {
	var key APIKey
	if !key.IsEnabled() || key.Expiry() != NeverExpires {
		t.Fatal("omitted fields must map to the documented defaults")
	}
	disabled, zero := false, int64(0)
	key.Enabled, key.ExpiresAt = &disabled, &zero
	if key.IsEnabled() || key.Expiry() != NeverExpires {
		t.Fatal("explicit values must be honoured")
	}
}

func TestTrustedDomainBatches(t *testing.T) {
	domains := make([]string, 25)
	for i := range domains {
		domains[i] = fmt.Sprintf("app%02d.example.com", i)
	}
	c, rec, _ := newTestClient(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 2 {
			writeJSON(w, http.StatusMultiStatus, `{"items":[{"trustedDomain":"app10.example.com","status":201},`+
				`{"trustedDomain":"app11.example.com","status":400367},{"trustedDomain":"app12.example.com","status":409000},`+
				`{"trustedDomain":"app13.example.com","status":404660}]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	err := c.AddTrustedDomains(t.Context(), testAppHRN, domains)
	var partial *PartialFailureError
	want := []DomainFailure{{"app11.example.com", 400367}, {"app13.example.com", 404660}}
	if !errors.As(err, &partial) || !slices.Equal(partial.Failures, want) {
		t.Fatalf("expected %v rejected, got %v", want, err)
	}
	if !strings.Contains(err.Error(), `"app11.example.com" (status 400367)`) {
		t.Fatalf("error does not name the rejected entry: %v", err)
	}
	reqs := rec.Requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d, want 3", len(reqs))
	}
	for i, size := range []int{10, 10, 5} {
		var body struct {
			Data []string `json:"data"`
		}
		if err := json.Unmarshal([]byte(reqs[i].Body), &body); err != nil || len(body.Data) != size {
			t.Fatalf("batch %d has %d entries (%v), want %d", i, len(body.Data), err, size)
		}
	}
}

func TestTrustedDomainRemovalEncoding(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("list"); got != "https://a.example.com:8443,b.example.com" {
			t.Errorf("decoded list = %q", got)
		}
		writeJSON(w, http.StatusMultiStatus, `{"items":[{"trustedDomain":"b.example.com","status":404}]}`)
	})
	if err := c.RemoveTrustedDomains(t.Context(), testAppHRN, []string{"https://a.example.com:8443", "b.example.com"}); err != nil {
		t.Fatalf("absent entries must count as removed: %v", err)
	}
	want := apiPrefix + "/apps/" + encodedAppHRN + "/trustedDomains?list=https%3A%2F%2Fa.example.com%3A8443,b.example.com"
	if got := rec.Requests()[0].RequestURI; got != want {
		t.Fatalf("RequestURI = %q, want %q", got, want)
	}
}

func TestMultiStatusWithoutItemsFailsWholeBatch(t *testing.T) {
	c, _, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusMultiStatus, `not json`)
	})
	err := c.AddTrustedDomains(t.Context(), testAppHRN, []string{"a.example.com", "b.example.com"})
	var partial *PartialFailureError
	if !errors.As(err, &partial) || len(partial.Failures) != 2 {
		t.Fatalf("expected both entries to fail, got %v", err)
	}
}

func TestTrustedDomainsReadAndToggle(t *testing.T) {
	c, rec, _ := newTestClient(t, func(n int, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/trustedDomainsEnabled"):
			writeJSON(w, http.StatusOK, `{"trustedDomainsEnabled":true}`)
		case r.Method == http.MethodGet && n == 1:
			writeJSON(w, http.StatusOK, `{"items":["a.example.com"],"pageToken":"next"}`)
		case r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, `{"items":["b.example.com"]}`)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	domains, err := c.ListTrustedDomains(t.Context(), testAppHRN)
	if err != nil || strings.Join(domains, ",") != "a.example.com,b.example.com" {
		t.Fatalf("ListTrustedDomains = %v, %v", domains, err)
	}
	enabled, err := c.TrustedDomainsEnabled(t.Context(), testAppHRN)
	if err != nil || !enabled {
		t.Fatalf("TrustedDomainsEnabled = %v, %v", enabled, err)
	}
	if err := c.SetTrustedDomainsEnabled(t.Context(), testAppHRN, true); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTrustedDomainsEnabled(t.Context(), testAppHRN, false); err != nil {
		t.Fatal(err)
	}
	reqs := rec.Requests()
	base := apiPrefix + "/apps/" + encodedAppHRN
	want := []string{
		"GET " + base + "/trustedDomains?limit=100",
		"GET " + base + "/trustedDomains?limit=100&pageToken=next",
		"GET " + base + "/trustedDomainsEnabled",
		"PUT " + base + "/trustedDomainsEnabled",
		"DELETE " + base + "/trustedDomainsEnabled",
	}
	for i, w := range want {
		if got := reqs[i].Method + " " + reqs[i].RequestURI; got != w {
			t.Errorf("request %d = %q, want %q", i, got, w)
		}
	}
}

func TestWaitForAppToleratesEventualConsistency(t *testing.T) {
	c, rec, sleeps := newTestClient(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		switch n {
		case 1:
			writeJSON(w, http.StatusNotFound, `{"errorCode":404660,"message":"No app exists"}`)
		case 2:
			writeJSON(w, http.StatusForbidden, `{"title":"Forbidden"}`)
		default:
			writeJSON(w, http.StatusOK, appJSON)
		}
	})
	app, err := c.WaitForApp(t.Context(), testAppHRN)
	if err != nil || app.ClientID != "abc123" {
		t.Fatalf("WaitForApp = %+v, %v", app, err)
	}
	if len(rec.Requests()) != 3 || len(sleeps.Durations()) != 2 {
		t.Fatalf("requests = %d, sleeps = %v", len(rec.Requests()), sleeps.Durations())
	}
}

func TestWaitForAPIKeyTimesOut(t *testing.T) {
	c, _, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, `{"errorCode":404666,"message":"The API key does not exist."}`)
	}, func(cfg *Config) {
		cfg.Sleep = nil
		cfg.Poll = PollPolicy{MinInterval: 2 * time.Millisecond, MaxInterval: 5 * time.Millisecond, DefaultTimeout: 50 * time.Millisecond}
	})
	_, err := c.WaitForAPIKey(t.Context(), testAppHRN, testKeyHRN)
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for API key") || !IsNotFound(err) {
		t.Fatalf("expected a wrapped 404 timeout, got %v", err)
	}
}

func TestRetryStopsOnNonRetryableError(t *testing.T) {
	c, rec, _ := newTestClient(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusBadRequest, `{"title":"bad"}`)
	})
	_, err := c.WaitForApp(t.Context(), testAppHRN)
	if !HasStatus(err, http.StatusBadRequest) || len(rec.Requests()) != 1 {
		t.Fatalf("err = %v, requests = %d", err, len(rec.Requests()))
	}
}

func TestRetryReportsUnconfirmedCreates(t *testing.T) {
	c, rec, _ := newTestClient(t, func(n int, w http.ResponseWriter, r *http.Request) {
		if n == 1 {
			writeJSON(w, http.StatusConflict, `{"title":"Too many API keys","status":409,"code":"409303"}`)
			return
		}
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	err := c.Retry(ctx, "a free API key slot", func(err error) bool { return HasCode(err, 409303) }, func(ctx context.Context) error {
		_, err := c.CreateAPIKey(ctx, testAppHRN, CreateAPIKeyInput{Name: "x"})
		return err
	})
	if !IsUnconfirmed(err) || len(rec.Requests()) != 2 {
		t.Fatalf("got %v after %d request(s), want the second create unconfirmed", err, len(rec.Requests()))
	}
}

func TestParseCredentials(t *testing.T) {
	in := "# generated by HERE\n" +
		"here.user.id = HERE-user\n" +
		"here.client.id = client-1\n" +
		"here.access.key.id = AKID\n" +
		"here.access.key.secret = sec=ret:value\n" +
		"here.token.endpoint.url : https://account.api.here.com/oauth2/token\n" +
		"! legacy comment\n\n"
	creds, err := ParseCredentials(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := Credentials{ClientID: "client-1", AccessKeyID: "AKID", AccessKeySecret: "sec=ret:value", TokenURL: DefaultTokenURL}
	if *creds != want {
		t.Fatalf("got %+v", *creds)
	}

	_, err = ParseCredentials(strings.NewReader("here.access.key.id = AKID\nTOPSECRETLINE\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "TOPSECRETLINE") {
		t.Fatalf("expected a line-number-only error, got %v", err)
	}
}

func TestReadCredentialsFile(t *testing.T) {
	if _, _, err := ReadCredentialsFile(t.TempDir() + "/missing.properties"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not reflect ACLs")
	}
	for mode, want := range map[os.FileMode]bool{0o600: false, 0o400: false, 0o640: true, 0o604: true, 0o620: true} {
		t.Run(mode.String(), func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "credentials.properties")
			if err := os.WriteFile(file, []byte("here.access.key.id = AKID\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Chmod, unlike WriteFile, ignores the umask.
			if err := os.Chmod(file, mode); err != nil {
				t.Fatal(err)
			}
			creds, shared, err := ReadCredentialsFile(file)
			if err != nil || creds.AccessKeyID != "AKID" || shared != want {
				t.Fatalf("ReadCredentialsFile = %+v, %t, %v; want shared = %t", creds, shared, err, want)
			}
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	valid := []string{
		DefaultTokenURL, DefaultAPIURL, "https://Account.API.here.com:443/x",
		"http://127.0.0.1:8080/x", "https://127.0.0.1:8443/x", "http://127.4.5.6/", "http://[::1]:9/",
	}
	for _, raw := range valid {
		if err := ValidateEndpoint(raw); err != nil {
			t.Errorf("ValidateEndpoint(%q) = %v", raw, err)
		}
	}
	custom := []string{
		"https://iam.example.com/authentication/v1.1",
		"https://account.api.here.com:8443/",
		"https://account.api.here.com.example.com/",
		"https://localhost/",
		"https://127.0.0.1.nip.io/",
	}
	for _, raw := range custom {
		if err := ValidateEndpoint(raw); !errors.Is(err, ErrCustomEndpoint) {
			t.Errorf("ValidateEndpoint(%q) = %v, want ErrCustomEndpoint", raw, err)
		}
	}
	invalid := []string{
		"http://account.api.here.com/oauth2/token",
		"http://localhost:1/",
		"http://2130706433/",
		"http://iam.example.com/",
		"https://user:hunter2@account.api.here.com/",
		"https://account.api.here.com/?a=b",
		"https://account.api.here.com/#frag",
		"ftp://account.api.here.com/",
		"/relative/path",
		"::not a url",
	}
	for _, raw := range invalid {
		err := ValidateEndpoint(raw)
		if err == nil || errors.Is(err, ErrCustomEndpoint) {
			t.Errorf("ValidateEndpoint(%q) = %v, want a hard error", raw, err)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error leaks URL credentials: %v", err)
		}
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	static := StaticTokenSource("x")
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected an error without authentication")
	}
	if _, err := New(Config{APIURL: "http://example.com", TokenSource: static}); err == nil {
		t.Fatal("expected an error for a plain HTTP API URL")
	}
	if _, err := New(Config{TokenURL: "http://example.com", TokenSource: static}); err == nil {
		t.Fatal("expected an error for a plain HTTP token URL")
	}
	for _, cfg := range []Config{
		{APIURL: "https://iam.example.com", TokenSource: static},
		{TokenURL: "https://iam.example.com/oauth2/token", TokenSource: static},
		{APIURL: "http://iam.example.com", TokenSource: static, AllowCustomEndpoints: true},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New accepted API URL %q and token URL %q", cfg.APIURL, cfg.TokenURL)
		}
	}
	allowed := Config{
		APIURL: "https://iam.example.com", TokenURL: "https://iam.example.com/oauth2/token",
		TokenSource: static, AllowCustomEndpoints: true,
	}
	if _, err := New(allowed); err != nil {
		t.Fatalf("opt-in rejected: %v", err)
	}
}

func TestPercentEncode(t *testing.T) {
	tests := map[string]string{
		testAppHRN:        encodedAppHRN,
		"AZaz09-._~":      "AZaz09-._~",
		"a b+c=d&e,f":     "a%20b%2Bc%3Dd%26e%2Cf",
		"ü":               "%C3%BC",
		"https://x.y:1/p": "https%3A%2F%2Fx.y%3A1%2Fp",
	}
	for in, want := range tests {
		if got := PercentEncode(in); got != want {
			t.Errorf("PercentEncode(%q) = %q, want %q", in, got, want)
		}
		if back, err := url.PathUnescape(PercentEncode(in)); err != nil || back != in {
			t.Errorf("round trip of %q = %q, %v", in, back, err)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false},
		{"0", 0, true},
		{" 12 ", 12 * time.Second, true},
		{"-1", 0, false},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0, true},
		{"soon", 0, false},
		{"99999999999999", maxRetryAfter, true},
		{"9223372036854775807", maxRetryAfter, true},
		{"99999999999999999999", maxRetryAfter, true},
		{"-99999999999999999999", 0, false},
		{time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Format(http.TimeFormat), maxRetryAfter, true},
	}
	for _, tt := range tests {
		got, ok := parseRetryAfter(tt.in, now)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseRetryAfter(%q) = %v, %v; want %v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestExpBackoffBounds(t *testing.T) {
	minDelay, maxDelay := time.Second, 30*time.Second
	for attempt := 1; attempt <= 10; attempt++ {
		ceiling := min(minDelay<<(attempt-1), maxDelay)
		for range 100 {
			d := expBackoff(attempt, minDelay, maxDelay)
			if d < ceiling/2 || d > ceiling {
				t.Fatalf("attempt %d: backoff %v outside [%v, %v]", attempt, d, ceiling/2, ceiling)
			}
		}
	}
}

func TestPolicyDefaults(t *testing.T) {
	if got := (RetryPolicy{}).withDefaults(); got != DefaultRetryPolicy() {
		t.Fatalf("RetryPolicy defaults = %+v", got)
	}
	if got := (PollPolicy{}).withDefaults(); got != DefaultPollPolicy() {
		t.Fatalf("PollPolicy defaults = %+v", got)
	}
	if got := (RetryPolicy{MinBackoff: time.Minute}).withDefaults(); got.MaxBackoff < got.MinBackoff {
		t.Fatalf("MaxBackoff below MinBackoff: %+v", got)
	}
}
