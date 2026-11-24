package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

const (
	fakeAPIPath   = "/authentication/v1.1"
	fakeTokenPath = "/oauth2/token"
	fakeRealm     = "org-fake"
	fakeClientID  = "tf-provider-client"
	fakeKeyID     = "fake-kid"
	fakeMaxKeys   = 2
	fakeBatchSize = 10
	fakeMaxLimit  = 100
	// HERE list endpoints default to 10 entries when limit is omitted.
	fakeDefaultLimit = 10
)

// Routes as recorded in fakeCall.Route.
const (
	routeToken              = "POST /oauth2/token"
	routeCreateApp          = "POST /apps"
	routeListApps           = "GET /apps"
	routeGetApp             = "GET /apps/{app}"
	routePatchApp           = "PATCH /apps/{app}"
	routeDeleteApp          = "DELETE /apps/{app}"
	routeEnableAppCreation  = "PUT /apps/{app}/appCreationEnabled"
	routeDisableAppCreation = "DELETE /apps/{app}/appCreationEnabled"
	routeCreateKey          = "POST /apps/{app}/apiKeys"
	routeGetKey             = "GET /apps/{app}/apiKeys/{key}"
	routePatchKey           = "PATCH /apps/{app}/apiKeys/{key}"
	routeDeleteKey          = "DELETE /apps/{app}/apiKeys/{key}"
	routeEnableKey          = "POST /apps/{app}/apiKeys/{key}/enable"
	routeDisableKey         = "POST /apps/{app}/apiKeys/{key}/disable"
	routeListDomains        = "GET /apps/{app}/trustedDomains"
	routeAddDomains         = "POST /apps/{app}/trustedDomains"
	routeRemoveDomains      = "DELETE /apps/{app}/trustedDomains"
	routeGetEnforcement     = "GET /apps/{app}/trustedDomainsEnabled"
	routeEnableEnforcement  = "PUT /apps/{app}/trustedDomainsEnabled"
	routeDisableEnforcement = "DELETE /apps/{app}/trustedDomainsEnabled"
)

var knownRoutes = map[string]bool{
	routeToken: true, routeCreateApp: true, routeListApps: true, routeGetApp: true, routePatchApp: true,
	routeDeleteApp: true, routeEnableAppCreation: true, routeDisableAppCreation: true, routeCreateKey: true,
	routeGetKey: true, routePatchKey: true, routeDeleteKey: true, routeEnableKey: true, routeDisableKey: true,
	routeListDomains: true, routeAddDomains: true, routeRemoveDomains: true, routeGetEnforcement: true,
	routeEnableEnforcement: true, routeDisableEnforcement: true,
}

var (
	// RSA generation dominates fake start-up; one key serves every test.
	fakeSigningKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

	fastRetry = client.RetryPolicy{
		MaxAttempts: 3, MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, MaxRetryAfter: 10 * time.Millisecond,
	}
	fastPoll = client.PollPolicy{MinInterval: time.Millisecond, MaxInterval: 5 * time.Millisecond, DefaultTimeout: 5 * time.Second}
)

type fakeApp struct {
	ID                 string
	HRN                string
	Name               string
	Description        string
	AppCreationEnabled bool
	CreatedTime        int64
	Keys               []*fakeKey
	Domains            []string
	DomainsEnabled     bool
	// Create attempts that still count a recently deleted key against the limit.
	ghostAttempts int
}

type fakeKey struct {
	HRN         string
	Value       string
	Name        string
	Enabled     bool
	CreatedTime int64
	ExpiresAt   int64
}

type fakeCall struct {
	Route    string
	App      string
	Key      string
	Query    url.Values
	RawQuery string
	Body     []byte
	Token    string
	// N counts the calls of Route since the fake started, from 1.
	N int
}

func (c fakeCall) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(c.Body, &m)
	return m
}

type fakeReply struct {
	status int
	body   any
	raw    string
	header map[string]string
}

// fakeHook overrides the reply to a call; the fake state is left untouched.
type fakeHook func(fakeCall) (fakeReply, bool)

// fakeHERE is a stateful in-memory HERE Authentication API v1.1 and token endpoint. It
// mirrors the documented contract and the provider's stated assumptions.
type fakeHERE struct {
	mu  sync.Mutex
	url string
	key *rsa.PrivateKey
	pem string

	now        func() time.Time
	seq        int
	store      []*fakeApp
	hooks      []fakeHook
	calls      []fakeCall
	count      map[string]int
	tokens     map[string]bool
	jtis       map[string]bool
	unexpected []string

	// Behaviour switches; change them through update.
	pageSize            int
	normalize           func(string) string
	rejectDomains       map[string]int
	conflictOnDuplicate bool
	ignoreCreateEnabled bool
	keySlotLag          int
}

func newFakeHERE(t *testing.T) *fakeHERE {
	t.Helper()
	key, err := fakeSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeHERE{
		key:    key,
		pem:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		now:    time.Now,
		count:  map[string]int{},
		tokens: map[string]bool{},
		jtis:   map[string]bool{},
	}
	srv := httptest.NewUnstartedServer(f)
	f.url = "http://" + srv.Listener.Addr().String()
	srv.Start()
	t.Cleanup(func() {
		srv.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, u := range f.unexpected {
			t.Errorf("fake HERE API received an unexpected request: %s", u)
		}
	})
	return f
}

func (f *fakeHERE) env() map[string]string {
	return map[string]string{
		envClientID:   fakeClientID,
		envPrivateKey: f.pem,
		envKeyID:      fakeKeyID,
		envTokenURL:   f.url + fakeTokenPath,
		envAPIURL:     f.url + fakeAPIPath,
	}
}

func (f *fakeHERE) factories() map[string]func() (tfprotov6.ProviderServer, error) {
	opts := []Option{WithEnv(envOf(f.env())), WithRetryPolicy(fastRetry), WithPollPolicy(fastPoll)}
	return map[string]func() (tfprotov6.ProviderServer, error){
		"hereplatform": providerserver.NewProtocol6WithError(New("test", opts...)()),
	}
}

// client builds an API client as the provider would, for tests that bypass Terraform.
func (f *fakeHERE) client(t *testing.T, mods ...func(*client.Config)) *client.Client {
	t.Helper()
	cfg, diags := resolveConfig(providerModel{}, envOf(f.env()))
	if diags.HasError() {
		t.Fatal(diagText(diags))
	}
	cfg.Retry, cfg.Poll = fastRetry, fastPoll
	for _, m := range mods {
		m(&cfg)
	}
	c, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeHERE) update(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeHERE) hook(hooks ...fakeHook) {
	f.update(func() { f.hooks = append(f.hooks, hooks...) })
}

func (f *fakeHERE) clearHooks() {
	f.update(func() { f.hooks = nil })
}

// mark returns a position in the call log for callsSince.
func (f *fakeHERE) mark() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeHERE) callsSince(mark int, routes ...string) []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeCall
	for _, c := range f.calls[mark:] {
		if len(routes) == 0 || slices.Contains(routes, c.Route) {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeHERE) callsOf(routes ...string) []fakeCall { return f.callsSince(0, routes...) }

func (f *fakeHERE) seedApp(name string, mods ...func(*fakeApp)) fakeApp {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.newApp(name, "")
	for _, m := range mods {
		m(a)
	}
	a.HRN = fakeAppHRN(a.ID)
	return a.clone()
}

func (f *fakeHERE) app(hrn string) (fakeApp, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := f.find(hrn); a != nil {
		return a.clone(), true
	}
	return fakeApp{}, false
}

func (f *fakeHERE) apps() []fakeApp {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeApp, len(f.store))
	for i, a := range f.store {
		out[i] = a.clone()
	}
	return out
}

func (f *fakeHERE) deleteApp(hrn string) {
	f.update(func() {
		f.store = slices.DeleteFunc(f.store, func(a *fakeApp) bool { return a.HRN == hrn })
	})
}

func (a *fakeApp) clone() fakeApp {
	c := *a
	c.Keys = make([]*fakeKey, len(a.Keys))
	for i, k := range a.Keys {
		kc := *k
		c.Keys[i] = &kc
	}
	c.Domains = slices.Clone(a.Domains)
	return c
}

func fakeAppHRN(id string) string { return "hrn:here:account::" + fakeRealm + ":app/" + id }

func (f *fakeHERE) newApp(name, description string) *fakeApp {
	f.seq++
	id := fmt.Sprintf("FakeApp%04d", f.seq)
	a := &fakeApp{ID: id, HRN: fakeAppHRN(id), Name: name, Description: description, CreatedTime: f.now().UnixMilli()}
	f.store = append(f.store, a)
	return a
}

func (f *fakeHERE) find(hrn string) *fakeApp {
	for _, a := range f.store {
		if a.HRN == hrn {
			return a
		}
	}
	return nil
}

func (a *fakeApp) findKey(hrn string) *fakeKey {
	for _, k := range a.Keys {
		if k.HRN == hrn {
			return k
		}
	}
	return nil
}

func (a *fakeApp) full() map[string]any {
	m := a.info()
	delete(m, "id")
	m["clientId"] = a.ID
	return m
}

// info is the AppInfo list item, which carries the client ID as id.
func (a *fakeApp) info() map[string]any {
	m := map[string]any{
		"id": a.ID, "hrn": a.HRN, "realm": fakeRealm, "name": a.Name, "status": "active",
		"appCreationEnabled": a.AppCreationEnabled, "createdTime": a.CreatedTime,
	}
	if a.Description != "" {
		m["description"] = a.Description
	}
	return m
}

func (k *fakeKey) json(a *fakeApp) map[string]any {
	m := map[string]any{
		"apiKeyId": k.Value, "apiKey": k.HRN, "identity": a.HRN, "realm": fakeRealm, "name": k.Name,
		"enabled": k.Enabled, "createdTime": k.CreatedTime,
	}
	if k.ExpiresAt > 0 {
		m["expiresAt"] = k.ExpiresAt
	}
	return m
}

func hereError(status int, code, title string) fakeReply {
	id := "corr-" + rand.Text()[:12]
	return fakeReply{
		status: status,
		header: map[string]string{"X-Correlation-ID": id},
		body: map[string]any{
			"title": title, "status": status, "code": code, "cause": title,
			"action": "Check the request.", "correlationId": id, "errorId": "ERROR-" + id,
		},
	}
}

func notFound() fakeReply { return hereError(http.StatusNotFound, "404660", "Resource not found") }

func badRequest(title string) fakeReply { return hereError(http.StatusBadRequest, "400200", title) }

func noContent() fakeReply { return fakeReply{status: http.StatusNoContent} }

func okJSON(body any) fakeReply { return fakeReply{status: http.StatusOK, body: body} }

// sequence answers successive calls of route with replies; a zero reply lets a call
// through, and the hook passes everything once replies run out.
func sequence(route string, replies ...fakeReply) fakeHook {
	return func(c fakeCall) (fakeReply, bool) {
		if c.Route != route || len(replies) == 0 {
			return fakeReply{}, false
		}
		r := replies[0]
		replies = replies[1:]
		return r, r.status != 0
	}
}

func always(route string, reply fakeReply) fakeHook {
	return func(c fakeCall) (fakeReply, bool) { return reply, c.Route == route }
}

func forApp(hrn string, h fakeHook) fakeHook {
	return func(c fakeCall) (fakeReply, bool) {
		if c.App != hrn {
			return fakeReply{}, false
		}
		return h(c)
	}
}

func (f *fakeHERE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	rep := f.handle(r, body)
	f.mu.Unlock()

	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	if rep.body != nil || rep.raw != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(rep.status)
	switch {
	case rep.raw != "":
		_, _ = io.WriteString(w, rep.raw)
	case rep.body != nil:
		_ = json.NewEncoder(w).Encode(rep.body)
	}
}

func (f *fakeHERE) handle(r *http.Request, body []byte) fakeReply {
	route, app, key, ok := parseRoute(r.Method, r.URL.EscapedPath())
	if !ok {
		f.unexpected = append(f.unexpected, r.Method+" "+r.URL.RequestURI())
		return badRequest("unexpected request")
	}
	f.count[route]++
	c := fakeCall{
		Route: route, App: app, Key: key, Query: r.URL.Query(), RawQuery: r.URL.RawQuery, Body: body, N: f.count[route],
	}
	if route != routeToken {
		c.Token, _ = strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	f.calls = append(f.calls, c)
	if route != routeToken && !f.tokens[c.Token] {
		return hereError(http.StatusUnauthorized, "401300", "Invalid or missing bearer token")
	}
	for _, h := range f.hooks {
		if rep, ok := h(c); ok {
			return rep
		}
	}
	if route == routeToken {
		return f.issueToken(c)
	}
	if route == routeCreateApp || route == routeListApps {
		return f.handleApps(c)
	}
	a := f.find(c.App)
	if a == nil {
		return notFound()
	}
	switch {
	case c.Key != "" || route == routeCreateKey:
		return f.handleKeys(c, a)
	case strings.Contains(route, "/trustedDomains"):
		return f.handleDomains(c, a)
	default:
		return f.handleApp(c, a)
	}
}

// parseRoute requires HRN path segments to be percent-encoded, as HERE does for ':' and '/'.
func parseRoute(method, escapedPath string) (route, app, key string, ok bool) {
	if escapedPath == fakeTokenPath {
		route = method + " " + escapedPath
		return route, "", "", knownRoutes[route]
	}
	rest, found := strings.CutPrefix(escapedPath, fakeAPIPath+"/")
	if !found {
		return "", "", "", false
	}
	segs := strings.Split(rest, "/")
	pattern := make([]string, len(segs))
	for i, s := range segs {
		pattern[i] = s
		isHRN := i == 1 || (i == 3 && segs[2] == "apiKeys")
		if !isHRN {
			continue
		}
		hrn, err := url.PathUnescape(s)
		if err != nil || hrn == "" || strings.Contains(s, ":") {
			return "", "", "", false
		}
		if i == 1 {
			app, pattern[i] = hrn, "{app}"
		} else {
			key, pattern[i] = hrn, "{key}"
		}
	}
	route = method + " /" + strings.Join(pattern, "/")
	return route, app, key, knownRoutes[route]
}

func (f *fakeHERE) issueToken(c fakeCall) fakeReply {
	form, err := url.ParseQuery(string(c.Body))
	if err != nil || form.Get("grant_type") != "client_credentials" ||
		form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return fakeReply{status: http.StatusBadRequest, body: map[string]any{"error": "invalid_request"}}
	}
	if err := f.verifyAssertion(form.Get("client_assertion")); err != nil {
		f.unexpected = append(f.unexpected, "client assertion rejected: "+err.Error())
		return fakeReply{status: http.StatusUnauthorized, body: map[string]any{
			"error": "invalid_client", "error_description": err.Error(),
		}}
	}
	token := "fake-access-token-" + rand.Text()
	f.tokens[token] = true
	return okJSON(map[string]any{"access_token": token, "token_type": "bearer", "expires_in": 3600})
}

func (f *fakeHERE) verifyAssertion(assertion string) error {
	tok, err := jwt.Parse(assertion, func(t *jwt.Token) (any, error) {
		if kid, _ := t.Header["kid"].(string); kid != fakeKeyID {
			return nil, fmt.Errorf("unexpected kid %q", kid)
		}
		return &f.key.PublicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(fakeClientID),
		jwt.WithSubject(fakeClientID),
		jwt.WithAudience(f.url+fakeTokenPath),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		// VM wall clocks (WSL2, CI runners) step backwards on resync; real token endpoints tolerate small skew too.
		jwt.WithLeeway(5*time.Second),
	)
	if err != nil {
		return err
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	if _, isString := claims["aud"].(string); !isString {
		return errors.New("aud must be a single string")
	}
	iat, errIat := claims.GetIssuedAt()
	exp, errExp := claims.GetExpirationTime()
	if errIat != nil || errExp != nil || iat == nil || exp.Sub(iat.Time) > 10*time.Minute {
		return errors.New("iat is required and the assertion must expire within 10 minutes")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || f.jtis[jti] {
		return errors.New("jti is missing or was already used")
	}
	f.jtis[jti] = true
	return nil
}

func (f *fakeHERE) handleApps(c fakeCall) fakeReply {
	if c.Route == routeListApps {
		infos := make([]map[string]any, len(f.store))
		for i, a := range f.store {
			infos[i] = a.info()
		}
		page, ok := fakePage(infos, c.Query, f.pageSize)
		if !ok {
			return badRequest("invalid paging parameters")
		}
		return okJSON(page)
	}
	var in struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if json.Unmarshal(c.Body, &in) != nil || in.Name == "" {
		return badRequest("name is required")
	}
	return okJSON(f.newApp(in.Name, in.Description).full())
}

func (f *fakeHERE) handleApp(c fakeCall, a *fakeApp) fakeReply {
	switch c.Route {
	case routeGetApp:
		return okJSON(a.full())
	case routePatchApp:
		var in struct {
			Name        *string `json:"name"`
			Description *string `json:"description"`
		}
		if json.Unmarshal(c.Body, &in) != nil || in.Name == nil || *in.Name == "" {
			return badRequest("name is required")
		}
		a.Name = *in.Name
		if in.Description != nil {
			a.Description = *in.Description
		}
		return okJSON(a.full())
	case routeDeleteApp:
		f.store = slices.DeleteFunc(f.store, func(s *fakeApp) bool { return s == a })
		return noContent()
	default:
		a.AppCreationEnabled = c.Route == routeEnableAppCreation
		return noContent()
	}
}

func (f *fakeHERE) handleKeys(c fakeCall, a *fakeApp) fakeReply {
	if c.Route == routeCreateKey {
		var in struct {
			Name      string `json:"name"`
			ExpiresAt *int64 `json:"expiresAt"`
			Enabled   *bool  `json:"enabled"`
		}
		if json.Unmarshal(c.Body, &in) != nil || in.Name == "" {
			return badRequest("name is required")
		}
		occupied := len(a.Keys)
		if a.ghostAttempts > 0 {
			occupied++
			a.ghostAttempts--
		}
		if occupied >= fakeMaxKeys {
			return hereError(http.StatusConflict, "409303", "Maximum number of API keys reached")
		}
		f.seq++
		k := &fakeKey{
			HRN:         fmt.Sprintf("hrn:here:account::%s:apikey/FakeKey%04d", fakeRealm, f.seq),
			Value:       fmt.Sprintf("fake-apikey-value-%d-%s", f.seq, rand.Text()),
			Name:        in.Name,
			Enabled:     true,
			CreatedTime: f.now().UnixMilli(),
			ExpiresAt:   client.NeverExpires,
		}
		if in.Enabled != nil && !f.ignoreCreateEnabled {
			k.Enabled = *in.Enabled
		}
		if in.ExpiresAt != nil && *in.ExpiresAt > 0 {
			k.ExpiresAt = *in.ExpiresAt
		}
		a.Keys = append(a.Keys, k)
		return fakeReply{status: http.StatusCreated, body: k.json(a)}
	}
	k := a.findKey(c.Key)
	if k == nil {
		return hereError(http.StatusNotFound, "404661", "API key not found")
	}
	switch c.Route {
	case routeGetKey:
		return okJSON(k.json(a))
	case routePatchKey:
		var in struct {
			Name      *string `json:"name"`
			ExpiresAt *int64  `json:"expiresAt"`
		}
		if json.Unmarshal(c.Body, &in) != nil {
			return badRequest("invalid body")
		}
		if in.Name != nil {
			k.Name = *in.Name
		}
		// HERE resets an omitted expiresAt to "never", which the provider must not rely on.
		k.ExpiresAt = client.NeverExpires
		if in.ExpiresAt != nil && *in.ExpiresAt > 0 {
			k.ExpiresAt = *in.ExpiresAt
		}
		return okJSON(k.json(a))
	case routeDeleteKey:
		a.Keys = slices.DeleteFunc(a.Keys, func(s *fakeKey) bool { return s == k })
		a.ghostAttempts += f.keySlotLag
		return noContent()
	default:
		k.Enabled = c.Route == routeEnableKey
		return noContent()
	}
}

func (f *fakeHERE) normalized(d string) string {
	if f.normalize == nil {
		return d
	}
	return f.normalize(d)
}

func (f *fakeHERE) handleDomains(c fakeCall, a *fakeApp) fakeReply {
	switch c.Route {
	case routeListDomains:
		page, ok := fakePage(a.Domains, c.Query, f.pageSize)
		if !ok {
			return badRequest("invalid paging parameters")
		}
		return okJSON(page)
	case routeAddDomains:
		var in struct {
			Data []string `json:"data"`
		}
		if json.Unmarshal(c.Body, &in) != nil || len(in.Data) == 0 || len(in.Data) > fakeBatchSize {
			return badRequest("data must hold 1 to 10 trusted domains")
		}
		return multiStatus(in.Data, func(d string) int {
			stored := f.normalized(d)
			switch {
			case f.rejectDomains[d] != 0:
				return f.rejectDomains[d]
			case slices.Contains(a.Domains, stored):
				if f.conflictOnDuplicate {
					return http.StatusConflict
				}
				return http.StatusNoContent
			default:
				a.Domains = append(a.Domains, stored)
				return http.StatusNoContent
			}
		})
	case routeRemoveDomains:
		raw, found := listParam(c.RawQuery)
		entries := strings.Split(raw, ",")
		if !found || raw == "" || len(entries) > fakeBatchSize {
			return badRequest("list must hold 1 to 10 trusted domains")
		}
		decoded := make([]string, len(entries))
		for i, e := range entries {
			d, err := url.PathUnescape(e)
			if err != nil || d == "" {
				return badRequest("invalid list entry")
			}
			decoded[i] = d
		}
		return multiStatus(decoded, func(d string) int {
			i := slices.Index(a.Domains, f.normalized(d))
			if i < 0 {
				return http.StatusNotFound
			}
			a.Domains = slices.Delete(a.Domains, i, i+1)
			return http.StatusNoContent
		})
	case routeGetEnforcement:
		return okJSON(map[string]any{"trustedDomainsEnabled": a.DomainsEnabled})
	default:
		a.DomainsEnabled = c.Route == routeEnableEnforcement
		return noContent()
	}
}

// multiStatus answers 204 when every entry succeeds and 207 with per-entry statuses otherwise.
func multiStatus(domains []string, apply func(string) int) fakeReply {
	items := make([]map[string]any, len(domains))
	partial := false
	for i, d := range domains {
		status := apply(d)
		partial = partial || status != http.StatusNoContent
		items[i] = map[string]any{"trustedDomain": d, "status": status}
	}
	if !partial {
		return noContent()
	}
	return fakeReply{status: http.StatusMultiStatus, body: map[string]any{"items": items, "total": len(items), "limit": len(items)}}
}

func listParam(rawQuery string) (string, bool) {
	for _, part := range strings.Split(rawQuery, "&") {
		if v, found := strings.CutPrefix(part, "list="); found {
			return v, true
		}
	}
	return "", false
}

func fakePage[T any](items []T, q url.Values, pageSize int) (map[string]any, bool) {
	limit := fakeDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > fakeMaxLimit {
			return nil, false
		}
		limit = n
	}
	if pageSize > 0 {
		limit = min(limit, pageSize)
	}
	start := 0
	if tok := q.Get("pageToken"); tok != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(tok, "page-"))
		if err != nil || !strings.HasPrefix(tok, "page-") || n < 0 || n > len(items) {
			return nil, false
		}
		start = n
	}
	end := min(start+limit, len(items))
	page := map[string]any{"items": append([]T{}, items[start:end]...), "limit": limit, "total": len(items)}
	if end < len(items) {
		page["pageToken"] = "page-" + strconv.Itoa(end)
	}
	return page, true
}

// hereNormalize models the normalisation the provider tolerates: scheme and host case,
// and a trailing slash.
func hereNormalize(d string) string {
	d = strings.TrimRight(d, "/")
	scheme, rest, hasScheme := strings.Cut(d, "://")
	if !hasScheme {
		scheme, rest = "", d
	}
	host, path, _ := strings.Cut(rest, "/")
	out := strings.ToLower(host)
	if hasScheme {
		out = strings.ToLower(scheme) + "://" + out
	}
	if path != "" {
		out += "/" + path
	}
	return out
}

func checkNoApps(f *fakeHERE) func(*terraform.State) error {
	return func(*terraform.State) error {
		if apps := f.apps(); len(apps) != 0 {
			return fmt.Errorf("%d app(s) left in the fake HERE API, first %q", len(apps), apps[0].Name)
		}
		return nil
	}
}

func stateID(s *terraform.State, addr string) (string, error) {
	rs, found := s.RootModule().Resources[addr]
	if !found {
		return "", fmt.Errorf("%s not found in state", addr)
	}
	return rs.Primary.ID, nil
}

// checkFakeApp runs check against the fake app whose HRN is the id of the resource at addr.
func checkFakeApp(f *fakeHERE, addr string, check func(fakeApp) error) func(*terraform.State) error {
	return func(s *terraform.State) error {
		id, err := stateID(s, addr)
		if err != nil {
			return err
		}
		a, found := f.app(id)
		if !found {
			return fmt.Errorf("app %s of %s not found in the fake HERE API", id, addr)
		}
		return check(a)
	}
}
