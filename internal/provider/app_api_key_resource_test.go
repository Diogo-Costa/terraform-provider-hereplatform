package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

const keyAddr = "hereplatform_app_api_key.test"

var (
	fakeKeyHRNRegexp   = regexp.MustCompile(`^hrn:here:account::org-fake:apikey/FakeKey\d{4}$`)
	fakeKeyValueRegexp = regexp.MustCompile(`^fake-apikey-value-\d+-[A-Z2-7]+$`)
)

func keyConfig(attrs ...string) string {
	return appConfig("tfacc-keys", unprotected) + keyBlock("test", appRef("test"), attrs...)
}

func expectKeyAttr(attr string, v knownvalue.Check) statecheck.StateCheck {
	return statecheck.ExpectKnownValue(keyAddr, tfjsonpath.New(attr), v)
}

// Run logs are public (W-10): key values are checked only by functions whose errors never echo them.

func checkKeyValueFormat(addr string) tfresource.TestCheckFunc {
	return tfresource.TestCheckResourceAttrWith(addr, "value", func(v string) error {
		if !fakeKeyValueRegexp.MatchString(v) {
			return errors.New("value is empty or malformed")
		}
		return nil
	})
}

// checkKeyValueStable records the value on its first run and fails when a later step changes it.
func checkKeyValueStable(seen *string) tfresource.TestCheckFunc {
	return tfresource.TestCheckResourceAttrWith(keyAddr, "value", func(v string) error {
		if *seen == "" {
			*seen = v
		}
		if v != *seen {
			return errors.New("value changed between steps")
		}
		return nil
	})
}

func checkImportedKeyValue(f *fakeHERE) tfresource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) != 1 {
			return fmt.Errorf("imported %d states, want 1", len(states))
		}
		a, found := f.app(states[0].Attributes["app_hrn"])
		if !found {
			return errors.New("imported app_hrn not found in the fake HERE API")
		}
		if k := a.findKey(states[0].ID); k == nil || states[0].Attributes["value"] != k.Value {
			return errors.New("imported value does not match the key value in HERE")
		}
		return nil
	}
}

// canonicalJSON re-encodes a body with sorted keys for comparisons.
func canonicalJSON(body []byte) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return string(body)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

func checkBodies(f *fakeHERE, mark *int, route string, want ...string) func(*terraform.State) error {
	return func(*terraform.State) error {
		calls := f.callsSince(*mark, route)
		got := make([]string, len(calls))
		for i, c := range calls {
			got[i] = canonicalJSON(c.Body)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			return fmt.Errorf("%s bodies = %q, want %q", route, got, want)
		}
		return nil
	}
}

func checkCalls(f *fakeHERE, mark *int, route string, want int) func(*terraform.State) error {
	return func(*terraform.State) error {
		if n := len(f.callsSince(*mark, route)); n != want {
			return fmt.Errorf("%d calls of %s, want %d", n, route, want)
		}
		return nil
	}
}

// checkFakeKey runs check against the fake key behind the resource at addr.
func checkFakeKey(f *fakeHERE, addr string, check func(fakeKey) error) func(*terraform.State) error {
	return func(s *terraform.State) error {
		rs, found := s.RootModule().Resources[addr]
		if !found {
			return fmt.Errorf("%s not found in state", addr)
		}
		a, found := f.app(rs.Primary.Attributes["app_hrn"])
		if !found {
			return fmt.Errorf("app of %s not found in the fake HERE API", addr)
		}
		k := a.findKey(rs.Primary.ID)
		if k == nil {
			return fmt.Errorf("key %s not found in the fake HERE API", rs.Primary.ID)
		}
		if rs.Primary.Attributes["value"] != k.Value {
			return errors.New("state value does not match the key value in HERE")
		}
		return check(*k)
	}
}

func TestAPIKeyResourceLifecycle(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	expiryMs := time.Date(2030, 1, 2, 15, 4, 5, 0, time.UTC).UnixMilli()
	sameID := statecheck.CompareValue(compare.ValuesSame())
	stable := func(checks ...statecheck.StateCheck) []statecheck.StateCheck {
		return append(checks, sameID.AddStateValue(keyAddr, tfjsonpath.New("id")))
	}
	var value string
	key := func(want fakeKey) func(*terraform.State) error {
		return tfresource.ComposeAggregateTestCheckFunc(
			checkKeyValueStable(&value),
			checkFakeKey(f, keyAddr, func(k fakeKey) error {
				if k.Name != want.Name || k.Enabled != want.Enabled || k.ExpiresAt != want.ExpiresAt {
					return fmt.Errorf("fake key = {%s %t %d}, want {%s %t %d}",
						k.Name, k.Enabled, k.ExpiresAt, want.Name, want.Enabled, want.ExpiresAt)
				}
				return nil
			}))
	}
	var mark int
	setMark := func() { mark = f.mark() }

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: keyConfig(`name = "primary"`),
				ConfigStateChecks: stable(
					statecheck.ExpectSensitiveValue(keyAddr, tfjsonpath.New("value")),
					expectKeyAttr("hrn", knownvalue.StringRegexp(fakeKeyHRNRegexp)),
					statecheck.CompareValuePairs(keyAddr, tfjsonpath.New("id"), keyAddr, tfjsonpath.New("hrn"), compare.ValuesSame()),
					statecheck.CompareValuePairs(keyAddr, tfjsonpath.New("app_hrn"), appAddr, tfjsonpath.New("id"), compare.ValuesSame()),
					expectKeyAttr("expires_at", knownvalue.Null()),
					expectKeyAttr("enabled", knownvalue.Bool(true)),
					expectKeyAttr("created_time", knownvalue.StringRegexp(rfc3339UTCRegexp)),
				),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkKeyValueFormat(keyAddr),
					key(fakeKey{Name: "primary", Enabled: true, ExpiresAt: client.NeverExpires}),
				),
			},
			{
				PreConfig:         setMark,
				Config:            keyConfig(`name = "primary"`, `expires_at = "2030-01-02T15:04:05Z"`),
				ConfigPlanChecks:  expectAction(keyAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: stable(expectKeyAttr("expires_at", knownvalue.StringExact("2030-01-02T15:04:05Z"))),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkBodies(f, &mark, routePatchKey, fmt.Sprintf(`{"expiresAt":%d,"name":"primary"}`, expiryMs)),
					key(fakeKey{Name: "primary", Enabled: true, ExpiresAt: expiryMs}),
				),
			},
			{
				// Same instant in another offset: the configured spelling survives refreshes.
				Config:            keyConfig(`name = "primary"`, `expires_at = "2030-01-02T16:04:05+01:00"`),
				ConfigStateChecks: stable(expectKeyAttr("expires_at", knownvalue.StringExact("2030-01-02T16:04:05+01:00"))),
				Check:             key(fakeKey{Name: "primary", Enabled: true, ExpiresAt: expiryMs}),
			},
			{
				// Assumption 2: expiresAt -1 removes the expiry.
				PreConfig:         setMark,
				Config:            keyConfig(`name = "primary"`),
				ConfigPlanChecks:  expectAction(keyAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: stable(expectKeyAttr("expires_at", knownvalue.Null())),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkBodies(f, &mark, routePatchKey, `{"expiresAt":-1,"name":"primary"}`),
					key(fakeKey{Name: "primary", Enabled: true, ExpiresAt: client.NeverExpires}),
				),
			},
			{
				PreConfig:         setMark,
				Config:            keyConfig(`name = "primary"`, "enabled = false"),
				ConfigStateChecks: stable(expectKeyAttr("enabled", knownvalue.Bool(false))),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkCalls(f, &mark, routeDisableKey, 1),
					checkCalls(f, &mark, routePatchKey, 0),
					key(fakeKey{Name: "primary", Enabled: false, ExpiresAt: client.NeverExpires}),
				),
			},
			{
				PreConfig:         setMark,
				Config:            keyConfig(`name = "primary"`),
				ConfigStateChecks: stable(expectKeyAttr("enabled", knownvalue.Bool(true))),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkCalls(f, &mark, routeEnableKey, 1),
					key(fakeKey{Name: "primary", Enabled: true, ExpiresAt: client.NeverExpires}),
				),
			},
			{
				// HERE resets an omitted expiresAt, so a rename must resend it.
				PreConfig:         setMark,
				Config:            keyConfig(`name = "renamed"`, `expires_at = "2030-01-02T15:04:05.123Z"`),
				ConfigStateChecks: stable(expectKeyAttr("name", knownvalue.StringExact("renamed"))),
				Check:             checkBodies(f, &mark, routePatchKey, fmt.Sprintf(`{"expiresAt":%d,"name":"renamed"}`, expiryMs+123)),
			},
			{
				PreConfig: setMark,
				Config:    keyConfig(`name = "renamed-again"`, `expires_at = "2030-01-02T15:04:05.123Z"`),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkBodies(f, &mark, routePatchKey, fmt.Sprintf(`{"expiresAt":%d,"name":"renamed-again"}`, expiryMs+123)),
					key(fakeKey{Name: "renamed-again", Enabled: true, ExpiresAt: expiryMs + 123}),
				),
			},
		},
	})
}

func TestAPIKeyResourceCreateDisabled(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var mark int
	second := keyConfig(`name = "first"`, "enabled = false") + keyBlock("second", appRef("test"), `name = "second"`, "enabled = false")
	disabled := func(addr string) func(*terraform.State) error {
		return checkFakeKey(f, addr, func(k fakeKey) error {
			if k.Enabled {
				return fmt.Errorf("key %s is enabled in HERE", k.HRN)
			}
			return nil
		})
	}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				PreConfig: func() { mark = f.mark() },
				Config:    keyConfig(`name = "first"`, "enabled = false"),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkBodies(f, &mark, routeCreateKey, `{"enabled":false,"name":"first"}`),
					checkCalls(f, &mark, routeDisableKey, 0),
					disabled(keyAddr),
				),
			},
			{
				// When HERE ignores enabled on create, the provider disables the key itself.
				PreConfig: func() {
					f.update(func() { f.ignoreCreateEnabled = true })
					mark = f.mark()
				},
				Config:            second,
				ConfigStateChecks: []statecheck.StateCheck{statecheck.ExpectKnownValue("hereplatform_app_api_key.second", tfjsonpath.New("enabled"), knownvalue.Bool(false))},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkCalls(f, &mark, routeDisableKey, 1),
					disabled("hereplatform_app_api_key.second"),
				),
			},
		},
	})
}

func TestAPIKeyResourceReplacedOnAppChange(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	config := func(owner string) string {
		return appBlock("a", "tfacc-owner-a", unprotected) + appBlock("b", "tfacc-owner-b", unprotected) +
			keyBlock("test", appRef(owner), `name = "moving"`)
	}
	differentID := statecheck.CompareValue(compare.ValuesDiffer())
	keyCount := func(addr string, want int) func(*terraform.State) error {
		return checkFakeApp(f, addr, func(a fakeApp) error {
			if len(a.Keys) != want {
				return fmt.Errorf("%s has %d keys, want %d", a.Name, len(a.Keys), want)
			}
			return nil
		})
	}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config:            config("a"),
				ConfigStateChecks: []statecheck.StateCheck{differentID.AddStateValue(keyAddr, tfjsonpath.New("id"))},
				Check:             tfresource.ComposeAggregateTestCheckFunc(keyCount("hereplatform_app.a", 1), keyCount("hereplatform_app.b", 0)),
			},
			{
				Config:           config("b"),
				ConfigPlanChecks: expectAction(keyAddr, plancheck.ResourceActionReplace),
				ConfigStateChecks: []statecheck.StateCheck{
					differentID.AddStateValue(keyAddr, tfjsonpath.New("id")),
					statecheck.CompareValuePairs(keyAddr, tfjsonpath.New("app_hrn"), "hereplatform_app.b", tfjsonpath.New("id"), compare.ValuesSame()),
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(keyCount("hereplatform_app.a", 0), keyCount("hereplatform_app.b", 1)),
			},
		},
	})
}

func TestAPIKeyResourceTwoKeyLimit(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	keys := func(names ...string) string {
		cfg := appConfig("tfacc-limit", unprotected)
		for _, n := range names {
			cfg += keyBlock(n, appRef("test"), "name = "+strconv.Quote(n), timeoutsAttr("create", "1s"))
		}
		return cfg
	}
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: keys("k1", "k2"),
			},
			{
				Config: keys("k1", "k2", "k3"),
				ExpectError: regexp.MustCompile(`(?s)Unable to create HERE API key.*409303.*HERE\s+allows\s+at\s+most\s+2\s+API\s+keys` +
					`\s+per\s+app.*two\s+API\s+keys,\s+the\s+HERE\s+maximum`),
			},
			{
				Config: keys("k1", "k2"),
				Check: checkFakeApp(f, appAddr, func(a fakeApp) error {
					if len(a.Keys) != fakeMaxKeys {
						return fmt.Errorf("app has %d keys, want %d", len(a.Keys), fakeMaxKeys)
					}
					return nil
				}),
			},
			{
				// A deleted key keeps counting for a while; the replacement waits for the slot.
				PreConfig: func() {
					f.update(func() { f.keySlotLag = 3 })
					mark = f.mark()
				},
				Taint:            []string{"hereplatform_app_api_key.k2"},
				Config:           keys("k1", "k2"),
				ConfigPlanChecks: expectAction("hereplatform_app_api_key.k2", plancheck.ResourceActionReplace),
				Check:            checkCalls(f, &mark, routeCreateKey, 4),
			},
		},
	})
}

func TestAPIKeyResourceImport(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	config := keyConfig(`name = "imported"`, `expires_at = "2030-01-02T15:04:05Z"`, "enabled = false")

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: config,
			},
			{
				ResourceName: keyAddr,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					rs := s.RootModule().Resources[keyAddr]
					return rs.Primary.Attributes["app_hrn"] + "," + rs.Primary.ID, nil
				},
				// HERE returns the plaintext key on GET; it is compared without printing it.
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"value", attrDeletionProtection},
				ImportStateCheck:        importChecks(checkImportedKeyValue(f), checkImportedProtected),
			},
			{
				ResourceName: keyAddr,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return s.RootModule().Resources[keyAddr].Primary.ID, nil
				},
				ExpectError: regexp.MustCompile(`Invalid import ID`),
			},
			{
				ResourceName: keyAddr,
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return s.RootModule().Resources[keyAddr].Primary.Attributes["app_hrn"] + ",hrn:here:account::org-fake:apikey/Gone", nil
				},
				ExpectError: regexp.MustCompile(`Cannot import non-existent remote object`),
			},
		},
	})
}

func importState(t *testing.T, r resource.Resource, id string) *resource.ImportStateResponse {
	t.Helper()
	ctx := t.Context()
	var schema resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schema)
	resp := &resource.ImportStateResponse{State: tfsdk.State{
		Schema: schema.Schema,
		Raw:    tftypes.NewValue(schema.Schema.Type().TerraformType(ctx), nil),
	}}
	importer, _ := r.(resource.ResourceWithImportState)
	importer.ImportState(ctx, resource.ImportStateRequest{ID: id}, resp)
	return resp
}

func TestAPIKeyImportIDValidation(t *testing.T) {
	t.Parallel()
	app := fakeAppHRN("FakeApp0001")
	key := "hrn:here:account::org-fake:apikey/FakeKey0002"
	invalid := map[string]string{
		"empty":                "",
		"app HRN only":         app,
		"key HRN only":         key,
		"reversed":             key + "," + app,
		"extra field":          app + "," + key + ",extra",
		"space after comma":    app + ", " + key,
		"leading comma":        "," + app + "," + key,
		"trailing comma":       app + "," + key + ",",
		"semicolon separator":  app + ";" + key,
		"wrong service":        "hrn:here:iam::org-fake:app/FakeApp0001," + key,
		"two key HRNs":         key + "," + key,
		"two app HRNs":         app + "," + app,
		"app HRN with a path":  app + "/extra," + key,
		"key HRN with a path":  app + "," + key + "/extra",
		"missing realm":        "hrn:here:account:::app/FakeApp0001," + key,
		"surrounding newlines": "\n" + app + "," + key + "\n",
	}
	for name, id := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resp := importState(t, newAppAPIKeyResource(), id)
			if !resp.Diagnostics.HasError() || !strings.Contains(diagText(resp.Diagnostics), "Invalid import ID") {
				t.Fatalf("import ID %q accepted: %s", id, diagText(resp.Diagnostics))
			}
		})
	}

	resp := importState(t, newAppAPIKeyResource(), app+","+key)
	if resp.Diagnostics.HasError() {
		t.Fatalf("valid import ID rejected: %s", diagText(resp.Diagnostics))
	}
	var m apiKeyModel
	if diags := resp.State.Get(t.Context(), &m); diags.HasError() {
		t.Fatal(diagText(diags))
	}
	if m.AppHRN.ValueString() != app || m.ID.ValueString() != key {
		t.Fatalf("imported app_hrn %q and id %q", m.AppHRN.ValueString(), m.ID.ValueString())
	}
}

func TestAPIKeyResourceValidation(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	config := func(appHRN string, attrs ...string) string { return keyBlock("test", strconv.Quote(appHRN), attrs...) }
	app := fakeAppHRN("FakeApp0001")

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				Config:      config(app, `name = "k"`, `expires_at = "2030-01-02"`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid RFC 3339 timestamp`),
			},
			{
				Config:      config(app, `name = "k"`, `expires_at = "2030-01-02T15:04:05"`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid RFC 3339 timestamp`),
			},
			{
				Config:      config("FakeApp0001", `name = "k"`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must\s+be\s+an\s+app\s+HRN`),
			},
			{
				Config:      config("hrn:here:account::org-fake:apikey/FakeKey0001", `name = "k"`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must\s+be\s+an\s+app\s+HRN`),
			},
			{
				Config:      config(app, `name = ""`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`length\s+must\s+be\s+at\s+least\s+1`),
			},
		},
	})
}

func TestAPIKeyResourceFailures(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: keyConfig(`name = "primary"`),
			},
			{
				PreConfig:   func() { f.hook(always(routePatchKey, badRequest("name rejected"))) },
				Config:      keyConfig(`name = "renamed"`),
				ExpectError: regexp.MustCompile(`Unable to update HERE API key`),
			},
			{
				// The rename succeeds and is recorded before the toggle fails.
				PreConfig: func() {
					f.clearHooks()
					f.hook(always(routeDisableKey, badRequest("key is locked")))
				},
				Config:      keyConfig(`name = "renamed"`, "enabled = false"),
				ExpectError: regexp.MustCompile(`Unable to change HERE API key state`),
			},
			{
				PreConfig: func() {
					f.clearHooks()
					mark = f.mark()
				},
				Config:           keyConfig(`name = "renamed"`, "enabled = false"),
				ConfigPlanChecks: expectAction(keyAddr, plancheck.ResourceActionUpdate),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkCalls(f, &mark, routePatchKey, 0),
					checkCalls(f, &mark, routeDisableKey, 1),
				),
			},
			{
				PreConfig:   func() { f.hook(sequence(routeGetKey, badRequest("malformed HRN"))) },
				Config:      keyConfig(`name = "renamed"`, "enabled = false"),
				ExpectError: regexp.MustCompile(`Unable to read HERE API key`),
			},
			{
				PreConfig:   func() { f.hook(sequence(routeDeleteKey, badRequest("key is in use"))) },
				Config:      keyConfig(`name = "renamed"`, "enabled = false"),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`Unable to delete HERE API key`),
			},
		},
	})
}

func TestAPIKeyResourceUnconfirmedCreateIsNotReplayed(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.hook(always(routeCreateKey, hereError(http.StatusGatewayTimeout, "504000", "Gateway timeout")))

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkCreatedOnce(f, routeCreateKey),
		Steps: []tfresource.TestStep{{
			Config: keyConfig(`name = "primary"`),
			ExpectError: regexp.MustCompile(
				`(?s)HERE\s+API\s+key\s+creation\s+could\s+not\s+be\s+confirmed.*Gateway\s+timeout.*<app_hrn>,<apikey_hrn>`),
		}},
	})
}

func TestAPIKeyResourceCreateFailures(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	slow := keyConfig(`name = "primary"`, timeoutsAttr("create", "1s"))
	var first string

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				PreConfig:   func() { f.hook(always(routeCreateKey, badRequest("name too long"))) },
				Config:      slow,
				ExpectError: regexp.MustCompile(`(?s)Unable to create HERE API key.*name\s+too\s+long`),
			},
			{
				PreConfig: func() {
					f.clearHooks()
					f.hook(always(routeGetKey, notFound()))
				},
				Config:      slow,
				ExpectError: regexp.MustCompile(`(?s)HERE API key created with errors.*timed\s+out\s+waiting\s+for\s+API\s+key`),
			},
			{
				PreConfig: func() {
					f.clearHooks()
					a := f.apps()[0]
					if len(a.Keys) != 1 {
						t.Fatalf("app has %d keys after the failed create, want the tracked one", len(a.Keys))
					}
					first = a.Keys[0].HRN
				},
				Config:           slow,
				ConfigPlanChecks: expectAction(keyAddr, plancheck.ResourceActionReplace),
				Check: checkFakeKey(f, keyAddr, func(k fakeKey) error {
					if k.HRN == first {
						return fmt.Errorf("tainted key %s was not replaced", first)
					}
					return nil
				}),
			},
			{
				PreConfig: func() {
					f.update(func() { f.ignoreCreateEnabled = true })
					f.hook(always(routeDisableKey, badRequest("key is locked")))
				},
				Config:      slow + keyBlock("second", appRef("test"), `name = "second"`, "enabled = false"),
				ExpectError: regexp.MustCompile(`(?s)HERE API key created with errors.*changing\s+enabled\s+failed`),
			},
			{
				PreConfig: f.clearHooks,
				Config:    slow,
			},
		},
	})
}
