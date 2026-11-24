package provider

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

var (
	// deleteRoutes destroy HERE objects or open an app's API keys to any origin.
	deleteRoutes = []string{routeDeleteApp, routeDeleteKey, routeRemoveDomains, routeDisableEnforcement}
	writeRoutes  = append([]string{
		routeCreateApp, routePatchApp, routeEnableAppCreation, routeDisableAppCreation, routeCreateKey, routePatchKey,
		routeEnableKey, routeDisableKey, routeAddDomains, routeEnableEnforcement,
	}, deleteRoutes...)
)

// wrapped matches text in a diagnostic that Terraform may wrap over several lines.
func wrapped(text string) *regexp.Regexp {
	words := strings.Fields(text)
	for i, w := range words {
		words[i] = regexp.QuoteMeta(w)
	}
	return regexp.MustCompile(strings.Join(words, `\s+`))
}

// guardedStack renders an app with a key and trusted domains, each with its own protection attribute.
func guardedStack(appAttr, keyAttr, domainsAttr string) string {
	return appConfig("tfacc-guarded", appAttr) +
		keyBlock("test", appRef("test"), `name = "primary"`, keyAttr) +
		domainsBlock(appRef("test"), []string{"a.example.com"}, domainsAttr, domainTimeouts)
}

func expectProtection(addr string, want bool) statecheck.StateCheck {
	return statecheck.ExpectKnownValue(addr, tfjsonpath.New(attrDeletionProtection), knownvalue.Bool(want))
}

func checkNoCalls(f *fakeHERE, mark *int, routes ...string) func(*terraform.State) error {
	return func(*terraform.State) error {
		if calls := f.callsSince(*mark, routes...); len(calls) != 0 {
			return fmt.Errorf("HERE received %d unexpected request(s), first %s", len(calls), calls[0].Route)
		}
		return nil
	}
}

// checkStackIntact asserts that the guarded app still has its key and enforced domains.
func checkStackIntact(f *fakeHERE, hrn string) error {
	a, found := f.app(hrn)
	if !found {
		return errors.New("the protected app was deleted")
	}
	if len(a.Keys) != 1 || len(a.Domains) != 1 || !a.DomainsEnabled {
		return fmt.Errorf("protected objects changed: %d key(s), domains %q, enforcement %t", len(a.Keys), a.Domains, a.DomainsEnabled)
	}
	return nil
}

func checkImportedProtected(states []*terraform.InstanceState) error {
	for _, s := range states {
		if got := s.Attributes[attrDeletionProtection]; got != "true" {
			return fmt.Errorf("%s = %q after import, want true", attrDeletionProtection, got)
		}
	}
	return nil
}

func importChecks(checks ...tfresource.ImportStateCheckFunc) tfresource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		for _, c := range checks {
			if err := c(states); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestDeletionProtectionFailsDestroyPlans(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var hrn string
	var mark int
	stack := func(keyAttr, domainsAttr, appAttr string) string { return guardedStack(appAttr, keyAttr, domainsAttr) }

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy: func(s *terraform.State) error {
			if err := checkNoApps(f)(s); err != nil {
				return err
			}
			// Unprotected, the stack is destroyed in dependency order: the app last.
			calls := f.callsSince(mark, deleteRoutes...)
			if len(calls) == 0 || calls[len(calls)-1].Route != routeDeleteApp || len(f.callsSince(mark, routeDeleteKey)) != 1 {
				return fmt.Errorf("unexpected destroy sequence %v", calls)
			}
			return nil
		},
		Steps: []tfresource.TestStep{
			{
				Config: stack(defaultProtection, defaultProtection, defaultProtection),
				ConfigStateChecks: []statecheck.StateCheck{
					expectProtection(appAddr, true), expectProtection(keyAddr, true), expectProtection(domainsAddr, true),
				},
				Check: func(s *terraform.State) (err error) {
					mark = f.mark()
					hrn, err = stateID(s, appAddr)
					return err
				},
			},
			{
				Config:      stack(defaultProtection, defaultProtection, defaultProtection),
				Destroy:     true,
				ExpectError: wrapped("This plan destroys API key"),
			},
			{
				Config:           stack(unprotected, defaultProtection, defaultProtection),
				ConfigPlanChecks: expectAction(keyAddr, plancheck.ResourceActionUpdate),
			},
			{
				Config:      stack(unprotected, defaultProtection, defaultProtection),
				Destroy:     true,
				ExpectError: wrapped("This plan destroys the trusted domain configuration of app"),
			},
			{
				Config:           stack(unprotected, unprotected, defaultProtection),
				ConfigPlanChecks: expectAction(domainsAddr, plancheck.ResourceActionUpdate),
			},
			{
				Config:      stack(unprotected, unprotected, defaultProtection),
				Destroy:     true,
				ExpectError: wrapped("This plan destroys app hrn:here:account::org-fake:app/"),
			},
			{
				PreConfig: func() {
					if err := checkStackIntact(f, hrn); err != nil {
						t.Error(err)
					}
					// Failed destroy plans and protection changes never reach HERE.
					if err := checkNoCalls(f, &mark, writeRoutes...)(nil); err != nil {
						t.Error(err)
					}
				},
				Config:           stack(unprotected, unprotected, unprotected),
				ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionUpdate),
				Check:            checkNoCalls(f, &mark, writeRoutes...),
			},
		},
	})
}

func TestDeletionProtectionFailsReplacePlans(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var mark int
	apps := func(nameA string) string {
		return appBlock("a", nameA, unprotected) + appBlock("b", "tfacc-guard-b", unprotected)
	}
	config := func(keyApp, domainsApp, nameA string) string {
		return apps(nameA) + keyBlock("test", appRef(keyApp), `name = "primary"`, defaultProtection) +
			domainsBlock(appRef(domainsApp), []string{"a.example.com"}, protected, domainTimeouts)
	}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: config("a", "a", "tfacc-guard-a"),
				Check:  func(*terraform.State) error { mark = f.mark(); return nil },
			},
			{
				Config:      config("b", "a", "tfacc-guard-a"),
				ExpectError: wrapped("while deletion_protection = true, because app_hrn changes"),
			},
			{
				Config:      config("a", "b", "tfacc-guard-a"),
				ExpectError: wrapped("This plan replaces the trusted domain configuration of app"),
			},
			{
				// Renaming an adopted app updates it in place: its id stays known, so nothing that
				// depends on it is replaced or blocked.
				Config: config("a", "a", "tfacc-guard-a-renamed"),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("hereplatform_app.a", plancheck.ResourceActionUpdate),
					plancheck.ExpectResourceAction(keyAddr, plancheck.ResourceActionNoop),
					plancheck.ExpectResourceAction(domainsAddr, plancheck.ResourceActionNoop),
				}},
				Check: checkNoCalls(f, &mark, deleteRoutes...),
			},
			{
				Taint:       []string{"hereplatform_app.a"},
				Config:      config("a", "a", "tfacc-guard-a-renamed"),
				ExpectError: wrapped("because app_hrn is unknown until apply, as when its app is replaced"),
			},
			{
				// Forgotten, the protected key and domains no longer hold back the tainted app.
				PreConfig: func() {
					if err := checkNoCalls(f, &mark, deleteRoutes...)(nil); err != nil {
						t.Error(err)
					}
				},
				Config: apps("tfacc-guard-a-renamed") + removedBlock(keyAddr) + removedBlock(domainsAddr),
				Check: func(s *terraform.State) error {
					if _, err := stateID(s, keyAddr); err == nil {
						return errors.New("the key is still in the state")
					}
					if calls := f.callsSince(mark, deleteRoutes...); len(calls) != 1 || calls[0].Route != routeDeleteApp {
						return fmt.Errorf("want only the tainted app deleted, got %v", calls)
					}
					return nil
				},
			},
		},
	})
}

func TestDeletionProtectionAllowsRemovedBlocks(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var hrn string

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: guardedStack(defaultProtection, defaultProtection, defaultProtection),
				Check: func(s *terraform.State) (err error) {
					hrn, err = stateID(s, appAddr)
					return err
				},
			},
			{
				Config: removedBlock(appAddr) + removedBlock(keyAddr) + removedBlock(domainsAddr),
				Check: func(s *terraform.State) error {
					if n := len(s.RootModule().Resources); n != 0 {
						return fmt.Errorf("%d resource(s) left in the state", n)
					}
					if n := len(f.callsOf(deleteRoutes...)); n != 0 {
						return fmt.Errorf("forgetting protected resources sent %d delete request(s)", n)
					}
					if err := checkStackIntact(f, hrn); err != nil {
						return err
					}
					// Forgotten objects stay in HERE; clean up for CheckDestroy.
					f.deleteApp(hrn)
					return nil
				},
			},
		},
	})
}

// Tainted resources are planned as creates, so only Delete can stop their replacement.
func TestDeletionProtectionStopsReplacementOfTaintedResources(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var hrn string
	zero := 0
	app := appConfig("tfacc-guarded", defaultProtection)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: guardedStack(defaultProtection, defaultProtection, defaultProtection),
				Check: func(s *terraform.State) (err error) {
					hrn, err = stateID(s, appAddr)
					return err
				},
			},
			{
				Taint:       []string{keyAddr},
				Config:      guardedStack(defaultProtection, defaultProtection, defaultProtection),
				ExpectError: wrapped("Terraform tried to delete API key"),
			},
			{
				Taint:       []string{domainsAddr},
				Config:      guardedStack(defaultProtection, defaultProtection, defaultProtection),
				ExpectError: wrapped("Terraform tried to delete the trusted domain configuration of app"),
			},
			{
				Config: app + removedBlock(keyAddr) + removedBlock(domainsAddr),
				Check:  checkNoCalls(f, &zero, deleteRoutes...),
			},
			{
				Taint:       []string{appAddr},
				Config:      app,
				ExpectError: wrapped("Terraform tried to delete app"),
			},
			{
				Config: removedBlock(appAddr),
				Check: func(s *terraform.State) error {
					if err := checkNoCalls(f, &zero, deleteRoutes...)(s); err != nil {
						return err
					}
					if n := len(f.callsOf(routeCreateApp, routeCreateKey)); n != 2 {
						return fmt.Errorf("%d creates; a refused delete must stop the replacement", n)
					}
					if err := checkStackIntact(f, hrn); err != nil {
						return err
					}
					f.deleteApp(hrn)
					return nil
				},
			},
		},
	})
}

// modifyPlan calls ModifyPlan directly, the only way to observe plan warnings; nil attrs
// make a null object, as for creates (prior) and destroys (planned).
func modifyPlan(t *testing.T, r resource.Resource, prior, planned map[string]any) diag.Diagnostics {
	t.Helper()
	ctx := t.Context()
	var sr resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sr)
	typ := sr.Schema.Type().TerraformType(ctx)
	state := tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(typ, nil)}
	plan := tfsdk.Plan{Schema: sr.Schema, Raw: tftypes.NewValue(typ, nil)}
	for name, v := range prior {
		if diags := state.SetAttribute(ctx, path.Root(name), v); diags.HasError() {
			t.Fatal(diagText(diags))
		}
	}
	for name, v := range planned {
		if diags := plan.SetAttribute(ctx, path.Root(name), v); diags.HasError() {
			t.Fatal(diagText(diags))
		}
	}
	req := resource.ModifyPlanRequest{State: state, Plan: plan, Config: tfsdk.Config{Schema: sr.Schema, Raw: plan.Raw}}
	resp := &resource.ModifyPlanResponse{Plan: plan}
	modifier, ok := r.(resource.ResourceWithModifyPlan)
	if !ok {
		t.Fatalf("%T does not implement ModifyPlan", r)
	}
	modifier.ModifyPlan(ctx, req, resp)
	return resp.Diagnostics
}

type planCase struct {
	prior, planned   map[string]any
	errors, warnings []string
}

func runPlanCases(t *testing.T, newResource func() resource.Resource, cases map[string]planCase, secrets ...string) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			diags := modifyPlan(t, newResource(), tc.prior, tc.planned)
			text := diagText(diags)
			if diags.ErrorsCount() != min(len(tc.errors), 1) || diags.WarningsCount() != min(len(tc.warnings), 1) {
				t.Fatalf("got %d error(s) and %d warning(s): %s", diags.ErrorsCount(), diags.WarningsCount(), text)
			}
			for _, want := range append(tc.errors, tc.warnings...) {
				if !strings.Contains(text, want) {
					t.Errorf("diagnostics do not contain %q: %s", want, text)
				}
			}
			for _, s := range secrets {
				if strings.Contains(text, s) {
					t.Errorf("diagnostics leak a secret: %s", text)
				}
			}
		})
	}
}

func TestAppModifyPlan(t *testing.T) {
	t.Parallel()
	hrn := fakeAppHRN("FakeApp0001")
	prior := func(protection types.Bool) map[string]any {
		return map[string]any{"id": hrn, "hrn": hrn, "name": "app", attrDeletionProtection: protection}
	}
	destroyError := []string{protectedSummary, "This plan destroys app " + hrn + " while deletion_protection = true",
		"set deletion_protection = false and apply", "removed block", "terraform state rm"}
	runPlanCases(t, newAppResource, map[string]planCase{
		"create":                     {planned: map[string]any{"name": "app"}},
		"destroy protected":          {prior: prior(types.BoolValue(true)), errors: destroyError},
		"destroy with null in state": {prior: prior(types.BoolNull()), errors: destroyError},
		"destroy unprotected":        {prior: prior(types.BoolValue(false))},
		"update protected":           {prior: prior(types.BoolValue(true)), planned: map[string]any{"name": "renamed"}},
	})
}

func TestAPIKeyModifyPlan(t *testing.T) {
	t.Parallel()
	app, other := fakeAppHRN("FakeApp0001"), fakeAppHRN("FakeApp0002")
	key := "hrn:here:account::org-fake:apikey/FakeKey0003"
	const value = "plaintext-api-key-value"
	prior := func(protection types.Bool) map[string]any {
		return map[string]any{"id": key, "hrn": key, "app_hrn": app, "name": "k", "value": value, attrDeletionProtection: protection}
	}
	planned := func(appHRN types.String) map[string]any {
		return map[string]any{"app_hrn": appHRN, "name": "k", attrDeletionProtection: types.BoolValue(true)}
	}
	rotation := "add a second hereplatform_app_api_key (HERE allows two per app), switch the clients to it"
	runPlanCases(t, newAppAPIKeyResource, map[string]planCase{
		"create": {planned: planned(types.StringValue(app))},
		"destroy protected": {prior: prior(types.BoolValue(true)), errors: []string{
			"This plan destroys API key " + key + " of app " + app, "breaks every client that uses it", rotation,
		}},
		"destroy with null in state": {prior: prior(types.BoolNull()), errors: []string{"This plan destroys API key"}},
		"destroy unprotected":        {prior: prior(types.BoolValue(false))},
		"in-place update":            {prior: prior(types.BoolValue(true)), planned: planned(types.StringValue(app))},
		"move to another app": {prior: prior(types.BoolValue(true)), planned: planned(types.StringValue(other)), errors: []string{
			"This plan replaces API key " + key, "because app_hrn changes", "terraform untaint on a tainted app", "apply deletion_protection = false in a plan that does not replace it", rotation,
		}},
		"app replaced": {prior: prior(types.BoolValue(true)), planned: planned(types.StringUnknown()), errors: []string{
			"because app_hrn is unknown until apply, as when its app is replaced",
		}},
		"replace unprotected": {prior: prior(types.BoolValue(false)), planned: planned(types.StringUnknown())},
	}, value)
}

func TestTrustedDomainsModifyPlan(t *testing.T) {
	t.Parallel()
	app, other := fakeAppHRN("FakeApp0001"), fakeAppHRN("FakeApp0002")
	prior := func(protection types.Bool, enabled bool) map[string]any {
		return map[string]any{
			"id": app, "app_hrn": app, "domains": []string{"a.example.com"}, "enabled": enabled, attrDeletionProtection: protection,
		}
	}
	planned := func(appHRN types.String, enabled types.Bool) map[string]any {
		return map[string]any{"app_hrn": appHRN, "domains": []string{"a.example.com"}, "enabled": enabled}
	}
	on, off := types.BoolValue(true), types.BoolValue(false)
	same := types.StringValue(app)
	failOpen := []string{failOpenSummary, "This plan deletes the trusted domain configuration of app " + app,
		"accepts the app's API keys from any origin"}
	runPlanCases(t, newAppTrustedDomainsResource, map[string]planCase{
		"create disabled": {planned: planned(same, off)},
		"destroy protected": {prior: prior(on, true), errors: []string{
			"This plan destroys the trusted domain configuration of app " + app, "turns enforcement off",
		}},
		"destroy with null in state":        {prior: prior(types.BoolNull(), false), errors: []string{protectedSummary}},
		"destroy unprotected and enforced":  {prior: prior(off, true), warnings: failOpen},
		"destroy unprotected, not enforced": {prior: prior(off, false)},
		"move to another app": {prior: prior(on, true), planned: planned(types.StringValue(other), on), errors: []string{
			"This plan replaces the trusted domain configuration of app " + app, "because app_hrn changes",
		}},
		"app replaced": {prior: prior(on, true), planned: planned(types.StringUnknown(), on), errors: []string{
			"app_hrn is unknown until apply",
		}},
		"replace unprotected and enforced": {prior: prior(off, true), planned: planned(types.StringValue(other), on), warnings: failOpen},
		"disable enforcement": {prior: prior(on, true), planned: planned(same, off), warnings: []string{
			failOpenSummary, "sets enabled = false",
		}},
		"enforcement unknown":     {prior: prior(on, true), planned: planned(same, types.BoolUnknown())},
		"keep enforcement":        {prior: prior(on, true), planned: planned(same, on)},
		"enable enforcement":      {prior: prior(on, false), planned: planned(same, on)},
		"stay disabled on update": {prior: prior(off, false), planned: planned(same, off)},
	})
}

func TestGuardsDestroyPlans(t *testing.T) {
	t.Parallel()
	for version, want := range map[string]bool{
		"1.3.0": true, "1.9.1": true, "1.10.0-beta1": true, "2.0.0": true,
		"1.2.9": false, "1.0.0": false, "0.15.5": false,
		"": true, "dev": true, "1": true, "1.x.0": true,
	} {
		if got := guardsDestroyPlans(version); got != want {
			t.Errorf("guardsDestroyPlans(%q) = %t, want %t", version, got, want)
		}
	}
}

func TestConfigureWarnsWithoutPlanTimeGuards(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	for version, warns := range map[string]bool{"1.2.9": true, "1.3.0": false, "1.9.1": false} {
		p := New("test", WithEnv(func(string) string { return "" }))()
		var sr fwprovider.SchemaResponse
		p.Schema(ctx, fwprovider.SchemaRequest{}, &sr)
		typ, _ := sr.Schema.Type().TerraformType(ctx).(tftypes.Object)
		attrs := make(map[string]tftypes.Value, len(typ.AttributeTypes))
		for name, at := range typ.AttributeTypes {
			attrs[name] = tftypes.NewValue(at, nil)
		}
		var resp fwprovider.ConfigureResponse
		p.Configure(ctx, fwprovider.ConfigureRequest{
			TerraformVersion: version,
			Config:           tfsdk.Config{Schema: sr.Schema, Raw: tftypes.NewValue(typ, attrs)},
		}, &resp)
		text := diagText(resp.Diagnostics)
		if got := strings.Contains(text, "deletion_protection is not checked at plan time"); got != warns {
			t.Errorf("Terraform %s: plan-time warning shown = %t, want %t: %s", version, got, warns, text)
		}
	}
}
