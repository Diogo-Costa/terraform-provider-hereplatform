package provider

import (
	"fmt"
	"net/http"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const appAddr = "hereplatform_app.test"

var (
	rfc3339UTCRegexp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)
	fakeAppHRNRegexp = regexp.MustCompile(`^hrn:here:account::org-fake:app/FakeApp\d{4}$`)
)

func expectAppAttr(attr string, v knownvalue.Check) statecheck.StateCheck {
	return statecheck.ExpectKnownValue(appAddr, tfjsonpath.New(attr), v)
}

func expectAction(addr string, action plancheck.ResourceActionType) tfresource.ConfigPlanChecks {
	return tfresource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(addr, action)}}
}

func TestAppResourceLifecycle(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	sameID := statecheck.CompareValue(compare.ValuesSame())
	sameClientID := statecheck.CompareValue(compare.ValuesSame())
	var mark int
	patchBody := func(want map[string]any) func(*terraform.State) error {
		return func(*terraform.State) error {
			patches := f.callsSince(mark, routePatchApp)
			if len(patches) != 1 {
				return fmt.Errorf("got %d PATCH requests, want 1", len(patches))
			}
			if got := patches[0].json(); fmt.Sprint(got) != fmt.Sprint(want) {
				return fmt.Errorf("PATCH body = %v, want %v", got, want)
			}
			if n := len(f.callsOf(routeCreateApp)); n != 1 {
				return fmt.Errorf("app created %d times; an update must never replace it", n)
			}
			return nil
		}
	}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: appConfig("tfacc-app", `description = "first"`, unprotected),
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(appAddr, tfjsonpath.New("id")),
					sameClientID.AddStateValue(appAddr, tfjsonpath.New("client_id")),
					statecheck.CompareValuePairs(appAddr, tfjsonpath.New("id"), appAddr, tfjsonpath.New("hrn"), compare.ValuesSame()),
					expectAppAttr("hrn", knownvalue.StringRegexp(fakeAppHRNRegexp)),
					expectAppAttr("client_id", knownvalue.StringRegexp(regexp.MustCompile(`^FakeApp\d{4}$`))),
					expectAppAttr("realm", knownvalue.StringExact(fakeRealm)),
					expectAppAttr("status", knownvalue.StringExact("active")),
					expectAppAttr("created_time", knownvalue.StringRegexp(rfc3339UTCRegexp)),
					expectAppAttr("description", knownvalue.StringExact("first")),
					expectAppAttr("app_creation_enabled", knownvalue.Bool(false)),
					expectAppAttr("deletion_protection", knownvalue.Bool(false)),
				},
				Check: checkFakeApp(f, appAddr, func(a fakeApp) error {
					if a.Name != "tfacc-app" || a.Description != "first" || a.AppCreationEnabled {
						return fmt.Errorf("fake app = {%s %q %t}", a.Name, a.Description, a.AppCreationEnabled)
					}
					return nil
				}),
			},
			{
				PreConfig:        func() { mark = f.mark() },
				Config:           appConfig("tfacc-app-renamed", `description = "second"`, unprotected),
				ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(appAddr, tfjsonpath.New("id")),
					sameClientID.AddStateValue(appAddr, tfjsonpath.New("client_id")),
					expectAppAttr("name", knownvalue.StringExact("tfacc-app-renamed")),
					expectAppAttr("description", knownvalue.StringExact("second")),
				},
				Check: patchBody(map[string]any{"name": "tfacc-app-renamed", "description": "second"}),
			},
			{
				PreConfig:        func() { mark = f.mark() },
				Config:           appConfig("tfacc-app-renamed", unprotected),
				ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(appAddr, tfjsonpath.New("id")),
					expectAppAttr("description", knownvalue.Null()),
				},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					// Assumption 1: an empty description clears it.
					patchBody(map[string]any{"name": "tfacc-app-renamed", "description": ""}),
					checkFakeApp(f, appAddr, func(a fakeApp) error {
						if a.Description != "" {
							return fmt.Errorf("description = %q, want it cleared", a.Description)
						}
						return nil
					}),
				),
			},
			{
				PreConfig: func() { mark = f.mark() },
				Config:    appConfig("tfacc-app-final", unprotected),
				ConfigStateChecks: []statecheck.StateCheck{
					sameID.AddStateValue(appAddr, tfjsonpath.New("id")),
					sameClientID.AddStateValue(appAddr, tfjsonpath.New("client_id")),
				},
				Check: patchBody(map[string]any{"name": "tfacc-app-final"}),
			},
		},
	})
}

func TestAppResourceAppCreationEnabled(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	// The creator's permissions on a new app propagate like any IAM change.
	f.hook(sequence(routeEnableAppCreation, notFound(), hereError(http.StatusForbidden, "403300", "Forbidden")))
	config := func(enabled bool) string {
		return appConfig("tfacc-app-creation", fmt.Sprintf("app_creation_enabled = %t", enabled), unprotected)
	}
	flag := func(want bool, route string, calls int) func(*terraform.State) error {
		return tfresource.ComposeAggregateTestCheckFunc(
			checkFakeApp(f, appAddr, func(a fakeApp) error {
				if a.AppCreationEnabled != want {
					return fmt.Errorf("appCreationEnabled = %t, want %t", a.AppCreationEnabled, want)
				}
				return nil
			}),
			func(*terraform.State) error {
				if n := len(f.callsOf(route)); n != calls {
					return fmt.Errorf("%d calls of %s, want %d", n, route, calls)
				}
				return nil
			},
		)
	}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config:            config(true),
				ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("app_creation_enabled", knownvalue.Bool(true))},
				Check:             flag(true, routeEnableAppCreation, 3),
			},
			{
				Config:            config(false),
				ConfigPlanChecks:  expectAction(appAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("app_creation_enabled", knownvalue.Bool(false))},
				Check:             flag(false, routeDisableAppCreation, 1),
			},
			{
				Config:            config(true),
				ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("app_creation_enabled", knownvalue.Bool(true))},
				Check:             flag(true, routeEnableAppCreation, 4),
			},
		},
	})
}

func TestAppResourceDeletionProtection(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var hrn string
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config:            appConfig("tfacc-protected"),
				ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("deletion_protection", knownvalue.Bool(true))},
				Check: func(s *terraform.State) (err error) {
					hrn, err = stateID(s, appAddr)
					return err
				},
			},
			{
				Config:      appConfig("tfacc-protected"),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`Deletion protection is enabled`),
			},
			{
				PreConfig: func() {
					if _, found := f.app(hrn); !found {
						t.Error("the protected app was deleted")
					}
					if n := len(f.callsOf(routeDeleteApp)); n != 0 {
						t.Errorf("%d DELETE requests reached HERE for a protected app", n)
					}
					mark = f.mark()
				},
				Config:            appConfig("tfacc-protected", unprotected),
				ConfigPlanChecks:  expectAction(appAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("deletion_protection", knownvalue.Bool(false))},
				Check: func(*terraform.State) error {
					// The guard is provider-side only.
					writes := f.callsSince(mark, routePatchApp, routeEnableAppCreation, routeDisableAppCreation, routeDeleteApp)
					if len(writes) != 0 {
						return fmt.Errorf("toggling deletion_protection sent %d requests to HERE", len(writes))
					}
					return nil
				},
			},
			{
				PreConfig:   func() { f.hook(sequence(routeDeleteApp, badRequest("app is in use"))) },
				Config:      appConfig("tfacc-protected", unprotected),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`Unable to delete HERE app`),
			},
		},
	})
}

func TestAppResourceImport(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: appConfig("tfacc-import", `description = "imported"`, "app_creation_enabled = true"),
			},
			{
				ResourceName:      appAddr,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:  appAddr,
				ImportState:   true,
				ImportStateId: "FakeApp0001",
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
			{
				ResourceName:  appAddr,
				ImportState:   true,
				ImportStateId: fakeAppHRN("FakeApp9999"),
				ExpectError:   regexp.MustCompile(`Cannot import non-existent remote object`),
			},
			{
				Config: appConfig("tfacc-import", `description = "imported"`, "app_creation_enabled = true", unprotected),
			},
		},
	})
}

func TestAppResourceFailedUpdateKeepsPriorState(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: appConfig("tfacc-before", unprotected),
			},
			{
				PreConfig:   func() { f.hook(always(routePatchApp, badRequest("name rejected"))) },
				Config:      appConfig("tfacc-after", unprotected, "app_creation_enabled = true"),
				ExpectError: regexp.MustCompile(`Unable to update HERE app`),
			},
			{
				PreConfig:        f.clearHooks,
				Config:           appConfig("tfacc-after", unprotected, "app_creation_enabled = true"),
				ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: []statecheck.StateCheck{
					expectAppAttr("name", knownvalue.StringExact("tfacc-after")),
					expectAppAttr("app_creation_enabled", knownvalue.Bool(true)),
				},
			},
			{
				PreConfig:   func() { f.hook(always(routeDisableAppCreation, badRequest("not allowed"))) },
				Config:      appConfig("tfacc-after", unprotected),
				ExpectError: regexp.MustCompile(`Unable to change app creation on HERE app`),
			},
			{
				PreConfig:   func() { f.clearHooks(); f.hook(sequence(routeGetApp, badRequest("malformed HRN"))) },
				Config:      appConfig("tfacc-after", unprotected),
				ExpectError: regexp.MustCompile(`Unable to read HERE app`),
			},
		},
	})
}

func TestAppResourceCreateFailure(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.hook(always(routeCreateApp, hereError(http.StatusConflict, "409100", "App name already in use")))

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{{
			Config:      appConfig("tfacc-taken"),
			ExpectError: regexp.MustCompile(`(?s)Unable to create HERE app.*App\s+name\s+already\s+in\s+use`),
		}},
	})
}

// checkCreatedOnce asserts that a create HERE may have applied was not replayed.
func checkCreatedOnce(f *fakeHERE, route string) func(*terraform.State) error {
	return func(s *terraform.State) error {
		if n := len(f.callsOf(route)); n != 1 {
			return fmt.Errorf("%d %s requests, want 1", n, route)
		}
		return checkNoApps(f)(s)
	}
}

func TestAppResourceUnconfirmedCreateIsNotReplayed(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.hook(always(routeCreateApp, hereError(http.StatusServiceUnavailable, "503000", "Service unavailable")))

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkCreatedOnce(f, routeCreateApp),
		Steps: []tfresource.TestStep{{
			Config: appConfig("tfacc-unconfirmed"),
			ExpectError: regexp.MustCompile(
				`(?s)HERE\s+app\s+creation\s+could\s+not\s+be\s+confirmed.*Service\s+unavailable.*import\s+it\s+by\s+its\s+HRN`),
		}},
	})
}

func TestAppResourceCreateTimeoutTaintsApp(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.hook(always(routeGetApp, notFound()))
	config := appConfig("tfacc-slow", unprotected, timeoutsAttr("create", "1s"))
	var first string

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`(?s)HERE app created with errors.*timed\s+out\s+waiting\s+for\s+app`),
			},
			{
				PreConfig: func() {
					apps := f.apps()
					if len(apps) != 1 {
						t.Fatalf("%d apps after the failed create, want the tracked one", len(apps))
					}
					first = apps[0].HRN
					f.clearHooks()
				},
				Config:           config,
				ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionReplace),
				Check: checkFakeApp(f, appAddr, func(a fakeApp) error {
					if _, found := f.app(first); found || a.HRN == first {
						return fmt.Errorf("tainted app %s was not replaced", first)
					}
					return nil
				}),
			},
		},
	})
}

func TestAppResourceCreateWithAppCreationFailureTaintsApp(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.hook(always(routeEnableAppCreation, badRequest("manage permission required")))

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config:      appConfig("tfacc-no-manage", "app_creation_enabled = true", unprotected),
				ExpectError: regexp.MustCompile(`(?s)HERE app created with errors.*changing\s+app_creation_enabled\s+failed`),
			},
			{
				Config:           appConfig("tfacc-no-manage", unprotected),
				ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionReplace),
			},
		},
	})
}
