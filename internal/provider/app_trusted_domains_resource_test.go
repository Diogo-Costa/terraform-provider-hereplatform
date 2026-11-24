package provider

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const domainsAddr = "hereplatform_app_trusted_domains.test"

// Short timeouts turn a convergence regression into a fast failure instead of a 10-minute wait.
var domainTimeouts = timeoutsAttr("create", "5s", "update", "5s", "delete", "5s")

func domainsConfig(appHRN string, domains []string, attrs ...string) string {
	return domainsBlock("test", strconv.Quote(appHRN), domains, attrs...)
}

func expectDomains(domains ...string) statecheck.StateCheck {
	checks := make([]knownvalue.Check, len(domains))
	for i, d := range domains {
		checks[i] = knownvalue.StringExact(d)
	}
	return statecheck.ExpectKnownValue(domainsAddr, tfjsonpath.New("domains"), knownvalue.SetExact(checks))
}

func checkLiveDomains(f *fakeHERE, appHRN string, enabled bool, domains ...string) func(*terraform.State) error {
	want := slices.Sorted(slices.Values(domains))
	return func(*terraform.State) error {
		a, found := f.app(appHRN)
		if !found {
			return fmt.Errorf("app %s not found in the fake HERE API", appHRN)
		}
		got := slices.Sorted(slices.Values(a.Domains))
		if !slices.Equal(got, want) || a.DomainsEnabled != enabled {
			return fmt.Errorf("HERE has domains %q with enforcement %t, want %q with %t", got, a.DomainsEnabled, want, enabled)
		}
		return nil
	}
}

// checkWriteOrder compares the order of trusted-domain writes since mark, merging repeats.
func checkWriteOrder(f *fakeHERE, mark *int, want ...string) func(*terraform.State) error {
	return func(*terraform.State) error {
		var got []string
		for _, c := range f.callsSince(*mark, routeAddDomains, routeRemoveDomains, routeEnableEnforcement, routeDisableEnforcement) {
			if len(got) == 0 || got[len(got)-1] != c.Route {
				got = append(got, c.Route)
			}
		}
		if !slices.Equal(got, want) {
			return fmt.Errorf("trusted domain writes ran as %q, want %q", got, want)
		}
		return nil
	}
}

func batchEntries(c fakeCall) []string {
	if c.Route == routeAddDomains {
		var in struct {
			Data []string `json:"data"`
		}
		_ = json.Unmarshal(c.Body, &in)
		return in.Data
	}
	raw, _ := listParam(c.RawQuery)
	return strings.Split(raw, ",")
}

func checkBatches(f *fakeHERE, mark *int, route string, sizes ...int) func(*terraform.State) error {
	return func(*terraform.State) error {
		var got []int
		for _, c := range f.callsSince(*mark, route) {
			got = append(got, len(batchEntries(c)))
		}
		if !slices.Equal(got, sizes) {
			return fmt.Errorf("%s batch sizes = %v, want %v", route, got, sizes)
		}
		return nil
	}
}

func numberedDomains(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%02d.example.com", prefix, i)
	}
	return out
}

func TestTrustedDomainsResourceBatching(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.pageSize = 10 })
	app := f.seedApp("tfacc-batching")
	initial := numberedDomains("d", 25)
	// Schemes, ports and paths exercise the encoding of bulk deletes.
	initial[0] = "https://d00.example.com"
	initial[1] = "https://d01.example.com:8443/app/v1"
	initial[2] = "http://192.168.1.1:8080"
	added := []string{"n00.example.com", "n01.example.com", "n02.example.com"}
	updated := append(slices.Clone(initial[12:]), added...)
	final := append(slices.Clone(updated[1:]), "n03.example.com")
	var mark int
	setMark := func() { mark = f.mark() }

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkLiveDomains(f, app.HRN, false),
		Steps: []tfresource.TestStep{
			{
				PreConfig:         setMark,
				Config:            domainsConfig(app.HRN, initial, domainTimeouts),
				ConfigStateChecks: []statecheck.StateCheck{expectDomains(initial...)},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					tfresource.TestCheckResourceAttr(domainsAddr, "id", app.HRN),
					tfresource.TestCheckResourceAttr(domainsAddr, "enabled", "true"),
					checkBatches(f, &mark, routeAddDomains, 10, 10, 5),
					checkBatches(f, &mark, routeRemoveDomains),
					checkWriteOrder(f, &mark, routeAddDomains, routeEnableEnforcement),
					checkLiveDomains(f, app.HRN, true, initial...),
					func(*terraform.State) error {
						// One page for the empty list, then three to confirm convergence.
						var tokens []string
						for _, c := range f.callsSince(mark, routeListDomains) {
							if c.Query.Get("limit") != "100" {
								return fmt.Errorf("list sent limit=%q, want 100", c.Query.Get("limit"))
							}
							tokens = append(tokens, c.Query.Get("pageToken"))
						}
						if want := []string{"", "", "page-10", "page-20"}; !slices.Equal(tokens, want) {
							return fmt.Errorf("page tokens = %q, want %q", tokens, want)
						}
						return nil
					},
				),
			},
			{
				// Disabling comes first so that a shrinking list is never enforced half-applied.
				PreConfig: setMark,
				Config:    domainsConfig(app.HRN, updated, "enabled = false", domainTimeouts),
				ConfigPlanChecks: tfresource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(domainsAddr, plancheck.ResourceActionUpdate)},
				},
				ConfigStateChecks: []statecheck.StateCheck{expectDomains(updated...)},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkWriteOrder(f, &mark, routeDisableEnforcement, routeAddDomains, routeRemoveDomains),
					checkBatches(f, &mark, routeAddDomains, 3),
					checkBatches(f, &mark, routeRemoveDomains, 10, 2),
					checkLiveDomains(f, app.HRN, false, updated...),
					func(*terraform.State) error {
						var removed, raw []string
						for _, c := range f.callsSince(mark, routeRemoveDomains) {
							raw = append(raw, c.RawQuery)
							for _, e := range batchEntries(c) {
								d, err := pathUnescape(e)
								if err != nil {
									return err
								}
								removed = append(removed, d)
							}
						}
						if got, want := slices.Sorted(slices.Values(removed)), slices.Sorted(slices.Values(initial[:12])); !slices.Equal(got, want) {
							return fmt.Errorf("removed %q, want %q", got, want)
						}
						joined := strings.Join(raw, "&")
						for _, enc := range []string{"https%3A%2F%2Fd01.example.com%3A8443%2Fapp%2Fv1", "http%3A%2F%2F192.168.1.1%3A8080"} {
							if !strings.Contains(joined, enc) {
								return fmt.Errorf("bulk delete queries %q lack %q", raw, enc)
							}
						}
						return nil
					},
				),
			},
			{
				// Enabling comes last so that only the complete list is enforced.
				PreConfig:         setMark,
				Config:            domainsConfig(app.HRN, final, domainTimeouts),
				ConfigStateChecks: []statecheck.StateCheck{expectDomains(final...)},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkWriteOrder(f, &mark, routeAddDomains, routeRemoveDomains, routeEnableEnforcement),
					checkLiveDomains(f, app.HRN, true, final...),
				),
			},
			{
				PreConfig: setMark,
				Config:    domainsConfig(app.HRN, final, domainTimeouts),
				Destroy:   true,
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkWriteOrder(f, &mark, routeDisableEnforcement, routeRemoveDomains),
					checkBatches(f, &mark, routeRemoveDomains, 10, 6),
				),
			},
		},
	})
}

func pathUnescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("truncated escape in %q", s)
		}
		n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", fmt.Errorf("invalid escape in %q", s)
		}
		b.WriteByte(byte(n))
		i += 2
	}
	return b.String(), nil
}

func TestTrustedDomainsResourcePartialFailure(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.rejectDomains = map[string]int{"bad.example.com": 400367} })
	app := f.seedApp("tfacc-partial")
	good := numberedDomains("g", 11)
	withBad := append(slices.Clone(good), "bad.example.com")
	rejected := `(?s)HERE\s+rejected\s+1\s+trusted\s+domain\(s\)\s+while\s+adding:\s+"bad\.example\.com"\s+\(status\s+400367\)` +
		`.*400367\s+marks\s+an\s+invalid\s+URI`
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				// The rejected entry sorts first; the remaining batch still runs.
				PreConfig:   func() { mark = f.mark() },
				Config:      domainsConfig(app.HRN, withBad, domainTimeouts),
				ExpectError: regexp.MustCompile(`(?s)Unable to configure HERE trusted domains.*` + rejected),
			},
			{
				PreConfig: func() {
					if err := checkBatches(f, &mark, routeAddDomains, 10, 2)(nil); err != nil {
						t.Fatal(err)
					}
					// Enforcement never turned on for the incomplete list.
					if err := checkLiveDomains(f, app.HRN, false, good...)(nil); err != nil {
						t.Fatal(err)
					}
				},
				Config:           domainsConfig(app.HRN, good, domainTimeouts),
				ConfigPlanChecks: expectAction(domainsAddr, plancheck.ResourceActionCreate),
				Check:            checkLiveDomains(f, app.HRN, true, good...),
			},
			{
				Config:      domainsConfig(app.HRN, withBad, domainTimeouts),
				ExpectError: regexp.MustCompile(`(?s)Unable to update HERE trusted domains.*` + rejected),
			},
			{
				// The failed update kept the prior state, which still matches HERE.
				Config:   domainsConfig(app.HRN, good, domainTimeouts),
				PlanOnly: true,
			},
		},
	})
}

func TestTrustedDomainsResourceConflictCountsAsAdded(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.conflictOnDuplicate = true })
	app := f.seedApp("tfacc-conflict", func(a *fakeApp) { a.Domains = []string{"a.example.com"} })
	// A stale empty list makes the provider re-add an entry HERE already holds, which HERE answers with a per-entry 409.
	f.hook(forApp(app.HRN, sequence(routeListDomains, okJSON(map[string]any{"items": []string{}, "total": 0, "limit": 100}))))

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				Config: domainsConfig(app.HRN, []string{"a.example.com", "b.example.com"}, domainTimeouts),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkBodies(f, new(int), routeAddDomains, `{"data":["a.example.com","b.example.com"]}`),
					checkLiveDomains(f, app.HRN, true, "a.example.com", "b.example.com"),
				),
			},
		},
	})
}

func TestTrustedDomainsResourceNormalisation(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.normalize = hereNormalize })
	app := f.seedApp("tfacc-normalised")
	spelled := []string{"API.Example.com/", "Example.COM", "HTTPS://WWW.Example.com:8443/Path/"}
	respelled := []string{"API.Example.com/", "example.com/", "HTTPS://WWW.Example.com:8443/Path/"}
	stored := []string{"api.example.com", "example.com", "https://www.example.com:8443/Path"}
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkLiveDomains(f, app.HRN, false),
		Steps: []tfresource.TestStep{
			{
				// The empty post-apply plans prove that HERE's spelling causes no diff, and two
				// list calls (diff, then one convergence poll) that the wait does not spin on it.
				Config:            domainsConfig(app.HRN, spelled, domainTimeouts),
				ConfigStateChecks: []statecheck.StateCheck{expectDomains(spelled...)},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkLiveDomains(f, app.HRN, true, stored...),
					checkCalls(f, &mark, routeListDomains, 2),
				),
			},
			{
				PreConfig:         func() { mark = f.mark() },
				Config:            domainsConfig(app.HRN, respelled, domainTimeouts),
				ConfigPlanChecks:  expectAction(domainsAddr, plancheck.ResourceActionUpdate),
				ConfigStateChecks: []statecheck.StateCheck{expectDomains(respelled...)},
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkWriteOrder(f, &mark),
					checkLiveDomains(f, app.HRN, true, stored...),
					checkCalls(f, &mark, routeListDomains, 3),
				),
			},
		},
	})
}

func TestTrustedDomainsResourceUnmodelledNormalisationTimesOut(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	// HERE could normalise beyond case and trailing slashes, for example by dropping the scheme.
	f.update(func() {
		f.normalize = func(d string) string {
			if _, rest, found := strings.Cut(d, "://"); found {
				return rest
			}
			return d
		}
	})
	app := f.seedApp("tfacc-unmodelled")
	started := time.Now()

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				Config: domainsConfig(app.HRN, []string{"https://strip.example.com"}, timeoutsAttr("create", "1s")),
				ExpectError: regexp.MustCompile(`(?s)Unable to configure HERE trusted domains.*timed\s+out\s+waiting\s+for\s+trusted` +
					`\s+domains\s+of\s+\S+\s+to\s+converge.*enabled=true,\s+1\s+missing\s+domain\(s\)\s+\["https://strip\.example\.com"\]` +
					`\s+and\s+1\s+unexpected\s+domain\(s\)\s+\["strip\.example\.com"\]`),
			},
		},
	})
	if elapsed := time.Since(started); elapsed > time.Minute {
		t.Errorf("convergence wait ignored the 1s create timeout: took %s", elapsed)
	}
}

func TestTrustedDomainsResourceDelete(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	app := f.seedApp("tfacc-delete")
	config := domainsConfig(app.HRN, []string{"a.example.com", "b.example.com"}, domainTimeouts)
	var mark int
	setMark := func() { mark = f.mark() }

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				Config: config,
				Check:  checkLiveDomains(f, app.HRN, true, "a.example.com", "b.example.com"),
			},
			{
				PreConfig: setMark,
				Config:    config,
				Destroy:   true,
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkWriteOrder(f, &mark, routeDisableEnforcement, routeRemoveDomains),
					checkLiveDomains(f, app.HRN, false),
				),
			},
			{
				Config: config,
				Check:  checkLiveDomains(f, app.HRN, true, "a.example.com", "b.example.com"),
			},
			{
				// Assumption 6: a 404 for the whole bulk delete means nothing is left to remove.
				PreConfig: func() {
					f.hook(always(routeRemoveDomains, notFound()))
					setMark()
				},
				Config:  config,
				Destroy: true,
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkWriteOrder(f, &mark, routeDisableEnforcement, routeRemoveDomains),
					checkLiveDomains(f, app.HRN, false, "a.example.com", "b.example.com"),
				),
			},
			{
				PreConfig: f.clearHooks,
				Config:    config,
			},
			{
				// The app vanished out of band: refresh drops the resource and destroy has nothing to do.
				PreConfig:          func() { f.deleteApp(app.HRN) },
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				PreConfig: setMark,
				Config:    config,
				Destroy:   true,
				Check:     checkCalls(f, &mark, routeRemoveDomains, 0),
			},
		},
	})
}

func TestTrustedDomainsResourceReplacedOnAppChange(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	first, second := f.seedApp("tfacc-first"), f.seedApp("tfacc-second")
	domains := []string{"a.example.com"}
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkLiveDomains(f, second.HRN, false),
		Steps: []tfresource.TestStep{
			{
				PreConfig: func() { mark = f.mark() },
				Config:    domainsConfig(first.HRN, domains, "enabled = false", domainTimeouts),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					tfresource.TestCheckResourceAttr(domainsAddr, "enabled", "false"),
					checkWriteOrder(f, &mark, routeAddDomains),
					checkLiveDomains(f, first.HRN, false, domains...),
				),
			},
			{
				Config:           domainsConfig(second.HRN, domains, domainTimeouts),
				ConfigPlanChecks: expectAction(domainsAddr, plancheck.ResourceActionReplace),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					tfresource.TestCheckResourceAttr(domainsAddr, "id", second.HRN),
					checkLiveDomains(f, first.HRN, false),
					checkLiveDomains(f, second.HRN, true, domains...),
				),
			},
		},
	})
}

func TestTrustedDomainsResourceImport(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	app := f.seedApp("tfacc-import")
	config := domainsConfig(app.HRN, []string{"a.example.com", "https://b.example.com:8443/path"}, domainTimeouts)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkLiveDomains(f, app.HRN, false),
		Steps: []tfresource.TestStep{
			{
				Config: config,
			},
			{
				ResourceName:            domainsAddr,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				ResourceName:  domainsAddr,
				ImportState:   true,
				ImportStateId: "FakeApp0001",
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
			{
				ResourceName:  domainsAddr,
				ImportState:   true,
				ImportStateId: fakeAppHRN("Gone"),
				ExpectError:   regexp.MustCompile(`Cannot import non-existent remote object`),
			},
		},
	})
}

func TestTrustedDomainsResourceFailures(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	app := f.seedApp("tfacc-failures")
	config := func(domains ...string) string { return domainsConfig(app.HRN, domains, domainTimeouts) }
	throttled := hereError(429, "429003", "Too many bulk changes")
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkLiveDomains(f, app.HRN, false),
		Steps: []tfresource.TestStep{
			{
				Config: config("a.example.com"),
			},
			{
				PreConfig:   func() { f.hook(always(routeAddDomains, badRequest("list is locked"))) },
				Config:      config("a.example.com", "b.example.com"),
				ExpectError: regexp.MustCompile(`(?s)Unable to update HERE trusted domains.*list\s+is\s+locked`),
			},
			{
				// HERE throttles bulk changes; once the transport gives up, the update retries the whole diff.
				PreConfig: func() {
					f.clearHooks()
					f.hook(sequence(routeAddDomains, throttled, throttled, throttled))
					mark = f.mark()
				},
				Config:           config("a.example.com", "b.example.com"),
				ConfigPlanChecks: expectAction(domainsAddr, plancheck.ResourceActionUpdate),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkCalls(f, &mark, routeAddDomains, 4),
					checkLiveDomains(f, app.HRN, true, "a.example.com", "b.example.com"),
				),
			},
			{
				PreConfig:   func() { f.hook(sequence(routeGetEnforcement, badRequest("enforcement unavailable"))) },
				Config:      config("a.example.com", "b.example.com"),
				ExpectError: regexp.MustCompile(`Unable to read HERE trusted domains`),
			},
			{
				PreConfig: func() {
					f.clearHooks()
					f.hook(always(routeDisableEnforcement, badRequest("enforcement is locked")))
				},
				Config:      config("a.example.com", "b.example.com"),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`(?s)Unable to remove HERE trusted domains.*enforcement\s+is\s+locked`),
			},
			{
				PreConfig: f.clearHooks,
				Config:    config("a.example.com", "b.example.com"),
			},
		},
	})
}

func TestTrustedDomainsResourceValidation(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	app := fakeAppHRN("FakeApp0001")
	invalid := func(domains []string, pattern string) tfresource.TestStep {
		return tfresource.TestStep{
			Config:      domainsConfig(app, domains),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(pattern),
		}
	}
	entry := `must\s+be\s+a\s+domain\s+name\s+or\s+IPv4\s+address`

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			invalid([]string{"Example.com", "example.com/"}, `(?s)Duplicate trusted domains.*"Example\.com"\s+and\s+"example\.com/"\s+differ\s+only`),
			invalid([]string{"a.example.com,b.example.com"}, entry),
			invalid([]string{"not a domain"}, entry),
			invalid([]string{"exa_mple.com"}, entry),
			invalid([]string{"-example.com"}, entry),
			invalid([]string{"example.com:123456"}, entry),
			invalid([]string{"example.com/" + strings.Repeat("a", 2048)}, `string\s+length\s+must\s+be\s+between\s+1\s+and\s+2048`),
			invalid([]string{}, `set\s+must\s+contain\s+at\s+least\s+1\s+elements`),
			{
				Config:      strings.Replace(domainsConfig(app, []string{"example.com"}), app, "FakeApp0001", 1),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`must\s+be\s+an\s+app\s+HRN`),
			},
		},
	})
}
