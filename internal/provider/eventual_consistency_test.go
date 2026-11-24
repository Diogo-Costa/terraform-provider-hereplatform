package provider

import (
	"errors"
	"net/http"
	"regexp"
	"testing"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// newStackConfig is an app with a key and trusted domains, all created in one apply.
func newStackConfig() string {
	return appConfig("tfacc-stack", unprotected) +
		keyBlock("test", appRef("test"), `name = "primary"`) +
		domainsBlock("test", appRef("test"), []string{"a.example.com"}, domainTimeouts)
}

func forbidden() fakeReply { return hereError(http.StatusForbidden, "403300", "Forbidden") }

// Assumptions 5 and 7: right after an app is created, IAM may answer 404 or 403 for it and
// 404 for its children until the change propagates.
func TestEventualConsistencyNewAppAndChildren(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.hook(
		sequence(routeGetApp, notFound(), notFound(), forbidden()),
		sequence(routeCreateKey, notFound(), notFound()),
		sequence(routeGetKey, notFound()),
		sequence(routeListDomains, notFound()),
		sequence(routeAddDomains, notFound()),
		sequence(routeGetEnforcement, notFound()),
	)
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{{
			// The empty post-apply plans prove that the retried creates left a consistent state.
			Config: newStackConfig(),
			Check: tfresource.ComposeAggregateTestCheckFunc(
				checkCalls(f, &mark, routeCreateApp, 1),
				checkCalls(f, &mark, routeGetApp, 4),
				checkCalls(f, &mark, routeCreateKey, 3),
				checkCalls(f, &mark, routeGetKey, 2),
				checkCalls(f, &mark, routeAddDomains, 2),
				func(*terraform.State) error {
					if a := f.apps(); len(a) != 1 || len(a[0].Keys) != 1 {
						return errors.New("retries created duplicate apps or keys")
					}
					return checkLiveDomains(f, f.apps()[0].HRN, true, "a.example.com")(nil)
				},
			),
		}},
	})
}

// Only 404 means "not propagated yet" for a key create; a 403 is a missing permission and
// must fail fast instead of polling for the whole create timeout.
func TestEventualConsistencyKeyCreateForbiddenFailsFast(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{
			{
				Config: appConfig("tfacc-keys", unprotected),
			},
			{
				PreConfig: func() {
					f.hook(always(routeCreateKey, forbidden()))
					mark = f.mark()
				},
				// The short timeout bounds the test should 403 ever become retryable.
				Config:      keyConfig(`name = "primary"`, timeoutsAttr("create", "2s")),
				ExpectError: regexp.MustCompile(`(?s)Unable to create HERE API key.*HTTP\s+403`),
			},
			{
				PreConfig: f.clearHooks,
				Config:    appConfig("tfacc-keys", unprotected),
				Check:     checkCalls(f, &mark, routeCreateKey, 1),
			},
		},
	})
}

// Updates of an existing app's domains do not treat 404 as propagation: the app is gone.
func TestEventualConsistencyDomainsUpdateNotFoundFails(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	app := f.seedApp("tfacc-domains")
	var mark int

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				Config: domainsConfig(app.HRN, []string{"a.example.com"}, domainTimeouts),
			},
			{
				PreConfig: func() {
					f.hook(sequence(routeAddDomains, notFound()))
					mark = f.mark()
				},
				Config:      domainsConfig(app.HRN, []string{"a.example.com", "b.example.com"}, domainTimeouts),
				ExpectError: regexp.MustCompile(`(?s)Unable to update HERE trusted domains.*HTTP\s+404`),
			},
			{
				Config: domainsConfig(app.HRN, []string{"a.example.com", "b.example.com"}, domainTimeouts),
				Check: tfresource.ComposeAggregateTestCheckFunc(
					checkCalls(f, &mark, routeAddDomains, 2),
					checkLiveDomains(f, app.HRN, true, "a.example.com", "b.example.com"),
				),
			},
		},
	})
}
