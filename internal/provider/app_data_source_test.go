package provider

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

const dataAddr = "data.hereplatform_app.test"

func expectDataAttr(attr string, v knownvalue.Check) statecheck.StateCheck {
	return statecheck.ExpectKnownValue(dataAddr, tfjsonpath.New(attr), v)
}

func expectDataApp(a fakeApp) []statecheck.StateCheck {
	var description knownvalue.Check = knownvalue.Null()
	if a.Description != "" {
		description = knownvalue.StringExact(a.Description)
	}
	return []statecheck.StateCheck{
		expectDataAttr("id", knownvalue.StringExact(a.HRN)),
		expectDataAttr("hrn", knownvalue.StringExact(a.HRN)),
		expectDataAttr("name", knownvalue.StringExact(a.Name)),
		expectDataAttr("description", description),
		expectDataAttr("app_creation_enabled", knownvalue.Bool(a.AppCreationEnabled)),
		expectDataAttr("client_id", knownvalue.StringExact(a.ID)),
		expectDataAttr("realm", knownvalue.StringExact(fakeRealm)),
		expectDataAttr("status", knownvalue.StringExact("active")),
		expectDataAttr("created_time", knownvalue.StringRegexp(rfc3339UTCRegexp)),
	}
}

// checkListWalks requires every lookup since mark to walk all pages in order at the maximum page size.
func checkListWalks(f *fakeHERE, mark *int, tokens ...string) func(*terraform.State) error {
	return func(*terraform.State) error {
		calls := f.callsSince(*mark, routeListApps)
		if len(calls) == 0 || len(calls)%len(tokens) != 0 {
			return fmt.Errorf("%d app list calls, want a positive multiple of %d", len(calls), len(tokens))
		}
		for i, c := range calls {
			if got, want := c.Query.Get("pageToken"), tokens[i%len(tokens)]; got != want || c.Query.Get("limit") != "100" {
				return fmt.Errorf("list call %d: pageToken %q limit %q, want pageToken %q limit 100",
					i, got, c.Query.Get("limit"), want)
			}
		}
		return nil
	}
}

func seedApps(f *fakeHERE, names ...string) []fakeApp {
	out := make([]fakeApp, len(names))
	for i, n := range names {
		out[i] = f.seedApp(n)
	}
	return out
}

func TestAppDataSourceByName(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.pageSize = 2 })
	seedApps(f, "tfacc-a", "tfacc-b", "tfacc-c", "tfacc-d")
	target := f.seedApp("tfacc-target", func(a *fakeApp) {
		a.Description = "Looked up by name."
		a.AppCreationEnabled = true
	})
	mark := f.mark()

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{{
			// The match is on the last page: lookups must not stop early.
			Config:            appDataBlock(`name = "tfacc-target"`),
			ConfigStateChecks: expectDataApp(target),
			Check:             checkListWalks(f, &mark, "", "page-2", "page-4"),
		}},
	})
}

func TestAppDataSourceByHRN(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	seedApps(f, "tfacc-other")
	target := f.seedApp("tfacc-target", func(a *fakeApp) { a.Description = "Looked up by HRN." })
	mark := f.mark()

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{{
			Config:            appDataBlock("hrn = " + strconv.Quote(target.HRN)),
			ConfigStateChecks: expectDataApp(target),
			Check:             checkCalls(f, &mark, routeListApps, 0),
		}},
	})
}

func TestAppDataSourceReadsManagedApp(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		CheckDestroy:             checkNoApps(f),
		Steps: []tfresource.TestStep{{
			Config: appConfig("tfacc-managed", unprotected, `description = "Managed."`) +
				appDataBlock("hrn = "+appRef("test")),
			Check: tfresource.ComposeAggregateTestCheckFunc(
				tfresource.TestCheckResourceAttrPair(dataAddr, "id", appAddr, "id"),
				tfresource.TestCheckResourceAttrPair(dataAddr, "client_id", appAddr, "client_id"),
				tfresource.TestCheckResourceAttrPair(dataAddr, "created_time", appAddr, "created_time"),
				tfresource.TestCheckResourceAttr(dataAddr, "description", "Managed."),
			),
		}},
	})
}

func TestAppDataSourceNameMatchesNoneOrMany(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.pageSize = 1 })
	dups := seedApps(f, "tfacc-dup", "tfacc-unique", "tfacc-dup")
	hrns := []string{regexp.QuoteMeta(dups[0].HRN), regexp.QuoteMeta(dups[2].HRN)}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps: []tfresource.TestStep{
			{
				Config: appDataBlock(`name = "tfacc-dup"`),
				ExpectError: regexp.MustCompile(`(?s)Multiple HERE apps match.*2\s+visible\s+apps\s+are\s+named\s+"tfacc-dup":\s+` +
					strings.Join(hrns, `,\s+`)),
			},
			{
				// Matching is exact: no prefix, substring or case-insensitive matches.
				Config:      appDataBlock(`name = "TFACC-UNIQUE"`),
				ExpectError: regexp.MustCompile(`(?s)HERE app not found.*No\s+app\s+named\s+"TFACC-UNIQUE"\s+is\s+visible`),
			},
			{
				Config:      appDataBlock(`name = "tfacc-uni"`),
				ExpectError: regexp.MustCompile(`HERE app not found`),
			},
		},
	})
}

func TestAppDataSourceFailures(t *testing.T) {
	t.Parallel()
	missing := fakeAppHRN("FakeApp9999")
	for name, tc := range map[string]struct {
		hook   fakeHook
		config string
		want   string
	}{
		"unknown hrn": {
			config: "hrn = " + strconv.Quote(missing),
			want:   `(?s)Unable to read HERE app.*HTTP\s+404`,
		},
		"list rejected": {
			hook:   always(routeListApps, badRequest("invalid paging parameters")),
			config: `name = "tfacc-a"`,
			want:   `(?s)Unable to list HERE apps.*invalid\s+paging\s+parameters`,
		},
		"page token never advances": {
			hook: always(routeListApps, okJSON(map[string]any{
				"items": []any{}, "total": 3, "limit": 100, "pageToken": "page-0",
			})),
			config: `name = "tfacc-a"`,
			want:   `(?s)Unable to list HERE apps.*pagination\s+did\s+not\s+advance`,
		},
		"listed without hrn": {
			hook: always(routeListApps, okJSON(map[string]any{
				"items": []any{map[string]any{"id": "client", "name": "tfacc-a"}}, "total": 1, "limit": 100,
			})),
			config: `name = "tfacc-a"`,
			want:   `(?s)Unable to read HERE app.*HERE\s+listed\s+the\s+app\s+without\s+an\s+HRN`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeHERE(t)
			if tc.hook != nil {
				f.hook(tc.hook)
			}
			tfresource.UnitTest(t, tfresource.TestCase{
				ProtoV6ProviderFactories: f.factories(),
				Steps: []tfresource.TestStep{{
					Config:      appDataBlock(tc.config),
					ExpectError: regexp.MustCompile(tc.want),
				}},
			})
		})
	}
}

func TestAppDataSourceValidation(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	steps := make([]tfresource.TestStep, 0, 4)
	for _, tc := range []struct {
		attrs []string
		want  string
	}{
		{[]string{`name = "tfacc-a"`, "hrn = " + strconv.Quote(fakeAppHRN("FakeApp0001"))}, `Invalid Attribute Combination`},
		{nil, `(?s)Missing Attribute Configuration.*Exactly\s+one\s+of\s+these\s+attributes\s+must\s+be\s+configured`},
		{[]string{`hrn = "hrn:here:account::org-fake:apikey/FakeKey0001"`}, `(?s)Invalid Attribute Value Match.*must\s+be\s+an\s+app\s+HRN`},
		{[]string{`name = ""`}, `Invalid Attribute Value Length`},
	} {
		steps = append(steps, tfresource.TestStep{
			Config:      appDataBlock(tc.attrs...),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(tc.want),
		})
	}

	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: f.factories(),
		Steps:                    steps,
	})
	if calls := f.callsOf(); slices.ContainsFunc(calls, func(c fakeCall) bool { return c.Route != routeToken }) {
		t.Errorf("invalid configurations reached the HERE API: %d calls", len(calls))
	}
}
