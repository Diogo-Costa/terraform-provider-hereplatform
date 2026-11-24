package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

// Acceptance tests change the sandbox realm for real. Every app they create is named by
// testAccAppName, so that the sweeper can remove leftovers, and is unprotected, so that destroy
// works. Run logs are public (W-10): key values are only checked by functions that never print them.

// HERE IAM propagates changes within about five minutes (HERE IAM FAQ).
const accPropagation = 5 * time.Minute

func testAccAppName() string { return acctest.RandomWithPrefix(strings.TrimSuffix(sweepPrefix, "-")) }

func testAccCase(t *testing.T, steps ...tfresource.TestStep) tfresource.TestCase {
	t.Helper()
	return tfresource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckAppsDestroyed(t),
		Steps:                    steps,
	}
}

var errStillThere = errors.New("still present")

// testAccEventually retries check while it fails with errStillThere, as reads may lag writes.
func testAccEventually(t *testing.T, what string, check func(context.Context, *client.Client) error) error {
	t.Helper()
	c, _, err := envClient(os.Getenv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(t.Context(), accPropagation)
	defer cancel()
	return c.Retry(ctx, what, func(err error) bool { return errors.Is(err, errStillThere) }, func(ctx context.Context) error {
		return check(ctx, c)
	})
}

func testAccCheckAppsDestroyed(t *testing.T) func(*terraform.State) error {
	t.Helper()
	return func(s *terraform.State) error {
		for _, rs := range s.RootModule().Resources {
			if rs.Type != "hereplatform_app" {
				continue
			}
			err := testAccEventually(t, "app "+rs.Primary.ID+" to be deleted", func(ctx context.Context, c *client.Client) error {
				_, err := c.GetApp(ctx, rs.Primary.ID)
				switch {
				case err == nil:
					return errStillThere
				// Deleting the app may also revoke the identity's permission on it.
				case client.HasStatus(err, http.StatusNotFound, http.StatusForbidden):
					return nil
				default:
					return err
				}
			})
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func checkKeyValueSet() tfresource.TestCheckFunc {
	return tfresource.TestCheckResourceAttrWith(keyAddr, "value", func(v string) error {
		if strings.TrimSpace(v) == "" {
			return errors.New("value is empty")
		}
		return nil
	})
}

func checkImportedKeyValueMatches(seen *string) tfresource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) != 1 {
			return fmt.Errorf("imported %d states, want 1", len(states))
		}
		if v := states[0].Attributes["value"]; v == "" || v != *seen {
			return errors.New("imported value is empty or differs from the created key's value")
		}
		return nil
	}
}

func keyImportID(s *terraform.State) (string, error) {
	rs, ok := s.RootModule().Resources[keyAddr]
	if !ok {
		return "", errors.New(keyAddr + " is not in the state")
	}
	return rs.Primary.Attributes["app_hrn"] + "," + rs.Primary.ID, nil
}

func TestAccAppLifecycle(t *testing.T) {
	name := testAccAppName()
	renamed := name + "-renamed"
	sameID := statecheck.CompareValue(compare.ValuesSame())
	sameClientID := statecheck.CompareValue(compare.ValuesSame())

	tfresource.Test(t, testAccCase(t,
		tfresource.TestStep{
			Config: appConfig(name, unprotected, `description = "Created by a terraform-provider-hereplatform acceptance test."`),
			ConfigStateChecks: []statecheck.StateCheck{
				sameID.AddStateValue(appAddr, tfjsonpath.New("id")),
				sameClientID.AddStateValue(appAddr, tfjsonpath.New("client_id")),
				expectAppAttr("hrn", knownvalue.StringRegexp(appHRNPattern)),
				expectAppAttr("client_id", knownvalue.NotNull()),
				expectAppAttr("realm", knownvalue.NotNull()),
				expectAppAttr("status", knownvalue.NotNull()),
				expectAppAttr("created_time", knownvalue.StringRegexp(rfc3339UTCRegexp)),
				expectAppAttr("app_creation_enabled", knownvalue.Bool(false)),
			},
		},
		tfresource.TestStep{
			// Assumption 1: an empty description clears it.
			Config:           appConfig(renamed, unprotected),
			ConfigPlanChecks: expectAction(appAddr, plancheck.ResourceActionUpdate),
			ConfigStateChecks: []statecheck.StateCheck{
				sameID.AddStateValue(appAddr, tfjsonpath.New("id")),
				sameClientID.AddStateValue(appAddr, tfjsonpath.New("client_id")),
				expectAppAttr("name", knownvalue.StringExact(renamed)),
				expectAppAttr("description", knownvalue.Null()),
			},
		},
		tfresource.TestStep{
			ResourceName:            appAddr,
			ImportState:             true,
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"deletion_protection"},
		},
	))
}

func TestAccAppCreationEnabled(t *testing.T) {
	name := testAccAppName()
	config := func(enabled bool) string {
		return appConfig(name, unprotected, "app_creation_enabled = "+strconv.FormatBool(enabled))
	}

	tfresource.Test(t, testAccCase(t,
		tfresource.TestStep{
			Config:            config(true),
			ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("app_creation_enabled", knownvalue.Bool(true))},
		},
		tfresource.TestStep{
			Config:            config(false),
			ConfigPlanChecks:  expectAction(appAddr, plancheck.ResourceActionUpdate),
			ConfigStateChecks: []statecheck.StateCheck{expectAppAttr("app_creation_enabled", knownvalue.Bool(false))},
		},
	))
}

func TestAccAPIKeyLifecycle(t *testing.T) {
	app := appConfig(testAccAppName(), unprotected)
	config := func(attrs ...string) string { return app + keyBlock("test", appRef("test"), attrs...) }
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	var value string

	tfresource.Test(t, testAccCase(t,
		tfresource.TestStep{
			Config: config(`name = "primary"`),
			Check:  tfresource.ComposeAggregateTestCheckFunc(checkKeyValueSet(), checkKeyValueStable(&value)),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectSensitiveValue(keyAddr, tfjsonpath.New("value")),
				expectKeyAttr("id", knownvalue.StringRegexp(apiKeyHRNPattern)),
				expectKeyAttr("enabled", knownvalue.Bool(true)),
				expectKeyAttr("expires_at", knownvalue.Null()),
				expectKeyAttr("created_time", knownvalue.StringRegexp(rfc3339UTCRegexp)),
			},
		},
		tfresource.TestStep{
			Config:           config(`name = "renamed"`, "expires_at = "+strconv.Quote(expires), "enabled = false"),
			ConfigPlanChecks: expectAction(keyAddr, plancheck.ResourceActionUpdate),
			Check:            checkKeyValueStable(&value),
			ConfigStateChecks: []statecheck.StateCheck{
				expectKeyAttr("name", knownvalue.StringExact("renamed")),
				expectKeyAttr("expires_at", knownvalue.StringExact(expires)),
				expectKeyAttr("enabled", knownvalue.Bool(false)),
			},
		},
		tfresource.TestStep{
			// Assumption 2: expiresAt -1 removes the expiry.
			Config:           config(`name = "renamed"`),
			ConfigPlanChecks: expectAction(keyAddr, plancheck.ResourceActionUpdate),
			Check:            checkKeyValueStable(&value),
			ConfigStateChecks: []statecheck.StateCheck{
				expectKeyAttr("expires_at", knownvalue.Null()),
				expectKeyAttr("enabled", knownvalue.Bool(true)),
			},
		},
		tfresource.TestStep{
			ResourceName:            keyAddr,
			ImportState:             true,
			ImportStateIdFunc:       keyImportID,
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"value"},
			ImportStateCheck:        checkImportedKeyValueMatches(&value),
		},
	))
}

func TestAccAPIKeyLimit(t *testing.T) {
	keys := appConfig(testAccAppName(), unprotected) +
		keyBlock("first", appRef("test"), `name = "first"`) + keyBlock("second", appRef("test"), `name = "second"`)

	tfresource.Test(t, testAccCase(t,
		tfresource.TestStep{Config: keys},
		tfresource.TestStep{
			Config:      keys + keyBlock("third", appRef("test"), `name = "third"`, timeoutsAttr("create", "30s")),
			ExpectError: regexp.MustCompile(`already\s+has\s+two\s+API\s+keys`),
		},
	))
}

func TestAccTrustedDomainsLifecycle(t *testing.T) {
	name := testAccAppName()
	app := appConfig(name, unprotected)
	config := func(domains []string, attrs ...string) string {
		return app + domainsBlock("test", appRef("test"), domains, attrs...)
	}
	one := []string{"https://" + name + ".example.com"}
	// More than one batch of ten.
	many := make([]string, 12)
	for i := range many {
		many[i] = fmt.Sprintf("https://d%02d.%s.example.com", i, name)
	}

	tfresource.Test(t, testAccCase(t,
		tfresource.TestStep{
			Config:            config(one),
			ConfigStateChecks: []statecheck.StateCheck{expectDomains(one...), expectDomainsEnabled(true)},
		},
		tfresource.TestStep{
			Config:            config(many),
			ConfigPlanChecks:  expectAction(domainsAddr, plancheck.ResourceActionUpdate),
			ConfigStateChecks: []statecheck.StateCheck{expectDomains(many...)},
		},
		tfresource.TestStep{
			Config:            config(one, "enabled = false"),
			ConfigPlanChecks:  expectAction(domainsAddr, plancheck.ResourceActionUpdate),
			ConfigStateChecks: []statecheck.StateCheck{expectDomains(one...), expectDomainsEnabled(false)},
		},
		tfresource.TestStep{
			ResourceName:            domainsAddr,
			ImportState:             true,
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{"timeouts"},
		},
		tfresource.TestStep{
			Config: config(one),
		},
		tfresource.TestStep{
			// Deleting the resource leaves the app without restrictions.
			Config: app,
			Check: func(s *terraform.State) error {
				hrn, err := stateID(s, appAddr)
				if err != nil {
					return err
				}
				return testAccEventually(t, "trusted domains of "+hrn+" to be cleared", func(ctx context.Context, c *client.Client) error {
					enabled, err := c.TrustedDomainsEnabled(ctx, hrn)
					if err != nil {
						return err
					}
					domains, err := c.ListTrustedDomains(ctx, hrn)
					if err != nil {
						return err
					}
					if enabled || len(domains) > 0 {
						return errStillThere
					}
					return nil
				})
			},
		},
	))
}

func TestAccAppDataSource(t *testing.T) {
	app := appConfig(testAccAppName(), unprotected, `description = "Read back by the data source."`)
	sameAsResource := func(attrs ...string) tfresource.TestCheckFunc {
		checks := make([]tfresource.TestCheckFunc, len(attrs))
		for i, a := range attrs {
			checks[i] = tfresource.TestCheckResourceAttrPair(dataAddr, a, appAddr, a)
		}
		return tfresource.ComposeAggregateTestCheckFunc(checks...)
	}
	attrs := []string{"id", "hrn", "name", "description", "client_id", "realm", "status", "created_time", "app_creation_enabled"}

	tfresource.Test(t, testAccCase(t,
		tfresource.TestStep{
			Config: app + appDataBlock("hrn = "+appRef("test")),
			Check:  sameAsResource(attrs...),
		},
		tfresource.TestStep{
			Config: app + appDataBlock("name = hereplatform_app.test.name"),
			Check:  sameAsResource(attrs...),
		},
	))
}
