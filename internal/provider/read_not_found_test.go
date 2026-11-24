package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

// W-14: IAM reads are eventually consistent, so a refresh right after a create can get a
// stale 404. Dropping the resource then makes Terraform create a duplicate while the
// original stays live, holding credentials and, for keys, one of the app's two slots.
func TestReadSurvivesStaleNotFound(t *testing.T) {
	t.Parallel()
	for name, route := range map[string]string{
		"app":             routeGetApp,
		"api key":         routeGetKey,
		"trusted domains": routeListDomains,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeHERE(t)
			var mark int

			tfresource.UnitTest(t, tfresource.TestCase{
				ProtoV6ProviderFactories: f.factories(),
				CheckDestroy:             checkNoApps(f),
				Steps: []tfresource.TestStep{{
					Config: newStackConfig(),
					// Check runs between the apply and the refresh, so the refresh gets the 404.
					Check: func(*terraform.State) error {
						f.hook(sequence(route, notFound()))
						mark = f.mark()
						return nil
					},
				}, {
					Config: newStackConfig(),
					Check:  checkCalls(f, &mark, routeCreateApp, 0),
				}},
			})
			if n := len(f.callsOf(routeCreateKey)); n != 1 {
				t.Errorf("%d API keys created, want 1", n)
			}
		})
	}
}

// readResource calls Read directly, which exposes the warnings Terraform only prints.
func readResource(ctx context.Context, t *testing.T, r resource.Resource, c *client.Client, attrs map[string]string) *resource.ReadResponse {
	t.Helper()
	var schema resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schema)
	state := tfsdk.State{Schema: schema.Schema, Raw: tftypes.NewValue(schema.Schema.Type().TerraformType(ctx), nil)}
	for k, v := range attrs {
		if diags := state.SetAttribute(ctx, path.Root(k), v); diags.HasError() {
			t.Fatal(diagText(diags))
		}
	}
	configurable, _ := r.(resource.ResourceWithConfigure)
	configurable.Configure(ctx, resource.ConfigureRequest{ProviderData: c}, &resource.ConfigureResponse{})
	resp := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)
	return resp
}

func TestReadRemovesConfirmedNotFoundWithWarning(t *testing.T) {
	t.Parallel()
	app := fakeAppHRN("FakeApp0001")
	key := "hrn:here:account::org-fake:apikey/FakeKey0002"
	for name, tc := range map[string]struct {
		r     func() resource.Resource
		route string
		attrs map[string]string
	}{
		"app":             {newAppResource, routeGetApp, map[string]string{"id": app}},
		"api key":         {newAppAPIKeyResource, routeGetKey, map[string]string{"id": key, "app_hrn": app}},
		"trusted domains": {newAppTrustedDomainsResource, routeListDomains, map[string]string{"id": app, "app_hrn": app}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFakeHERE(t)
			resp := readResource(t.Context(), t, tc.r(), f.client(t), tc.attrs)
			if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
				t.Fatalf("want the resource removed without error, got: %s", diagText(resp.Diagnostics))
			}
			warnings := resp.Diagnostics.Warnings()
			if len(warnings) != 1 {
				t.Fatalf("want one warning, got: %s", diagText(resp.Diagnostics))
			}
			for _, hrn := range tc.attrs {
				if !strings.Contains(warnings[0].Detail(), hrn) {
					t.Errorf("warning does not name %s: %s", hrn, warnings[0].Detail())
				}
			}
			if n := len(f.callsOf(tc.route)); n != 2 {
				t.Errorf("%d reads of %s, want 2: the 404 and its confirmation", n, tc.route)
			}
		})
	}
}

func TestReadKeepsResourceWhenConfirmationIsInterrupted(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// Terraform is interrupted while the provider waits to confirm the first 404.
	c := f.client(t, func(cfg *client.Config) {
		cfg.Sleep = func(context.Context, time.Duration) error {
			cancel()
			return context.Canceled
		}
	})

	resp := readResource(ctx, t, newAppResource(), c, map[string]string{"id": fakeAppHRN("FakeApp0001")})
	if resp.State.Raw.IsNull() || !resp.Diagnostics.HasError() || len(resp.Diagnostics.Warnings()) != 0 {
		t.Fatalf("want the resource kept with an error, got: %s", diagText(resp.Diagnostics))
	}
	if n := len(f.callsOf(routeGetApp)); n != 1 {
		t.Errorf("%d reads, want 1", n)
	}
}
