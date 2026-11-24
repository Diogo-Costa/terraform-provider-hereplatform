package provider

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	tfresource "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testAccProtoV6ProviderFactories serves the provider in-process for each Terraform command.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"hereplatform": providerserver.NewProtocol6WithError(New("test")()),
}

// TestMain runs the sweepers instead of the tests when -sweep is set (make sweep).
func TestMain(m *testing.M) {
	tfresource.AddTestSweepers("hereplatform_app", &tfresource.Sweeper{Name: "hereplatform_app", F: sweepApps})
	tfresource.TestMain(m)
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	jwt := os.Getenv(envClientID) != "" && os.Getenv(envPrivateKey) != ""
	accessKey := os.Getenv(envAccessKeyID) != "" && os.Getenv(envAccessKeySecret) != ""
	if !jwt && !accessKey && os.Getenv(envCredentialsFile) == "" {
		t.Fatalf("acceptance tests need %s and %s, %s and %s, or %s",
			envClientID, envPrivateKey, envAccessKeyID, envAccessKeySecret, envCredentialsFile)
	}
}

func TestProviderSchemasAreValid(t *testing.T) {
	ctx := t.Context()
	p := New("test")()

	var providerSchema fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &providerSchema)
	if diags := append(providerSchema.Diagnostics, providerSchema.Schema.ValidateImplementation(ctx)...); diags.HasError() {
		t.Fatalf("provider schema: %v", diags)
	}
	for _, newResource := range p.Resources(ctx) {
		r := newResource()
		var meta resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "hereplatform"}, &meta)
		var resp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &resp)
		if diags := append(resp.Diagnostics, resp.Schema.ValidateImplementation(ctx)...); diags.HasError() {
			t.Fatalf("%s schema: %v", meta.TypeName, diags)
		}
	}
	for _, newDataSource := range p.DataSources(ctx) {
		d := newDataSource()
		var meta datasource.MetadataResponse
		d.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "hereplatform"}, &meta)
		var resp datasource.SchemaResponse
		d.Schema(ctx, datasource.SchemaRequest{}, &resp)
		if diags := append(resp.Diagnostics, resp.Schema.ValidateImplementation(ctx)...); diags.HasError() {
			t.Fatalf("%s schema: %v", meta.TypeName, diags)
		}
	}
}

func TestProviderRequiresCredentials(t *testing.T) {
	noEnv := func(string) string { return "" }
	tfresource.UnitTest(t, tfresource.TestCase{
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"hereplatform": providerserver.NewProtocol6WithError(New("test", WithEnv(noEnv))()),
		},
		Steps: []tfresource.TestStep{{
			Config: `
provider "hereplatform" {}

data "hereplatform_app" "test" {
  hrn = "hrn:here:account::example:app/test"
}
`,
			ExpectError: regexp.MustCompile(`Missing HERE credentials`),
		}},
	})
}

// TestAccProviderAuthenticates proves the credentials obtain a token and can list apps,
// without creating anything.
func TestAccProviderAuthenticates(t *testing.T) {
	name := "tfacc-missing-" + acctest.RandString(10)
	tfresource.Test(t, tfresource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []tfresource.TestStep{{
			Config:      appDataBlock("name = " + strconv.Quote(name)),
			ExpectError: regexp.MustCompile(`HERE app not found`),
		}},
	})
}
