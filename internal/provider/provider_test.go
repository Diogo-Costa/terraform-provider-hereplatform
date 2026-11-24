package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

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
