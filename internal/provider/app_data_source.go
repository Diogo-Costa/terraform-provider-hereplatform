package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

var (
	_ datasource.DataSourceWithConfigure        = (*appDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*appDataSource)(nil)
)

func newAppDataSource() datasource.DataSource { return &appDataSource{} }

type appDataSource struct {
	client *client.Client
}

type appDataSourceModel struct {
	ID                 types.String `tfsdk:"id"`
	HRN                types.String `tfsdk:"hrn"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	AppCreationEnabled types.Bool   `tfsdk:"app_creation_enabled"`
	ClientID           types.String `tfsdk:"client_id"`
	Realm              types.String `tfsdk:"realm"`
	Status             types.String `tfsdk:"status"`
	CreatedTime        types.String `tfsdk:"created_time"`
}

func (d *appDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app"
}

func (d *appDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up a HERE platform app by HRN or by exact name.\n\n" +
			"Lookups by name list the apps visible to the provider's identity: HERE filters `GET /apps` by the " +
			"caller's permissions, so apps the identity cannot read, write, manage or share are not found.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: descAppHRN,
				Computed:            true,
			},
			"hrn": schema.StringAttribute{
				MarkdownDescription: "HRN of the app to look up. Exactly one of `hrn` or `name` is required.",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.String{appHRNValidator()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Exact name of the app to look up. The lookup fails unless exactly one visible " +
					"app has this name.",
				Optional:   true,
				Computed:   true,
				Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Free-text description.",
				Computed:            true,
			},
			"app_creation_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the app may create other apps.",
				Computed:            true,
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: descClientID,
				Computed:            true,
			},
			"realm": schema.StringAttribute{
				MarkdownDescription: descRealm,
				Computed:            true,
			},
			"status": schema.StringAttribute{
				MarkdownDescription: descStatus,
				Computed:            true,
			},
			"created_time": schema.StringAttribute{
				MarkdownDescription: descCreatedTime,
				Computed:            true,
			},
		},
	}
}

func (d *appDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("hrn"), path.MatchRoot("name")),
	}
}

func (d *appDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *appDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg appDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hrn := cfg.HRN.ValueString()
	if hrn == "" {
		name := cfg.Name.ValueString()
		matches, err := d.client.FindAppsByName(ctx, name)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list HERE apps", err.Error())
			return
		}
		switch len(matches) {
		case 0:
			resp.Diagnostics.AddAttributeError(path.Root("name"), "HERE app not found",
				fmt.Sprintf("No app named %q is visible to the provider's identity. HERE lists only apps the "+
					"caller has read, write, manage or share permission on; grant access or look the app up by hrn.", name))
			return
		case 1:
			if hrn = matches[0].HRN; hrn == "" {
				resp.Diagnostics.AddError("Unable to read HERE app", "HERE listed the app without an HRN.")
				return
			}
		default:
			hrns := make([]string, len(matches))
			for i, m := range matches {
				hrns[i] = m.HRN
			}
			resp.Diagnostics.AddAttributeError(path.Root("name"), "Multiple HERE apps match",
				fmt.Sprintf("%d visible apps are named %q: %s. Look the app up by hrn instead.",
					len(matches), name, strings.Join(hrns, ", ")))
			return
		}
	}

	app, err := d.client.GetApp(ctx, hrn)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read HERE app", err.Error())
		return
	}
	state := appDataSourceModel{
		ID:                 types.StringValue(app.HRN),
		HRN:                types.StringValue(app.HRN),
		Name:               types.StringValue(app.Name),
		Description:        stringOrNull(app.Description),
		AppCreationEnabled: types.BoolValue(app.AppCreationEnabled),
		ClientID:           stringOrNull(app.AppClientID()),
		Realm:              stringOrNull(app.Realm),
		Status:             stringOrNull(app.Status),
		CreatedTime:        millisToRFC3339(app.CreatedTime),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
