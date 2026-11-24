package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

const (
	defaultAPIKeyTimeout = 5 * time.Minute
	codeMaxAPIKeys       = 409303
)

var (
	_ resource.ResourceWithConfigure   = (*appAPIKeyResource)(nil)
	_ resource.ResourceWithImportState = (*appAPIKeyResource)(nil)
)

func newAppAPIKeyResource() resource.Resource { return &appAPIKeyResource{} }

type appAPIKeyResource struct {
	client *client.Client
}

type apiKeyModel struct {
	ID          types.String   `tfsdk:"id"`
	HRN         types.String   `tfsdk:"hrn"`
	AppHRN      types.String   `tfsdk:"app_hrn"`
	Name        types.String   `tfsdk:"name"`
	ExpiresAt   types.String   `tfsdk:"expires_at"`
	Enabled     types.Bool     `tfsdk:"enabled"`
	Value       types.String   `tfsdk:"value"`
	CreatedTime types.String   `tfsdk:"created_time"`
	Timeouts    timeouts.Value `tfsdk:"timeouts"`
}

func (r *appAPIKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app_api_key"
}

func (r *appAPIKeyResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	stable := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an API key of a HERE platform app.\n\n" +
			"HERE allows at most two API keys per app. The plaintext key is stored in the Terraform state as the " +
			"sensitive `value` attribute, so protect the state accordingly. Deleting a key is permanent.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "HRN of the API key.",
				Computed:            true,
				PlanModifiers:       stable,
			},
			"hrn": schema.StringAttribute{
				MarkdownDescription: "HRN of the API key, such as `" + apiKeyHRNFormat + "`. It carries an obfuscated " +
					"form of the key and cannot authenticate requests.",
				Computed:      true,
				PlanModifiers: stable,
			},
			"app_hrn": schema.StringAttribute{
				MarkdownDescription: "HRN of the app that owns the key. Changing it replaces the key.",
				Required:            true,
				Validators:          []validator.String{appHRNValidator()},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name or short description of the key. Updated in place.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"expires_at": schema.StringAttribute{
				MarkdownDescription: "Expiry as an RFC 3339 timestamp, such as `2030-01-02T15:04:05Z`, kept at millisecond " +
					"precision. Omit it for a key that never expires. Updated in place.",
				Optional:   true,
				Validators: []validator.String{rfc3339Validator{}},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the key can authenticate requests. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"value": schema.StringAttribute{
				MarkdownDescription: "Plaintext API key (HERE `apiKeyId`), passed as the `apiKey` query parameter.",
				Computed:            true,
				Sensitive:           true,
				PlanModifiers:       stable,
			},
			"created_time": schema.StringAttribute{
				MarkdownDescription: descCreatedTime,
				Computed:            true,
				PlanModifiers:       stable,
			},
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{Create: true, Update: true, Delete: true}),
		},
	}
}

func (r *appAPIKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *appAPIKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	timeout, diags := plan.Timeouts.Create(ctx, defaultAPIKeyTimeout)
	resp.Diagnostics.Append(diags...)
	expiresAt := expiryMillis(plan.ExpiresAt, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	appHRN := plan.AppHRN.ValueString()
	in := client.CreateAPIKeyInput{Name: plan.Name.ValueString(), Enabled: plan.Enabled.ValueBoolPointer()}
	if expiresAt != client.NeverExpires {
		in.ExpiresAt = &expiresAt
	}

	// A replacement deletes the old key first, and IAM may count it against the two-key
	// limit for a while; a just-created app may also not be visible yet.
	var created *client.APIKey
	err := r.client.Retry(ctx, "app "+appHRN+" to accept a new API key", func(err error) bool {
		return client.HasCode(err, codeMaxAPIKeys) || client.IsNotFound(err)
	}, func(ctx context.Context) error {
		var err error
		created, err = r.client.CreateAPIKey(ctx, appHRN, in)
		return err
	})
	if err != nil {
		detail := err.Error()
		if client.HasCode(err, codeMaxAPIKeys) {
			detail += "\n\nThe app already has two API keys, the HERE maximum. Keys deleted in the last few minutes " +
				"can still count while IAM converges. Delete an unused key, or raise timeouts.create to wait longer."
		}
		resp.Diagnostics.AddError("Unable to create HERE API key", detail)
		return
	}

	// Saved before polling: the key holds one of the app's two slots and must stay tracked.
	state := plan
	state.applyComputed(created)
	state.Enabled = types.BoolValue(created.IsEnabled())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := r.client.WaitForAPIKey(ctx, appHRN, created.HRN)
	if err != nil {
		addCreatedKeyError(&resp.Diagnostics, created.HRN, "IAM did not return it before the create timeout", err)
		return
	}
	state.applyComputed(key)
	state.Enabled = types.BoolValue(key.IsEnabled())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

	if want := plan.Enabled.ValueBool(); want != key.IsEnabled() {
		err := r.client.Retry(ctx, "API key "+key.HRN+" to change state", client.IsNotFound, func(ctx context.Context) error {
			return r.client.SetAPIKeyEnabled(ctx, appHRN, key.HRN, want)
		})
		if err != nil {
			addCreatedKeyError(&resp.Diagnostics, key.HRN, "changing enabled failed", err)
			return
		}
		state.Enabled = plan.Enabled
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func addCreatedKeyError(diags *diag.Diagnostics, hrn, what string, err error) {
	diags.AddError("HERE API key created with errors",
		fmt.Sprintf("API key %s was created, but %s: %s\n\nTerraform marks the key as tainted and replaces it on "+
			"the next apply; run `terraform untaint` on this resource to keep it instead.", hrn, what, err))
}

func (r *appAPIKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := r.client.GetAPIKey(ctx, state.AppHRN.ValueString(), state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read HERE API key", err.Error())
		return
	}
	state.applyComputed(key)
	state.Name = types.StringValue(key.Name)
	state.Enabled = types.BoolValue(key.IsEnabled())
	state.ExpiresAt = expiresAtFromAPI(state.ExpiresAt, key.Expiry())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *appAPIKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	timeout, diags := plan.Timeouts.Update(ctx, defaultAPIKeyTimeout)
	resp.Diagnostics.Append(diags...)
	expiresAt := expiryMillis(plan.ExpiresAt, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The framework seeds the new state with the plan, which Terraform would persist on
	// error; record only what actually changed instead.
	state.Timeouts = plan.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	appHRN, keyHRN := state.AppHRN.ValueString(), state.ID.ValueString()

	if !plan.Name.Equal(state.Name) || !plan.ExpiresAt.Equal(state.ExpiresAt) {
		// HERE resets an omitted expiresAt to "never", so both fields are always sent.
		in := client.UpdateAPIKeyInput{Name: plan.Name.ValueString(), ExpiresAt: expiresAt}
		if _, err := r.client.UpdateAPIKey(ctx, appHRN, keyHRN, in); err != nil {
			resp.Diagnostics.AddError("Unable to update HERE API key", err.Error())
			return
		}
		state.Name = plan.Name
		state.ExpiresAt = plan.ExpiresAt
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}

	if !plan.Enabled.Equal(state.Enabled) {
		if err := r.client.SetAPIKeyEnabled(ctx, appHRN, keyHRN, plan.Enabled.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Unable to change HERE API key state", err.Error())
			return
		}
		state.Enabled = plan.Enabled
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func (r *appAPIKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	timeout, diags := state.Timeouts.Delete(ctx, defaultAPIKeyTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := r.client.DeleteAPIKey(ctx, state.AppHRN.ValueString(), state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete HERE API key", err.Error())
	}
}

// ImportState takes "<app_hrn>,<apikey_hrn>": HERE reads keys only through their app.
func (r *appAPIKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	appHRN, keyHRN, ok := strings.Cut(req.ID, ",")
	if !ok || !appHRNPattern.MatchString(appHRN) || !apiKeyHRNPattern.MatchString(keyHRN) {
		resp.Diagnostics.AddError("Invalid import ID",
			"Expected \"<app_hrn>,<apikey_hrn>\", such as \""+appHRNFormat+","+apiKeyHRNFormat+"\".")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("app_hrn"), appHRN)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), keyHRN)...)
}

func (m *apiKeyModel) applyComputed(key *client.APIKey) {
	m.ID = types.StringValue(key.HRN)
	m.HRN = types.StringValue(key.HRN)
	if key.Value != "" {
		m.Value = types.StringValue(key.Value)
	} else if m.Value.IsUnknown() {
		m.Value = types.StringNull()
	}
	if key.CreatedTime > 0 {
		m.CreatedTime = millisToRFC3339(key.CreatedTime)
	} else if m.CreatedTime.IsUnknown() {
		m.CreatedTime = types.StringNull()
	}
}

func expiryMillis(v types.String, diags *diag.Diagnostics) int64 {
	if v.IsNull() || v.IsUnknown() {
		return client.NeverExpires
	}
	ms, err := rfc3339ToMillis(v.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("expires_at"), "Invalid expires_at", err.Error())
		return client.NeverExpires
	}
	return ms
}

// expiresAtFromAPI keeps the configured spelling while it denotes the same millisecond.
func expiresAtFromAPI(prior types.String, ms int64) types.String {
	if ms == client.NeverExpires {
		return types.StringNull()
	}
	if !prior.IsNull() && !prior.IsUnknown() {
		if p, err := rfc3339ToMillis(prior.ValueString()); err == nil && p == ms {
			return prior
		}
	}
	return millisToRFC3339(ms)
}
