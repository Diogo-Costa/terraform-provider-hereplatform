package provider

import (
	"context"
	"fmt"
	"net/http"
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

const defaultAppTimeout = 5 * time.Minute

var (
	_ resource.ResourceWithConfigure   = (*appResource)(nil)
	_ resource.ResourceWithImportState = (*appResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*appResource)(nil)
)

func newAppResource() resource.Resource { return &appResource{} }

type appResource struct {
	client *client.Client
}

type appModel struct {
	ID                 types.String   `tfsdk:"id"`
	HRN                types.String   `tfsdk:"hrn"`
	Name               types.String   `tfsdk:"name"`
	Description        types.String   `tfsdk:"description"`
	AppCreationEnabled types.Bool     `tfsdk:"app_creation_enabled"`
	DeletionProtection types.Bool     `tfsdk:"deletion_protection"`
	ClientID           types.String   `tfsdk:"client_id"`
	Realm              types.String   `tfsdk:"realm"`
	Status             types.String   `tfsdk:"status"`
	CreatedTime        types.String   `tfsdk:"created_time"`
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
}

func (r *appResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app"
}

func (r *appResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	stable := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a HERE platform app, the identity that owns OAuth credentials and API keys.\n\n" +
			"Deleting an app is permanent and revokes all of its credentials, so `deletion_protection` " +
			"is on by default. New apps start with HERE's `restricted-iam-access` filter attached.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: descAppHRN,
				Computed:            true,
				PlanModifiers:       stable,
			},
			"hrn": schema.StringAttribute{
				MarkdownDescription: "HRN of the app, such as `" + appHRNFormat + "`.",
				Computed:            true,
				PlanModifiers:       stable,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Display name. Renaming updates the app in place and keeps its HRN and credentials.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Free-text description.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"app_creation_enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the app may create other apps. Requires `manage` permission on the app. " +
					"Defaults to `false`. When you import an app that creates apps, such as the app the provider " +
					"authenticates as, set it to `true`: otherwise the next apply turns app creation off.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
			},
			"deletion_protection": schema.BoolAttribute{
				MarkdownDescription: "Provider-side guard against deleting the app. While `true`, a plan that destroys " +
					"the app fails (Terraform 1.3 or later), and so does any apply that would delete it, such as the " +
					"replacement of a tainted app. Set it to `false` and apply before deleting the app. HERE has no " +
					"such setting. Defaults to `true`.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: descClientID,
				Computed:            true,
				PlanModifiers:       stable,
			},
			"realm": schema.StringAttribute{
				MarkdownDescription: descRealm,
				Computed:            true,
				PlanModifiers:       stable,
			},
			"status": schema.StringAttribute{
				MarkdownDescription: descStatus,
				Computed:            true,
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

func (r *appResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *appResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan appModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	timeout, diags := plan.Timeouts.Create(ctx, defaultAppTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	created, err := r.client.CreateApp(ctx, client.CreateAppInput{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create HERE app", err.Error())
		return
	}

	// Saved before polling: a failure from here on leaves a tracked (tainted) app instead of an orphan.
	state := plan
	state.applyComputed(created)
	state.AppCreationEnabled = types.BoolValue(created.AppCreationEnabled)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	app, err := r.client.WaitForApp(ctx, created.HRN)
	if err != nil {
		addCreatedAppError(&resp.Diagnostics, created.HRN, "IAM did not return it before the create timeout", err)
		return
	}
	state.applyComputed(app)
	state.AppCreationEnabled = types.BoolValue(app.AppCreationEnabled)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)

	if want := plan.AppCreationEnabled.ValueBool(); want != app.AppCreationEnabled {
		err := r.client.Retry(ctx, "app creation setting of "+app.HRN, propagating, func(ctx context.Context) error {
			return r.client.SetAppCreationEnabled(ctx, app.HRN, want)
		})
		if err != nil {
			addCreatedAppError(&resp.Diagnostics, app.HRN, "changing app_creation_enabled failed", err)
			return
		}
		state.AppCreationEnabled = plan.AppCreationEnabled
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func addCreatedAppError(diags *diag.Diagnostics, hrn, what string, err error) {
	diags.AddError("HERE app created with errors",
		fmt.Sprintf("App %s was created, but %s: %s\n\nTerraform marks the app as tainted, and replacing it "+
			"would delete it permanently: run terraform untaint on this resource and apply again. While "+
			"deletion_protection is true, the provider refuses that replacement. Raise timeouts.create if IAM is "+
			"slow to converge.", hrn, what, err))
}

func guardedApp(hrn string) guarded {
	return guarded{what: "app " + hrn, consequence: "Deleting a HERE app is permanent and revokes all of its credentials."}
}

// ModifyPlan fails the destroy plan of a protected app, before Terraform deletes the keys
// and trusted domains that depend on it. Replacements reach the provider as creates; Delete
// stops those.
func (r *appResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || !req.Plan.Raw.IsNull() {
		return
	}
	id := stringAttr(ctx, req.State.GetAttribute, "id", &resp.Diagnostics)
	if priorProtected(ctx, req.State, &resp.Diagnostics) {
		guardedApp(id.ValueString()).addDestroyError(&resp.Diagnostics)
	}
}

func (r *appResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state appModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hrn := state.ID.ValueString()
	var app *client.App
	err := readConfirmingNotFound(ctx, r.client, "app "+hrn, func(ctx context.Context) error {
		var err error
		app, err = r.client.GetApp(ctx, hrn)
		return err
	})
	if client.IsNotFound(err) {
		warnRemoved(&resp.Diagnostics, "app "+hrn)
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read HERE app", err.Error())
		return
	}
	state.applyComputed(app)
	state.Name = types.StringValue(app.Name)
	state.Description = stringOrNull(app.Description)
	state.AppCreationEnabled = types.BoolValue(app.AppCreationEnabled)
	state.DeletionProtection = types.BoolValue(isProtected(state.DeletionProtection))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *appResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state appModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	timeout, diags := plan.Timeouts.Update(ctx, defaultAppTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The framework seeds the new state with the plan, which Terraform would persist on
	// error; record only what actually changed instead.
	state.DeletionProtection = plan.DeletionProtection
	state.Timeouts = plan.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hrn := state.ID.ValueString()

	if !plan.Name.Equal(state.Name) || !plan.Description.Equal(state.Description) {
		// HERE requires name on every PATCH; an empty description clears it.
		in := client.UpdateAppInput{Name: plan.Name.ValueStringPointer()}
		if !plan.Description.IsNull() || !state.Description.IsNull() {
			desc := plan.Description.ValueString()
			in.Description = &desc
		}
		if _, err := r.client.UpdateApp(ctx, hrn, in); err != nil {
			resp.Diagnostics.AddError("Unable to update HERE app", err.Error())
			return
		}
		state.Name = plan.Name
		state.Description = plan.Description
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}

	if !plan.AppCreationEnabled.Equal(state.AppCreationEnabled) {
		if err := r.client.SetAppCreationEnabled(ctx, hrn, plan.AppCreationEnabled.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Unable to change app creation on HERE app", err.Error())
			return
		}
		state.AppCreationEnabled = plan.AppCreationEnabled
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func (r *appResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state appModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if isProtected(state.DeletionProtection) {
		guardedApp(state.ID.ValueString()).addDeleteError(&resp.Diagnostics)
		return
	}
	timeout, diags := state.Timeouts.Delete(ctx, defaultAppTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := r.client.DeleteApp(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete HERE app", err.Error())
	}
}

func (r *appResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !appHRNPattern.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import ID", "Expected an app HRN like "+appHRNFormat+".")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("deletion_protection"), true)...)
}

func (m *appModel) applyComputed(app *client.App) {
	m.ID = types.StringValue(app.HRN)
	m.HRN = types.StringValue(app.HRN)
	m.ClientID = stringOrNull(app.AppClientID())
	m.Realm = stringOrNull(app.Realm)
	m.Status = stringOrNull(app.Status)
	m.CreatedTime = millisToRFC3339(app.CreatedTime)
}

// propagating matches errors IAM returns while a new resource or permission propagates.
func propagating(err error) bool {
	return client.HasStatus(err, http.StatusNotFound, http.StatusForbidden)
}
