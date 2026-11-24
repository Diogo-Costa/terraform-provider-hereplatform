package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
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
	// Up to 3,000 domains in batches of 10, with HERE throttling bulk changes (429003).
	defaultTrustedDomainsTimeout = 10 * time.Minute
	maxTrustedDomains            = 3000
	maxTrustedDomainLength       = 2048
)

// HERE rules: a domain name or IPv4 address, optional scheme, port and path. Commas are
// excluded because bulk deletes pass entries as a comma-separated list.
var trustedDomainPattern = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9+.-]*://)?` +
	`[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*` +
	`(?::[0-9]{1,5})?(?:/[^\s,]*)?$`)

var (
	_ resource.ResourceWithConfigure      = (*appTrustedDomainsResource)(nil)
	_ resource.ResourceWithImportState    = (*appTrustedDomainsResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*appTrustedDomainsResource)(nil)
	_ resource.ResourceWithValidateConfig = (*appTrustedDomainsResource)(nil)
)

func newAppTrustedDomainsResource() resource.Resource { return &appTrustedDomainsResource{} }

type appTrustedDomainsResource struct {
	client *client.Client
}

type trustedDomainsModel struct {
	ID                 types.String   `tfsdk:"id"`
	AppHRN             types.String   `tfsdk:"app_hrn"`
	Domains            types.Set      `tfsdk:"domains"`
	Enabled            types.Bool     `tfsdk:"enabled"`
	DeletionProtection types.Bool     `tfsdk:"deletion_protection"`
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
}

func (r *appTrustedDomainsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app_trusted_domains"
}

func (r *appTrustedDomainsResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages the trusted domains of a HERE platform app: the referrers allowed to use its API keys.\n\n" +
			"This resource is authoritative: it owns the complete list, and removes entries of the app that are not in " +
			"`domains`. Declare at most one per app. HERE can take up to 30 minutes to enforce a change.\n\n" +
			"Deleting the resource turns enforcement off, which lets the app's API keys be used from any origin, so " +
			"`deletion_protection` is on by default.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: descAppHRN,
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"app_hrn": schema.StringAttribute{
				MarkdownDescription: "HRN of the app. Changing it moves the configuration to another app.",
				Required:            true,
				Validators:          []validator.String{appHRNValidator()},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"domains": schema.SetAttribute{
				MarkdownDescription: "Trusted domains, from 1 to 3,000. Each entry has a domain name or IPv4 address and an " +
					"optional scheme, port and path, such as `example.com`, `https://www.example.com:1080` or " +
					"`192.168.1.1`. A bare domain also matches its subdomains and any scheme or port.",
				ElementType: types.StringType,
				Required:    true,
				Validators: []validator.Set{
					setvalidator.SizeBetween(1, maxTrustedDomains),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthBetween(1, maxTrustedDomainLength),
						stringvalidator.RegexMatches(trustedDomainPattern,
							"must be a domain name or IPv4 address with an optional scheme, port and path"),
					),
				},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether HERE enforces the list. While enforcement is off, HERE accepts the app's " +
					"API keys from any origin, and plans that turn it off show a warning. Defaults to `true`.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"deletion_protection": schema.BoolAttribute{
				MarkdownDescription: "Provider-side guard against deleting the resource. While `true`, a plan that destroys " +
					"or replaces it fails (Terraform 1.3 or later), and so does any apply that would delete it, such as " +
					"the replacement of a tainted resource. Defaults to `true`, also after import.",
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"timeouts": timeouts.Attributes(ctx, timeouts.Opts{Create: true, Update: true, Delete: true}),
		},
	}
}

func (r *appTrustedDomainsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

// ValidateConfig rejects entries that differ only in ways the diff treats as equal.
func (r *appTrustedDomainsResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var domains types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("domains"), &domains)...)
	if resp.Diagnostics.HasError() || domains.IsNull() || domains.IsUnknown() {
		return
	}
	seen := map[string]string{}
	for _, v := range domains.Elements() {
		s, ok := v.(types.String)
		if !ok || s.IsNull() || s.IsUnknown() {
			continue
		}
		d := s.ValueString()
		if prev, dup := seen[domainKey(d)]; dup {
			resp.Diagnostics.AddAttributeError(path.Root("domains"), "Duplicate trusted domains",
				fmt.Sprintf("%q and %q differ only in letter case or a trailing slash; keep one of them.", prev, d))
			continue
		}
		seen[domainKey(d)] = d
	}
}

func guardedDomains(appHRN string) guarded {
	return guarded{
		what: "the trusted domain configuration of app " + appHRN,
		consequence: "Deleting it removes the managed domains and turns enforcement off, which lets the app's API keys " +
			"be used from any origin.",
	}
}

const failOpenSummary = "Trusted domain enforcement turns off"

// ModifyPlan fails plans that destroy or replace a protected configuration, and warns when
// a plan stops enforcement: HERE then accepts the app's API keys from any origin.
func (r *appTrustedDomainsResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() {
		return
	}
	appHRN := stringAttr(ctx, req.State.GetAttribute, "id", &resp.Diagnostics).ValueString()
	priorApp := stringAttr(ctx, req.State.GetAttribute, "app_hrn", &resp.Diagnostics)
	var priorEnabled, plannedEnabled types.Bool
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("enabled"), &priorEnabled)...)

	destroy := req.Plan.Raw.IsNull()
	var plannedApp types.String
	if !destroy {
		plannedApp = stringAttr(ctx, req.Plan.GetAttribute, "app_hrn", &resp.Diagnostics)
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("enabled"), &plannedEnabled)...)
	}
	replace := !destroy && !plannedApp.Equal(priorApp)
	if (destroy || replace) && priorProtected(ctx, req.State, &resp.Diagnostics) {
		if destroy {
			guardedDomains(appHRN).addDestroyError(&resp.Diagnostics)
		} else {
			guardedDomains(appHRN).addReplaceError(&resp.Diagnostics, plannedApp)
		}
		return
	}

	if !priorEnabled.ValueBool() {
		return
	}
	switch {
	case destroy || replace:
		resp.Diagnostics.AddWarning(failOpenSummary, fmt.Sprintf("This plan deletes the trusted domain configuration "+
			"of app %s, which turns its enforcement off: HERE then accepts the app's API keys from any origin.", appHRN))
	case !plannedEnabled.IsUnknown() && !plannedEnabled.ValueBool():
		resp.Diagnostics.AddWarning(failOpenSummary, fmt.Sprintf("This plan sets enabled = false for the trusted "+
			"domains of app %s. While enforcement is off, HERE accepts the app's API keys from any origin.", appHRN))
	}
}

func (r *appTrustedDomainsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan trustedDomainsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	timeout, diags := plan.Timeouts.Create(ctx, defaultTrustedDomainsTimeout)
	resp.Diagnostics.Append(diags...)
	domains := setStrings(ctx, plan.Domains, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// No partial state on failure: the next apply converges from the live list, whereas a
	// tainted resource would be replaced by removing every domain first.
	appHRN := plan.AppHRN.ValueString()
	retryable := func(err error) bool { return throttled(err) || client.IsNotFound(err) }
	if err := r.apply(ctx, appHRN, domains, plan.Enabled.ValueBool(), retryable); err != nil {
		addDomainsError(&resp.Diagnostics, "Unable to configure HERE trusted domains", err)
		return
	}
	plan.ID = plan.AppHRN
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *appTrustedDomainsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state trustedDomainsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	prior := setStrings(ctx, state.Domains, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	appHRN := state.ID.ValueString()

	var live []string
	var enabled bool
	err := readConfirmingNotFound(ctx, r.client, "trusted domains of "+appHRN, func(ctx context.Context) error {
		var err error
		if live, err = r.client.ListTrustedDomains(ctx, appHRN); err != nil {
			return err
		}
		enabled, err = r.client.TrustedDomainsEnabled(ctx, appHRN)
		return err
	})
	if client.IsNotFound(err) {
		warnRemoved(&resp.Diagnostics, "the trusted domains of app "+appHRN)
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read HERE trusted domains", err.Error())
		return
	}

	set, diags := types.SetValueFrom(ctx, types.StringType, alignDomains(live, prior))
	resp.Diagnostics.Append(diags...)
	state.Domains = set
	state.Enabled = types.BoolValue(enabled)
	state.AppHRN = types.StringValue(appHRN)
	state.DeletionProtection = types.BoolValue(isProtected(state.DeletionProtection))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *appTrustedDomainsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state trustedDomainsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	timeout, diags := plan.Timeouts.Update(ctx, defaultTrustedDomainsTimeout)
	resp.Diagnostics.Append(diags...)
	domains := setStrings(ctx, plan.Domains, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// On failure keep the prior state, except for the provider-side attributes; the next
	// refresh reads what actually changed.
	unchanged := plan.Domains.Equal(state.Domains) && plan.Enabled.Equal(state.Enabled)
	state.DeletionProtection = plan.DeletionProtection
	state.Timeouts = plan.Timeouts
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() || unchanged {
		return
	}
	if err := r.apply(ctx, state.ID.ValueString(), domains, plan.Enabled.ValueBool(), throttled); err != nil {
		addDomainsError(&resp.Diagnostics, "Unable to update HERE trusted domains", err)
		return
	}
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *appTrustedDomainsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state trustedDomainsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if isProtected(state.DeletionProtection) {
		guardedDomains(state.ID.ValueString()).addDeleteError(&resp.Diagnostics)
		return
	}
	timeout, diags := state.Timeouts.Delete(ctx, defaultTrustedDomainsTimeout)
	resp.Diagnostics.Append(diags...)
	domains := setStrings(ctx, state.Domains, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	appHRN := state.ID.ValueString()

	// Enforcement goes off first so that the shrinking list never blocks legitimate referrers.
	err := r.client.Retry(ctx, "trusted domains of "+appHRN+" to be released", throttled, func(ctx context.Context) error {
		if err := r.client.SetTrustedDomainsEnabled(ctx, appHRN, false); err != nil {
			return err
		}
		return r.client.RemoveTrustedDomains(ctx, appHRN, domains)
	})
	if err != nil && !client.IsNotFound(err) {
		addDomainsError(&resp.Diagnostics, "Unable to remove HERE trusted domains", err)
	}
}

func (r *appTrustedDomainsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !appHRNPattern.MatchString(req.ID) {
		resp.Diagnostics.AddError("Invalid import ID", "Expected an app HRN like "+appHRNFormat+".")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("app_hrn"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(attrDeletionProtection), true)...)
}

// apply converges the live configuration on the target. Disabling happens before the list
// changes and enabling after them, so a partially applied list is never newly enforced.
func (r *appTrustedDomainsResource) apply(ctx context.Context, appHRN string, domains []string, enabled bool, retryable func(error) bool) error {
	if !enabled {
		if err := r.setEnforcement(ctx, appHRN, false, retryable); err != nil {
			return err
		}
	}
	err := r.client.Retry(ctx, "trusted domains of "+appHRN+" to accept changes", retryable, func(ctx context.Context) error {
		live, err := r.client.ListTrustedDomains(ctx, appHRN)
		if err != nil {
			return err
		}
		add, remove := diffDomains(live, domains)
		// Adding first never leaves an enforced list empty, which HERE treats as unrestricted.
		if err := r.client.AddTrustedDomains(ctx, appHRN, add); err != nil {
			return err
		}
		return r.client.RemoveTrustedDomains(ctx, appHRN, remove)
	})
	if err != nil {
		return err
	}
	if enabled {
		if err := r.setEnforcement(ctx, appHRN, true, retryable); err != nil {
			return err
		}
	}
	return r.waitConverged(ctx, appHRN, domains, enabled, retryable)
}

func (r *appTrustedDomainsResource) setEnforcement(ctx context.Context, appHRN string, enabled bool, retryable func(error) bool) error {
	return r.client.Retry(ctx, "trusted domain enforcement of "+appHRN+" to change", retryable, func(ctx context.Context) error {
		current, err := r.client.TrustedDomainsEnabled(ctx, appHRN)
		if err != nil || current == enabled {
			return err
		}
		return r.client.SetTrustedDomainsEnabled(ctx, appHRN, enabled)
	})
}

// waitConverged polls until reads reflect the change, so the next plan is clean while
// IAM converges.
func (r *appTrustedDomainsResource) waitConverged(ctx context.Context, appHRN string, domains []string, enabled bool, retryable func(error) bool) error {
	return r.client.Retry(ctx, "trusted domains of "+appHRN+" to converge", func(err error) bool {
		var pending *pendingDomainsError
		return errors.As(err, &pending) || retryable(err)
	}, func(ctx context.Context) error {
		live, err := r.client.ListTrustedDomains(ctx, appHRN)
		if err != nil {
			return err
		}
		current, err := r.client.TrustedDomainsEnabled(ctx, appHRN)
		if err != nil {
			return err
		}
		missing, unexpected := diffDomains(live, domains)
		if len(missing) > 0 || len(unexpected) > 0 || current != enabled {
			return &pendingDomainsError{missing: missing, unexpected: unexpected, enabled: current}
		}
		return nil
	})
}

type pendingDomainsError struct {
	missing, unexpected []string
	enabled             bool
}

func (e *pendingDomainsError) Error() string {
	return fmt.Sprintf("HERE still reports enforcement enabled=%t, %d missing domain(s) %s and %d unexpected domain(s) %s",
		e.enabled, len(e.missing), quoteList(e.missing), len(e.unexpected), quoteList(e.unexpected))
}

func quoteList(items []string) string {
	const shown = 10
	quoted := make([]string, 0, min(len(items), shown))
	for _, s := range items[:min(len(items), shown)] {
		quoted = append(quoted, fmt.Sprintf("%q", s))
	}
	if len(items) > shown {
		quoted = append(quoted, "...")
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func addDomainsError(diags *diag.Diagnostics, summary string, err error) {
	var partial *client.PartialFailureError
	if errors.As(err, &partial) {
		diags.AddAttributeError(path.Root("domains"), summary, err.Error()+
			". Status 400367 marks an invalid URI and 400368 one that is too long.")
		return
	}
	diags.AddError(summary, err.Error())
}

func throttled(err error) bool {
	return client.HasStatus(err, http.StatusTooManyRequests)
}

// domainKey is the identity used to match entries, tolerating case and trailing-slash
// normalisation by HERE, which the API reference does not specify.
func domainKey(d string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(d)), "/")
}

// diffDomains returns the desired entries absent from live and the live entries not desired.
func diffDomains(live, desired []string) (add, remove []string) {
	liveKeys := make(map[string]bool, len(live))
	for _, d := range live {
		liveKeys[domainKey(d)] = true
	}
	desiredKeys := make(map[string]bool, len(desired))
	for _, d := range desired {
		desiredKeys[domainKey(d)] = true
		if !liveKeys[domainKey(d)] {
			add = append(add, d)
		}
	}
	for _, d := range live {
		if !desiredKeys[domainKey(d)] {
			remove = append(remove, d)
		}
	}
	return add, remove
}

// alignDomains returns the live entries, keeping the prior spelling of matching ones.
func alignDomains(live, prior []string) []string {
	spelling := make(map[string]string, len(prior))
	for _, d := range prior {
		spelling[domainKey(d)] = d
	}
	out := make([]string, 0, len(live))
	seen := make(map[string]bool, len(live))
	for _, d := range live {
		k := domainKey(d)
		if seen[k] {
			continue
		}
		seen[k] = true
		if p, ok := spelling[k]; ok {
			d = p
		}
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

func setStrings(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(set.ElementsAs(ctx, &out, false)...)
	slices.Sort(out)
	return out
}
