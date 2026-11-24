package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	attrDeletionProtection = "deletion_protection"
	protectedSummary       = "Deletion protection is enabled"

	// Terraform 1.3 started planning destroys through PlanResourceChange, which runs ModifyPlan.
	minGuardedTerraformMinor = 3
)

// guarded describes a protected object in diagnostics. Built from individual attributes:
// formatting a whole state would expose API key values.
type guarded struct {
	what        string
	consequence string
	// rotation is appended to the remedies; API keys explain the outage-free rotation.
	rotation string
}

// isProtected treats null as protected: state written before the attribute existed.
func isProtected(v types.Bool) bool {
	return v.IsNull() || v.IsUnknown() || v.ValueBool()
}

func priorProtected(ctx context.Context, state tfsdk.State, diags *diag.Diagnostics) bool {
	var v types.Bool
	diags.Append(state.GetAttribute(ctx, path.Root(attrDeletionProtection), &v)...)
	return isProtected(v)
}

func stringAttr(ctx context.Context, get func(context.Context, path.Path, any) diag.Diagnostics, name string, diags *diag.Diagnostics) types.String {
	var v types.String
	diags.Append(get(ctx, path.Root(name), &v)...)
	return v
}

func (g guarded) addDestroyError(diags *diag.Diagnostics) {
	diags.AddError(protectedSummary, fmt.Sprintf("This plan destroys %s while deletion_protection = true. %s\n\n"+
		"To delete it, set deletion_protection = false and apply, and then remove or destroy it. To stop managing it "+
		"without changing HERE, use a removed block with lifecycle { destroy = false } (Terraform 1.7 or later), or "+
		"run terraform state rm.%s",
		g.what, g.consequence, g.rotation))
}

// addReplaceError covers app_hrn changes; an unknown app_hrn usually means the app itself
// is planned for replacement, which ModifyPlan of the app cannot detect.
func (g guarded) addReplaceError(diags *diag.Diagnostics, appHRN types.String) {
	reason := "app_hrn changes"
	if appHRN.IsUnknown() {
		reason = "app_hrn is unknown until apply, as when its app is replaced"
	}
	diags.AddError(protectedSummary, fmt.Sprintf("This plan replaces %s while deletion_protection = true, "+
		"because %s. %s\n\nTo keep it, plan again without what replaces it: revert app_hrn, run terraform untaint on "+
		"a tainted app, or drop -replace. To replace it, first apply deletion_protection = false in a plan that does "+
		"not replace it, and then apply the replacement.%s", g.what, reason, g.consequence, g.rotation))
}

// addDeleteError is the apply-time fallback for what plans cannot reveal: tainted objects,
// -replace and replace_triggered_by, which Terraform plans as creates, and Terraform < 1.3.
func (g guarded) addDeleteError(diags *diag.Diagnostics) {
	diags.AddError(protectedSummary, fmt.Sprintf("Terraform tried to delete %s while deletion_protection = true, "+
		"so the provider stopped. %s\n\nThis happens when Terraform replaces a tainted resource or one targeted "+
		"by -replace or replace_triggered_by, and on Terraform older than 1.3. To keep it, run terraform untaint on "+
		"the resource, or plan again without -replace. To delete it anyway, untaint it if it is tainted, set "+
		"deletion_protection = false and apply, and then destroy or replace it.%s", g.what, g.consequence, g.rotation))
}

// guardsDestroyPlans reports whether this Terraform version plans destroys through the
// provider; unparsable versions get the benefit of the doubt.
func guardsDestroyPlans(version string) bool {
	parts := strings.SplitN(version, ".", 3) //nolint:mnd // major, minor and the rest.
	if len(parts) < 2 {                      //nolint:mnd // major and minor are required.
		return true
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return true
	}
	return major > 1 || (major == 1 && minor >= minGuardedTerraformMinor)
}
