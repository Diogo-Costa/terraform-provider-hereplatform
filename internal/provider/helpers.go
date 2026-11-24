package provider

import (
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

// HRNs never contain ',' or whitespace, which keeps composite import IDs unambiguous.
var (
	appHRNPattern = regexp.MustCompile(`^hrn:[^:,\s]+:account::[^:,\s]+:app/[^/,\s]+$`)
)

const (
	appHRNFormat = "hrn:here:account::<realm>:app/<app-id>"

	descAppHRN      = "HRN of the app."
	descClientID    = "OAuth client ID of the app."
	descCreatedTime = "Creation time (RFC 3339)."
	descRealm       = "Realm (organization ID) the app belongs to."
	descStatus      = "Lifecycle status reported by HERE."
)

func appHRNValidator() validator.String {
	return stringvalidator.RegexMatches(appHRNPattern, "must be an app HRN like "+appHRNFormat)
}

func clientFromProviderData(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data",
			fmt.Sprintf("Expected *client.Client, got %T. Please report this issue to the provider developers.", data))
		return nil
	}
	return c
}

// millisToRFC3339 renders HERE epoch-millisecond timestamps; zero or negative means unset.
func millisToRFC3339(ms int64) types.String {
	if ms <= 0 {
		return types.StringNull()
	}
	return types.StringValue(time.UnixMilli(ms).UTC().Format(time.RFC3339Nano))
}

func stringOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}
