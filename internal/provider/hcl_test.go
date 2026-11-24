package provider

import (
	"fmt"
	"strconv"
	"strings"
)

// Test configurations are rendered only by these helpers, one per resource, so that a
// schema change such as a new protection attribute is a one-place edit.

// unprotected lets the post-test destroy delete an app.
const unprotected = "deletion_protection = false"

func hclBlock(kind, typ, label string, attrs []string) string {
	return fmt.Sprintf("%s %q %q {\n  %s\n}\n", kind, typ, label, strings.Join(attrs, "\n  "))
}

func appBlock(label, name string, attrs ...string) string {
	return hclBlock("resource", "hereplatform_app", label, append([]string{"name = " + strconv.Quote(name)}, attrs...))
}

// appConfig renders the app most tests manage, hereplatform_app.test.
func appConfig(name string, attrs ...string) string { return appBlock("test", name, attrs...) }

func appRef(label string) string { return "hereplatform_app." + label + ".id" }

func keyBlock(label, appHRN string, attrs ...string) string {
	return hclBlock("resource", "hereplatform_app_api_key", label, append([]string{"app_hrn = " + appHRN}, attrs...))
}

func domainsBlock(label, appHRN string, domains []string, attrs ...string) string {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = strconv.Quote(d)
	}
	return hclBlock("resource", "hereplatform_app_trusted_domains", label,
		append([]string{"app_hrn = " + appHRN, "domains = [" + strings.Join(quoted, ", ") + "]"}, attrs...))
}

// appDataBlock renders data.hereplatform_app.test.
func appDataBlock(attrs ...string) string {
	return hclBlock("data", "hereplatform_app", "test", attrs)
}

// timeoutsAttr renders a timeouts attribute from operation and duration pairs.
func timeoutsAttr(pairs ...string) string {
	items := make([]string, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		items = append(items, pairs[i]+" = "+strconv.Quote(pairs[i+1]))
	}
	return "timeouts = { " + strings.Join(items, ", ") + " }"
}
