package provider

import (
	"fmt"
	"strconv"
	"strings"
)

// Test configurations are rendered only by these helpers, one per resource, so that a
// schema change such as a new protection attribute is a one-place edit.

const (
	// unprotected lets the post-test destroy delete a resource.
	unprotected = "deletion_protection = false"
	protected   = "deletion_protection = true"
	// defaultProtection leaves deletion_protection unset; an HCL comment, so it renders nothing.
	defaultProtection = "# deletion_protection unset"
)

// withProtection makes keys and trusted domains unprotected unless attrs set the protection,
// so that tests not about it can be destroyed.
func withProtection(attrs []string) []string {
	for _, a := range attrs {
		if strings.Contains(a, "deletion_protection") {
			return attrs
		}
	}
	return append(attrs, unprotected)
}

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
	return hclBlock("resource", "hereplatform_app_api_key", label,
		append([]string{"app_hrn = " + appHRN}, withProtection(attrs)...))
}

// domainsBlock renders hereplatform_app_trusted_domains.test; HERE allows one per app.
func domainsBlock(appHRN string, domains []string, attrs ...string) string {
	quoted := make([]string, len(domains))
	for i, d := range domains {
		quoted[i] = strconv.Quote(d)
	}
	return hclBlock("resource", "hereplatform_app_trusted_domains", "test",
		append([]string{"app_hrn = " + appHRN, "domains = [" + strings.Join(quoted, ", ") + "]"}, withProtection(attrs)...))
}

// removedBlock forgets addr without destroying it.
func removedBlock(addr string) string {
	return "removed {\n  from = " + addr + "\n  lifecycle {\n    destroy = false\n  }\n}\n"
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
