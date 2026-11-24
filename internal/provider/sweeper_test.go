package provider

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

// sweepPrefix starts the name of every app the acceptance tests create. HERE deletes are
// permanent and app listings name no owner, so the sweeper deletes these apps and no others.
const sweepPrefix = "tfacc-"

const sweepTimeout = 10 * time.Minute

// sweepApps is the hereplatform_app sweeper. HERE has no regions, so the region is ignored.
func sweepApps(string) error { return sweep(context.Background(), os.Getenv) }

func sweep(ctx context.Context, getenv func(string) string) error {
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	c, self, err := envClient(getenv)
	if err != nil {
		return err
	}
	return sweepTestApps(ctx, c, self)
}

// envClient builds a client from the provider's HERE_* sources, and returns the client ID of
// the identity it acts as.
func envClient(getenv func(string) string) (*client.Client, string, error) {
	cfg, diags := resolveConfig(providerModel{}, getenv)
	if diags.HasError() {
		return nil, "", errors.New("HERE sandbox credentials are needed: " + diagText(diags))
	}
	s, _ := resolveSettings(providerModel{}, getenv)
	if s.clientID == "" {
		return nil, "", errors.New("the client ID of the sandbox identity is needed, so that its own app is never deleted: set " + envClientID)
	}
	cfg.UserAgent = "terraform-provider-hereplatform/acceptance"
	c, err := client.New(cfg)
	if err != nil {
		return nil, "", err
	}
	return c, s.clientID, nil
}

// sweepTestApps deletes the apps that acceptance tests left behind. deletion_protection lives
// in Terraform state only, so HERE accepts these deletes as it would any other.
func sweepTestApps(ctx context.Context, c *client.Client, self string) error {
	if self == "" {
		return errors.New("refusing to sweep without the client ID of the sweeping identity")
	}
	apps, err := c.ListApps(ctx)
	if err != nil {
		return fmt.Errorf("listing HERE apps: %w", err)
	}
	var errs []error
	for _, app := range apps {
		if !sweepable(app, self) {
			continue
		}
		if err := c.DeleteApp(ctx, app.HRN); err != nil && !client.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("deleting HERE app %q (%s): %w", app.Name, app.HRN, err))
			continue
		}
		log.Printf("[INFO] Swept HERE app %q (%s)", app.Name, app.HRN)
	}
	return errors.Join(errs...)
}

// sweepable reports whether an acceptance test created app. The sweeping identity's own app
// is kept whatever its name, compared loosely so that doubt spares it.
func sweepable(app client.App, self string) bool {
	if self == "" || app.HRN == "" || !strings.HasPrefix(app.Name, sweepPrefix) {
		return false
	}
	appID := app.HRN[strings.LastIndex(app.HRN, "/")+1:]
	return !strings.EqualFold(app.AppClientID(), self) && !strings.EqualFold(appID, self)
}

func TestSweepableKeepsEverythingButTestApps(t *testing.T) {
	t.Parallel()
	const self = "SandboxClient01"
	hrn := fakeAppHRN("App1")
	for _, tc := range []struct {
		name string
		app  client.App
		want bool
	}{
		{"test app", client.App{Name: "tfacc-4242", HRN: hrn, ClientID: "App1"}, true},
		{"listed test app", client.App{Name: "tfacc-4242", HRN: hrn, ID: "App1"}, true},
		{"bare prefix", client.App{Name: "tfacc-", HRN: hrn}, true},
		{"other app", client.App{Name: "payments-web", HRN: hrn}, false},
		{"no dash", client.App{Name: "tfacc4242", HRN: hrn}, false},
		{"underscore", client.App{Name: "tfacc_4242", HRN: hrn}, false},
		{"upper case", client.App{Name: "TFACC-4242", HRN: hrn}, false},
		{"leading space", client.App{Name: " tfacc-4242", HRN: hrn}, false},
		{"prefix inside", client.App{Name: "prod-tfacc-4242", HRN: hrn}, false},
		{"no name", client.App{HRN: hrn}, false},
		{"no HRN", client.App{Name: "tfacc-4242", ClientID: "App1"}, false},
		{"self by client ID", client.App{Name: "tfacc-self", HRN: hrn, ClientID: self}, false},
		{"self by list ID", client.App{Name: "tfacc-self", HRN: hrn, ID: self}, false},
		{"self by HRN", client.App{Name: "tfacc-self", HRN: fakeAppHRN(self)}, false},
		{"self in another case", client.App{Name: "tfacc-self", HRN: hrn, ClientID: strings.ToLower(self)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sweepable(tc.app, self); got != tc.want {
				t.Errorf("sweepable = %t, want %t", got, tc.want)
			}
		})
	}
	if sweepable(client.App{Name: "tfacc-4242", HRN: hrn}, "") {
		t.Error("an unknown sweeping identity must spare every app")
	}
	if a, b := testAccAppName(), testAccAppName(); !strings.HasPrefix(a, sweepPrefix) || a == b {
		t.Errorf("acceptance app names %q and %q must be random and start with %q", a, b, sweepPrefix)
	}
}

func TestSweepDeletesOnlyTestApps(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	f.update(func() { f.pageSize = 2 })
	var swept, kept []string
	for _, name := range []string{"tfacc-1", "tfacc-2", "tfacc-3"} {
		swept = append(swept, f.seedApp(name).HRN)
	}
	for _, name := range []string{"payments-web", "TFACC-upper", "my-tfacc-app"} {
		kept = append(kept, f.seedApp(name).HRN)
	}
	self := f.seedApp("tfacc-sandbox-identity", func(a *fakeApp) { a.ID = fakeClientID }).HRN
	gone := f.seedApp("tfacc-gone").HRN
	locked := f.seedApp("tfacc-locked").HRN
	f.hook(forApp(gone, always(routeDeleteApp, notFound())), forApp(locked, always(routeDeleteApp, forbidden())))

	err := sweep(t.Context(), envOf(f.env()))

	if err == nil || strings.Count(err.Error(), "deleting HERE app") != 1 || !strings.Contains(err.Error(), locked) {
		t.Errorf("want exactly one error, for %s; got %v", locked, err)
	}
	var deleted []string
	for _, c := range f.callsOf(routeDeleteApp) {
		deleted = append(deleted, c.App)
	}
	slices.Sort(deleted)
	want := slices.Sorted(slices.Values(append(slices.Clone(swept), gone, locked)))
	if !slices.Equal(deleted, want) {
		t.Errorf("deleted %v, want %v", deleted, want)
	}
	for _, hrn := range append(kept, self, locked) {
		if _, ok := f.app(hrn); !ok {
			t.Errorf("app %s was deleted, want it kept", hrn)
		}
	}
	if n := len(f.callsOf(routeListApps)); n != 5 {
		t.Errorf("%d list requests for 9 apps in pages of 2, want 5", n)
	}
}

func TestSweepNeedsTheSandboxIdentity(t *testing.T) {
	t.Parallel()
	f := newFakeHERE(t)
	endpoints := map[string]string{envTokenURL: f.url + fakeTokenPath, envAPIURL: f.url + fakeAPIPath}
	with := func(vars map[string]string) func(string) string {
		all := maps.Clone(endpoints)
		maps.Copy(all, vars)
		return envOf(all)
	}

	if err := sweep(t.Context(), with(nil)); err == nil || !strings.Contains(err.Error(), "Missing HERE credentials") {
		t.Errorf("without credentials: %v", err)
	}
	err := sweep(t.Context(), with(map[string]string{envAccessKeyID: "AKID", envAccessKeySecret: testSecret}))
	switch {
	case err == nil || !strings.Contains(err.Error(), envClientID):
		t.Error("with an access key but no client ID: want an error asking for " + envClientID)
	case strings.Contains(err.Error(), testSecret):
		t.Error("the error contains the access key secret")
	}
	if err := sweepTestApps(t.Context(), f.client(t), ""); err == nil {
		t.Error("sweepTestApps swept without knowing the sweeping identity")
	}
	if n := len(f.callsOf()); n != 0 {
		t.Errorf("%d requests to HERE, want none before the sweeping identity is known", n)
	}
}
