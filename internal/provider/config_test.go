package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

const testSecret = "s3cr3t-value-that-must-not-leak"

func testPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func envOf(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func authType(cfg client.Config) string { return fmt.Sprintf("%T", cfg.Auth) }

func diagText(diags diag.Diagnostics) string {
	var b strings.Builder
	for _, d := range diags {
		b.WriteString(d.Summary() + ": " + d.Detail() + "\n")
	}
	return b.String()
}

func TestResolveConfigPrefersJWT(t *testing.T) {
	m := providerModel{
		ClientID:   types.StringValue("client-1"),
		PrivateKey: types.StringValue(testPEM(t)),
		KeyID:      types.StringValue("key-1"),
	}
	cfg, diags := resolveConfig(m, envOf(map[string]string{envAccessKeyID: "AKID", envAccessKeySecret: testSecret}))
	if diags.HasError() {
		t.Fatalf("unexpected errors: %s", diagText(diags))
	}
	if got := authType(cfg); got != "*client.jwtAuth" {
		t.Fatalf("auth = %s, want JWT", got)
	}
	if diags.WarningsCount() != 1 || !strings.Contains(diagText(diags), "uses private_key_jwt") {
		t.Fatalf("expected a warning about both methods, got %s", diagText(diags))
	}
	if cfg.TokenURL != client.DefaultTokenURL || cfg.APIURL != client.DefaultAPIURL {
		t.Fatalf("endpoints = %q, %q", cfg.TokenURL, cfg.APIURL)
	}
}

func TestResolveConfigWarnsWithoutKeyID(t *testing.T) {
	pem := testPEM(t)
	for keyID, warnings := range map[string]int{"": 1, "key-1": 0} {
		m := providerModel{ClientID: types.StringValue("client-1"), PrivateKey: types.StringValue(pem), KeyID: types.StringValue(keyID)}
		_, diags := resolveConfig(m, envOf(nil))
		text := diagText(diags)
		if diags.HasError() || diags.WarningsCount() != warnings || strings.Contains(text, "key_id is not set") != (warnings == 1) {
			t.Fatalf("key_id %q: unexpected diagnostics %s", keyID, text)
		}
	}
}

func TestResolveSettingsWarnsAboutSharedCredentialsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not reflect ACLs")
	}
	for mode, warns := range map[os.FileMode]bool{0o600: false, 0o644: true} {
		file := filepath.Join(t.TempDir(), "credentials.properties")
		if err := os.WriteFile(file, []byte("here.access.key.id = AKID\nhere.access.key.secret = "+testSecret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		_, diags := resolveConfig(providerModel{CredentialsFile: types.StringValue(file)}, envOf(nil))
		text := diagText(diags)
		if diags.HasError() || strings.Contains(text, "Credentials file is accessible to other users") != warns {
			t.Fatalf("mode %v: unexpected diagnostics %s", mode, text)
		}
		if strings.Contains(text, testSecret) || strings.Contains(text, file) {
			t.Fatalf("mode %v: diagnostics echo the file path or its secret", mode)
		}
	}
}

func TestResolveConfigAccessKeyFromEnv(t *testing.T) {
	cfg, diags := resolveConfig(providerModel{}, envOf(map[string]string{
		envAccessKeyID: "AKID", envAccessKeySecret: testSecret, envKeyID: "ignored",
		envAPIURL: "http://127.0.0.1:8080/authentication/v1.1",
	}))
	if diags.HasError() {
		t.Fatalf("unexpected errors: %s", diagText(diags))
	}
	if got := authType(cfg); got != "*client.oauth1Auth" {
		t.Fatalf("auth = %s, want OAuth 1.0", got)
	}
	if !strings.Contains(diagText(diags), "key_id is ignored") {
		t.Fatalf("expected a key_id warning, got %s", diagText(diags))
	}
	if cfg.APIURL != "http://127.0.0.1:8080/authentication/v1.1" {
		t.Fatalf("api_url = %q", cfg.APIURL)
	}
}

func TestResolveSettingsPrecedence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "credentials.properties")
	content := "here.user.id = HERE-user\nhere.client.id = file-client\nhere.access.key.id = file-akid\n" +
		"here.access.key.secret = file-secret\nhere.token.endpoint.url = https://token.example.com/oauth2/token\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	m := providerModel{AccessKeySecret: types.StringValue(" attr-secret ")}
	s, diags := resolveSettings(m, envOf(map[string]string{
		envCredentialsFile: file, envAccessKeyID: "env-akid", envAllowCustomEndpoints: "1",
	}))
	if diags.HasError() {
		t.Fatalf("unexpected errors: %s", diagText(diags))
	}
	want := settings{
		clientID:             "file-client",
		accessKeyID:          "env-akid",
		accessKeySecret:      "attr-secret",
		tokenURL:             "https://token.example.com/oauth2/token",
		apiURL:               client.DefaultAPIURL,
		allowCustomEndpoints: true,
	}
	if s != want {
		t.Fatalf("settings = %+v, want %+v", s, want)
	}
}

func TestResolveSettingsEndpointPolicy(t *testing.T) {
	tests := map[string]struct {
		model          providerModel
		env            map[string]string
		error, warning string
	}{
		"HERE endpoints": {},
		"loopback test servers": {env: map[string]string{
			envAPIURL: "http://127.0.0.1:8080/authentication/v1.1", envTokenURL: "https://[::1]:8443/oauth2/token",
		}},
		"localhost by name": {
			env:   map[string]string{envAPIURL: "http://localhost:8080/authentication/v1.1"},
			error: "Invalid api_url: HTTPS is required (plain HTTP is accepted only for literal loopback IP addresses).",
		},
		"custom host": {
			model: providerModel{APIURL: types.StringValue("https://iam.example.com/authentication/v1.1")},
			error: "Invalid api_url: not a HERE endpoint: iam.example.com is neither account.api.here.com nor a " +
				"literal loopback IP address. To send requests to another HTTPS host, set HERE_ALLOW_CUSTOM_ENDPOINTS=1",
		},
		"lookalike HERE host": {
			env:   map[string]string{envTokenURL: "https://account.api.here.com.example.com/oauth2/token"},
			error: "Invalid token_url: not a HERE endpoint",
		},
		"opt-in": {
			model: providerModel{TokenURL: types.StringValue("https://token.example.com:8443/oauth2/token")},
			env:   map[string]string{envAllowCustomEndpoints: "1"},
			warning: "Custom HERE endpoint: token_url points to token.example.com:8443, which is not a HERE endpoint " +
				"and receives the signed client credentials",
		},
		"opt-in still requires HTTPS": {
			env:   map[string]string{envAllowCustomEndpoints: "1", envAPIURL: "http://iam.example.com/"},
			error: "Invalid api_url: HTTPS is required",
		},
		"opt-in other than 1": {
			env:   map[string]string{envAllowCustomEndpoints: "true", envAPIURL: "https://iam.example.com/"},
			error: "Invalid api_url: not a HERE endpoint",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, diags := resolveSettings(tc.model, envOf(tc.env))
			text := diagText(diags)
			if diags.HasError() != (tc.error != "") || diags.WarningsCount() != min(len(tc.warning), 1) {
				t.Fatalf("unexpected diagnostics: %s", text)
			}
			for _, want := range []string{tc.error, tc.warning} {
				if !strings.Contains(text, want) {
					t.Fatalf("diagnostics %q do not contain %q", text, want)
				}
			}
		})
	}
}

func TestResolveConfigErrors(t *testing.T) {
	validPEM := testPEM(t)
	tests := map[string]struct {
		model providerModel
		env   map[string]string
		want  string
	}{
		"private key without client ID": {
			model: providerModel{PrivateKey: types.StringValue(validPEM)},
			env:   map[string]string{envAccessKeyID: "AKID", envAccessKeySecret: testSecret},
			want:  "Incomplete private_key_jwt configuration",
		},
		"missing credentials": {
			env:  map[string]string{envAccessKeySecret: testSecret},
			want: "Set: access_key_secret. Missing: client_id, private_key, access_key_id.",
		},
		"invalid private key": {
			model: providerModel{ClientID: types.StringValue("client-1"), PrivateKey: types.StringValue(testSecret)},
			want:  "Invalid private key",
		},
		"invalid key ID": {
			model: providerModel{ClientID: types.StringValue("c"), PrivateKey: types.StringValue(validPEM), KeyID: types.StringValue("bad kid")},
			want:  "Invalid key_id",
		},
		"plain HTTP endpoint": {
			model: providerModel{TokenURL: types.StringValue("http://token.example.com/oauth2/token")},
			env:   map[string]string{envAccessKeyID: "AKID", envAccessKeySecret: testSecret},
			want:  "Invalid token_url: HTTPS is required",
		},
		"unknown value": {
			model: providerModel{ClientID: types.StringUnknown()},
			want:  "Unknown client_id",
		},
		"unreadable credentials file": {
			model: providerModel{CredentialsFile: types.StringValue(filepath.Join(t.TempDir(), "absent"))},
			want:  "Unable to read the HERE credentials file",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, diags := resolveConfig(tc.model, envOf(tc.env))
			text := diagText(diags)
			if !diags.HasError() || !strings.Contains(text, tc.want) {
				t.Fatalf("diagnostics %q do not contain %q", text, tc.want)
			}
			if strings.Contains(text, testSecret) || strings.Contains(text, "PRIVATE KEY") {
				t.Fatalf("diagnostics leak a secret: %s", text)
			}
		})
	}
}

func TestNormalizePEM(t *testing.T) {
	flattened := strings.ReplaceAll(testPEM(t), "\n", `\n`)
	if _, err := client.ParseRSAPrivateKey(normalizePEM(flattened)); err != nil {
		t.Fatalf("flattened PEM not restored: %v", err)
	}
	if got := normalizePEM("a\nb\\nc"); got != "a\nb\\nc" {
		t.Fatalf("PEM with real newlines must be left alone, got %q", got)
	}
}
