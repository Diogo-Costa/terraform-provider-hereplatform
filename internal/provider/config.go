package provider

import (
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Diogo-Costa/terraform-provider-hereplatform/internal/client"
)

const (
	envClientID        = "HERE_CLIENT_ID"
	envPrivateKey      = "HERE_PRIVATE_KEY"
	envKeyID           = "HERE_KEY_ID"
	envAccessKeyID     = "HERE_ACCESS_KEY_ID"
	envAccessKeySecret = "HERE_ACCESS_KEY_SECRET"
	envCredentialsFile = "HERE_CREDENTIALS_FILE"
	envTokenURL        = "HERE_TOKEN_URL" //nolint:gosec // an environment variable name, not a credential.
	envAPIURL          = "HERE_API_URL"
	// Read from the environment only: no configuration alone can send credentials outside HERE.
	envAllowCustomEndpoints = "HERE_ALLOW_CUSTOM_ENDPOINTS"
)

// HERE JWK kid rules: 1-256 characters from [A-Za-z0-9._-].
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)

type settings struct {
	clientID        string
	privateKey      string
	keyID           string
	accessKeyID     string
	accessKeySecret string
	tokenURL        string
	apiURL          string
	// allowCustomEndpoints is the HERE_ALLOW_CUSTOM_ENDPOINTS=1 opt-in.
	allowCustomEndpoints bool
}

// resolveConfig merges provider arguments, HERE_* variables and the credentials file, in
// that order, and selects exactly one client authentication method. Diagnostics name
// arguments but never echo their values.
func resolveConfig(m providerModel, getenv func(string) string) (client.Config, diag.Diagnostics) {
	s, diags := resolveSettings(m, getenv)
	if diags.HasError() {
		return client.Config{}, diags
	}
	auth := resolveAuth(s, &diags)
	if diags.HasError() {
		return client.Config{}, diags
	}
	return client.Config{
		APIURL: s.apiURL, TokenURL: s.tokenURL, Auth: auth, AllowCustomEndpoints: s.allowCustomEndpoints,
	}, diags
}

func resolveSettings(m providerModel, getenv func(string) string) (settings, diag.Diagnostics) {
	var diags diag.Diagnostics
	if getenv == nil {
		getenv = os.Getenv
	}

	attrs := []struct {
		name  string
		value types.String
		env   string
	}{
		{"client_id", m.ClientID, envClientID},
		{"private_key", m.PrivateKey, envPrivateKey},
		{"key_id", m.KeyID, envKeyID},
		{"access_key_id", m.AccessKeyID, envAccessKeyID},
		{"access_key_secret", m.AccessKeySecret, envAccessKeySecret},
		{"credentials_file", m.CredentialsFile, envCredentialsFile},
		{"token_url", m.TokenURL, envTokenURL},
		{"api_url", m.APIURL, envAPIURL},
	}
	for _, a := range attrs {
		if a.value.IsUnknown() {
			diags.AddAttributeError(path.Root(a.name), "Unknown "+a.name,
				"The provider cannot be configured with a value known only after apply. Set "+a.name+
					" to a static value or use the "+a.env+" environment variable.")
		}
	}
	if diags.HasError() {
		return settings{}, diags
	}

	var creds client.Credentials
	if file := firstValue(m.CredentialsFile, getenv(envCredentialsFile)); file != "" {
		c, err := client.ReadCredentialsFile(file)
		if err != nil {
			diags.AddAttributeError(path.Root("credentials_file"), "Unable to read the HERE credentials file", err.Error())
			return settings{}, diags
		}
		creds = *c
	}

	s := settings{
		clientID:        firstValue(m.ClientID, getenv(envClientID), creds.ClientID),
		privateKey:      normalizePEM(firstValue(m.PrivateKey, getenv(envPrivateKey))),
		keyID:           firstValue(m.KeyID, getenv(envKeyID)),
		accessKeyID:     firstValue(m.AccessKeyID, getenv(envAccessKeyID), creds.AccessKeyID),
		accessKeySecret: firstValue(m.AccessKeySecret, getenv(envAccessKeySecret), creds.AccessKeySecret),
		tokenURL:        firstValue(m.TokenURL, getenv(envTokenURL), creds.TokenURL, client.DefaultTokenURL),
		apiURL:          firstValue(m.APIURL, getenv(envAPIURL), client.DefaultAPIURL),

		allowCustomEndpoints: getenv(envAllowCustomEndpoints) == "1",
	}
	checkEndpoints(s, &diags)
	return s, diags
}

func checkEndpoints(s settings, diags *diag.Diagnostics) {
	for _, e := range []struct{ name, value, receives string }{
		{"token_url", s.tokenURL, "the signed client credentials of every token request"},
		{"api_url", s.apiURL, "the access token, which can manage every app the provider can reach"},
	} {
		err := client.ValidateEndpoint(e.value)
		switch {
		case err == nil:
		case !errors.Is(err, client.ErrCustomEndpoint):
			diags.AddAttributeError(path.Root(e.name), "Invalid "+e.name, err.Error()+".")
		case !s.allowCustomEndpoints:
			diags.AddAttributeError(path.Root(e.name), "Invalid "+e.name, err.Error()+". To send requests to "+
				"another HTTPS host, set "+envAllowCustomEndpoints+"=1 in the environment of Terraform.")
		default:
			u, _ := url.Parse(e.value)
			diags.AddAttributeWarning(path.Root(e.name), "Custom HERE endpoint",
				e.name+" points to "+u.Host+", which is not a HERE endpoint and receives "+e.receives+". It is "+
					"accepted because "+envAllowCustomEndpoints+"=1 is set; unset it unless you trust that host.")
		}
	}
}

func resolveAuth(s settings, diags *diag.Diagnostics) client.Auth {
	jwtReady := s.clientID != "" && s.privateKey != ""
	accessKeyReady := s.accessKeyID != "" && s.accessKeySecret != ""

	switch {
	case jwtReady:
		key, err := client.ParseRSAPrivateKey(s.privateKey)
		if err != nil {
			diags.AddAttributeError(path.Root("private_key"), "Invalid private key",
				"The private key from private_key or "+envPrivateKey+" is unusable: "+err.Error()+".")
			return nil
		}
		if s.keyID != "" && !keyIDPattern.MatchString(s.keyID) {
			diags.AddAttributeError(path.Root("key_id"), "Invalid key_id",
				"key_id must be 1 to 256 characters from A-Z, a-z, 0-9, '.', '_' and '-'.")
			return nil
		}
		if accessKeyReady {
			diags.AddWarning("Multiple HERE authentication methods configured",
				"Both private_key_jwt (client_id and private_key) and an access key (access_key_id and "+
					"access_key_secret) are configured. The provider uses private_key_jwt.")
		}
		auth, err := client.NewJWTAuth(s.clientID, s.keyID, key)
		if err != nil {
			diags.AddError("Invalid private_key_jwt configuration", err.Error())
		}
		return auth

	case accessKeyReady:
		if s.privateKey != "" {
			diags.AddAttributeError(path.Root("client_id"), "Incomplete private_key_jwt configuration",
				"private_key is set, but no client ID was found in client_id, "+envClientID+" or credentials_file. "+
					"Set the client ID, or unset private_key to authenticate with the access key.")
			return nil
		}
		if s.keyID != "" {
			diags.AddAttributeWarning(path.Root("key_id"), "key_id is ignored",
				"key_id applies only to private_key_jwt; the provider authenticates with the access key.")
		}
		auth, err := client.NewOAuth1Auth(s.accessKeyID, s.accessKeySecret)
		if err != nil {
			diags.AddError("Invalid access key configuration", err.Error())
		}
		return auth

	default:
		diags.AddError("Missing HERE credentials", missingCredentialsDetail(s))
		return nil
	}
}

func missingCredentialsDetail(s settings) string {
	var set, missing []string
	for _, f := range []struct{ name, value string }{
		{"client_id", s.clientID},
		{"private_key", s.privateKey},
		{"access_key_id", s.accessKeyID},
		{"access_key_secret", s.accessKeySecret},
	} {
		if f.value != "" {
			set = append(set, f.name)
		} else {
			missing = append(missing, f.name)
		}
	}
	detail := "Configure one complete authentication method:\n" +
		"  - private_key_jwt (recommended): client_id and private_key, plus key_id when the JWK has one;\n" +
		"  - access key (OAuth 1.0): access_key_id and access_key_secret.\n" +
		"Each value can come from the provider block, its HERE_* environment variable or credentials_file.\n\n"
	if len(set) > 0 {
		detail += "Set: " + strings.Join(set, ", ") + ". "
	}
	return detail + "Missing: " + strings.Join(missing, ", ") + "."
}

func firstValue(attr types.String, fallbacks ...string) string {
	if v := strings.TrimSpace(attr.ValueString()); v != "" {
		return v
	}
	for _, f := range fallbacks {
		if v := strings.TrimSpace(f); v != "" {
			return v
		}
	}
	return ""
}

// normalizePEM restores newlines that CI secret stores often flatten to literal "\n".
func normalizePEM(s string) string {
	if !strings.Contains(s, "\n") && strings.Contains(s, `\n`) {
		return strings.ReplaceAll(s, `\n`, "\n")
	}
	return s
}
