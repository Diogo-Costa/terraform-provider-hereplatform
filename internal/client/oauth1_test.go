package client

import (
	"crypto/sha1"
	"crypto/sha256"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// RFC 5849 section 3.4.1.1 example request.
func rfc5849Example(t *testing.T) (*url.URL, url.Values) {
	t.Helper()
	u, err := url.Parse("http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")
	if err != nil {
		t.Fatal(err)
	}
	body, err := url.ParseQuery("c2&a3=2+q")
	if err != nil {
		t.Fatal(err)
	}
	params := url.Values{}
	for k, vs := range u.Query() {
		params[k] = append(params[k], vs...)
	}
	for k, vs := range body {
		params[k] = append(params[k], vs...)
	}
	params.Set("oauth_consumer_key", "9djdj82h48djs9d2")
	params.Set("oauth_token", "kkk9d7dh3k39sjv7")
	params.Set("oauth_signature_method", "HMAC-SHA1")
	params.Set("oauth_timestamp", "137131201")
	params.Set("oauth_nonce", "7d8f3e4a")
	return u, params
}

const rfc5849BaseString = "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" +
	"%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2" +
	"%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201" +
	"%26oauth_token%3Dkkk9d7dh3k39sjv7"

func TestSignatureBaseStringRFC5849(t *testing.T) {
	u, params := rfc5849Example(t)
	if got := signatureBaseString(http.MethodPost, u, params); got != rfc5849BaseString {
		t.Fatalf("base string mismatch\n got: %s\nwant: %s", got, rfc5849BaseString)
	}
}

func TestHMACSignature(t *testing.T) {
	tests := []struct {
		name string
		alg  string
		want string
	}{
		// RFC 5849 erratum 2550 corrects the signature printed in section 3.4.1.1.
		{name: "RFC 5849 HMAC-SHA1", alg: "sha1", want: "r6/TJjbCOr97/+UU0NsvSne7s5g="},
		{name: "HMAC-SHA256 over the RFC 5849 input", alg: "sha256", want: "lIfydhbOitvsm4DvUwgM0NdR1Mzd08HnXI+q+EG0QKo="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newHash := sha256.New
			if tt.alg == "sha1" {
				newHash = sha1.New
			}
			got := hmacSignature(newHash, "j49sk3j29djd", "dh893hdasih9", rfc5849BaseString)
			if got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBaseStringURI(t *testing.T) {
	tests := map[string]string{
		"HTTP://EXAMPLE.COM:80/r%20v/X?id=123":          "http://example.com/r%20v/X",
		"https://www.example.net:8080/?q=1":             "https://www.example.net:8080/",
		"https://account.api.here.com:443/oauth2/token": "https://account.api.here.com/oauth2/token",
		"http://127.0.0.1:4567":                         "http://127.0.0.1:4567/",
	}
	for raw, want := range tests {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := baseStringURI(u); got != want {
			t.Errorf("baseStringURI(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestOAuth1AuthenticateHEREVector(t *testing.T) {
	auth, err := NewOAuth1Auth("test-access-key-id", "test/secret+value=")
	if err != nil {
		t.Fatal(err)
	}
	oa, ok := auth.(*oauth1Auth)
	if !ok {
		t.Fatalf("unexpected type %T", auth)
	}
	oa.nonce = func() string { return "NONCE123" }

	form := url.Values{"grant_type": {"client_credentials"}}
	header := http.Header{}
	secrets, err := oa.authenticate(form, header, DefaultTokenURL, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}

	want := `OAuth oauth_consumer_key="test-access-key-id",oauth_nonce="NONCE123",` +
		`oauth_signature="O2KCEmpzaCxNJbACr8bo86OkjcmSTA4oKMJIzSQjaGw%3D",oauth_signature_method="HMAC-SHA256",` +
		`oauth_timestamp="1700000000",oauth_version="1.0"`
	if got := header.Get("Authorization"); got != want {
		t.Fatalf("Authorization header mismatch\n got: %s\nwant: %s", got, want)
	}
	if got := form.Encode(); got != "grant_type=client_credentials" {
		t.Fatalf("form must only carry grant_type, got %q", got)
	}
	signature := "O2KCEmpzaCxNJbACr8bo86OkjcmSTA4oKMJIzSQjaGw="
	if !slices.Equal(secrets, []string{"test/secret+value=", signature, PercentEncode(signature)}) {
		t.Fatal("authenticate must report the access key secret and both forms of the signature")
	}
}

func TestOAuth1NonceIsUniquePerRequest(t *testing.T) {
	auth, err := NewOAuth1Auth("id", "secret")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 50 {
		header := http.Header{}
		if _, err := auth.authenticate(url.Values{}, header, DefaultTokenURL, time.Now()); err != nil {
			t.Fatal(err)
		}
		params := parseOAuthHeader(t, header.Get("Authorization"))
		nonce := params["oauth_nonce"]
		if nonce == "" || seen[nonce] {
			t.Fatalf("nonce %q is empty or reused", nonce)
		}
		seen[nonce] = true
	}
}

func TestNewOAuth1AuthRequiresBothValues(t *testing.T) {
	if _, err := NewOAuth1Auth("", "secret"); err == nil {
		t.Fatal("expected an error without an access key ID")
	}
	if _, err := NewOAuth1Auth("id", ""); err == nil {
		t.Fatal("expected an error without an access key secret")
	}
}

func parseOAuthHeader(t *testing.T, h string) map[string]string {
	t.Helper()
	rest, ok := strings.CutPrefix(h, "OAuth ")
	if !ok {
		t.Fatalf("not an OAuth header: %q", h)
	}
	out := map[string]string{}
	for part := range strings.SplitSeq(rest, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			t.Fatalf("malformed OAuth header part %q", part)
		}
		unquoted, err := url.PathUnescape(strings.Trim(v, `"`))
		if err != nil {
			t.Fatal(err)
		}
		out[k] = unquoted
	}
	return out
}
