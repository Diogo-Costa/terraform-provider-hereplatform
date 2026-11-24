package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func TestJWTAssertion(t *testing.T) {
	key := testRSAKey(t)
	auth, err := NewJWTAuth("client-123", "key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	form := url.Values{"grant_type": {"client_credentials"}}
	header := http.Header{}
	secrets, err := auth.authenticate(form, header, DefaultTokenURL, now)
	if err != nil {
		t.Fatal(err)
	}

	if got := form.Get("client_assertion_type"); got != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("client_assertion_type = %q", got)
	}
	if form.Has("scope") || form.Has("client_secret") {
		t.Fatalf("unexpected form fields: %v", form)
	}
	if len(header) != 0 {
		t.Fatalf("private_key_jwt must not set headers, got %v", header)
	}

	assertion := form.Get("client_assertion")
	if len(secrets) != 1 || secrets[0] != assertion {
		t.Fatal("the client assertion must be reported as a secret")
	}
	parsed, err := jwt.Parse(assertion, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("assertion does not verify: %v", err)
	}
	if kid := parsed.Header["kid"]; kid != "key-1" {
		t.Fatalf("kid = %v", kid)
	}

	segments := strings.Split(assertion, ".")
	raw, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "client-123" || claims["sub"] != "client-123" {
		t.Fatalf("iss/sub = %v/%v", claims["iss"], claims["sub"])
	}
	if aud, ok := claims["aud"].(string); !ok || aud != DefaultTokenURL {
		t.Fatalf("aud must be the token URL as a string, got %#v", claims["aud"])
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int64(iat) != now.Unix() || exp-iat != 300 {
		t.Fatalf("iat=%v exp=%v", iat, exp)
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatal("jti is empty")
	}
	if _, ok := claims["scope"]; ok {
		t.Fatal("assertion must not request a scope")
	}
}

func TestJWTAssertionIsUniqueAndKidOptional(t *testing.T) {
	auth, err := NewJWTAuth("client-123", "", testRSAKey(t))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 10 {
		form := url.Values{}
		if _, err := auth.authenticate(form, http.Header{}, DefaultTokenURL, time.Now()); err != nil {
			t.Fatal(err)
		}
		tok, _, err := jwt.NewParser().ParseUnverified(form.Get("client_assertion"), jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := tok.Header["kid"]; ok {
			t.Fatal("kid header must be omitted when no key ID is configured")
		}
		claims, _ := tok.Claims.(jwt.MapClaims)
		jti, _ := claims["jti"].(string)
		if jti == "" || seen[jti] {
			t.Fatalf("jti %q is empty or reused", jti)
		}
		seen[jti] = true
	}
}

func TestNewJWTAuthValidation(t *testing.T) {
	if _, err := NewJWTAuth("", "", testRSAKey(t)); err == nil {
		t.Fatal("expected an error without a client ID")
	}
	if _, err := NewJWTAuth("client", "", nil); err == nil {
		t.Fatal("expected an error without a key")
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key := testRSAKey(t)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	for name, in := range map[string]string{"PKCS1": pkcs1, "PKCS8": pkcs8} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseRSAPrivateKey(in)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(key) {
				t.Fatal("parsed key differs")
			}
		})
	}

	t.Run("weak key", func(t *testing.T) {
		weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // exercising the size check.
		if err != nil {
			t.Fatal(err)
		}
		in := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}))
		if _, err := ParseRSAPrivateKey(in); err == nil || !strings.Contains(err.Error(), "2048") {
			t.Fatalf("expected a key size error, got %v", err)
		}
	})

	t.Run("garbage is not echoed", func(t *testing.T) {
		in := "-----BEGIN RSA PRIVATE KEY-----\nTOPSECRETMATERIAL\n-----END RSA PRIVATE KEY-----\n"
		_, err := ParseRSAPrivateKey(in)
		if err == nil || strings.Contains(err.Error(), "TOPSECRETMATERIAL") {
			t.Fatalf("expected a generic error, got %v", err)
		}
	})
}
