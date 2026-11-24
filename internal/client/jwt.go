package client

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// Matches the HERE OAuth 2.1 example; a short window limits replay of a leaked assertion.
	assertionLifetime = 5 * time.Minute
	minRSAKeyBits     = 2048
)

type jwtAuth struct {
	clientID string
	keyID    string
	key      *rsa.PrivateKey
}

// NewJWTAuth authenticates token requests with an RS256 private_key_jwt client assertion.
func NewJWTAuth(clientID, keyID string, key *rsa.PrivateKey) (Auth, error) {
	if clientID == "" {
		return nil, errors.New("client ID is required")
	}
	if key == nil {
		return nil, errors.New("private key is required")
	}
	return &jwtAuth{clientID: clientID, keyID: keyID, key: key}, nil
}

// ParseRSAPrivateKey decodes a PEM-encoded PKCS #1 or PKCS #8 RSA private key. Errors
// never include key material.
func ParseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemData))
	if err != nil {
		return nil, errors.New("expected a PEM-encoded, unencrypted PKCS #1 or PKCS #8 RSA private key")
	}
	if bits := key.N.BitLen(); bits < minRSAKeyBits {
		return nil, fmt.Errorf("RSA key is %d bits; at least %d bits are required", bits, minRSAKeyBits)
	}
	return key, nil
}

func (a *jwtAuth) authenticate(form url.Values, _ http.Header, tokenURL string, now time.Time) error {
	claims := jwt.MapClaims{
		"iss": a.clientID,
		"sub": a.clientID,
		// A plain string, not a one-element array: the audience is the exact token URL.
		"aud": tokenURL,
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
		"jti": rand.Text(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if a.keyID != "" {
		token.Header["kid"] = a.keyID
	}
	signed, err := token.SignedString(a.key)
	if err != nil {
		return errors.New("signing client assertion failed")
	}
	form.Set("client_assertion_type", clientAssertionType)
	form.Set("client_assertion", signed)
	return nil
}

func (*jwtAuth) secrets() []string { return nil }
