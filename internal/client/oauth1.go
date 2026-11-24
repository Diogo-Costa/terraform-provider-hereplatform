package client

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const oauthSignatureMethod = "HMAC-SHA256"

type oauth1Auth struct {
	accessKeyID     string
	accessKeySecret string
	nonce           func() string
}

// NewOAuth1Auth authenticates token requests with an OAuth 1.0 HMAC-SHA256 signature
// (RFC 5849) made with a HERE access key.
func NewOAuth1Auth(accessKeyID, accessKeySecret string) (Auth, error) {
	if accessKeyID == "" || accessKeySecret == "" {
		return nil, errors.New("access key ID and secret are required")
	}
	return &oauth1Auth{accessKeyID: accessKeyID, accessKeySecret: accessKeySecret, nonce: rand.Text}, nil
}

func (a *oauth1Auth) authenticate(form url.Values, header http.Header, tokenURL string, now time.Time) ([]string, error) {
	u, err := url.Parse(tokenURL)
	if err != nil {
		return nil, errors.New("invalid token URL")
	}
	oauth := map[string]string{
		"oauth_consumer_key":     a.accessKeyID,
		"oauth_nonce":            a.nonce(),
		"oauth_signature_method": oauthSignatureMethod,
		"oauth_timestamp":        strconv.FormatInt(now.Unix(), 10),
		"oauth_version":          "1.0",
	}
	params := url.Values{}
	for k, vs := range u.Query() {
		params[k] = append(params[k], vs...)
	}
	for k, vs := range form {
		params[k] = append(params[k], vs...)
	}
	for k, v := range oauth {
		params.Add(k, v)
	}
	base := signatureBaseString(http.MethodPost, u, params)
	signature := hmacSignature(sha256.New, a.accessKeySecret, "", base)
	oauth["oauth_signature"] = signature
	header.Set("Authorization", oauthHeader(oauth))
	return []string{a.accessKeySecret, signature, PercentEncode(signature)}, nil
}

// signatureBaseString implements RFC 5849 3.4.1; params must already merge query, body
// and oauth_* protocol parameters (excluding oauth_signature and realm).
func signatureBaseString(method string, u *url.URL, params url.Values) string {
	type pair struct{ k, v string }
	pairs := make([]pair, 0, len(params))
	for k, vs := range params {
		for _, v := range vs {
			pairs = append(pairs, pair{PercentEncode(k), PercentEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	normalized := make([]string, len(pairs))
	for i, p := range pairs {
		normalized[i] = p.k + "=" + p.v
	}
	return strings.ToUpper(method) + "&" + PercentEncode(baseStringURI(u)) + "&" +
		PercentEncode(strings.Join(normalized, "&"))
}

func baseStringURI(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" && (scheme != schemeHTTP || port != "80") && (scheme != schemeHTTPS || port != "443") {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

func hmacSignature(newHash func() hash.Hash, consumerSecret, tokenSecret, base string) string {
	mac := hmac.New(newHash, []byte(PercentEncode(consumerSecret)+"&"+PercentEncode(tokenSecret)))
	mac.Write([]byte(base))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func oauthHeader(oauth map[string]string) string {
	keys := make([]string, 0, len(oauth))
	for k := range oauth {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = PercentEncode(k) + `="` + PercentEncode(oauth[k]) + `"`
	}
	return "OAuth " + strings.Join(parts, ",")
}
