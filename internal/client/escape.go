package client

import "strings"

const upperHex = "0123456789ABCDEF"

// PercentEncode applies strict RFC 3986 encoding: HERE requires ':' and '/' in HRN path
// parameters to be encoded, which url.PathEscape leaves alone. OAuth 1.0 (RFC 5849 3.6)
// mandates the same alphabet.
func PercentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 3) //nolint:mnd // worst case: every byte becomes %XX.
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0x0F])
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
}
