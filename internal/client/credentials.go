package client

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Credentials holds the fields of a HERE credentials.properties file.
type Credentials struct {
	ClientID        string
	AccessKeyID     string
	AccessKeySecret string
	TokenURL        string
}

// ReadCredentialsFile parses a HERE credentials.properties file.
func ReadCredentialsFile(path string) (*Credentials, error) {
	f, err := os.Open(path) //nolint:gosec // the path is operator-supplied configuration.
	if err != nil {
		return nil, fmt.Errorf("opening credentials file: %w", err)
	}
	defer f.Close()
	return ParseCredentials(f)
}

// ParseCredentials reads the "key = value" lines HERE generates. Errors cite line
// numbers only, because lines carry secrets.
func ParseCredentials(r io.Reader) (*Credentials, error) {
	creds := &Credentials{}
	fields := map[string]*string{
		"here.client.id":          &creds.ClientID,
		"here.access.key.id":      &creds.AccessKeyID,
		"here.access.key.secret":  &creds.AccessKeySecret,
		"here.token.endpoint.url": &creds.TokenURL,
	}
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "!") {
			continue
		}
		sep := strings.IndexAny(text, "=:")
		if sep < 0 {
			return nil, fmt.Errorf("credentials file line %d: expected key = value", line)
		}
		key := strings.TrimSpace(text[:sep])
		if dst, ok := fields[key]; ok {
			*dst = strings.TrimSpace(text[sep+1:])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading credentials file: %w", err)
	}
	return creds, nil
}
