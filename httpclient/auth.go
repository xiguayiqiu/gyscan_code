package httpclient

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type AuthType int

const (
	AuthBasic AuthType = iota
	AuthDigest
	AuthBearer
	AuthToken
)

type Auth struct {
	Type     AuthType
	Username string
	Password string
	Token    string
	Scheme   string
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func applyDigestAuth(req *http.Request, resp *http.Response, username, password string) error {
	authHeader := resp.Header.Get("WWW-Authenticate")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Digest ") {
		return fmt.Errorf("httpclient: no digest challenge")
	}

	params := parseDigestParams(authHeader[7:])

	realm := params["realm"]
	nonce := params["nonce"]
	qop := params["qop"]
	opaque := params["opaque"]
	algorithm := params["algorithm"]
	if algorithm == "" {
		algorithm = "MD5"
	}

	uri := req.URL.RequestURI()

	cnonce := generateCnonce()
	nc := "00000001"

	ha1 := md5Hash(fmt.Sprintf("%s:%s:%s", username, realm, password))
	if strings.ToUpper(algorithm) == "MD5-SESS" {
		ha1 = md5Hash(fmt.Sprintf("%s:%s:%s", ha1, nonce, cnonce))
	}

	ha2 := md5Hash(fmt.Sprintf("%s:%s", req.Method, uri))

	var response string
	if qop == "auth" || qop == "auth-int" {
		response = md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2))
	} else {
		response = md5Hash(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}

	authVal := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		username, realm, nonce, uri, response)

	if qop != "" {
		authVal += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nc, cnonce)
	}
	if opaque != "" {
		authVal += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	if algorithm != "" {
		authVal += fmt.Sprintf(`, algorithm=%s`, algorithm)
	}

	req.Header.Set("Authorization", authVal)
	return nil
}

func parseDigestParams(s string) map[string]string {
	params := make(map[string]string)
	currentKey := ""
	currentValue := ""
	inQuote := false
	escapeNext := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escapeNext {
			if inQuote {
				currentValue += string(c)
			}
			escapeNext = false
			continue
		}
		if c == '\\' {
			escapeNext = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == '=' {
			currentKey = strings.TrimSpace(currentValue)
			currentValue = ""
			continue
		}
		if !inQuote && c == ',' {
			if currentKey != "" {
				params[currentKey] = strings.TrimSpace(currentValue)
			}
			currentKey = ""
			currentValue = ""
			continue
		}
		if !inQuote && c == ' ' && currentKey == "" {
			continue
		}
		currentValue += string(c)
	}

	if currentKey != "" {
		params[currentKey] = strings.TrimSpace(currentValue)
	}

	return params
}

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func generateCnonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return fmt.Sprintf("%x", b)
}