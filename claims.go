package nine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// Claims are the claims of a verified token (or an introspection answer), as 9in sent
// them: numbers are float64, lists []any, objects map[string]any. The methods read the
// common ones.
type Claims map[string]any

// String returns a string claim, or "".
func (c Claims) String(name string) string {
	s, _ := c[name].(string)
	return s
}

// Bool returns a boolean claim, or false.
func (c Claims) Bool(name string) bool {
	b, _ := c[name].(bool)
	return b
}

// Int returns a numeric claim (exp, iat, auth_time…) and whether it is a number.
func (c Claims) Int(name string) (int64, bool) {
	switch v := c[name].(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			f, ferr := v.Float64()
			if ferr != nil {
				return 0, false
			}
			return int64(f), true
		}
		return n, true
	case int64:
		return v, true
	case int:
		return int64(v), true
	}
	return 0, false
}

// Time returns a claim holding unix seconds (exp, iat, auth_time…) as a time, or the zero time.
func (c Claims) Time(name string) time.Time {
	if n, ok := c.Int(name); ok {
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// Strings returns a claim that is a string or a list of strings (aud, amr).
func (c Claims) Strings(name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Subject is the sub claim: the user's id, or the client ID for a client-credentials token.
func (c Claims) Subject() string { return c.String("sub") }

// Issuer is the iss claim.
func (c Claims) Issuer() string { return c.String("iss") }

// Audience is the aud claim (a single audience is returned as a one-item list).
func (c Claims) Audience() []string { return c.Strings("aud") }

// ClientID is the client_id claim: the application the token was issued to.
func (c Claims) ClientID() string { return c.String("client_id") }

// SessionID is the sid claim (absent for client-credentials tokens).
func (c Claims) SessionID() string { return c.String("sid") }

// TokenID is the jti claim.
func (c Claims) TokenID() string { return c.String("jti") }

// Scopes are the scopes in the space-separated scope claim.
func (c Claims) Scopes() []string { return strings.Fields(c.String("scope")) }

// HasScope reports whether the scope claim contains scope.
func (c Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// ExpiresAt is the exp claim as a time (the zero time when absent).
func (c Claims) ExpiresAt() time.Time { return c.Time("exp") }

// IsMachine reports whether this is a client-credentials token: its subject is the
// application itself (sub equals client_id) and it has no session.
func (c Claims) IsMachine() bool {
	return c.Subject() != "" && c.Subject() == c.ClientID() && c.SessionID() == ""
}

// ---------------------------------------------------------------------------
// JWT decoding

// Longest token accepted, so a junk header can't make us parse megabytes.
const maxTokenLength = 64 << 10

type jwtParts struct {
	header       map[string]any
	payload      Claims
	signingInput string
	signature    []byte
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, errNotObject
	}
	return out, nil
}

var errNotObject = &Error{Code: "invalid_token", Description: "not a JSON object"}

func decodeJWT(token string) (*jwtParts, bool) {
	if len(token) > maxTokenLength {
		return nil, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	headerJSON, err1 := decodeSegment(parts[0])
	payloadJSON, err2 := decodeSegment(parts[1])
	signature, err3 := decodeSegment(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, false
	}
	header, err := decodeJSONObject(headerJSON)
	if err != nil {
		return nil, false
	}
	payload, err := decodeJSONObject(payloadJSON)
	if err != nil {
		return nil, false
	}
	return &jwtParts{header: header, payload: payload, signingInput: parts[0] + "." + parts[1], signature: signature}, true
}

// stripBearer accepts a bare token or an Authorization header value ("Bearer …").
func stripBearer(token string) string {
	token = strings.TrimSpace(token)
	if len(token) >= 6 && strings.EqualFold(token[:6], "bearer") && (len(token) == 6 || token[6] == ' ' || token[6] == '\t') {
		return strings.TrimSpace(token[6:])
	}
	return token
}
