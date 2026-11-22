package nine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Headers of 9in's signed requests (adapter protocol v2 and webhooks).
const (
	// SignatureHeader carries t=<unix seconds>,v1=<hex HMAC-SHA256>.
	SignatureHeader = "9in-signature"
	// RequestIDHeader identifies an adapter request; responses are signed over it.
	RequestIDHeader = "9in-request-id"
	// EventIDHeader, EventTypeHeader and DeliveryIDHeader come with webhooks.
	EventIDHeader    = "9in-event-id"
	EventTypeHeader  = "9in-event-type"
	DeliveryIDHeader = "9in-delivery-id"
)

// DefaultTolerance is how far a signature's timestamp may be from now.
const DefaultTolerance = 5 * time.Minute

var (
	signatureTimestamp = regexp.MustCompile(`^\d{1,12}$`)
	signatureValue     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SignPayload signs a request or response the way 9in does, with the current time:
// t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<METHOD>.<path>.<body>")>. It returns the
// 9in-signature header value. Adapter responses are signed over "<path>#<request id>".
func SignPayload(secret, method, path string, body []byte) string {
	return SignPayloadAt(secret, method, path, body, time.Now())
}

// SignPayloadAt is SignPayload with a given time.
func SignPayloadAt(secret, method, path string, body []byte, at time.Time) string {
	t := at.Unix()
	return "t=" + strconv.FormatInt(t, 10) + ",v1=" + signatureMAC(secret, t, method, path, body)
}

func signatureMAC(secret string, t int64, method, path string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t, 10) + "." + strings.ToUpper(method) + "." + path + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// parseSignature parses a 9in-signature header strictly: comma-separated name=value
// parts, t of 1 to 12 digits, v1 of 64 lowercase hex digits (several allowed), other
// names ignored. ok is false for a malformed header.
func parseSignature(header string) (t int64, v1 []string, ok bool) {
	hasT := false
	for _, part := range strings.Split(header, ",") {
		i := strings.IndexByte(part, '=')
		if i < 1 {
			return 0, nil, false
		}
		name := strings.TrimSpace(part[:i])
		value := strings.TrimSpace(part[i+1:])
		switch name {
		case "t":
			if !signatureTimestamp.MatchString(value) {
				return 0, nil, false
			}
			t, _ = strconv.ParseInt(value, 10, 64)
			hasT = true
		case "v1":
			if !signatureValue.MatchString(value) {
				return 0, nil, false
			}
			v1 = append(v1, value)
		}
	}
	if !hasT || len(v1) == 0 {
		return 0, nil, false
	}
	return t, v1, true
}

// checkSignature returns "" when the header is valid for one of the secrets, else the
// reason: missing, malformed, expired or mismatch.
func checkSignature(secrets []string, header, method, path string, body []byte, tolerance time.Duration, now time.Time) string {
	if header == "" {
		return "missing"
	}
	t, signatures, ok := parseSignature(header)
	if !ok {
		return "malformed"
	}
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	age := now.Sub(time.Unix(t, 0))
	if age > tolerance || age < -tolerance {
		return "expired"
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		expected := []byte(signatureMAC(secret, t, method, path, body))
		for _, candidate := range signatures {
			if hmac.Equal(expected, []byte(candidate)) {
				return ""
			}
		}
	}
	return "mismatch"
}

// VerifySignature checks a 9in-signature header against a request's method, path and
// raw body, with any of secrets (several while you rotate) and a timestamp tolerance
// (0 means [DefaultTolerance]). It fails with invalid_signature (Status 401), whose
// Description is the reason: missing, malformed, expired or mismatch.
func VerifySignature(secrets []string, header, method, path string, body []byte, tolerance time.Duration) error {
	if reason := checkSignature(secrets, header, method, path, body, tolerance, time.Now()); reason != "" {
		return newError("invalid_signature", reason, http.StatusUnauthorized)
	}
	return nil
}

// requestPath is the path of r as the client sent it (percent-encoded), which is what
// 9in signs. It is read from the request line, so http.StripPrefix doesn't change it.
func requestPath(r *http.Request) string {
	if r.RequestURI != "" && r.RequestURI != "*" {
		if u, err := url.ParseRequestURI(r.RequestURI); err == nil {
			return u.EscapedPath()
		}
	}
	return r.URL.EscapedPath()
}

func secretList(secret string, secrets []string) []string {
	var out []string
	for _, s := range append([]string{secret}, secrets...) {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
