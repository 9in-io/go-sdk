package nine

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	vectorSecret = "adapter_secret_test"
	vectorBody   = `{"identifier":{"type":"email","value":"jane@acme.com"},"password":"hunter2"}`
)

// The reference vectors of sso-sdk/php/tests/SignatureTest.php, computed with the 9in
// server's scheme. Every 9in SDK must produce exactly these.
func TestSignatureMatchesTheReferenceVectors(t *testing.T) {
	at := time.Unix(1762682400, 0)
	if got := SignPayloadAt(vectorSecret, "post", "/nine/authenticate", []byte(vectorBody), at); got != "t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c" {
		t.Fatalf("vector 1: %s", got)
	}
	if got := SignPayloadAt(vectorSecret, "POST", "/nine/authenticate#req_123", []byte(`{"user":{"id":"42"}}`), at); got != "t=1762682400,v1=1b9fb41e87bb256836ea5d5d6600270b77578ffd166d84a2cf35ab9841b3585a" {
		t.Fatalf("vector 2: %s", got)
	}
	// And they verify, at that time.
	if r := checkSignature([]string{vectorSecret}, "t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c", "POST", "/nine/authenticate", []byte(vectorBody), 0, at); r != "" {
		t.Fatalf("vector 1 did not verify: %s", r)
	}
}

// RFC 7636 Appendix B.
func TestCodeChallengeMatchesRFC7636(t *testing.T) {
	if got := CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	header := SignPayload(vectorSecret, "POST", "/nine/user", []byte(`{"id":"1"}`))
	if err := VerifySignature([]string{vectorSecret}, header, "POST", "/nine/user", []byte(`{"id":"1"}`), 0); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureRejectsTamperedBodyPathMethodAndSecret(t *testing.T) {
	header := SignPayload(vectorSecret, "POST", "/nine/user", []byte(`{"id":"1"}`))
	cases := map[string]func() string{
		"body": func() string {
			return checkSignature([]string{vectorSecret}, header, "POST", "/nine/user", []byte(`{"id":"2"}`), 0, time.Now())
		},
		"path": func() string {
			return checkSignature([]string{vectorSecret}, header, "POST", "/nine/authenticate", []byte(`{"id":"1"}`), 0, time.Now())
		},
		"method": func() string {
			return checkSignature([]string{vectorSecret}, header, "GET", "/nine/user", []byte(`{"id":"1"}`), 0, time.Now())
		},
		"secret": func() string {
			return checkSignature([]string{"other"}, header, "POST", "/nine/user", []byte(`{"id":"1"}`), 0, time.Now())
		},
	}
	for name, check := range cases {
		if got := check(); got != "mismatch" {
			t.Errorf("%s: want mismatch, got %q", name, got)
		}
	}
	err := VerifySignature([]string{"other"}, header, "POST", "/nine/user", []byte(`{"id":"1"}`), 0)
	if e := wantCode(t, err, "invalid_signature", 401); e.Description != "mismatch" {
		t.Fatalf("description %q", e.Description)
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatal("errors.Is(ErrInvalidSignature) is false")
	}
}

func TestSignatureRejectsReplaysOutsideTheTolerance(t *testing.T) {
	now := time.Now()
	old := SignPayloadAt(vectorSecret, "POST", "/p", []byte("b"), now.Add(-301*time.Second))
	if got := checkSignature([]string{vectorSecret}, old, "POST", "/p", []byte("b"), 0, now); got != "expired" {
		t.Fatalf("old: %q", got)
	}
	if got := checkSignature([]string{vectorSecret}, old, "POST", "/p", []byte("b"), 600*time.Second, now); got != "" {
		t.Fatalf("old with a 600 s tolerance: %q", got)
	}
	future := SignPayloadAt(vectorSecret, "POST", "/p", []byte("b"), now.Add(301*time.Second))
	if got := checkSignature([]string{vectorSecret}, future, "POST", "/p", []byte("b"), 0, now); got != "expired" {
		t.Fatalf("future: %q", got)
	}
	edge := SignPayloadAt(vectorSecret, "POST", "/p", []byte("b"), now.Add(-299*time.Second))
	if got := checkSignature([]string{vectorSecret}, edge, "POST", "/p", []byte("b"), 0, now); got != "" {
		t.Fatalf("within the tolerance: %q", got)
	}
}

func TestSignatureMissingAndMalformedHeaders(t *testing.T) {
	if got := checkSignature([]string{vectorSecret}, "", "POST", "/p", []byte("b"), 0, time.Now()); got != "missing" {
		t.Fatalf("empty: %q", got)
	}
	hex := strings.Repeat("a", 64)
	for _, bad := range []string{"garbage", "t=abc,v1=" + hex, "t=1", "v1=" + hex, "t=1,v1=ABC", "=x", "t=1,v1=" + strings.Repeat("A", 64), "t=1234567890123,v1=" + hex, "t=1,v1=" + hex + ",", "t=-1,v1=" + hex} {
		if got := checkSignature([]string{vectorSecret}, bad, "POST", "/p", []byte("b"), 0, time.Now()); got != "malformed" {
			t.Errorf("%q: want malformed, got %q", bad, got)
		}
	}
	// Unknown parts are ignored, spaces around parts are fine.
	now := time.Now()
	header := SignPayloadAt(vectorSecret, "POST", "/p", []byte("b"), now)
	if got := checkSignature([]string{vectorSecret}, "v0=x, "+strings.ReplaceAll(header, ",", " , "), "POST", "/p", []byte("b"), 0, now); got != "" {
		t.Fatalf("unknown part: %q", got)
	}
}

func TestSignatureSecretRotationAndMultipleSignatures(t *testing.T) {
	now := time.Now()
	header := SignPayloadAt("new-secret", "POST", "/p", []byte("b"), now)
	if got := checkSignature([]string{"old-secret", "new-secret"}, header, "POST", "/p", []byte("b"), 0, now); got != "" {
		t.Fatalf("rotation: %q", got)
	}
	old := SignPayloadAt("old-secret", "POST", "/p", []byte("b"), now)
	combined := old + "," + strings.Split(SignPayloadAt("new-secret", "POST", "/p", []byte("b"), now), ",")[1]
	if got := checkSignature([]string{"new-secret"}, combined, "POST", "/p", []byte("b"), 0, now); got != "" {
		t.Fatalf("several v1: %q", got)
	}
	// Empty secrets never match (an unset variable must not verify an empty-key HMAC).
	empty := SignPayloadAt("", "POST", "/p", []byte("b"), now)
	if got := checkSignature([]string{""}, empty, "POST", "/p", []byte("b"), 0, now); got != "mismatch" {
		t.Fatalf("empty secret: %q", got)
	}
}

func TestSignPayloadFormat(t *testing.T) {
	header := SignPayload("s", "post", "/x", nil)
	parts := strings.Split(header, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || len(parts[1]) != 3+64 {
		t.Fatalf("header %q", header)
	}
	ts, _ := strconv.ParseInt(parts[0][2:], 10, 64)
	if d := time.Since(time.Unix(ts, 0)); d < 0 || d > 5*time.Second {
		t.Fatalf("timestamp %d", ts)
	}
}
