package nine

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestNormalizeIssuer(t *testing.T) {
	t.Setenv("NINE_ALLOW_INSECURE_ISSUER", "")
	if got := must[string](t)(NormalizeIssuer("https://acme.9in.io/", false)); got != "https://acme.9in.io" {
		t.Fatalf("trailing slash: %s", got)
	}
	for _, local := range []string{"http://localhost:8787", "http://acme.localhost:8787", "http://127.0.0.1:8897", "http://[::1]:8897", "http://127.1.2.3"} {
		if got, err := NormalizeIssuer(local, false); err != nil || got != local {
			t.Errorf("%s: %v %s", local, err, got)
		}
	}
	for _, insecure := range []string{"http://acme.9in.io", "http://login.acme.com", "http://localhost.evil.com", "http://127.0.0.1.evil.com", "ftp://acme.9in.io"} {
		_, err := NormalizeIssuer(insecure, false)
		wantCode(t, err, "insecure_issuer", 0)
		if !errors.Is(err, ErrInsecureIssuer) {
			t.Errorf("%s: errors.Is(ErrInsecureIssuer) false", insecure)
		}
	}
	for _, invalid := range []string{"acme.9in.io", "https://acme.9in.io/?x=1", "https://acme.9in.io/#f", "https://acme.9in.io?", "https://user:pw@acme.9in.io", "", "https://", "mailto:x@y"} {
		_, err := NormalizeIssuer(invalid, false)
		wantCode(t, err, "invalid_issuer", 0)
	}
	if got := must[string](t)(NormalizeIssuer("http://auth:8897", true)); got != "http://auth:8897" {
		t.Fatalf("allowed: %s", got)
	}
}

func TestNormalizeIssuerHonoursTheEnvironment(t *testing.T) {
	t.Setenv("NINE_ALLOW_INSECURE_ISSUER", "true")
	if got := must[string](t)(NormalizeIssuer("http://auth:8897", false)); got != "http://auth:8897" {
		t.Fatalf("env: %s", got)
	}
	t.Setenv("NINE_ALLOW_INSECURE_ISSUER", "no")
	_, err := NormalizeIssuer("http://auth:8897", false)
	wantCode(t, err, "insecure_issuer", 0)
}

func TestEveryConstructorRejectsAnInsecureIssuer(t *testing.T) {
	t.Setenv("NINE_ALLOW_INSECURE_ISSUER", "")
	const issuer = "http://acme.9in.io"
	_, err := NewVerifier(VerifierConfig{Issuer: issuer})
	wantCode(t, err, "insecure_issuer", 0)
	_, err = NewWebAppAuth(WebAppAuthConfig{Issuer: issuer, ClientID: "a"})
	wantCode(t, err, "insecure_issuer", 0)
	_, err = NewManagementClient(ManagementConfig{Issuer: issuer, ClientID: "a", ClientSecret: "s"})
	wantCode(t, err, "insecure_issuer", 0)
	_, err = NewDeviceAuth(DeviceAuthConfig{Issuer: issuer, ClientID: "a"})
	wantCode(t, err, "insecure_issuer", 0)
	_, err = NewClientCredentials(ClientCredentialsConfig{Issuer: issuer, ClientID: "a", ClientSecret: "s"})
	wantCode(t, err, "insecure_issuer", 0)
	_, err = NewWebApp(WebAppConfig{Issuer: issuer, ClientID: "a", Secret: "0123456789abcdef0123456789abcdef"})
	wantCode(t, err, "insecure_issuer", 0)

	v := must[*Verifier](t)(NewVerifier(VerifierConfig{Issuer: "http://auth.internal/", AllowInsecureIssuer: true}))
	if v.Issuer() != "http://auth.internal" {
		t.Fatalf("issuer %s", v.Issuer())
	}
}

func TestConstructorsRequireTheirSettings(t *testing.T) {
	_, err := NewVerifier(VerifierConfig{})
	wantCode(t, err, "invalid_options", 0)
	_, err = NewWebAppAuth(WebAppAuthConfig{Issuer: "https://a.9in.io"})
	wantCode(t, err, "invalid_options", 0)
	_, err = NewManagementClient(ManagementConfig{Issuer: "https://a.9in.io", ClientID: "a"})
	wantCode(t, err, "invalid_options", 0)
	_, err = NewClientCredentials(ClientCredentialsConfig{Issuer: "https://a.9in.io", ClientID: "a"})
	wantCode(t, err, "invalid_options", 0)
	_, err = NewDeviceAuth(DeviceAuthConfig{Issuer: "https://a.9in.io"})
	wantCode(t, err, "invalid_options", 0)
	_, err = NewVerifier(VerifierConfig{Issuer: "https://a.9in.io", Mode: "fast"})
	wantCode(t, err, "invalid_options", 0)
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatal("errors.Is(ErrInvalidOptions)")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NINE_ISSUER", "https://acme.9in.io")
	t.Setenv("NINE_CLIENT_ID", "app_1")
	t.Setenv("NINE_CLIENT_SECRET", "secret")
	t.Setenv("NINE_REDIRECT_URI", "https://app.acme.test/nine/callback")
	t.Setenv("NINE_AUDIENCE", "https://api.acme.test")
	t.Setenv("NINE_API_SECRET", "hmac")
	t.Setenv("NINE_SECRET", " new-secret , old-secret ")
	t.Setenv("NINE_BASE_URL", "https://app.acme.test")
	t.Setenv("NINE_ALLOW_INSECURE_ISSUER", "1")

	if Env("ISSUER") != "https://acme.9in.io" || Env("NINE_ISSUER") != "https://acme.9in.io" {
		t.Fatal("Env")
	}
	v := VerifierConfigFromEnv()
	if v.Issuer != "https://acme.9in.io" || v.Audience != "https://api.acme.test" || v.ClientID != "app_1" || v.ClientSecret != "secret" || v.Secret != "hmac" || !v.AllowInsecureIssuer {
		t.Fatalf("verifier %+v", v)
	}
	w := WebAppAuthConfigFromEnv()
	if w.RedirectURI != "https://app.acme.test/nine/callback" || w.ClientSecret != "secret" {
		t.Fatalf("web app auth %+v", w)
	}
	app := WebAppConfigFromEnv()
	if app.Secret != "new-secret" || len(app.Secrets) != 1 || app.Secrets[0] != "old-secret" || app.BaseURL != "https://app.acme.test" {
		t.Fatalf("web app %+v", app)
	}
	m := ManagementConfigFromEnv()
	if m.ClientID != "app_1" || m.ClientSecret != "secret" {
		t.Fatalf("management %+v", m)
	}
	c := ClientCredentialsConfigFromEnv()
	if c.Audience != "https://api.acme.test" {
		t.Fatalf("client credentials %+v", c)
	}
}

func TestHTTPClientNeverFollowsRedirectsAndHasATimeout(t *testing.T) {
	c := newHTTPClient(nil)
	if c.Timeout != 10*time.Second || c.CheckRedirect == nil {
		t.Fatalf("defaults: %+v", c)
	}
	mine := &http.Client{Timeout: 3 * time.Second}
	c = newHTTPClient(mine)
	if c.Timeout != 3*time.Second || mine.CheckRedirect != nil {
		t.Fatal("the caller's client must be copied, not changed")
	}
}

func TestEncodeURIComponent(t *testing.T) {
	if got := encodeURIComponent("a b+c:d/é~*'()!-_."); got != "a%20b%2Bc%3Ad%2F%C3%A9~*'()!-_." {
		t.Fatalf("got %s", got)
	}
	if got := basicAuth("app:1", "p@ss word"); got != "Basic YXBwJTNBMTpwJTQwc3MlMjB3b3Jk" {
		t.Fatalf("basic %s", got)
	}
}
