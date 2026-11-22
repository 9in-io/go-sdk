package nine

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeviceFlow(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	f.device = func(r *http.Request, form url.Values) (int, any) {
		if form.Get("client_id") != "app_tv" {
			return 401, map[string]any{"error": "invalid_client"}
		}
		return 200, map[string]any{
			"device_code": "dev-123", "user_code": "BDWP-HQXZ", "verification_uri": f.issuer + "/device",
			"verification_uri_complete": f.issuer + "/device?user_code=BDWP-HQXZ", "expires_in": 600, "interval": 5,
		}
	}
	var polls atomic.Int32
	answers := []string{"authorization_pending", "slow_down", "authorization_pending", ""}
	f.token = func(r *http.Request, form url.Values) (int, any) {
		if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || form.Get("device_code") != "dev-123" || form.Get("client_id") != "app_tv" {
			return 400, map[string]any{"error": "invalid_request"}
		}
		n := polls.Add(1)
		if a := answers[n-1]; a != "" {
			return 400, map[string]any{"error": a}
		}
		return 200, map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": 3600, "id_token": f.idToken(t, "app_tv", "", nil)}
	}
	d := must[*DeviceAuth](t)(NewDeviceAuth(DeviceAuthConfig{Issuer: f.issuer, ClientID: "app_tv", Audience: "https://api.acme.test"}))
	var mu sync.Mutex
	var slept []time.Duration
	d.sleep = func(_ context.Context, dur time.Duration) error {
		mu.Lock()
		slept = append(slept, dur)
		mu.Unlock()
		return nil
	}
	code, err := d.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if code.UserCode != "BDWP-HQXZ" || code.Interval != 5 || time.Until(code.ExpiresAt) < 9*time.Minute {
		t.Fatalf("code %+v", code)
	}
	form := f.form("/oauth/device/authorize")
	if form.Get("scope") != "openid profile offline_access" || form.Get("audience") != "https://api.acme.test" {
		t.Fatalf("authorize form %v", form)
	}
	tokens, err := d.Wait(ctx, code)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken != "at" || tokens.Claims.Subject() != "usr_1" {
		t.Fatalf("tokens %+v", tokens)
	}
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if len(slept) != len(want) {
		t.Fatalf("slept %v", slept)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("slept %v, want %v (slow_down adds 5 s)", slept, want)
		}
	}
}

func TestDeviceFlowStops(t *testing.T) {
	f := newFakeIssuer(t)
	f.setKeys(asymmetricKeys(t)...)
	answer := "access_denied"
	f.token = func(r *http.Request, form url.Values) (int, any) { return 400, map[string]any{"error": answer} }
	d := must[*DeviceAuth](t)(NewDeviceAuth(DeviceAuthConfig{Issuer: f.issuer, ClientID: "app_tv"}))
	d.sleep = func(context.Context, time.Duration) error { return nil }
	code := &DeviceCode{DeviceCode: "x", Interval: 1, ExpiresAt: time.Now().Add(time.Minute)}
	_, err := d.Wait(ctx, code)
	wantCode(t, err, "access_denied", 400)
	answer = "expired_token"
	_, err = d.Wait(ctx, code)
	wantCode(t, err, "expired_token", 400)
	// Expiry is also noticed locally.
	_, err = d.Wait(ctx, &DeviceCode{DeviceCode: "x", ExpiresAt: time.Now().Add(-time.Second)})
	wantCode(t, err, "expired_token", 400)
	// A cancelled context stops waiting.
	answer = "authorization_pending"
	d.sleep = sleepContext
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := d.Wait(cancelled, code); err != context.Canceled {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	// A bad ID token fails the sign-in.
	f.token = func(r *http.Request, form url.Values) (int, any) {
		return 200, map[string]any{"access_token": "at", "id_token": f.idToken(t, "someone_else", "", nil)}
	}
	_, err = d.Poll(ctx, code)
	wantCode(t, err, "invalid_id_token", 401)
	_, err = d.Poll(ctx, nil)
	wantCode(t, err, "invalid_options", 0)
	// The device grant not enabled for the client.
	f.device = func(*http.Request, url.Values) (int, any) {
		return 400, map[string]any{"error": "unauthorized_client", "error_description": "the device flow is not enabled for this client"}
	}
	_, err = d.Start(ctx)
	wantCode(t, err, "unauthorized_client", 400)
}

func TestClientCredentialsCachesTheToken(t *testing.T) {
	f := newFakeIssuer(t)
	var calls atomic.Int32
	release := make(chan struct{})
	f.token = func(r *http.Request, form url.Values) (int, any) {
		calls.Add(1)
		<-release
		if r.Header.Get("Authorization") != basicAuth("app_svc", "s3cret") || form.Get("grant_type") != "client_credentials" {
			return 401, map[string]any{"error": "invalid_client"}
		}
		return 200, map[string]any{"access_token": "tok-" + form.Get("audience") + "-" + form.Get("scope"), "expires_in": 3600}
	}
	cc := must[*ClientCredentials](t)(NewClientCredentials(ClientCredentialsConfig{Issuer: f.issuer, ClientID: "app_svc", ClientSecret: "s3cret", Audience: "api", Scopes: []string{"a b", "c"}}))
	c := newClock()
	cc.o.verifier.now = c.Now
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, err := cc.Token(ctx); err != nil || tok != "tok-api-a b c" {
				t.Errorf("%v %q", err, tok)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d token requests for 10 concurrent callers", calls.Load())
	}
	c.Advance(59 * time.Minute)
	_, _ = cc.Token(ctx)
	if calls.Load() != 1 {
		t.Fatal("cached until shortly before expiry")
	}
	c.Advance(31 * time.Second)
	_, _ = cc.Token(ctx)
	if calls.Load() != 2 {
		t.Fatal("renewed 30 s before expiry")
	}
	cc.Invalidate()
	_, _ = cc.Token(ctx)
	if calls.Load() != 3 {
		t.Fatal("Invalidate")
	}

	// HTTPClient adds the token to requests.
	var got string
	api := newFakeIssuer(t)
	api.api = func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }
	res, err := cc.HTTPClient(nil).Get(api.URL + "/api/v1/things")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got != "Bearer tok-api-a b c" {
		t.Fatalf("Authorization %q", got)
	}

	wrong := must[*ClientCredentials](t)(NewClientCredentials(ClientCredentialsConfig{Issuer: f.issuer, ClientID: "app_svc", ClientSecret: "nope"}))
	_, err = wrong.Token(ctx)
	wantCode(t, err, "invalid_client", 401)
	_, err = wrong.HTTPClient(nil).Get(api.URL + "/api/v1/things")
	if err == nil {
		t.Fatal("a failed token request fails the call")
	}
}

func TestConfidentialDeviceClientSendsClientIDInTheForm(t *testing.T) {
	f := newFakeIssuer(t)
	f.device = func(r *http.Request, form url.Values) (int, any) {
		// 9in reads client_id from the form even when the client uses HTTP Basic.
		if form.Get("client_id") != "app_tv" || r.Header.Get("Authorization") != basicAuth("app_tv", "s") {
			return 401, map[string]any{"error": "invalid_client"}
		}
		return 200, map[string]any{"device_code": "d", "user_code": "BCDF-GHJK", "verification_uri": f.issuer + "/device"}
	}
	d := must[*DeviceAuth](t)(NewDeviceAuth(DeviceAuthConfig{Issuer: f.issuer, ClientID: "app_tv", ClientSecret: "s"}))
	code, err := d.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if code.Interval != 5 || code.ExpiresIn != 600 {
		t.Fatalf("RFC 8628 defaults: %+v", code)
	}
}
