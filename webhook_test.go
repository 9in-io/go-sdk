package nine

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const webhookSecret = "whsec_test_secret"

func webhookBody(id, typ string) []byte {
	return []byte(`{"id":"` + id + `","event_type":"` + typ + `","created_at":"2026-11-10T09:30:00.000Z","tenant":"tnt_1","environment":"sandbox","data":{"user":{"id":"usr_1","email":"jane@acme.test"},"token_type":"access_token","jti":"jti_1"}}`)
}

func signedWebhook(path string, body []byte, secret string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.Header.Set(SignatureHeader, SignPayload(secret, "POST", path, body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestVerifyWebhook(t *testing.T) {
	body := webhookBody("evt_1", "user.created")
	header := SignPayload(webhookSecret, "POST", "/nine/webhook", body)
	event, err := VerifyWebhook([]string{webhookSecret}, body, header, "/nine/webhook")
	if err != nil {
		t.Fatal(err)
	}
	if event.ID != "evt_1" || event.EventType != "user.created" || event.Tenant != "tnt_1" || event.Environment != "sandbox" || event.UserID() != "usr_1" || event.CreatedAt.IsZero() {
		t.Fatalf("event %+v", event)
	}
	// Rotation.
	if _, err := VerifyWebhook([]string{"whsec_old", webhookSecret}, body, header, "/nine/webhook"); err != nil {
		t.Fatal(err)
	}
	refusals := map[string]func() error{
		"wrong secret": func() error {
			_, err := VerifyWebhook([]string{"whsec_wrong"}, body, header, "/nine/webhook")
			return err
		},
		"altered body": func() error {
			_, err := VerifyWebhook([]string{webhookSecret}, bytes.Replace(body, []byte("user.created"), []byte("user.deleted"), 1), header, "/nine/webhook")
			return err
		},
		"other path":   func() error { _, err := VerifyWebhook([]string{webhookSecret}, body, header, "/elsewhere"); return err },
		"no signature": func() error { _, err := VerifyWebhook([]string{webhookSecret}, body, "", "/nine/webhook"); return err },
		"no secret":    func() error { _, err := VerifyWebhook(nil, body, header, "/nine/webhook"); return err },
	}
	for name, verify := range refusals {
		err := verify()
		wantCode(t, err, "invalid_signature", 401)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("%s: errors.Is", name)
		}
	}
	// Too old: refused once the tolerance has passed.
	old := SignPayloadAt(webhookSecret, "POST", "/nine/webhook", body, time.Now().Add(-6*time.Minute))
	_, err = VerifyWebhook([]string{webhookSecret}, body, old, "/nine/webhook")
	wantCode(t, err, "invalid_signature", 401)
	wantDescription(t, err, "expired")
	// Signed, but not an event.
	for _, junk := range []string{"not json", `{"id":"evt"}`, `{"event_type":"user.created"}`, `[]`, `null`, `{"id":"e","event_type":"x","created_at":"yesterday"}`} {
		_, err := VerifyWebhook([]string{webhookSecret}, []byte(junk), SignPayload(webhookSecret, "POST", "/p", []byte(junk)), "/p")
		wantCode(t, err, "invalid_payload", 400)
	}
}

func TestVerifyWebhookRequest(t *testing.T) {
	body := webhookBody("evt_2", "user.login")
	r := signedWebhook("/nine/webhook?x=1", body, webhookSecret)
	if _, err := VerifyWebhookRequest(r, webhookSecret); err == nil {
		// the query is not part of the signed path, so signing over "/nine/webhook?x=1" fails…
		t.Fatal("signed over the query")
	}
	r = httptest.NewRequest(http.MethodPost, "/nine/webhook?x=1", bytes.NewReader(body))
	r.Header.Set(SignatureHeader, SignPayload(webhookSecret, "POST", "/nine/webhook", body))
	event, err := VerifyWebhookRequest(r, webhookSecret)
	if err != nil || event.ID != "evt_2" {
		t.Fatalf("%v %v", err, event)
	}
	// Behind http.StripPrefix the signed path is still the one sent.
	r = signedWebhook("/hooks/nine/webhook", body, webhookSecret)
	var got error
	http.StripPrefix("/hooks", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, got = VerifyWebhookRequest(r, webhookSecret)
	})).ServeHTTP(httptest.NewRecorder(), r)
	if got != nil {
		t.Fatalf("StripPrefix: %v", got)
	}
	r = signedWebhook("/nine/webhook", body, webhookSecret)
	r.Method = http.MethodPut
	_, err = VerifyWebhookRequest(r, webhookSecret)
	wantCode(t, err, "invalid_signature", 401)
	big := httptest.NewRequest(http.MethodPost, "/nine/webhook", bytes.NewReader(make([]byte, maxRequestBody+1)))
	_, err = VerifyWebhookRequest(big, webhookSecret)
	wantCode(t, err, "invalid_payload", 413)
}

func TestWebhookHandler(t *testing.T) {
	var handled atomic.Int32
	fail := atomic.Bool{}
	var seen sync.Map
	h := WebhookHandler(WebhookConfig{
		Secret: webhookSecret,
		Handle: func(ctx context.Context, e *WebhookEvent) error {
			handled.Add(1)
			seen.Store(e.ID, e.EventType)
			if fail.Load() {
				return errors.New("database down")
			}
			return nil
		},
	})
	serve := func(r *http.Request) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	body := webhookBody("evt_3", "user.created")
	if code := serve(signedWebhook("/nine/webhook", body, webhookSecret)); code != 204 {
		t.Fatalf("first delivery: %d", code)
	}
	if code := serve(signedWebhook("/nine/webhook", body, webhookSecret)); code != 204 {
		t.Fatalf("retry: %d", code)
	}
	if handled.Load() != 1 {
		t.Fatalf("handled %d times", handled.Load())
	}
	if code := serve(signedWebhook("/nine/webhook", body, "whsec_wrong")); code != 401 {
		t.Fatalf("bad signature: %d", code)
	}
	get := httptest.NewRequest(http.MethodGet, "/nine/webhook", nil)
	if code := serve(get); code != 405 {
		t.Fatalf("GET: %d", code)
	}
	junk := []byte("{}")
	if code := serve(signedWebhook("/nine/webhook", junk, webhookSecret)); code != 400 {
		t.Fatalf("not an event: %d", code)
	}
	// A failing handler: 500, and the retry runs it again.
	fail.Store(true)
	body4 := webhookBody("evt_4", "user.updated")
	if code := serve(signedWebhook("/nine/webhook", body4, webhookSecret)); code != 500 {
		t.Fatalf("failing handler: %d", code)
	}
	fail.Store(false)
	if code := serve(signedWebhook("/nine/webhook", body4, webhookSecret)); code != 204 {
		t.Fatalf("retry after failure: %d", code)
	}
	if handled.Load() != 3 {
		t.Fatalf("handled %d", handled.Load())
	}
}

func TestWebhookHandlerConcurrentDeliveryIsInProgress(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	h := WebhookHandler(WebhookConfig{
		Secret: webhookSecret,
		Handle: func(ctx context.Context, e *WebhookEvent) error {
			close(started)
			<-release
			return nil
		},
	})
	body := webhookBody("evt_5", "user.created")
	first := make(chan int)
	go func() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, signedWebhook("/nine/webhook", body, webhookSecret))
		first <- w.Code
	}()
	<-started
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedWebhook("/nine/webhook", body, webhookSecret))
	if w.Code != 409 {
		t.Fatalf("concurrent duplicate: %d", w.Code)
	}
	close(release)
	if code := <-first; code != 204 {
		t.Fatalf("first: %d", code)
	}
}

func TestWebhookHandlerEvictsTheVerifierAndHonoursOptions(t *testing.T) {
	v, f, active, _ := hybridSetup(t, ModeHybrid)
	token := makeToken(t, "ES256", nil, claimsFor(f.issuer, nil))
	active.Store(token, activeClaims(f.issuer, nil))
	if _, err := v.Verify(ctx, token); err != nil {
		t.Fatal(err)
	}
	var errs []error
	h := WebhookHandler(WebhookConfig{Secret: "new", Secrets: []string{webhookSecret}, Verifier: v, Path: "/public/nine/webhook", OnError: func(r *http.Request, err error) { errs = append(errs, err) }})
	body := webhookBody("evt_6", "token.revoked")
	// Signed for the public path; a proxy rewrote it to /internal.
	r := httptest.NewRequest(http.MethodPost, "/internal", bytes.NewReader(body))
	r.Header.Set(SignatureHeader, SignPayload(webhookSecret, "POST", "/public/nine/webhook", body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	active.Delete(token)
	_, err := v.Verify(ctx, token)
	wantCode(t, err, "invalid_token", 401)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a handler without a secret must panic at startup")
		}
	}()
	WebhookHandler(WebhookConfig{})
}

// A store whose writes fail.
type brokenStore struct{ MemoryEventStore }

func (b *brokenStore) Add(context.Context, string, string, time.Duration) (bool, error) {
	return false, errors.New("redis down")
}

func TestWebhookHandlerStoreFailure(t *testing.T) {
	var reported error
	h := WebhookHandler(WebhookConfig{Secret: webhookSecret, Store: &brokenStore{}, OnError: func(r *http.Request, err error) { reported = err }})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedWebhook("/nine/webhook", webhookBody("evt_7", "user.created"), webhookSecret))
	if w.Code != 500 || reported == nil || !strings.Contains(reported.Error(), "redis down") {
		t.Fatalf("%d %v", w.Code, reported)
	}
}
