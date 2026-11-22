package nine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const adapterSecret = "adapter_secret_test"

type testAdapter struct {
	events []*AdapterEvent
	fail   error
}

func (a *testAdapter) Authenticate(_ context.Context, id Identifier, password string) (*AdapterUser, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	switch strings.ToLower(id.Value) {
	case "jane@acme.test":
		if password == "hunter2" {
			return &AdapterUser{ID: "42", Email: "jane@acme.test", EmailVerified: true, Name: "Jane", Metadata: map[string]any{"plan": "pro"}}, nil
		}
		return nil, ErrInvalidCredentials
	case "bob@acme.test":
		return nil, ErrUserBlocked
	case "carol@acme.test":
		return &AdapterUser{ID: "43", Blocked: true}, nil
	case "noid@acme.test":
		return &AdapterUser{}, nil
	}
	return nil, nil
}

func (a *testAdapter) FindUser(_ context.Context, q UserQuery) (*AdapterUser, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	if q.ID == "42" || (q.Identifier != nil && q.Identifier.Type == "phone" && q.Identifier.Value == "+447700900123") {
		return &AdapterUser{ID: "42", PhoneNumber: "+447700900123"}, nil
	}
	if q.ID == "gone" {
		return nil, ErrNotFound
	}
	return nil, nil
}

func (a *testAdapter) OnEvent(_ context.Context, e *AdapterEvent) error {
	if a.fail != nil {
		return a.fail
	}
	a.events = append(a.events, e)
	return nil
}

type adapterReply struct {
	status    int
	body      map[string]any
	raw       string
	signature string
}

func callAdapter(t *testing.T, h http.Handler, method, path, body, secret, requestID string) adapterReply {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set(SignatureHeader, SignPayload(secret, "POST", path, []byte(body)))
	r.Header.Set(RequestIDHeader, requestID)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	reply := adapterReply{status: w.Code, raw: w.Body.String(), signature: w.Header().Get(SignatureHeader)}
	_ = json.Unmarshal(w.Body.Bytes(), &reply.body)
	return reply
}

// signedFor checks a reply is signed over "<path>#<request id>".
func (r adapterReply) signedFor(path, requestID string, secrets ...string) bool {
	return VerifySignature(secrets, r.signature, "POST", path+"#"+requestID, []byte(r.raw), 0) == nil
}

func TestAdapterHandlerRoutesAndStatusCodes(t *testing.T) {
	adapter := &testAdapter{}
	h := AdapterHandler(AdapterConfig{Adapter: adapter, Secret: adapterSecret})
	const base = "/nine"
	cases := []struct {
		name, route, body string
		status            int
		errorCode         string
	}{
		{"authenticated", "/authenticate", `{"identifier":{"type":"email","value":"Jane@Acme.test"},"password":"hunter2"}`, 200, ""},
		{"wrong password", "/authenticate", `{"identifier":{"type":"email","value":"jane@acme.test"},"password":"nope"}`, 401, "invalid_credentials"},
		{"unknown user", "/authenticate", `{"identifier":{"type":"username","value":"who"},"password":"x"}`, 401, "invalid_credentials"},
		{"blocked (error)", "/authenticate", `{"identifier":{"type":"email","value":"bob@acme.test"},"password":"x"}`, 403, "blocked"},
		{"blocked (user)", "/authenticate", `{"identifier":{"type":"email","value":"carol@acme.test"},"password":"x"}`, 403, "blocked"},
		{"no identifier", "/authenticate", `{"password":"x"}`, 400, "invalid_request"},
		{"bad identifier type", "/authenticate", `{"identifier":{"type":"sms","value":"x"},"password":"x"}`, 400, "invalid_request"},
		{"empty identifier", "/authenticate", `{"identifier":{"type":"email","value":""},"password":"x"}`, 400, "invalid_request"},
		{"no password", "/authenticate", `{"identifier":{"type":"email","value":"jane@acme.test"}}`, 400, "invalid_request"},
		{"password not a string", "/authenticate", `{"identifier":{"type":"email","value":"jane@acme.test"},"password":1}`, 400, "invalid_request"},
		{"empty body", "/authenticate", ``, 400, "invalid_request"},
		{"by id", "/user", `{"id":"42"}`, 200, ""},
		{"by numeric id", "/user", `{"id":42}`, 200, ""},
		{"by identifier", "/user", `{"identifier":{"type":"phone","value":"+447700900123"}}`, 200, ""},
		{"unknown", "/user", `{"id":"7"}`, 404, "not_found"},
		{"not found error", "/user", `{"id":"gone"}`, 404, "not_found"},
		{"neither", "/user", `{}`, 400, "invalid_request"},
		{"event", "/event", `{"id":"evt_1","event_type":"otp.requested","created_at":"2026-11-10T09:30:00.000Z","data":{"user_id":"42","channel":"email","to":"jane@acme.test","code":"123456"}}`, 204, ""},
		{"event without data", "/event", `{"id":"evt_2","event_type":"user.updated"}`, 204, ""},
		{"event without type", "/event", `{"id":"evt_3"}`, 400, "invalid_request"},
		{"not JSON", "/user", `{"id":`, 400, "invalid_json"},
		{"a JSON array", "/user", `[1]`, 400, "invalid_json"},
		{"other route", "/delete", `{}`, 404, "not_found"},
	}
	for _, c := range cases {
		reply := callAdapter(t, h, "POST", base+c.route, c.body, adapterSecret, "req_"+c.name)
		if reply.status != c.status {
			t.Errorf("%s: status %d, want %d (%s)", c.name, reply.status, c.status, reply.raw)
			continue
		}
		if c.errorCode != "" && reply.body["error"] != c.errorCode {
			t.Errorf("%s: error %v, want %s", c.name, reply.body["error"], c.errorCode)
		}
		if !reply.signedFor(base+c.route, "req_"+c.name, adapterSecret) {
			t.Errorf("%s: the reply is not signed over path#request-id", c.name)
		}
		if reply.signedFor(base+c.route, "req_other", adapterSecret) {
			t.Errorf("%s: the signature must be bound to the request id", c.name)
		}
	}
	ok := callAdapter(t, h, "POST", "/nine/authenticate", `{"identifier":{"type":"email","value":"jane@acme.test"},"password":"hunter2"}`, adapterSecret, "r1")
	user := ok.body["user"].(map[string]any)
	if user["id"] != "42" || user["email_verified"] != true || user["metadata"].(map[string]any)["plan"] != "pro" {
		t.Fatalf("user %v", user)
	}
	if _, has := user["phone_number"]; has {
		t.Fatal("empty fields are left out")
	}
	if len(adapter.events) != 2 || adapter.events[0].EventType != "otp.requested" || adapter.events[0].UserID() != "42" || adapter.events[0].Data["code"] != "123456" || adapter.events[1].Data == nil {
		t.Fatalf("events %+v", adapter.events)
	}
	// 204 has no body and no content type.
	r := callAdapter(t, h, "POST", "/nine/event", `{"id":"e","event_type":"x"}`, adapterSecret, "r2")
	if r.raw != "" {
		t.Fatalf("204 body %q", r.raw)
	}
}

func TestAdapterHandlerRefusesUnsignedAndOtherRequests(t *testing.T) {
	h := AdapterHandler(AdapterConfig{Adapter: &testAdapter{}, Secret: adapterSecret})
	body := `{"identifier":{"type":"email","value":"jane@acme.test"},"password":"hunter2"}`
	for name, reply := range map[string]adapterReply{
		"wrong secret": callAdapter(t, h, "POST", "/nine/authenticate", body, "other", "r"),
	} {
		if reply.status != 401 || reply.body["error"] != "invalid_signature" || reply.signature != "" {
			t.Fatalf("%s: %+v", name, reply)
		}
	}
	// Signed for another path.
	r := httptest.NewRequest("POST", "/elsewhere/authenticate", strings.NewReader(body))
	r.Header.Set(SignatureHeader, SignPayload(adapterSecret, "POST", "/nine/authenticate", []byte(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("other path: %d", w.Code)
	}
	// Altered body.
	r = httptest.NewRequest("POST", "/nine/authenticate", strings.NewReader(strings.Replace(body, "jane", "bob", 1)))
	r.Header.Set(SignatureHeader, SignPayload(adapterSecret, "POST", "/nine/authenticate", []byte(body)))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("altered body: %d", w.Code)
	}
	// No signature, an old one.
	r = httptest.NewRequest("POST", "/nine/authenticate", strings.NewReader(body))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unsigned: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/nine/authenticate", strings.NewReader(body))
	r.Header.Set(SignatureHeader, SignPayloadAt(adapterSecret, "POST", "/nine/authenticate", []byte(body), time.Now().Add(-10*time.Minute)))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("old: %d", w.Code)
	}
	// GET.
	r = httptest.NewRequest("GET", "/nine/authenticate", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 405 || w.Header().Get("Allow") != "POST" {
		t.Fatalf("GET: %d", w.Code)
	}
	// Too large.
	r = httptest.NewRequest("POST", "/nine/user", bytes.NewReader(make([]byte, maxRequestBody+1)))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("too large: %d", w.Code)
	}
}

func TestAdapterHandlerRotationAndStripPrefix(t *testing.T) {
	h := AdapterHandler(AdapterConfig{Adapter: &testAdapter{}, Secret: "new-secret", Secrets: []string{adapterSecret}})
	reply := callAdapter(t, h, "POST", "/nine/user", `{"id":"42"}`, adapterSecret, "r1")
	if reply.status != 200 {
		t.Fatalf("old secret: %d", reply.status)
	}
	if !reply.signedFor("/nine/user", "r1", "new-secret") || reply.signedFor("/nine/user", "r1", adapterSecret) {
		t.Fatal("replies are signed with the first secret")
	}
	// Mounted with http.StripPrefix: the signed path is the one sent.
	mounted := http.StripPrefix("/hooks", h)
	r := httptest.NewRequest("POST", "/hooks/nine/user", strings.NewReader(`{"id":"42"}`))
	r.Header.Set(SignatureHeader, SignPayload(adapterSecret, "POST", "/hooks/nine/user", []byte(`{"id":"42"}`)))
	w := httptest.NewRecorder()
	mounted.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("StripPrefix: %d %s", w.Code, w.Body)
	}
}

func TestAdapterHandlerFailures(t *testing.T) {
	var reported []error
	adapter := &testAdapter{fail: errors.New("database down")}
	h := AdapterHandler(AdapterConfig{Adapter: adapter, Secret: adapterSecret, OnError: func(r *http.Request, err error) { reported = append(reported, err) }})
	for _, c := range []struct{ route, body string }{
		{"/authenticate", `{"identifier":{"type":"email","value":"jane@acme.test"},"password":"x"}`},
		{"/user", `{"id":"42"}`},
		{"/event", `{"id":"e","event_type":"user.updated"}`},
	} {
		reply := callAdapter(t, h, "POST", "/nine"+c.route, c.body, adapterSecret, "r")
		if reply.status != 500 || reply.body["error"] != "server_error" || strings.Contains(reply.raw, "database") || !reply.signedFor("/nine"+c.route, "r", adapterSecret) {
			t.Fatalf("%s: %+v", c.route, reply)
		}
	}
	if len(reported) != 3 {
		t.Fatalf("reported %v", reported)
	}
	// A user without an id is the adapter's bug.
	h = AdapterHandler(AdapterConfig{Adapter: &testAdapter{}, Secret: adapterSecret})
	reply := callAdapter(t, h, "POST", "/nine/authenticate", `{"identifier":{"type":"email","value":"noid@acme.test"},"password":"x"}`, adapterSecret, "r")
	if reply.status != 500 {
		t.Fatalf("user without an id: %d", reply.status)
	}
	for _, cfg := range []AdapterConfig{{Adapter: &testAdapter{}}, {Secret: adapterSecret}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%+v must panic", cfg)
				}
			}()
			AdapterHandler(cfg)
		}()
	}
}
