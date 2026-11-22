package nine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type apiCall struct {
	method, path, query, scope string
	body                       map[string]any
}

// managementServer issues one token per scope and records API calls with the scope of
// the token they carried.
type managementServer struct {
	*fakeIssuer
	mu      sync.Mutex
	calls   []apiCall
	reply   func(c apiCall) (int, any)
	expired map[string]bool // tokens that answer 401
}

func newManagementServer(t *testing.T) *managementServer {
	m := &managementServer{fakeIssuer: newFakeIssuer(t), expired: map[string]bool{}}
	n := 0
	m.token = func(r *http.Request, form url.Values) (int, any) {
		if r.Header.Get("Authorization") != basicAuth("app_mgmt", "s3cret") {
			return 401, map[string]any{"error": "invalid_client"}
		}
		m.mu.Lock()
		n++
		token := "token-" + form.Get("scope") + "-" + string(rune('0'+n))
		m.mu.Unlock()
		return 200, map[string]any{"access_token": token, "expires_in": 3600}
	}
	m.api = func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		m.mu.Lock()
		if m.expired[token] {
			m.mu.Unlock()
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}
		m.mu.Unlock()
		scope := strings.Join(strings.Split(strings.TrimPrefix(token, "token-"), "-")[:1], "")
		c := apiCall{method: r.Method, path: strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1"), query: r.URL.RawQuery, scope: scope}
		if data, _ := io.ReadAll(r.Body); len(data) > 0 {
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content type %q", r.Header.Get("Content-Type"))
			}
			_ = json.Unmarshal(data, &c.body)
		}
		m.mu.Lock()
		m.calls = append(m.calls, c)
		m.mu.Unlock()
		status, body := 200, any(map[string]any{})
		if m.reply != nil {
			status, body = m.reply(c)
		}
		if body == nil {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	return m
}

func (m *managementServer) last() apiCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[len(m.calls)-1]
}

var sampleUser = map[string]any{
	"id": "usr_1", "email": "jane@acme.test", "email_verified": true, "phone_number": nil, "name": "Jane",
	"blocked": false, "metadata": map[string]any{"plan": "pro"}, "created_at": "2026-11-10T09:30:00.000Z",
	"updated_at": "2026-11-10T09:30:00.000Z", "last_login_at": nil, "login_count": 3,
}

func newTestManagement(t *testing.T, m *managementServer) *ManagementClient {
	return must[*ManagementClient](t)(NewManagementClient(ManagementConfig{Issuer: m.issuer, ClientID: "app_mgmt", ClientSecret: "s3cret"}))
}

func TestManagementCalls(t *testing.T) {
	m := newManagementServer(t)
	m.reply = func(c apiCall) (int, any) {
		switch {
		case c.method == "GET" && c.path == "/users":
			return 200, map[string]any{"users": []any{sampleUser}, "next_cursor": "c2", "total": 1}
		case c.method == "GET" && c.path == "/users/lookup":
			return 200, map[string]any{"user": sampleUser}
		case c.method == "GET" && strings.HasSuffix(c.path, "/sessions"):
			return 200, map[string]any{"sessions": []any{map[string]any{"sid": "s1", "user_id": "usr_1", "auth_time": "2026-11-10T09:30:00.000Z", "amr": []string{"pwd"}, "expires_at": "2026-12-10T09:30:00.000Z"}}}
		case c.method == "GET":
			return 200, map[string]any{"user": sampleUser, "identities": []any{}, "sessions": []any{}, "has_password": true, "mfa": map[string]any{"enabled": true, "enabled_at": "2026-11-01T10:00:00.000Z", "recovery_codes_left": 9}}
		case c.method == "POST" && c.path == "/users":
			return 201, map[string]any{"user": sampleUser}
		case c.method == "POST" && c.path == "/users/import":
			return 200, map[string]any{"results": []any{map[string]any{"index": 0, "ok": true, "status": "created", "id": "auth0|42"}}}
		case c.method == "POST" && strings.HasSuffix(c.path, "/login-link"):
			return 201, map[string]any{"url": m.issuer + "/login-link/abc", "expires_at": "2026-11-10T09:40:00.000Z"}
		case c.method == "PATCH":
			u := map[string]any{}
			for k, v := range sampleUser {
				u[k] = v
			}
			for k, v := range c.body {
				u[k] = v
			}
			return 200, map[string]any{"user": u}
		case c.method == "DELETE" && strings.HasSuffix(c.path, "/sessions"):
			return 200, map[string]any{"revoked": 2}
		case c.method == "DELETE":
			return 204, nil
		}
		return 404, map[string]any{"error": "not_found"}
	}
	nine := newTestManagement(t, m)

	list := must[*UserList](t)(nine.ListUsers(ctx, ListUsersOptions{Query: "jane doe", Cursor: "c1", Limit: 5}))
	if c := m.last(); c.query != "cursor=c1&limit=5&q=jane+doe" || c.scope != "management:users:read" {
		t.Fatalf("list %+v", c)
	}
	if len(list.Users) != 1 || list.NextCursor != "c2" || list.Total != 1 || list.Users[0].Metadata["plan"] != "pro" || list.Users[0].LastLoginAt != nil || list.Users[0].CreatedAt.IsZero() {
		t.Fatalf("list %+v", list)
	}
	_, _ = nine.ListUsers(ctx, ListUsersOptions{})
	if c := m.last(); c.query != "" || c.path != "/users" {
		t.Fatalf("empty list %+v", c)
	}

	detail := must[*UserDetail](t)(nine.GetUser(ctx, "e2e|42"))
	if c := m.last(); c.path != "/users/e2e%7C42" || c.scope != "management:users:read" {
		t.Fatalf("get %+v", c)
	}
	if !detail.HasPassword || !detail.MFA.Enabled || *detail.MFA.RecoveryCodesLeft != 9 || detail.User.Email != "jane@acme.test" {
		t.Fatalf("detail %+v", detail)
	}

	u := must[*ManagedUser](t)(nine.FindUser(ctx, "phone_number", "+447700900000"))
	if c := m.last(); c.path != "/users/lookup" || c.query != "phone_number=%2B447700900000" || u.ID != "usr_1" {
		t.Fatalf("find %+v", c)
	}
	_, _ = nine.FindUserByEmail(ctx, "Jane@Acme.test")
	if c := m.last(); c.query != "email=Jane%40Acme.test" {
		t.Fatalf("find by email %+v", c)
	}
	_, err := nine.FindUser(ctx, "phone", "+44")
	wantCode(t, err, "invalid_options", 0)

	_, _ = nine.CreateUser(ctx, NewUser{Email: "jane@acme.test", EmailVerified: true, Password: "pw", Metadata: map[string]any{"run": "x"}})
	if c := m.last(); c.method != "POST" || c.scope != "management:users:write" || c.body["email"] != "jane@acme.test" || c.body["email_verified"] != true || c.body["password"] != "pw" || len(c.body) != 4 {
		t.Fatalf("create %+v", c)
	}

	updated := must[*ManagedUser](t)(nine.UpdateUser(ctx, "usr_1", UserChanges{"name": "Renamed", "phone_number": nil}))
	if c := m.last(); c.method != "PATCH" || c.body["name"] != "Renamed" || len(c.body) != 2 || updated.Name != "Renamed" {
		t.Fatalf("update %+v", c)
	}
	if !sentAsNull(m.last().body, "phone_number") {
		t.Fatal("a nil change must be sent as null")
	}
	blocked := must[*ManagedUser](t)(nine.BlockUser(ctx, "usr_1"))
	if c := m.last(); c.body["blocked"] != true || !blocked.Blocked {
		t.Fatalf("block %+v", c)
	}
	_, _ = nine.UnblockUser(ctx, "usr_1")
	if c := m.last(); c.body["blocked"] != false {
		t.Fatalf("unblock %+v", c)
	}

	if err := nine.DeleteUser(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	if c := m.last(); c.method != "DELETE" || c.scope != "management:users:write" {
		t.Fatalf("delete %+v", c)
	}

	created := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	results := must[[]ImportResult](t)(nine.ImportUsers(ctx, []ImportUser{{ID: "auth0|42", NewUser: NewUser{Email: "jane@acme.test", PasswordHash: "$2b$10$abc"}, Identities: []ImportIdentity{{Connection: "social:google", Subject: "1069"}}, CreatedAt: &created}}, ImportOptions{OnConflict: "update", Source: "auth0"}))
	c := m.last()
	rec := c.body["users"].([]any)[0].(map[string]any)
	if c.body["on_conflict"] != "update" || c.body["source"] != "auth0" || rec["id"] != "auth0|42" || rec["password_hash"] != "$2b$10$abc" || rec["created_at"] != "2021-03-04T05:06:07Z" || rec["identities"].([]any)[0].(map[string]any)["connection"] != "social:google" {
		t.Fatalf("import %+v", c.body)
	}
	if _, has := rec["last_login_at"]; has {
		t.Fatal("unset dates are left out")
	}
	if len(results) != 1 || results[0].Status != "created" || results[0].ID != "auth0|42" {
		t.Fatalf("results %+v", results)
	}

	link := must[*LoginLink](t)(nine.CreateLoginLink(ctx, "usr_1", LoginLinkOptions{ReturnTo: "https://app.acme.test/nine/callback", TTL: 10 * time.Minute}))
	if c := m.last(); c.path != "/users/usr_1/login-link" || c.body["return_to"] != "https://app.acme.test/nine/callback" || c.body["ttl_seconds"] != float64(600) || c.scope != "management:users:write" {
		t.Fatalf("login link %+v", c)
	}
	if !strings.HasPrefix(link.URL, m.issuer) || link.ExpiresAt.IsZero() {
		t.Fatalf("link %+v", link)
	}
	_, _ = nine.CreateLoginLink(ctx, "usr_1", LoginLinkOptions{})
	if c := m.last(); len(c.body) != 0 {
		t.Fatalf("empty login link options %+v", c.body)
	}

	sessions := must[[]ManagedSession](t)(nine.ListUserSessions(ctx, "usr_1"))
	if c := m.last(); c.scope != "management:users:read" || len(sessions) != 1 || sessions[0].SID != "s1" || sessions[0].AMR[0] != "pwd" {
		t.Fatalf("sessions %+v %+v", c, sessions)
	}
	if n := must[int](t)(nine.RevokeUserSessions(ctx, "usr_1")); n != 2 {
		t.Fatalf("revoked %d", n)
	}
	if c := m.last(); c.scope != "management:sessions:write" {
		t.Fatalf("revoke all %+v", c)
	}
	if err := nine.RevokeSession(ctx, "sid/1"); err != nil {
		t.Fatal(err)
	}
	if c := m.last(); c.path != "/sessions/sid%2F1" || c.scope != "management:sessions:write" {
		t.Fatalf("revoke one %+v", c)
	}
	// One token per scope, each requested once.
	if n := m.count("/oauth/token"); n != 3 {
		t.Fatalf("%d token requests, want 3 (one per scope)", n)
	}
}

func sentAsNull(body map[string]any, key string) bool {
	v, ok := body[key]
	return ok && v == nil
}

func TestManagementErrors(t *testing.T) {
	m := newManagementServer(t)
	m.reply = func(c apiCall) (int, any) {
		switch c.method {
		case "POST":
			return 409, map[string]any{"error": "identifier_taken", "error_description": "email is taken", "details": []any{map[string]any{"path": "email"}}}
		case "PATCH":
			return 400, map[string]any{"error": "invalid_user", "details": []any{map[string]any{"path": "nmae", "message": "unknown field"}}}
		case "DELETE":
			return 500, nil
		}
		return 404, map[string]any{"error": "not_found", "error_description": "no such user"}
	}
	nine := newTestManagement(t, m)
	_, err := nine.CreateUser(ctx, NewUser{Email: "jane@acme.test"})
	e := wantCode(t, err, "identifier_taken", 409)
	if e.Description != "email is taken" || e.Details == nil {
		t.Fatalf("%+v", e)
	}
	_, err = nine.UpdateUser(ctx, "usr_1", UserChanges{"nmae": "x"})
	e = wantCode(t, err, "invalid_user", 400)
	if d, ok := e.Details.([]any); !ok || len(d) != 1 {
		t.Fatalf("details %+v", e.Details)
	}
	_, err = nine.GetUser(ctx, "usr_missing")
	wantCode(t, err, "not_found", 404)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("errors.Is(ErrNotFound)")
	}
	_, err = nine.FindUserByEmail(ctx, "nobody@acme.test")
	wantCode(t, err, "not_found", 404)
	err = nine.DeleteUser(ctx, "usr_1")
	wantCode(t, err, "request_failed", 500)

	wrong := must[*ManagementClient](t)(NewManagementClient(ManagementConfig{Issuer: m.issuer, ClientID: "app_mgmt", ClientSecret: "nope"}))
	_, err = wrong.ListUsers(ctx, ListUsersOptions{})
	wantCode(t, err, "invalid_client", 401)
}

func TestManagementRetriesOnceWithANewToken(t *testing.T) {
	m := newManagementServer(t)
	m.reply = func(apiCall) (int, any) { return 200, map[string]any{"users": []any{}} }
	nine := newTestManagement(t, m)
	_, _ = nine.ListUsers(ctx, ListUsersOptions{})
	// The cached token stops working (a scope was removed, say): one retry with a new one.
	m.mu.Lock()
	m.expired["token-management:users:read-1"] = true
	m.mu.Unlock()
	if _, err := nine.ListUsers(ctx, ListUsersOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := m.count("/oauth/token"); n != 2 {
		t.Fatalf("token requests %d", n)
	}
	// A second 401 is an error.
	m.mu.Lock()
	m.expired["token-management:users:read-2"] = true
	m.expired["token-management:users:read-3"] = true
	m.mu.Unlock()
	_, err := nine.ListUsers(ctx, ListUsersOptions{})
	wantCode(t, err, "invalid_token", 401)
}

func TestWebhookEventUser(t *testing.T) {
	e := &WebhookEvent{Data: map[string]any{"user": sampleUser}}
	u, err := e.User()
	if err != nil || u.ID != "usr_1" || !u.EmailVerified || u.LoginCount != 3 || e.UserID() != "usr_1" {
		t.Fatalf("%v %+v", err, u)
	}
	none := &WebhookEvent{Data: map[string]any{"user": nil}}
	if u, err := none.User(); u != nil || err != nil || none.UserID() != "" {
		t.Fatal("no user")
	}
}
