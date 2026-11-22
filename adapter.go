package nine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Identifier is how a user signs in: Type is "email", "username" or "phone".
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// UserQuery is what 9in looks a user up by: ID (your own user id) or Identifier.
type UserQuery struct {
	ID         string
	Identifier *Identifier
}

// AdapterUser is a user from your database, in the shape 9in expects (OpenID Connect
// claim names). Empty fields are left out. Metadata is stored on the 9in user.
type AdapterUser struct {
	// ID is your user id (required, up to 256 characters).
	ID                  string         `json:"id"`
	Email               string         `json:"email,omitempty"`
	EmailVerified       bool           `json:"email_verified,omitempty"`
	PhoneNumber         string         `json:"phone_number,omitempty"` // E.164
	PhoneNumberVerified bool           `json:"phone_number_verified,omitempty"`
	Username            string         `json:"username,omitempty"`
	Name                string         `json:"name,omitempty"`
	GivenName           string         `json:"given_name,omitempty"`
	FamilyName          string         `json:"family_name,omitempty"`
	Picture             string         `json:"picture,omitempty"` // https URL
	Locale              string         `json:"locale,omitempty"`
	Zoneinfo            string         `json:"zoneinfo,omitempty"`
	Birthdate           string         `json:"birthdate,omitempty"` // YYYY-MM-DD
	Blocked             bool           `json:"blocked,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

// AdapterEvent is what 9in posts to …/event. Data["user_id"] is your own user id.
// otp.requested carries user_id, channel ("email" or "sms"), to, code, purpose ("login"
// or "password_reset") and expires_at; user.updated and user.password_changed carry
// user_id and fields.
type AdapterEvent struct {
	ID        string         `json:"id"`
	EventType string         `json:"event_type"`
	CreatedAt time.Time      `json:"created_at"`
	Data      map[string]any `json:"data"`
}

// UserID is data.user_id: your own user id, or "".
func (e *AdapterEvent) UserID() string {
	id, _ := e.Data["user_id"].(string)
	return id
}

// Adapter is your user database, as 9in sees it (adapter protocol v2).
type Adapter interface {
	// Authenticate checks a password. Return the user, or ErrInvalidCredentials (or a nil
	// user) for an unknown user or a wrong password, or ErrUserBlocked (or a user with
	// Blocked set) for a blocked one. Any other error answers 500.
	Authenticate(ctx context.Context, id Identifier, password string) (*AdapterUser, error)
	// FindUser looks a user up by id or identifier. Return a nil user (or ErrNotFound)
	// when there is none.
	FindUser(ctx context.Context, query UserQuery) (*AdapterUser, error)
	// OnEvent receives notifications, including otp.requested when you deliver one-time
	// codes yourself.
	OnEvent(ctx context.Context, event *AdapterEvent) error
}

// AdapterConfig configures [AdapterHandler].
type AdapterConfig struct {
	// Adapter is your user database (required).
	Adapter Adapter
	// Secret is the connection's shared secret (Connections → User database;
	// NINE_ADAPTER_SECRET). Responses are signed with it.
	Secret string
	// Secrets are more secrets accepted while you rotate.
	Secrets []string
	// Tolerance is the signature timestamp tolerance. Default 5 minutes.
	Tolerance time.Duration
	// OnError is told about adapter errors that were answered with 500. Optional.
	OnError func(r *http.Request, err error)
}

// AdapterHandler returns an http.Handler for the adapter protocol v2. Mount it at your
// adapter's base URL; it serves …/authenticate, …/user and …/event, answering with the
// same routes, bodies and status codes as the other 9in SDKs:
//
//   - authenticate: 200 {user}, 401 invalid_credentials, 403 blocked
//   - user: 200 {user}, 404 not_found
//   - event: 204
//   - 400 invalid_json or invalid_request for a malformed body, 404 for another route,
//     500 server_error when the adapter fails
//
// Requests must carry a valid 9in-signature over the method, the path as sent and the raw
// body (unsigned answers: 401 invalid_signature, 405 for non-POST). Every other answer is
// signed over "<path>#<9in-request-id>", so it can't be replayed for another request.
//
// Mount it on the path 9in calls (http.StripPrefix is fine: the signed path is read from
// the request line). It panics when Adapter or the secret is missing.
func AdapterHandler(cfg AdapterConfig) http.Handler {
	secrets := secretList(cfg.Secret, cfg.Secrets)
	if len(secrets) == 0 {
		panic("nine: AdapterHandler needs a Secret (NINE_ADAPTER_SECRET)")
	}
	if cfg.Adapter == nil {
		panic("nine: AdapterHandler needs an Adapter")
	}
	h := &adapterHandler{cfg: cfg, secrets: secrets}
	if h.cfg.OnError == nil {
		h.cfg.OnError = func(*http.Request, error) {}
	}
	return h
}

type adapterHandler struct {
	cfg     AdapterConfig
	secrets []string
}

func (h *adapterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("Method not allowed"))
		return
	}
	path := requestPath(r)
	body, err := readBody(r)
	if err == nil {
		if reason := checkSignature(h.secrets, r.Header.Get(SignatureHeader), http.MethodPost, path, body, h.cfg.Tolerance, time.Now()); reason != "" {
			err = newError("invalid_signature", reason, http.StatusUnauthorized)
		}
	}
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_signature"})
		return
	}
	respond := func(status int, payload any) {
		var text []byte
		if payload != nil {
			text, _ = json.Marshal(payload)
		}
		w.Header().Set(SignatureHeader, SignPayload(h.secrets[0], http.MethodPost, path+"#"+r.Header.Get(RequestIDHeader), text))
		w.Header().Set("Cache-Control", "no-store")
		if len(text) > 0 {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = w.Write(text)
	}
	failure := func(err error) {
		h.cfg.OnError(r, err)
		respond(http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}

	input := map[string]any{}
	if len(strings.TrimSpace(string(body))) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber() // numeric ids keep every digit
		if err := dec.Decode(&input); err != nil || input == nil || dec.More() {
			respond(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
			return
		}
	}
	ctx := r.Context()
	switch path[strings.LastIndexByte(path, '/')+1:] {
	case "authenticate":
		id, ok := parseIdentifier(input["identifier"])
		password, isString := input["password"].(string)
		if !ok || !isString {
			respond(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		user, err := h.cfg.Adapter.Authenticate(ctx, id, password)
		switch {
		case errors.Is(err, ErrUserBlocked) || (err == nil && user != nil && user.Blocked):
			respond(http.StatusForbidden, map[string]string{"error": "blocked"})
		case errors.Is(err, ErrInvalidCredentials) || (err == nil && user == nil):
			respond(http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		case err != nil:
			failure(err)
		case user.ID == "":
			failure(errors.New("nine: Authenticate returned a user without an ID"))
		default:
			respond(http.StatusOK, map[string]any{"user": user})
		}
	case "user":
		var query UserQuery
		switch v := input["id"].(type) {
		case string:
			query.ID = v
		case json.Number:
			query.ID = v.String()
		}
		if query.ID == "" {
			id, ok := parseIdentifier(input["identifier"])
			if !ok {
				respond(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
				return
			}
			query.Identifier = &id
		}
		user, err := h.cfg.Adapter.FindUser(ctx, query)
		switch {
		case errors.Is(err, ErrNotFound) || (err == nil && user == nil):
			respond(http.StatusNotFound, map[string]string{"error": "not_found"})
		case err != nil:
			failure(err)
		case user.ID == "":
			failure(errors.New("nine: FindUser returned a user without an ID"))
		default:
			respond(http.StatusOK, map[string]any{"user": user})
		}
	case "event":
		var event AdapterEvent
		eventType, _ := input["event_type"].(string)
		if eventType == "" || json.Unmarshal(body, &event) != nil {
			respond(http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		if event.Data == nil {
			event.Data = map[string]any{}
		}
		if err := h.cfg.Adapter.OnEvent(ctx, &event); err != nil {
			failure(err)
			return
		}
		respond(http.StatusNoContent, nil)
	default:
		respond(http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func parseIdentifier(v any) (Identifier, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return Identifier{}, false
	}
	typ, _ := m["type"].(string)
	value, _ := m["value"].(string)
	if value == "" || (typ != "email" && typ != "username" && typ != "phone") {
		return Identifier{}, false
	}
	return Identifier{Type: typ, Value: value}, true
}
