package nine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// WebhookEvent is a webhook from 9in. Data carries the event's details plus "user", the
// user the event is about (the Management API user object, or nil when there is none;
// for user.deleted, the user as it was just before the deletion). ID is the same on
// every retry and redelivery.
type WebhookEvent struct {
	ID        string    `json:"id"`
	EventType string    `json:"event_type"`
	CreatedAt time.Time `json:"created_at"`
	// Tenant is the tenant id (tnt_…).
	Tenant string `json:"tenant"`
	// Environment is "production" or "sandbox".
	Environment string         `json:"environment"`
	Data        map[string]any `json:"data"`
}

// UserID is the id of the user the event is about (data.user.id), or "".
func (e *WebhookEvent) UserID() string {
	user, _ := e.Data["user"].(map[string]any)
	id, _ := user["id"].(string)
	return id
}

// User decodes data.user into a ManagedUser; nil when the event is about no user.
func (e *WebhookEvent) User() (*ManagedUser, error) {
	raw, ok := e.Data["user"]
	if !ok || raw == nil {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var user ManagedUser
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// Largest webhook or adapter body read.
const maxRequestBody = 1 << 20

// VerifyWebhook checks a webhook's 9in-signature header against the raw body and the path
// 9in posted to (r.URL.Path, or what it was before a proxy rewrote it), with any of
// secrets (several while you rotate), and returns the event. It fails with
// invalid_signature (401), or invalid_payload (400) when the body isn't an event.
func VerifyWebhook(secrets []string, body []byte, signature, path string) (*WebhookEvent, error) {
	return verifyWebhookAt(secrets, body, signature, path, DefaultTolerance, time.Now())
}

func verifyWebhookAt(secrets []string, body []byte, signature, path string, tolerance time.Duration, now time.Time) (*WebhookEvent, error) {
	if reason := checkSignature(secrets, signature, http.MethodPost, path, body, tolerance, now); reason != "" {
		return nil, newError("invalid_signature", reason, http.StatusUnauthorized)
	}
	var event WebhookEvent
	if err := json.Unmarshal(body, &event); err != nil || event.ID == "" || event.EventType == "" {
		return nil, newError("invalid_payload", "the body is not a 9in event", http.StatusBadRequest)
	}
	if event.Data == nil {
		event.Data = map[string]any{}
	}
	return &event, nil
}

// VerifyWebhookRequest reads and verifies a webhook request (POST, signature over the raw
// body and the request path as sent). It consumes r.Body.
func VerifyWebhookRequest(r *http.Request, secrets ...string) (*WebhookEvent, error) {
	if r.Method != http.MethodPost {
		return nil, newError("invalid_signature", "webhooks are POST requests", http.StatusUnauthorized)
	}
	body, err := readBody(r)
	if err != nil {
		return nil, err
	}
	return VerifyWebhook(secrets, body, r.Header.Get(SignatureHeader), requestPath(r))
}

func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		return nil, &Error{Code: "invalid_payload", Description: "reading the body failed", Status: http.StatusBadRequest, cause: err}
	}
	if len(body) > maxRequestBody {
		return nil, newError("invalid_payload", "the body is too large", http.StatusRequestEntityTooLarge)
	}
	return body, nil
}

// WebhookConfig configures [WebhookHandler].
type WebhookConfig struct {
	// Secret is the endpoint's signing secret (NINE_WEBHOOK_SECRET).
	Secret string
	// Secrets are more secrets accepted while you rotate.
	Secrets []string
	// Handle is called once per event (after verification and de-duplication). Return
	// an error to have 9in retry the delivery later.
	Handle func(ctx context.Context, event *WebhookEvent) error
	// Store remembers processed event ids so each event is handled once. Default: in
	// memory (one process). With several instances, use a shared store (the same one
	// can serve the Verifier).
	Store Store
	// TTL is how long processed ids are remembered. Default 3 days.
	TTL time.Duration
	// Verifier is a hybrid verifier to keep current: every verified event goes to its
	// HandleEvent, so token.revoked, session.revoked and user.* evict cached answers.
	// When that fails (its shared Store is down), the delivery gets a 500 and 9in retries.
	Verifier *Verifier
	// Path is the path 9in posts to, when a proxy rewrites it before it reaches you.
	// Default: the request path as received.
	Path string
	// Tolerance is the signature timestamp tolerance. Default 5 minutes.
	Tolerance time.Duration
	// OnError is told about a failed Handle (the delivery gets a 500 and 9in retries) and
	// about store failures. Optional.
	OnError func(r *http.Request, err error)
}

// WebhookHandler returns an http.Handler for your webhook endpoint. It answers:
//
//   - 204 when the event was handled, or had already been (a retry or redelivery);
//   - 409 while another delivery of the same event is still being handled (9in retries);
//   - 401 for a bad signature, 400 for a body that isn't an event, 405 for non-POST;
//   - 500 when Handle failed (the event id is released, so 9in's retry handles it), or when
//     the Verifier couldn't record a revocation in its shared Store.
//
// It panics when no secret is given (a configuration error, found at startup).
func WebhookHandler(cfg WebhookConfig) http.Handler {
	secrets := secretList(cfg.Secret, cfg.Secrets)
	if len(secrets) == 0 {
		panic("nine: WebhookHandler needs a Secret (NINE_WEBHOOK_SECRET)")
	}
	store := cfg.Store
	if store == nil {
		store = NewMemoryStore()
	}
	dedupe := &EventDeduplicator{Store: store, TTL: cfg.TTL}
	onError := cfg.OnError
	if onError == nil {
		onError = func(*http.Request, error) {}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		body, err := readBody(r)
		if err != nil {
			writeJSON(w, errorStatus(err, http.StatusBadRequest), map[string]string{"error": errorCode(err)})
			return
		}
		path := cfg.Path
		if path == "" {
			path = requestPath(r)
		}
		event, err := verifyWebhookAt(secrets, body, r.Header.Get(SignatureHeader), path, cfg.Tolerance, time.Now())
		if err != nil {
			writeJSON(w, errorStatus(err, http.StatusUnauthorized), map[string]string{"error": errorCode(err)})
			return
		}
		if cfg.Verifier != nil {
			if _, err := cfg.Verifier.HandleEvent(r.Context(), event); err != nil {
				onError(r, err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store_failed"})
				return
			}
		}
		handle := func(ctx context.Context) error {
			if cfg.Handle == nil {
				return nil
			}
			return cfg.Handle(ctx, event)
		}
		status, err := dedupe.Process(r.Context(), event.ID, handle)
		switch {
		case status == InProgress:
			writeJSON(w, http.StatusConflict, map[string]string{"error": "in_progress"})
		case status == Processed || status == Duplicate:
			if err != nil {
				onError(r, err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			onError(r, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "handler_failed"})
		}
	})
}

func errorStatus(err error, fallback int) int {
	var e *Error
	if errors.As(err, &e) && e.Status != 0 {
		return e.Status
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
