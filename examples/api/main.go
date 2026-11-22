// Command api is an API protected with 9in access tokens, with a webhook endpoint that
// keeps hybrid verification current.
//
//	NINE_ISSUER=https://acme.9in.io NINE_AUDIENCE=https://api.acme.com \
//	NINE_CLIENT_ID=app_… NINE_CLIENT_SECRET=… NINE_WEBHOOK_SECRET=whsec_… \
//	go run ./examples/api
//
// With NINE_CLIENT_ID and NINE_CLIENT_SECRET (a confidential application) tokens are
// verified in hybrid mode; without them, locally. Subscribe the webhook endpoint
// (…/nine/webhook) to token.revoked, session.revoked and the user.* events.
//
//	curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:4000/api/me
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	nine "github.com/9in-io/go-sdk"
)

func main() {
	verifier, err := nine.NewVerifier(nine.VerifierConfigFromEnv())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("verifying access tokens in %s mode", verifier.Mode())

	mux := http.NewServeMux()

	// Any valid token for this API.
	mux.Handle("GET /api/me", nine.RequireAuth(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := nine.ClaimsFrom(r.Context())
		writeJSON(w, map[string]any{
			"sub":       claims.Subject(),
			"client_id": claims.ClientID(),
			"scopes":    claims.Scopes(),
			"machine":   claims.IsMachine(),
		})
	})))

	// Only tokens with the read:things scope (403 insufficient_scope otherwise).
	mux.Handle("GET /api/things", nine.RequireAuth(verifier, "read:things")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"things": []string{"a", "b", "c"}})
	})))

	// Webhooks: verified, each event handled once, revocations evict cached answers.
	if secret := nine.Env("WEBHOOK_SECRET"); secret != "" {
		mux.Handle("POST /nine/webhook", nine.WebhookHandler(nine.WebhookConfig{
			Secret:   secret,
			Verifier: verifier,
			Handle: func(ctx context.Context, e *nine.WebhookEvent) error {
				log.Printf("webhook %s %s (user %s)", e.ID, e.EventType, e.UserID())
				return nil
			},
		}))
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "127.0.0.1:4000"
	}
	log.Printf("listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
