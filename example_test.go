package nine_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	nine "github.com/9in-io/go-sdk"
)

// Sign users in to a web app: the routes, an encrypted cookie session and protected pages.
func Example() {
	// NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_SECRET (32+ characters) and NINE_BASE_URL.
	app, err := nine.NewWebApp(nine.WebAppConfigFromEnv())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/nine/", app) // /nine/login, /nine/signup, /nine/callback, /nine/logout
	mux.Handle("/dashboard", app.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := nine.UserFrom(r.Context())
		fmt.Fprintf(w, "Hello %s", user.Name)
	})))
	log.Fatal(http.ListenAndServe(":3000", mux))
}

func ExampleNewWebApp() {
	app, err := nine.NewWebApp(nine.WebAppConfig{
		Issuer:       "https://acme.9in.io",
		ClientID:     "app_7f3k2m9q",
		ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
		Secret:       os.Getenv("NINE_SECRET"), // encrypts the session cookie
		BaseURL:      "https://app.acme.com",   // callback: https://app.acme.com/nine/callback
		Audience:     "https://api.acme.com",   // access tokens for your API
	})
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/nine/", app)
	http.Handle("/orders", app.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := app.AccessToken(w, r) // refreshed (and rotated) when needed
		if err != nil {
			http.Redirect(w, r, "/nine/login", http.StatusFound)
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://api.acme.com/orders", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		// … call your API
	})))
}

func ExampleWebAppAuth() {
	auth, err := nine.NewWebAppAuth(nine.WebAppAuthConfig{
		Issuer:       "https://acme.9in.io",
		ClientID:     "app_7f3k2m9q",
		ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
		RedirectURI:  "https://app.acme.com/nine/callback",
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()

	// /nine/login: keep login.Pending (server-side session, or encrypted) and redirect.
	login, err := auth.CreateLogin(ctx, nine.LoginOptions{ReturnTo: "/dashboard"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("redirect to", login.URL)

	// /nine/callback: checks state, iss and PKCE, and verifies the ID token.
	var r *http.Request // the callback request
	tokens, err := auth.HandleCallback(ctx, r.URL.Query(), login.Pending)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tokens.Claims.Subject(), tokens.Claims.String("email"), tokens.ReturnTo)

	// Later: refresh before expiry and keep the result (9in rotates refresh tokens).
	tokens, err = auth.EnsureFresh(ctx, tokens, time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	_ = tokens
}

func ExampleNewVerifier() {
	verifier, err := nine.NewVerifier(nine.VerifierConfig{
		Issuer:   "https://acme.9in.io",
		Audience: "https://api.acme.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	claims, err := verifier.Verify(context.Background(), "eyJhbGciOi…", "orders:read")
	switch {
	case errors.Is(err, nine.ErrInsufficientScope): // 403
	case errors.Is(err, nine.ErrInvalidToken): // 401
	case err != nil: // 9in unreachable
	default:
		fmt.Println(claims.Subject(), claims.Scopes())
	}
}

// Hybrid verification: revocations take effect as soon as the webhook arrives.
func ExampleNewVerifier_hybrid() {
	verifier, err := nine.NewVerifier(nine.VerifierConfig{
		Issuer:       "https://acme.9in.io",
		Audience:     "https://api.acme.com",
		ClientID:     os.Getenv("NINE_CLIENT_ID"), // a confidential application:
		ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
		// Mode: nine.ModeHybrid is the default with client credentials.
		CacheTTL: 5 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/orders", nine.RequireAuth(verifier, "orders:read")(http.HandlerFunc(listOrders)))
	// Subscribed to token.revoked, session.revoked and user.* events.
	mux.Handle("/nine/webhook", nine.WebhookHandler(nine.WebhookConfig{
		Secret:   os.Getenv("NINE_WEBHOOK_SECRET"),
		Verifier: verifier,
	}))
}

func listOrders(w http.ResponseWriter, r *http.Request) {}

func ExampleRequireAuth() {
	verifier, err := nine.NewVerifier(nine.VerifierConfigFromEnv()) // NINE_ISSUER, NINE_AUDIENCE…
	if err != nil {
		log.Fatal(err)
	}
	orders := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := nine.ClaimsFrom(r.Context())
		if claims.IsMachine() { // a client-credentials token: no user
			http.Error(w, "users only", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, "orders of %s", claims.Subject())
	})
	http.Handle("GET /api/orders", nine.RequireAuth(verifier, "orders:read")(orders))
}

func ExampleManagementClient() {
	m, err := nine.NewManagementClient(nine.ManagementConfig{
		Issuer:       "https://acme.9in.io",
		ClientID:     os.Getenv("NINE_CLIENT_ID"), // an application with management scopes
		ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	user, err := m.CreateUser(ctx, nine.NewUser{Email: "jane@acme.com", EmailVerified: true, Password: "a long passphrase"})
	var e *nine.Error
	if errors.As(err, &e) && e.Code == "identifier_taken" {
		user, err = m.FindUserByEmail(ctx, "jane@acme.com")
	}
	if err != nil {
		log.Fatal(err)
	}
	_, _ = m.UpdateUser(ctx, user.ID, nine.UserChanges{"metadata": map[string]any{"plan": "pro"}})
	link, _ := m.CreateLoginLink(ctx, user.ID, nine.LoginLinkOptions{ReturnTo: "https://app.acme.com/nine/callback", TTL: 10 * time.Minute})
	fmt.Println(link.URL)
}

// myUsers is your user database.
type myUsers struct{}

func (myUsers) Authenticate(ctx context.Context, id nine.Identifier, password string) (*nine.AdapterUser, error) {
	// Look the user up by id.Type ("email", "username" or "phone") and id.Value, check the password.
	if id.Value != "jane@acme.com" || password != "hunter2" {
		return nil, nine.ErrInvalidCredentials
	}
	return &nine.AdapterUser{ID: "42", Email: "jane@acme.com", EmailVerified: true, Name: "Jane Doe"}, nil
}

func (myUsers) FindUser(ctx context.Context, q nine.UserQuery) (*nine.AdapterUser, error) {
	if q.ID == "42" || (q.Identifier != nil && q.Identifier.Value == "jane@acme.com") {
		return &nine.AdapterUser{ID: "42", Email: "jane@acme.com", Name: "Jane Doe"}, nil
	}
	return nil, nil // not found
}

func (myUsers) OnEvent(ctx context.Context, e *nine.AdapterEvent) error {
	if e.EventType == "otp.requested" {
		return sendCode(ctx, e.Data["channel"], e.Data["to"], e.Data["code"])
	}
	return nil
}

func sendCode(ctx context.Context, channel, to, code any) error { return nil }

func ExampleAdapterHandler() {
	// Serves /nine/authenticate, /nine/user and /nine/event.
	http.Handle("/nine/", nine.AdapterHandler(nine.AdapterConfig{
		Secret:  os.Getenv("NINE_ADAPTER_SECRET"),
		Adapter: myUsers{},
	}))
}

func ExampleWebhookHandler() {
	http.Handle("POST /nine/webhook", nine.WebhookHandler(nine.WebhookConfig{
		Secret: os.Getenv("NINE_WEBHOOK_SECRET"),
		// Called once per event; return an error to have 9in retry later.
		Handle: func(ctx context.Context, e *nine.WebhookEvent) error {
			switch e.EventType {
			case "user.created":
				user, err := e.User()
				if err != nil {
					return err
				}
				fmt.Println("welcome", user.Email)
			case "user.deleted":
				fmt.Println("goodbye", e.UserID())
			}
			return nil
		},
		// Store: a shared EventStore (Redis SET NX…) when you run several instances.
	}))
}

func ExampleVerifyWebhook() {
	http.HandleFunc("POST /nine/webhook", func(w http.ResponseWriter, r *http.Request) {
		event, err := nine.VerifyWebhookRequest(r, os.Getenv("NINE_WEBHOOK_SECRET"))
		if err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		status, err := nine.ProcessEventOnce(r.Context(), store, event.ID, func(ctx context.Context) error {
			return handle(ctx, event)
		})
		switch {
		case status == nine.InProgress:
			w.WriteHeader(http.StatusConflict) // 9in retries later
		case err != nil:
			w.WriteHeader(http.StatusInternalServerError) // released: 9in retries
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

var store = nine.NewMemoryEventStore()

func handle(context.Context, *nine.WebhookEvent) error { return nil }

func ExampleDeviceAuth() {
	device, err := nine.NewDeviceAuth(nine.DeviceAuthConfig{Issuer: "https://acme.9in.io", ClientID: "app_tv123"})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	code, err := device.Start(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Open %s and enter %s\n", code.VerificationURI, code.UserCode)
	tokens, err := device.Wait(ctx, code) // polls until the user approves
	if err != nil {
		log.Fatal(err) // access_denied, expired_token…
	}
	fmt.Println("signed in as", tokens.Claims.Subject())
}

func ExampleClientCredentials() {
	service, err := nine.NewClientCredentials(nine.ClientCredentialsConfig{
		Issuer:       "https://acme.9in.io",
		ClientID:     os.Getenv("NINE_CLIENT_ID"),
		ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
		Audience:     "https://api.acme.com",
	})
	if err != nil {
		log.Fatal(err)
	}
	// Every request carries a cached, renewed-before-expiry access token.
	client := service.HTTPClient(&http.Client{Timeout: 10 * time.Second})
	res, err := client.Get("https://api.acme.com/reports")
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
}

func ExampleSignPayloadAt() {
	body := []byte(`{"identifier":{"type":"email","value":"jane@acme.com"},"password":"hunter2"}`)
	header := nine.SignPayloadAt("adapter_secret_test", "POST", "/nine/authenticate", body, time.Unix(1762682400, 0))
	fmt.Println(header)
	// Output: t=1762682400,v1=f8c341feb9ffa2698aa90a3e762f7108a324e503aa260bbc305e8ba3be9ca49c
}

func ExampleVerifySignature() {
	body := []byte(`{"id":"42"}`)
	header := nine.SignPayload("new-secret", "POST", "/nine/user", body)
	// Several secrets while you rotate; 0 means the default 5-minute tolerance.
	err := nine.VerifySignature([]string{"new-secret", "old-secret"}, header, "POST", "/nine/user", body, 0)
	fmt.Println(err)
	err = nine.VerifySignature([]string{"other"}, header, "POST", "/nine/user", body, 0)
	fmt.Println(err)
	// Output:
	// <nil>
	// nine: invalid_signature: mismatch
}

func ExampleNormalizeIssuer() {
	issuer, err := nine.NormalizeIssuer("https://acme.9in.io/", false)
	fmt.Println(issuer, err)
	_, err = nine.NormalizeIssuer("http://acme.9in.io", false)
	fmt.Println(err)
	issuer, err = nine.NormalizeIssuer("http://localhost:8787", false)
	fmt.Println(issuer, err)
	// Output:
	// https://acme.9in.io <nil>
	// nine: insecure_issuer: issuer must use https (got http://acme.9in.io); plain http is only accepted for localhost
	// http://localhost:8787 <nil>
}

func ExampleCodeChallenge() {
	fmt.Println(nine.CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
	// Output: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
}

func ExampleSafeReturnPath() {
	for _, p := range []string{"/dashboard?tab=2", "https://evil.example", "//evil.example", "/\\evil.example"} {
		fmt.Printf("%q\n", nine.SafeReturnPath(p))
	}
	// Output:
	// "/dashboard?tab=2"
	// ""
	// ""
	// ""
}

func ExampleError() {
	err := error(&nine.Error{Code: "insufficient_scope", Description: "missing orders:write", Status: 403})
	var e *nine.Error
	if errors.As(err, &e) {
		fmt.Println(e.Code, e.Status)
	}
	fmt.Println(errors.Is(err, nine.ErrInsufficientScope), errors.Is(err, nine.ErrInvalidToken))
	// Output:
	// insufficient_scope 403
	// true false
}

func ExampleClaims() {
	var claims nine.Claims
	_ = json.NewDecoder(strings.NewReader(`{"sub":"usr_8k2","client_id":"app_1","scope":"openid orders:read","exp":1794203600,"aud":"https://api.acme.com"}`)).Decode(&claims)
	fmt.Println(claims.Subject(), claims.Scopes(), claims.HasScope("orders:read"), claims.Audience(), claims.ExpiresAt().UTC().Format(time.RFC3339))
	// Output: usr_8k2 [openid orders:read] true [https://api.acme.com] 2026-11-09T05:53:20Z
}
