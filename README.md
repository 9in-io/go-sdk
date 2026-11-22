9in Go SDK
==========

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official Go SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO.

`github.com/9in-io/go-sdk` (package `nine`) uses only the standard library. Every call takes a
`context.Context`, every type is safe for concurrent use, and it works with any router that
speaks `http.Handler`.

- **Sign users in to web apps** with `nine.WebApp`: `/nine/login`, `/nine/callback` and
  `/nine/logout` handlers, an encrypted cookie session (AES-256-GCM), refresh token rotation
  and `RequireUser` middleware. `nine.WebAppAuth` is the flow underneath: authorization code
  with PKCE, state, nonce, the RFC 9207 issuer check and ID token verification.
- **Protect your API**: verify access tokens locally with every algorithm of the 9in key
  library, or in hybrid mode so revocations take effect at once. `nine.RequireAuth` is the
  `net/http` middleware.
- **Manage users** through the Management API: users, sessions, single-use sign-in links and
  bulk import.
- **Keep users in your own database** with the adapter protocol v2 (`/authenticate`, `/user`,
  `/event`) and signed requests and responses.
- **Receive webhooks**, verify their signature and process each event once.
- **Sign in from CLIs and devices** with the device flow (RFC 8628), and get tokens for your
  services with client credentials.

Requires Go 1.23 or later.

```bash
go get github.com/9in-io/go-sdk
```

```go
import nine "github.com/9in-io/go-sdk"
```

Guides are at [9in.io/docs](https://9in.io/docs/), and every function is documented on
[pkg.go.dev](https://pkg.go.dev/github.com/9in-io/go-sdk). The other 9in SDKs:
[JavaScript](https://github.com/9in-io/sdk), [Node.js](https://github.com/9in-io/node-sdk),
[Next.js](https://github.com/9in-io/nextjs), [PHP](https://github.com/9in-io/php-sdk),
[Laravel](https://github.com/9in-io/laravel).

## Sign users in (web apps)

Create a **Regular Web App** in the console, with `https://app.acme.com/nine/callback` as a
callback URL and `https://app.acme.com/` as a logout URL, and set:

```bash
NINE_ISSUER=https://acme.9in.io      # or your custom login domain
NINE_CLIENT_ID=app_...
NINE_CLIENT_SECRET=...
NINE_SECRET=...                       # 32+ characters: openssl rand -base64 32 (encrypts the session cookie)
NINE_BASE_URL=https://app.acme.com    # http://localhost:3000 in development
# NINE_AUDIENCE=https://api.acme.com  # access tokens for your own API
```

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	nine "github.com/9in-io/go-sdk"
)

func main() {
	app, err := nine.NewWebApp(nine.WebAppConfigFromEnv())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/nine/", app) // /nine/login, /nine/signup, /nine/callback, /nine/logout
	mux.Handle("/dashboard", app.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := nine.UserFrom(r.Context()) // Subject, Email, Name, … and every claim in Claims
		fmt.Fprintf(w, "Hello %s", user.Name)
	})))
	log.Fatal(http.ListenAndServe(":3000", mux))
}
```

Link to `/nine/login` (add `?return_to=/dashboard`, `screen=signup`, `login_hint=…` or
`locale=de`), `/nine/signup` and `/nine/logout`. Signed-out visitors of a `RequireUser` page
are sent to the sign-in page and brought back; requests that aren't page navigations get a 401
JSON answer. `app.Middleware` loads the user without requiring one.

Call your API with the user's access token. It is refreshed shortly before it expires, and
9in rotates refresh tokens, so the new one is saved in the cookie: call `AccessToken` before
you write the response body.

```go
token, err := app.AccessToken(w, r) // nine.ErrLoginRequired when the session has ended
```

The session lives in the encrypted cookie (no server-side storage); `NINE_SECRET` can hold
several comma-separated secrets while you rotate (the first encrypts). The `WebAppConfig`
fields change the routes (`BasePath`), scopes, cookie name, session length, where users land
(`AfterSignInPath`, `AfterSignOutPath`) and the error page (`OnError`).

### Other routers

`WebApp` and every middleware are plain `http.Handler`s:

```go
// chi
router := chi.NewRouter()
router.Mount("/nine", app)
router.With(app.RequireUser).Get("/dashboard", dashboard)

// gin
g := gin.Default()
g.Any("/nine/*action", gin.WrapH(app))
g.GET("/dashboard", gin.WrapH(app.RequireUser(http.HandlerFunc(dashboard))))

// echo
e := echo.New()
e.Any("/nine/*", echo.WrapHandler(app))
e.GET("/dashboard", echo.WrapHandler(app.RequireUser(http.HandlerFunc(dashboard))))
```

### Your own session: WebAppAuth

`WebAppAuth` is the protocol without the cookie handling, for apps that keep sessions
elsewhere (a database, `gorilla/sessions`, `scs`):

```go
auth, err := nine.NewWebAppAuth(nine.WebAppAuthConfig{
	Issuer:       "https://acme.9in.io",
	ClientID:     os.Getenv("NINE_CLIENT_ID"),
	ClientSecret: os.Getenv("NINE_CLIENT_SECRET"), // leave empty for a public application
	RedirectURI:  "https://app.acme.com/nine/callback",
})

// /nine/login: keep login.Pending in the session (it holds the PKCE verifier), then redirect.
login, err := auth.CreateLogin(ctx, nine.LoginOptions{ReturnTo: "/dashboard"}) // Screen: "signup"
http.Redirect(w, r, login.URL, http.StatusFound)

// /nine/callback: checks state (once), iss and PKCE, and verifies the ID token.
tokens, err := auth.HandleCallback(ctx, r.URL.Query(), pending)
// tokens.Claims: sub, email, name, amr…; tokens.ReturnTo: a same-site path only

tokens, err = auth.EnsureFresh(ctx, tokens, time.Minute) // refreshed when needed: save the result
logoutURL, err := auth.LogoutURL(ctx, nine.LogoutOptions{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: "https://app.acme.com/"})
```

`TokenSet` and `PendingLogin` marshal to JSON. `auth.Revoke`, `auth.UserInfo` and
`auth.ClientCredentials` cover the other endpoints.

## Protect your API

```go
verifier, err := nine.NewVerifier(nine.VerifierConfig{
	Issuer:   "https://acme.9in.io",
	Audience: "https://api.acme.com",
})

mux.Handle("GET /api/orders", nine.RequireAuth(verifier, "orders:read")(http.HandlerFunc(
	func(w http.ResponseWriter, r *http.Request) {
		claims := nine.ClaimsFrom(r.Context())
		fmt.Fprintf(w, "orders of %s", claims.Subject())
	})))
```

`RequireAuth` answers 401 `invalid_token` or 403 `insufficient_scope` with a
`WWW-Authenticate` header, and 503 when tokens can't be checked (9in unreachable).
`verifier.Verify(ctx, token, scopes...)` does the same check anywhere else.

Tokens are verified locally against your tenant's JWKS (cached for ten minutes, fetched again
once when a token names an unknown key, with unknown keys throttled). Every algorithm of the
9in key library is supported: RS256/384/512, PS256/384/512, ES256, ES384 and EdDSA through
JWKS, and HS256/384/512 when your API uses a shared secret (`Secret: os.Getenv("NINE_API_SECRET")`).
The key's own algorithm is enforced, only access tokens (`typ: at+jwt`) are accepted, and the
issuer, expiry, audience and scopes are checked.

### Revocation: hybrid verification

A local check can't see revocations: a token revoked through `/oauth/revoke`, a sign-out or a
blocked user keeps passing until it expires. With the credentials of a confidential
application the verifier runs in **hybrid** mode: a local check, then one introspection per
token, cached until a webhook says otherwise.

```go
verifier, err := nine.NewVerifier(nine.VerifierConfig{
	Issuer:       "https://acme.9in.io",
	Audience:     "https://api.acme.com",
	ClientID:     os.Getenv("NINE_CLIENT_ID"),
	ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
	CacheTTL:     5 * time.Minute, // the longest an answer is trusted without news from 9in
})

// Subscribe this endpoint to token.revoked, session.revoked and the user.* events.
mux.Handle("POST /nine/webhook", nine.WebhookHandler(nine.WebhookConfig{
	Secret:   os.Getenv("NINE_WEBHOOK_SECRET"),
	Verifier: verifier, // revocations evict cached answers
}))
```

| `Mode` | What it does |
|---|---|
| `nine.ModeLocal` | Signature and claims only. No calls to 9in. The default without client credentials. |
| `nine.ModeHybrid` | Local check, then one introspection per token. The answer is cached until a webhook says otherwise or `CacheTTL` passes; a refusal is cached until the token expires. The default with client credentials. |
| `nine.ModeIntrospect` | Introspection on every call. |

Opaque access tokens (`9in_at_…`) are always introspected, and cached in hybrid mode. The
cache is in memory, per process; implement `nine.AnswerCache` to share it, or give each
process the webhooks.

## Manage users

Give a confidential application management scopes (**Applications → app → API Access →
Management API**):

```go
m, err := nine.NewManagementClient(nine.ManagementConfig{
	Issuer:       "https://acme.9in.io", // https://acme-sandbox.9in.io for the sandbox's users
	ClientID:     os.Getenv("NINE_CLIENT_ID"),
	ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
})

user, err := m.CreateUser(ctx, nine.NewUser{Email: "jane@acme.com", Password: "…", EmailVerified: true})
user, err = m.UpdateUser(ctx, user.ID, nine.UserChanges{"phone_number": "+447700900000", "phone_number_verified": true})
user, err = m.BlockUser(ctx, user.ID)
user, err = m.FindUser(ctx, "phone_number", "+447700900000") // or "email", "username"; nine.ErrNotFound when unknown

// Sessions: list them, end one (its sid), or sign the user out everywhere
sessions, err := m.ListUserSessions(ctx, user.ID)
err = m.RevokeSession(ctx, sessions[0].SID)
n, err := m.RevokeUserSessions(ctx, user.ID)

// A single-use sign-in link (magic links, moving a signed-in user from your app to 9in)
link, err := m.CreateLoginLink(ctx, user.ID, nine.LoginLinkOptions{ReturnTo: "https://app.acme.com/nine/callback", TTL: 10 * time.Minute})

// Bulk import (500 per call): old ids, password hashes (bcrypt, argon2, PBKDF2, Firebase scrypt), social identities
results, err := m.ImportUsers(ctx, []nine.ImportUser{
	{ID: "auth0|42", NewUser: nine.NewUser{Email: "jane@acme.com", PasswordHash: "$2b$10$…"}},
}, nine.ImportOptions{OnConflict: "skip", Source: "auth0"})
```

The client gets and caches a client-credentials token for each management scope it uses. Users
and sessions have the API's snake_case JSON names (`email_verified`, `phone_number`,
`created_at`), and `UserChanges` takes them as keys. Errors are `*nine.Error` with the API's
code (`identifier_taken`, `invalid_user`, `not_found`…), HTTP status and `Details`.

## Keep users in your own database

Point a **user database** connection at your server and implement three methods:

```go
type users struct{ db *sql.DB }

func (u users) Authenticate(ctx context.Context, id nine.Identifier, password string) (*nine.AdapterUser, error) {
	user, err := findByLogin(ctx, u.db, id.Type, id.Value) // id.Type: "email", "username" or "phone"
	if err != nil || user == nil || !checkPassword(user, password) {
		return nil, nine.ErrInvalidCredentials
	}
	if user.Disabled {
		return nil, nine.ErrUserBlocked
	}
	return &nine.AdapterUser{ID: user.ID, Email: user.Email, EmailVerified: true, Name: user.Name}, nil
}

func (u users) FindUser(ctx context.Context, q nine.UserQuery) (*nine.AdapterUser, error) {
	user, err := findByQuery(ctx, u.db, q) // q.ID (your id) or q.Identifier
	if err != nil || user == nil {
		return nil, err // nil, nil: there is no such user (404)
	}
	return &nine.AdapterUser{ID: user.ID, Email: user.Email, Name: user.Name}, nil
}

func (u users) OnEvent(ctx context.Context, e *nine.AdapterEvent) error {
	// e.EventType "otp.requested": deliver e.Data["code"] to e.Data["to"] (e.Data["channel"] is "email" or "sms")
	return nil
}

// Serves /nine/authenticate, /nine/user and /nine/event.
mux.Handle("/nine/", nine.AdapterHandler(nine.AdapterConfig{
	Secret:  os.Getenv("NINE_ADAPTER_SECRET"),
	Adapter: users{db},
}))
```

Requests are verified (`9in-signature`: HMAC-SHA256 over the timestamp, method, path and raw
body, 5-minute window, several secrets while you rotate), and every response is signed and
bound to its request id. A runnable version is in [examples/adapter](examples/adapter).

## Webhooks

Add an endpoint under **Advanced → Webhooks** and keep the signing secret it shows once.
`WebhookHandler` verifies each delivery, runs your function once per event, and answers what
9in expects:

```go
mux.Handle("POST /nine/webhook", nine.WebhookHandler(nine.WebhookConfig{
	Secret: os.Getenv("NINE_WEBHOOK_SECRET"),
	Handle: func(ctx context.Context, e *nine.WebhookEvent) error {
		// e.ID, e.EventType, e.CreatedAt, e.Tenant, e.Environment, e.Data
		if e.EventType == "user.created" {
			user, err := e.User()
			if err != nil {
				return err
			}
			return addToCRM(ctx, user)
		}
		return nil // an error answers 500 and 9in retries later
	},
	// Store: a shared nine.EventStore (Redis SET NX, a SQL unique key) with several instances.
}))
```

It answers 204 when the event was handled (or already had been), 409 while another delivery
of the same event is still running (9in retries later), 401 for a bad signature and 500 when
your function failed (the event is released, so the retry handles it). Processed event ids are
kept in memory by default (one process); pass a shared `Store` when you run several.

For your own handler, `nine.VerifyWebhookRequest(r, secret)` (or `nine.VerifyWebhook` with
the raw body, header and path) verifies and parses an event, and `nine.ProcessEventOnce`
runs a function once per event id. Several secrets are accepted while you rotate.

## CLIs, devices and services

The device flow signs users in where there is no browser (a "TV & Device" application):

```go
device, err := nine.NewDeviceAuth(nine.DeviceAuthConfig{Issuer: "https://acme.9in.io", ClientID: "app_tv123"})
code, err := device.Start(ctx)
fmt.Printf("Open %s and enter %s\n", code.VerificationURI, code.UserCode)
tokens, err := device.Wait(ctx, code) // polls until the user approves; nine.ErrAccessDenied, nine.ErrExpiredToken
```

Services get tokens for themselves with client credentials (a machine-to-machine
application), cached until shortly before they expire:

```go
service, err := nine.NewClientCredentials(nine.ClientCredentialsConfig{
	Issuer:       "https://acme.9in.io",
	ClientID:     os.Getenv("NINE_CLIENT_ID"),
	ClientSecret: os.Getenv("NINE_CLIENT_SECRET"),
	Audience:     "https://api.acme.com",
})
token, err := service.Token(ctx)
client := service.HTTPClient(nil) // adds "Authorization: Bearer …" to every request
```

## Issuers must use https

Every constructor rejects an issuer that is not `https://` (`insecure_issuer`), so a typo
can't send tokens or credentials in clear text. Plain http is accepted for `localhost`,
`*.localhost` and loopback addresses; for other development hosts (e.g. `http://auth:8897` in
Docker) set `AllowInsecureIssuer: true` or `NINE_ALLOW_INSECURE_ISSUER=true`. Issuers with a
query, fragment or credentials are rejected too.

## Configuration from the environment

The `…ConfigFromEnv` functions read `NINE_ISSUER`, `NINE_CLIENT_ID`, `NINE_CLIENT_SECRET`,
`NINE_REDIRECT_URI`, `NINE_AUDIENCE`, `NINE_API_SECRET`, `NINE_SECRET`, `NINE_BASE_URL` and
`NINE_ALLOW_INSECURE_ISSUER`; `nine.Env("WEBHOOK_SECRET")` reads any other `NINE_*` setting
(`NINE_ADAPTER_SECRET`, `NINE_WEBHOOK_SECRET`). Constructors never read the environment
themselves: change the returned config before you pass it on.

## Errors

Every failure is a `*nine.Error` with a `Code` (`invalid_token`, `insufficient_scope`,
`login_required`, `invalid_grant`, `invalid_state`, `insecure_issuer`, …), a `Description`
and, for HTTP errors, a `Status`. Test for codes with `errors.Is` and the `nine.Err…` values,
or read the fields with `errors.As`:

```go
claims, err := verifier.Verify(ctx, token, "orders:write")
switch {
case errors.Is(err, nine.ErrInsufficientScope): // 403
case errors.Is(err, nine.ErrInvalidToken): // 401
case err != nil: // 9in unreachable: errors.As(err, &e) gives e.Code and e.Status
}
```

The codes are listed in the [SDK reference](https://9in.io/docs/reference/sdk/#nineerror-codes).
Network calls have a 10-second timeout by default (pass your own `HTTPClient` to change it),
never follow redirects, and nothing is logged.

## Development

```bash
go test -race ./...     # unit tests (Go 1.23+)
go vet ./... && staticcheck ./...
```

The live end-to-end tests run against 9in's test tenants and need their settings
(`NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e go test -run Live ./...`); without them they are
skipped. Report bugs in [issues](https://github.com/9in-io/go-sdk/issues).

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in is by [Cubelet Ltd](https://cubelet.co.uk).
