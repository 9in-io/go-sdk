# Changelog

## 0.2.0

Hybrid verification shares answers and revocations across processes, through one small store
interface for everything the SDK keeps between requests.

- `Store`: a key-value store with expiry (`Get`, `Set`, atomic `Add`, `Delete`), optionally
  `MultiGetter` (`GetMany`). `MemoryStore` is the one-process implementation. It is the same
  interface as 0.1.0's `EventStore`, so an existing implementation keeps working; `EventStore`,
  `MemoryEventStore` and `NewMemoryEventStore` remain as deprecated aliases.
- `VerifierConfig.Store`: with a shared store, every process sees the answers 9in gave and the
  revocations any process received. The process that gets a `token.revoked`,
  `session.revoked` or `user.*` webhook writes a revocation marker for the `jti`, `sid` or user,
  and every process checks those markers before trusting a cached answer (answers are dated
  when 9in was asked, with an allowance for clocks that disagree). Without a store the
  in-memory, per-process cache is unchanged.
- `WebhookHandler` answers 500 when the verifier can't record a revocation in its shared store,
  so 9in delivers the event again.

Breaking (Go 0.x):

- `VerifierConfig.Cache`, `AnswerCache`, `CachedAnswer`, `MemoryAnswerCache` and
  `NewMemoryAnswerCache` are removed. An `AnswerCache` had to find answers by claim to evict
  them, which a plain key-value store can't do; use `VerifierConfig.Store`.
- `Verifier.HandleEvent` returns `(int, error)` and `Verifier.Clear` returns `error`, so a
  store failure isn't lost.

## 0.1.0

The first release of the official Go SDK for 9in (`github.com/9in-io/go-sdk`, package `nine`).
Standard library only, Go 1.23 or later.

- `WebApp`: sign-in for server-rendered apps, ready to mount on any `http.Handler` router:
  `/nine/login`, `/nine/signup`, `/nine/callback` and `/nine/logout`, an encrypted cookie
  session (AES-256-GCM with HKDF-derived keys, secret rotation, chunked cookies), token refresh
  before expiry with rotation (concurrent requests share one refresh), `RequireUser` and
  `Middleware`, `UserFrom(ctx)` and `AccessToken`.
- `WebAppAuth`: the authorization code flow with PKCE (S256), single-use state compared in
  constant time, nonce, the RFC 9207 `iss` check, ID token verification against the JWKS,
  refresh with rotation (`Refresh`, `EnsureFresh`), `Revoke`, `LogoutURL`, `UserInfo` and
  `ClientCredentials`. `return_to` paths are kept only when they stay on your site.
- `Verifier`: access token verification with every algorithm of the key library (RS256/384/512,
  PS256/384/512, ES256, ES384, EdDSA from the JWKS; HS256/384/512 with the API's secret),
  `typ: at+jwt`, the key's own algorithm and type, issuer, `exp`/`nbf`, audience and scopes.
  JWKS cached for 10 minutes, refetched once for an unknown key, unknown keys throttled.
  Modes `local`, `hybrid` (default with client credentials) and `introspect`; opaque
  `9in_at_` tokens are always introspected; `HandleEvent` evicts cached answers on
  `token.revoked`, `session.revoked` and `user.*` webhooks; pluggable `AnswerCache`.
  `VerifyIDToken` for ID tokens.
- `RequireAuth` / `AuthMiddleware`: `net/http` middleware with `ClaimsFrom(ctx)`, answering
  401 `invalid_token`, 403 `insufficient_scope` (RFC 6750 `WWW-Authenticate`) or 503.
- `ManagementClient`: users (list, get, find by email, phone number or username, create,
  update, delete, block, unblock, import), login links and sessions (list, revoke all, revoke
  one), with one cached client-credentials token per management scope.
- `AdapterHandler`: the adapter protocol v2 (`/authenticate`, `/user`, `/event`) with signed
  requests and responses, secret rotation and the same status codes as the other 9in SDKs.
- `VerifyWebhook`, `VerifyWebhookRequest` and `WebhookHandler` (process-once with
  `EventStore` / `MemoryEventStore`, 409 for a concurrent duplicate, verifier eviction);
  `ProcessEventOnce` and `EventDeduplicator`.
- `SignPayload` and `VerifySignature`: the `9in-signature` scheme with strict header parsing.
- `DeviceAuth` (RFC 8628) and `ClientCredentials` (cached tokens and an `http.Client` that
  adds them).
- Issuers must use https (`insecure_issuer`), except localhost and loopback, or with
  `AllowInsecureIssuer` / `NINE_ALLOW_INSECURE_ISSUER=true`.
- `…ConfigFromEnv` functions for the `NINE_*` settings; `*Error` with `Code`, `Description`,
  `Status` and `Details`, and `Err…` values for `errors.Is`.
