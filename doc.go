// Package nine is the official Go SDK for 9in (https://9in.io): hosted login, OpenID
// Connect provider and single sign-on.
//
// It uses only the standard library and covers:
//
//   - Signing users in to web apps: [WebApp] mounts /nine/login, /nine/callback and
//     /nine/logout with an encrypted cookie session and [WebApp.RequireUser] middleware;
//     [WebAppAuth] is the flow underneath (authorization code + PKCE, state, nonce, the
//     RFC 9207 iss check, ID token verification, refresh token rotation, logout).
//   - Protecting APIs: [Verifier] checks access tokens locally with every algorithm of
//     9in's key library, or in hybrid mode (local check plus one cached introspection per
//     token, evicted by webhooks) so revocations apply at once. [RequireAuth] is the
//     net/http middleware and [ClaimsFrom] reads the claims.
//   - The Management API: [ManagementClient] (users, sessions, login links, imports).
//   - Keeping users in your own database: [AdapterHandler] serves the adapter protocol v2.
//   - Webhooks: [VerifyWebhook] and [WebhookHandler], which processes each event once
//     ([EventStore], [MemoryEventStore]).
//   - CLIs, devices and services: [DeviceAuth] (RFC 8628) and [ClientCredentials].
//
// Every type is safe for concurrent use: create clients once and share them. Every call
// takes a [context.Context]; network calls have a 10-second timeout by default, never
// follow redirects, and nothing is logged. Every failure is an [*Error] with an
// OAuth-style Code and an HTTP Status; test for codes with [errors.Is] and the Err values.
//
// Issuers must use https: http is accepted only for localhost, *.localhost and loopback
// addresses, unless you allow it (AllowInsecureIssuer, NINE_ALLOW_INSECURE_ISSUER=true).
//
// Guides are at https://9in.io/docs/.
package nine
