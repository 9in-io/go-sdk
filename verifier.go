package nine

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mode is how a [Verifier] checks access tokens: the trade-off between speed and how
// quickly a revocation takes effect.
type Mode string

const (
	// ModeLocal checks the signature and claims only. No calls to 9in per request; a
	// revoked token keeps working until it expires.
	ModeLocal Mode = "local"
	// ModeHybrid checks locally, then asks 9in once per token (introspection) and caches
	// the answer until a webhook says otherwise ([Verifier.HandleEvent]) or CacheTTL
	// passes. A refusal is cached until the token expires.
	ModeHybrid Mode = "hybrid"
	// ModeIntrospect asks 9in about every token on every call.
	ModeIntrospect Mode = "introspect"
)

// OpaquePrefix starts 9in's opaque access tokens, which are always introspected.
const OpaquePrefix = "9in_at_"

// VerifierConfig configures a [Verifier].
type VerifierConfig struct {
	// Issuer is your tenant's issuer, exactly as in the tokens' iss claim, e.g.
	// https://acme.9in.io or your custom login domain.
	Issuer string
	// Audience is your API's identifier: tokens must have it in aud. Leave empty to
	// accept any audience (not recommended).
	Audience string
	// Audiences are more API identifiers to accept, besides Audience.
	Audiences []string
	// Secret is your API's shared secret, for APIs that sign with an HMAC key
	// (HS256/384/512) from the console's key library. JWKS keys need nothing.
	Secret string

	// Mode defaults to ModeHybrid when ClientID and ClientSecret are set, else ModeLocal.
	Mode Mode
	// ClientID and ClientSecret are a confidential application of the tenant, used for
	// introspection (ModeHybrid, ModeIntrospect and opaque tokens).
	ClientID     string
	ClientSecret string
	// CacheTTL is the longest a hybrid answer is trusted without news from 9in.
	// Default 5 minutes. An answer is never kept past the token's expiry.
	CacheTTL time.Duration
	// Store keeps hybrid answers in a store shared by all your processes (Redis, your
	// database), so a revocation webhook received by one of them reaches them all: the
	// process that gets the event writes a small revocation marker, which every process
	// checks before trusting a cached answer. The same Store can serve [WebhookHandler].
	// Default: in memory, per process (then every process must get the webhooks).
	Store Store
	// CacheSize is the most answers the default in-memory cache keeps (default 10 000;
	// the least recently used go first). Not used with Store.
	CacheSize int

	// Leeway is the clock skew allowed for exp and nbf. Default 30 seconds.
	Leeway time.Duration
	// HTTPClient is used for discovery, JWKS and introspection. Default: a client with a
	// 10-second timeout. Redirects are never followed.
	HTTPClient *http.Client
	// AllowInsecureIssuer accepts a plain-http issuer other than localhost (development only).
	AllowInsecureIssuer bool
}

// VerifierConfigFromEnv returns a VerifierConfig from NINE_ISSUER, NINE_AUDIENCE,
// NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_API_SECRET and NINE_ALLOW_INSECURE_ISSUER.
// With a client ID and secret the verifier runs in hybrid mode.
func VerifierConfigFromEnv() VerifierConfig {
	return VerifierConfig{
		Issuer:              Env("ISSUER"),
		Audience:            Env("AUDIENCE"),
		Secret:              Env("API_SECRET"),
		ClientID:            Env("CLIENT_ID"),
		ClientSecret:        Env("CLIENT_SECRET"),
		AllowInsecureIssuer: envBool("ALLOW_INSECURE_ISSUER"),
	}
}

// Verifier verifies 9in access tokens for your API. Create one at startup and share it:
// it caches your tenant's keys (and, in hybrid mode, 9in's answers), and is safe for
// concurrent use.
//
// Every algorithm of 9in's key library is accepted: RS256/384/512, PS256/384/512, ES256,
// ES384 and EdDSA against the tenant's JWKS, and HS256/384/512 with the API's shared
// secret. Tokens must be access tokens (typ at+jwt); when the JWKS key names an
// algorithm, the token must use exactly that one, and the key type must fit it. The
// issuer, expiry (exp, nbf), audience and required scopes are checked. Keys are cached
// for ten minutes and fetched again once when a token names an unknown key.
type Verifier struct {
	issuer       string
	audiences    []string
	secret       string
	mode         Mode
	clientID     string
	clientSecret string
	ttl          time.Duration
	leeway       time.Duration
	http         *http.Client
	provider     *provider
	keys         *keySet
	answers      answerCache
	inflight     flight[Claims]
	now          func() time.Time
}

// NewVerifier returns a Verifier. It fails for a malformed or insecure issuer, an
// unknown mode, or hybrid/introspect mode without client credentials.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, invalidOptions("Issuer is required (NINE_ISSUER)")
	}
	issuer, err := NormalizeIssuer(cfg.Issuer, cfg.AllowInsecureIssuer)
	if err != nil {
		return nil, err
	}
	mode := cfg.Mode
	if mode == "" {
		mode = ModeLocal
		if cfg.ClientID != "" && cfg.ClientSecret != "" {
			mode = ModeHybrid
		}
	}
	switch mode {
	case ModeLocal, ModeHybrid, ModeIntrospect:
	default:
		return nil, invalidOptions("unknown mode " + string(mode) + ` (use "local", "hybrid" or "introspect")`)
	}
	if mode != ModeLocal && (cfg.ClientID == "" || cfg.ClientSecret == "") {
		return nil, invalidOptions(string(mode) + " mode needs ClientID and ClientSecret (a confidential application) for introspection")
	}
	v := &Verifier{
		issuer:       issuer,
		secret:       cfg.Secret,
		mode:         mode,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		ttl:          cfg.CacheTTL,
		leeway:       cfg.Leeway,
		http:         newHTTPClient(cfg.HTTPClient),
		now:          time.Now,
	}
	for _, a := range append([]string{cfg.Audience}, cfg.Audiences...) {
		if a != "" {
			v.audiences = append(v.audiences, a)
		}
	}
	if v.ttl <= 0 {
		v.ttl = 5 * time.Minute
	}
	if v.leeway <= 0 {
		v.leeway = 30 * time.Second
	}
	clock := func() time.Time { return v.now() }
	if cfg.Store != nil {
		v.answers = newStoreAnswers(cfg.Store, issuer, v.ttl, v.leeway, clock)
	} else {
		v.answers = newMemoryAnswers(cfg.CacheSize, clock)
	}
	v.provider = newProvider(issuer, v.http)
	v.keys = newKeySet(v.provider, v.http, func() time.Time { return v.now() })
	v.provider.now = func() time.Time { return v.now() }
	return v, nil
}

// Issuer is the normalised issuer.
func (v *Verifier) Issuer() string { return v.issuer }

// Mode is the verification mode in use.
func (v *Verifier) Mode() Mode { return v.mode }

// Verify verifies an access token (or an Authorization header value, "Bearer …") and
// returns its claims. Each scope argument may hold several space-separated scopes; all
// must be granted.
//
// It fails with invalid_token (Status 401) for a bad token and insufficient_scope (403)
// when a scope is missing. Other errors (9in unreachable, introspection refused) are
// your server's problem, not the caller's.
func (v *Verifier) Verify(ctx context.Context, token string, scopes ...string) (Claims, error) {
	token = stripBearer(token)
	if token == "" {
		return nil, invalidToken("missing token")
	}
	required := splitScopes(scopes)
	opaque := strings.HasPrefix(token, OpaquePrefix)
	if opaque && v.mode == ModeLocal {
		return nil, invalidToken("opaque tokens need hybrid or introspect mode (set ClientID and ClientSecret)")
	}
	var local Claims
	if !opaque {
		var err error
		if local, err = v.verifyLocal(ctx, token, required); err != nil {
			return nil, err
		}
		if v.mode == ModeLocal {
			return local, nil
		}
	}
	claims, err := v.lookup(ctx, token, local)
	if err != nil {
		return nil, err
	}
	if claims == nil {
		return nil, invalidToken("token revoked or no longer active")
	}
	if local == nil {
		if err := v.checkClaims(claims, required); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

func splitScopes(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		out = append(out, strings.Fields(s)...)
	}
	return out
}

var accessTokenTypes = map[string]bool{"at+jwt": true, "application/at+jwt": true}

func (v *Verifier) verifyLocal(ctx context.Context, token string, scopes []string) (Claims, error) {
	parts, ok := decodeJWT(token)
	if !ok {
		return nil, invalidToken("malformed token")
	}
	typ, _ := parts.header["typ"].(string)
	if !accessTokenTypes[strings.ToLower(typ)] {
		return nil, invalidToken("not an access token")
	}
	if err := v.checkSignature(ctx, parts, true, invalidToken); err != nil {
		return nil, err
	}
	if err := v.checkClaims(parts.payload, scopes); err != nil {
		return nil, err
	}
	return parts.payload, nil
}

// checkSignature verifies a JWT's signature with the key the token names, using that
// key's algorithm. HMAC is accepted only for access tokens (allowHMAC).
func (v *Verifier) checkSignature(ctx context.Context, parts *jwtParts, allowHMAC bool, fail func(string) *Error) error {
	if _, ok := parts.header["crit"]; ok {
		return fail("unsupported critical header")
	}
	alg, _ := parts.header["alg"].(string)
	if _, ok := hmacAlgorithms[alg]; ok && allowHMAC {
		if v.secret == "" {
			return fail("HMAC-signed token: pass the API's secret (VerifierConfig.Secret)")
		}
		if !verifyHMAC(alg, v.secret, parts.signingInput, parts.signature) {
			return fail("bad signature")
		}
		return nil
	}
	if _, ok := asymmetricAlgorithms[alg]; !ok {
		return fail("unsupported algorithm")
	}
	kid, hasKid := parts.header["kid"].(string)
	if _, present := parts.header["kid"]; present && !hasKid {
		return fail("unknown signing key")
	}
	key, err := v.keys.find(ctx, kid, hasKid)
	if err != nil {
		return err
	}
	if key == nil {
		return fail("unknown signing key")
	}
	// The key decides the algorithm, never the token alone (no algorithm confusion).
	if (key.alg != "" && key.alg != alg) || !key.fits(alg) {
		return fail("algorithm does not match the key")
	}
	if key.err != nil {
		return fail("unusable signing key: " + key.err.Error())
	}
	if !key.verify(alg, parts.signingInput, parts.signature) {
		return fail("bad signature")
	}
	return nil
}

func (v *Verifier) audienceOK(claims Claims, wanted []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, have := range claims.Audience() {
		for _, w := range wanted {
			if have == w {
				return true
			}
		}
	}
	return false
}

// timeClaims checks iss, exp and nbf.
func (v *Verifier) timeClaims(claims Claims, fail func(string) *Error) error {
	now := v.now()
	if !sameIssuer(claims.Issuer(), v.issuer) {
		return fail("issuer mismatch")
	}
	exp, ok := claims.Int("exp")
	if !ok || time.Unix(exp, 0).Add(v.leeway).Before(now) {
		return fail("token expired")
	}
	if nbf, ok := claims.Int("nbf"); ok && time.Unix(nbf, 0).Add(-v.leeway).After(now) {
		return fail("token not yet valid")
	}
	return nil
}

// checkClaims: issuer, exp/nbf, audience and scopes of a verified JWT or an
// introspection answer.
func (v *Verifier) checkClaims(claims Claims, scopes []string) error {
	if err := v.timeClaims(claims, invalidToken); err != nil {
		return err
	}
	if !v.audienceOK(claims, v.audiences) {
		return invalidToken("audience mismatch")
	}
	var missing []string
	for _, s := range scopes {
		if !claims.HasScope(s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return newError("insufficient_scope", "missing "+strings.Join(missing, ", "), http.StatusForbidden)
	}
	return nil
}

// VerifyIDToken verifies an ID token issued to clientID: the signature (asymmetric keys
// only: 9in signs ID tokens with the tenant's default key), issuer, audience (and azp
// when there are several audiences), expiry, the nonce when expected is not empty, and
// that it is not an access token. It fails with invalid_id_token.
func (v *Verifier) VerifyIDToken(ctx context.Context, idToken, clientID, nonce string) (Claims, error) {
	if idToken == "" {
		return nil, invalidIDToken("missing ID token")
	}
	parts, ok := decodeJWT(idToken)
	if !ok {
		return nil, invalidIDToken("malformed ID token")
	}
	typ, _ := parts.header["typ"].(string)
	if accessTokenTypes[strings.ToLower(typ)] {
		return nil, invalidIDToken("not an ID token")
	}
	if err := v.checkSignature(ctx, parts, false, invalidIDToken); err != nil {
		return nil, err
	}
	claims := parts.payload
	if err := v.timeClaims(claims, invalidIDToken); err != nil {
		return nil, err
	}
	aud := claims.Audience()
	if !v.audienceOK(claims, []string{clientID}) {
		return nil, invalidIDToken("audience mismatch")
	}
	if azp := claims.String("azp"); (len(aud) > 1 || azp != "") && azp != clientID {
		return nil, invalidIDToken("authorized party mismatch")
	}
	if nonce != "" && subtle.ConstantTimeCompare([]byte(claims.String("nonce")), []byte(nonce)) != 1 {
		return nil, invalidIDToken("nonce mismatch")
	}
	if claims.Subject() == "" {
		return nil, invalidIDToken("missing subject")
	}
	return claims, nil
}

// ---------------------------------------------------------------------------
// Hybrid verification

func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// lookup returns the live claims (the token's own for a JWT, once 9in confirms it is
// active), or nil when 9in says it is not active.
func (v *Verifier) lookup(ctx context.Context, token string, local Claims) (Claims, error) {
	key := tokenKey(token)
	if v.mode == ModeHybrid {
		if hit, ok := v.answers.get(ctx, key); ok && hit.Until.After(v.now()) {
			return hit.Claims, nil
		}
	}
	// When 9in was asked, not when it answered: a revocation that lands while the request
	// is in flight must still make this answer stale.
	asked := v.now()
	answer, err := v.inflight.do(ctx, key, func(ctx context.Context) (Claims, error) {
		return v.introspect(ctx, token)
	})
	if err != nil {
		return nil, err
	}
	claims := answer
	if answer != nil && local != nil {
		claims = local
	}
	if v.mode == ModeHybrid {
		now := v.now()
		var expiry time.Time
		if exp, ok := claims.Int("exp"); ok {
			expiry = time.Unix(exp, 0)
		} else if exp, ok := local.Int("exp"); ok {
			expiry = time.Unix(exp, 0)
		}
		var until time.Time
		switch {
		case claims != nil:
			// Trusted for CacheTTL at most, and never past the token's expiry.
			if !expiry.IsZero() {
				until = now.Add(v.ttl)
				if expiry.Before(until) {
					until = expiry
				}
			}
		case !expiry.IsZero():
			// A revoked token never comes back: remember the refusal until it expires.
			until = expiry
		default:
			until = now.Add(time.Minute)
		}
		if until.After(now) {
			v.answers.set(ctx, key, cachedAnswer{Claims: claims, Until: until, At: asked})
		}
	}
	return claims, nil
}

func (v *Verifier) introspect(ctx context.Context, token string) (Claims, error) {
	doc, err := v.provider.discovery(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := doc.IntrospectionEndpoint
	if endpoint == "" {
		endpoint = v.issuer + "/oauth/introspect"
	}
	var answer Claims
	err = postForm(ctx, v.http, endpoint, url.Values{"token": {token}}, clientAuth{v.clientID, v.clientSecret}, "introspection_failed", &answer)
	if err != nil {
		return nil, err
	}
	if active, _ := answer["active"].(bool); !active || answer.String("token_type") == "refresh_token" {
		return nil, nil
	}
	return answer, nil
}

// Events that make cached answers about a user stale.
var userEvictingEvents = map[string]bool{
	"user.sessions_revoked": true,
	"user.deleted":          true,
	"user.updated":          true,
	"user.password_changed": true,
}

// HandleEvent drops the cached hybrid answers a webhook event makes stale: token.revoked
// (an access token) by jti, session.revoked by sid, and user.sessions_revoked,
// user.deleted, user.updated and user.password_changed by user. Subscribe your webhook
// endpoint to those events and pass every verified event here ([WebhookConfig].Verifier
// does it for you).
//
// It returns how many answers it dropped from the in-memory cache, or, with a shared
// [VerifierConfig].Store, 1 when it wrote a revocation marker (the answers it covers can't
// be counted). An error means the shared store couldn't be written: answer the webhook
// with a 5xx so 9in delivers it again.
func (v *Verifier) HandleEvent(ctx context.Context, event *WebhookEvent) (int, error) {
	if event == nil {
		return 0, nil
	}
	data := event.Data
	str := func(name string) string { s, _ := data[name].(string); return s }
	switch {
	case event.EventType == "token.revoked" && str("token_type") == "access_token" && str("jti") != "":
		return v.answers.evict(ctx, "jti", str("jti"))
	case event.EventType == "session.revoked" && str("sid") != "":
		return v.answers.evict(ctx, "sid", str("sid"))
	case userEvictingEvents[event.EventType]:
		if id := event.UserID(); id != "" {
			return v.answers.evict(ctx, "sub", id)
		}
	}
	return 0, nil
}

// Clear forgets every cached hybrid answer (in every process, with a shared Store).
func (v *Verifier) Clear(ctx context.Context) error { return v.answers.clear(ctx) }
