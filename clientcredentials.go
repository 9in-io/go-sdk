package nine

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ClientCredentialsConfig configures a [ClientCredentials] token source.
type ClientCredentialsConfig struct {
	// Issuer is your tenant's issuer.
	Issuer string
	// ClientID and ClientSecret are a confidential (machine-to-machine) application.
	ClientID     string
	ClientSecret string
	// Audience is the API to call; leave empty for the Management API.
	Audience string
	// Scopes to request; empty means every scope the application was granted for Audience.
	Scopes []string
	// HTTPClient is used for the token requests. Default: a client with a 10-second timeout.
	HTTPClient *http.Client
	// AllowInsecureIssuer accepts a plain-http issuer other than localhost (development only).
	AllowInsecureIssuer bool
}

// ClientCredentialsConfigFromEnv returns a ClientCredentialsConfig from NINE_ISSUER,
// NINE_CLIENT_ID, NINE_CLIENT_SECRET, NINE_AUDIENCE and NINE_ALLOW_INSECURE_ISSUER.
func ClientCredentialsConfigFromEnv() ClientCredentialsConfig {
	return ClientCredentialsConfig{
		Issuer:              Env("ISSUER"),
		ClientID:            Env("CLIENT_ID"),
		ClientSecret:        Env("CLIENT_SECRET"),
		Audience:            Env("AUDIENCE"),
		AllowInsecureIssuer: envBool("ALLOW_INSECURE_ISSUER"),
	}
}

// ClientCredentials gets access tokens for a service itself (no user) with the client
// credentials grant, and caches each until shortly before it expires. Concurrent
// callers share one request. Safe for concurrent use.
type ClientCredentials struct {
	o    *oauthClient
	opts ClientCredentialsOptions

	mu     sync.Mutex
	token  string
	until  time.Time
	flight flight[string]
}

// How long before expiry a cached token is replaced.
const tokenRenewBefore = 30 * time.Second

// NewClientCredentials returns a ClientCredentials token source.
func NewClientCredentials(cfg ClientCredentialsConfig) (*ClientCredentials, error) {
	if cfg.Issuer == "" {
		return nil, invalidOptions("Issuer is required (NINE_ISSUER)")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, invalidOptions("ClientID and ClientSecret are required (a confidential application)")
	}
	issuer, err := NormalizeIssuer(cfg.Issuer, cfg.AllowInsecureIssuer)
	if err != nil {
		return nil, err
	}
	o, err := newOAuthClient(issuer, cfg.ClientID, cfg.ClientSecret, cfg.HTTPClient, 0)
	if err != nil {
		return nil, err
	}
	return &ClientCredentials{o: o, opts: ClientCredentialsOptions{Audience: cfg.Audience, Scope: strings.Join(splitScopes(cfg.Scopes), " ")}}, nil
}

// Token returns a valid access token, from the cache or a new client-credentials request.
func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && c.o.now().Before(c.until) {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()
	return c.flight.do(ctx, "token", func(ctx context.Context) (string, error) {
		set, err := c.o.clientCredentials(ctx, c.opts)
		if err != nil {
			return "", err
		}
		c.mu.Lock()
		c.token, c.until = set.AccessToken, set.ExpiresAt.Add(-tokenRenewBefore)
		c.mu.Unlock()
		return set.AccessToken, nil
	})
}

// Invalidate forgets the cached token, so the next call gets a new one (after a 401
// from your API, say).
func (c *ClientCredentials) Invalidate() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

// HTTPClient returns a copy of base (or of http.DefaultClient) that adds
// "Authorization: Bearer <token>" to every request. Use it only for the API the token
// is for.
func (c *ClientCredentials) HTTPClient(base *http.Client) *http.Client {
	var out http.Client
	if base != nil {
		out = *base
	}
	next := out.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	out.Transport = &bearerTransport{source: c, next: next}
	return &out
}

type bearerTransport struct {
	source *ClientCredentials
	next   http.RoundTripper
}

func (t *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := t.source.Token(r.Context())
	if err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+token)
	return t.next.RoundTrip(clone)
}
