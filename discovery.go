package nine

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Discovery is your tenant's OpenID Connect discovery document
// (<issuer>/.well-known/openid-configuration), with the fields this package uses.
type Discovery struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint,omitempty"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint,omitempty"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
}

// How long a discovery document is kept before it is fetched again.
const discoveryTTL = time.Hour

// provider is one issuer's discovery document, fetched once and cached. Failures are
// not cached. Safe for concurrent use.
type provider struct {
	issuer string
	http   *http.Client
	now    func() time.Time

	mu      sync.Mutex
	doc     *Discovery
	fetched time.Time
	flight  flight[*Discovery]
}

func newProvider(issuer string, client *http.Client) *provider {
	return &provider{issuer: issuer, http: client, now: time.Now}
}

func (p *provider) discovery(ctx context.Context) (*Discovery, error) {
	p.mu.Lock()
	if p.doc != nil && p.now().Sub(p.fetched) < discoveryTTL {
		doc := p.doc
		p.mu.Unlock()
		return doc, nil
	}
	p.mu.Unlock()
	return p.flight.do(ctx, "discovery", func(ctx context.Context) (*Discovery, error) {
		var doc Discovery
		if err := getJSON(ctx, p.http, p.issuer+"/.well-known/openid-configuration", nil, "discovery_failed", &doc); err != nil {
			if e, ok := err.(*Error); ok && e.Code != "discovery_failed" {
				// A JSON error body from a non-OAuth endpoint: keep the status, use our code.
				e.Description = e.Code + ": " + e.Description
				e.Code = "discovery_failed"
			}
			return nil, err
		}
		if doc.TokenEndpoint == "" || doc.JWKSURI == "" {
			return nil, newError("discovery_failed", "the discovery document has no token_endpoint or jwks_uri", 0)
		}
		// OpenID Connect Discovery §4.3: the document must be for the issuer we asked.
		if doc.Issuer != "" && !sameIssuer(doc.Issuer, p.issuer) {
			return nil, newError("discovery_failed", "the discovery document is for issuer "+doc.Issuer+", not "+p.issuer, 0)
		}
		p.mu.Lock()
		p.doc, p.fetched = &doc, p.now()
		p.mu.Unlock()
		return &doc, nil
	})
}
