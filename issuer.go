package nine

import (
	"net/url"
	"regexp"
	"strings"
)

var loopbackV4 = regexp.MustCompile(`^127(\.\d{1,3}){3}$`)

func isLocalHost(hostname string) bool {
	host := strings.ToLower(strings.Trim(hostname, "[]"))
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "::1" || loopbackV4.MatchString(host)
}

// NormalizeIssuer checks an issuer URL and returns it without a trailing slash.
//
// Issuers must use https, so a typo can't send tokens or credentials in clear text. Plain
// http is accepted for localhost, *.localhost and loopback addresses (development), when
// allowInsecure is true, or when NINE_ALLOW_INSECURE_ISSUER=true. An issuer with a query,
// a fragment or credentials is refused. The errors are invalid_issuer and insecure_issuer.
//
// Every constructor in this package calls it, so you only need it to check a setting early.
func NormalizeIssuer(issuer string, allowInsecure bool) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return "", newError("invalid_issuer", "not a URL: "+issuer, 0)
	}
	if strings.ContainsAny(issuer, "?#") || u.User != nil {
		return "", newError("invalid_issuer", "an issuer has no query, fragment or credentials", 0)
	}
	scheme := strings.ToLower(u.Scheme)
	secure := scheme == "https" ||
		(scheme == "http" && (allowInsecure || isLocalHost(u.Hostname()) || envBool("ALLOW_INSECURE_ISSUER")))
	if !secure {
		return "", newError("insecure_issuer", "issuer must use https (got "+scheme+"://"+u.Host+"); plain http is only accepted for localhost", 0)
	}
	return strings.TrimRight(issuer, "/"), nil
}

// sameIssuer compares an iss value with the normalised issuer (a trailing slash is ignored).
func sameIssuer(iss, issuer string) bool {
	return iss != "" && strings.TrimRight(iss, "/") == issuer
}
