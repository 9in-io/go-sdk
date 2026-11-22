package nine

import (
	"os"
	"strings"
)

// Env returns the value of the NINE_<name> environment variable, or "" when it is unset.
// Env("ISSUER") and Env("NINE_ISSUER") both read NINE_ISSUER.
//
// The settings this package reads are NINE_ISSUER, NINE_CLIENT_ID, NINE_CLIENT_SECRET,
// NINE_REDIRECT_URI, NINE_AUDIENCE, NINE_API_SECRET (an API's HMAC secret),
// NINE_ADAPTER_SECRET, NINE_WEBHOOK_SECRET, NINE_SECRET and NINE_BASE_URL ([WebApp]),
// and NINE_ALLOW_INSECURE_ISSUER. Only the …FromEnv functions read them.
func Env(name string) string {
	if !strings.HasPrefix(name, "NINE_") {
		name = "NINE_" + name
	}
	return strings.TrimSpace(os.Getenv(name))
}

func envBool(name string) bool {
	switch strings.ToLower(Env(name)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// envList splits a comma-separated variable (several secrets during a rotation).
func envList(name string) []string {
	var out []string
	for _, part := range strings.Split(Env(name), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
