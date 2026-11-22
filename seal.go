package nine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// sealer encrypts cookie values with AES-256-GCM. Each secret gives a key through
// HKDF-SHA-256; the cookie's purpose is the additional data, so a value sealed for one
// cookie can't be used as another. The first secret seals; all of them open, so secrets
// can be rotated.
type sealer struct {
	aeads []cipher.AEAD
}

// Shortest secret accepted for cookie encryption.
const minSecretLength = 32

func newSealer(secrets []string) (*sealer, error) {
	if len(secrets) == 0 {
		return nil, invalidOptions("Secret is required (NINE_SECRET): 32+ characters, e.g. `openssl rand -base64 32`")
	}
	s := &sealer{}
	for _, secret := range secrets {
		if len(secret) < minSecretLength {
			return nil, invalidOptions("Secret must be at least 32 characters (e.g. `openssl rand -base64 32`)")
		}
		block, err := aes.NewCipher(hkdfSHA256([]byte(secret), []byte("9in-go"), []byte("cookie encryption"), 32))
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.aeads = append(s.aeads, aead)
	}
	return s, nil
}

// hkdfSHA256 is HKDF (RFC 5869) with SHA-256, for length ≤ 32 bytes.
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{1})
	return expand.Sum(nil)[:length]
}

// seal returns base64url(nonce ‖ ciphertext) of v as JSON.
func (s *sealer) seal(v any, purpose string) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	aead := s.aeads[0]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte(purpose))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open decrypts a sealed value into v with any of the secrets; false when it doesn't open.
func (s *sealer) open(text, purpose string, v any) bool {
	data, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return false
	}
	for _, aead := range s.aeads {
		if len(data) < aead.NonceSize()+aead.Overhead() {
			return false
		}
		plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(purpose))
		if err != nil {
			continue
		}
		return json.Unmarshal(plain, v) == nil
	}
	return false
}

// ---------------------------------------------------------------------------
// Cookies (browsers keep about 4 KB per cookie, so large values are split)

// Leaves room for the name and attributes within the ~4096-byte limit.
const cookieChunkSize = 3800

// chunkCookie splits a value into name (when it fits) or name.0, name.1, …
func chunkCookie(name, value string) map[string]string {
	if len(value) <= cookieChunkSize {
		return map[string]string{name: value}
	}
	out := map[string]string{}
	for i := 0; i*cookieChunkSize < len(value); i++ {
		end := min((i+1)*cookieChunkSize, len(value))
		out[name+"."+strconv.Itoa(i)] = value[i*cookieChunkSize : end]
	}
	return out
}

// readChunked joins what chunkCookie wrote; "" when the cookie isn't there.
func readChunked(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	var b strings.Builder
	for i := 0; ; i++ {
		c, err := r.Cookie(name + "." + strconv.Itoa(i))
		if err != nil {
			break
		}
		b.WriteString(c.Value)
	}
	return b.String()
}

// chunkNames lists the request's cookies that belong to name (whole or chunked).
func chunkNames(r *http.Request, name string) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range r.Cookies() {
		if seen[c.Name] {
			continue
		}
		if c.Name == name || isChunkOf(c.Name, name) {
			seen[c.Name] = true
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

func isChunkOf(cookie, name string) bool {
	rest, ok := strings.CutPrefix(cookie, name+".")
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
