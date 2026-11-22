package nine

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// The JWS algorithms of 9in's key library.
type algKind int

const (
	kindRSA algKind = iota + 1
	kindPSS
	kindECDSA
	kindEdDSA
)

type algorithm struct {
	kind  algKind
	hash  crypto.Hash
	curve string // ECDSA: the JWK crv
	size  int    // ECDSA: bytes per coordinate (r and s each)
}

var asymmetricAlgorithms = map[string]algorithm{
	"RS256": {kind: kindRSA, hash: crypto.SHA256},
	"RS384": {kind: kindRSA, hash: crypto.SHA384},
	"RS512": {kind: kindRSA, hash: crypto.SHA512},
	"PS256": {kind: kindPSS, hash: crypto.SHA256},
	"PS384": {kind: kindPSS, hash: crypto.SHA384},
	"PS512": {kind: kindPSS, hash: crypto.SHA512},
	"ES256": {kind: kindECDSA, hash: crypto.SHA256, curve: "P-256", size: 32},
	"ES384": {kind: kindECDSA, hash: crypto.SHA384, curve: "P-384", size: 48},
	"EdDSA": {kind: kindEdDSA},
}

var hmacAlgorithms = map[string]func() hash.Hash{
	"HS256": sha256.New,
	"HS384": sha512.New384,
	"HS512": sha512.New,
}

func digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	default:
		sum := sha512.Sum512(data)
		return sum[:]
	}
}

func verifyHMAC(alg, secret string, input string, signature []byte) bool {
	mac := hmac.New(hmacAlgorithms[alg], []byte(secret))
	mac.Write([]byte(input))
	return hmac.Equal(mac.Sum(nil), signature)
}

// jsonWebKey is a public key from a JWKS document.
type jsonWebKey struct {
	Kty    string   `json:"kty"`
	Kid    *string  `json:"kid"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
	Crv    string   `json:"crv"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

// publicKey is a parsed JWK, ready to verify signatures.
type publicKey struct {
	kid    string
	hasKid bool
	alg    string // the JWK's alg member ("" when it names none)
	kty    string
	crv    string
	key    crypto.PublicKey // *rsa.PublicKey, *ecdsa.PublicKey or ed25519.PublicKey
	err    error            // why the key can't be used, when it can't
}

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// Smallest RSA modulus accepted (the key library uses 2048 or 4096 bits).
const minRSABits = 2048

func parseJWK(j jsonWebKey) *publicKey {
	k := &publicKey{alg: j.Alg, kty: j.Kty, crv: j.Crv}
	if j.Kid != nil {
		k.kid, k.hasKid = *j.Kid, true
	}
	switch j.Kty {
	case "RSA":
		n, err1 := decodeSegment(j.N)
		e, err2 := decodeSegment(j.E)
		if err1 != nil || err2 != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			k.err = errors.New("malformed RSA key")
			return k
		}
		exponent := int(new(big.Int).SetBytes(e).Int64())
		modulus := new(big.Int).SetBytes(n)
		if exponent < 3 || exponent%2 == 0 {
			k.err = errors.New("bad RSA exponent")
			return k
		}
		if modulus.BitLen() < minRSABits {
			k.err = errors.New("RSA key too short")
			return k
		}
		k.key = &rsa.PublicKey{N: modulus, E: exponent}
	case "EC":
		var oid asn1.ObjectIdentifier
		var size int
		switch j.Crv {
		case "P-256":
			oid, size = oidP256, 32
		case "P-384":
			oid, size = oidP384, 48
		default:
			k.err = errors.New("unsupported curve")
			return k
		}
		x, err1 := decodeSegment(j.X)
		y, err2 := decodeSegment(j.Y)
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			k.err = errors.New("malformed EC key")
			return k
		}
		// Through SubjectPublicKeyInfo, so the standard library checks the point is on the curve.
		params, _ := asn1.Marshal(oid)
		point := append(append([]byte{4}, x...), y...)
		der, err := asn1.Marshal(struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECPublicKey, Parameters: asn1.RawValue{FullBytes: params}},
			PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
		})
		if err != nil {
			k.err = errors.New("malformed EC key")
			return k
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			k.err = errors.New("invalid EC key")
			return k
		}
		k.key = parsed
	case "OKP":
		x, err := decodeSegment(j.X)
		if j.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			k.err = errors.New("unsupported OKP key")
			return k
		}
		k.key = ed25519.PublicKey(x)
	default:
		k.err = errors.New("unsupported key type")
	}
	return k
}

// fits reports whether the key's type (and curve) can verify alg, whatever its alg member says.
func (k *publicKey) fits(alg string) bool {
	a, ok := asymmetricAlgorithms[alg]
	if !ok {
		return false
	}
	switch a.kind {
	case kindRSA, kindPSS:
		return k.kty == "RSA"
	case kindECDSA:
		return k.kty == "EC" && k.crv == a.curve
	case kindEdDSA:
		return k.kty == "OKP" && k.crv == "Ed25519"
	}
	return false
}

func (k *publicKey) verify(alg string, input string, signature []byte) bool {
	a := asymmetricAlgorithms[alg]
	switch a.kind {
	case kindRSA:
		pub, ok := k.key.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(pub, a.hash, digest(a.hash, []byte(input)), signature) == nil
	case kindPSS:
		pub, ok := k.key.(*rsa.PublicKey)
		// RFC 7518 §3.5: the salt is as long as the hash.
		return ok && rsa.VerifyPSS(pub, a.hash, digest(a.hash, []byte(input)), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.hash}) == nil
	case kindECDSA:
		pub, ok := k.key.(*ecdsa.PublicKey)
		// JWS signatures are r‖s, each exactly the curve's size.
		if !ok || len(signature) != 2*a.size {
			return false
		}
		der, err := asn1.Marshal(struct{ R, S *big.Int }{
			new(big.Int).SetBytes(signature[:a.size]),
			new(big.Int).SetBytes(signature[a.size:]),
		})
		return err == nil && ecdsa.VerifyASN1(pub, digest(a.hash, []byte(input)), der)
	case kindEdDSA:
		pub, ok := k.key.(ed25519.PublicKey)
		return ok && len(signature) == ed25519.SignatureSize && ed25519.Verify(pub, []byte(input), signature)
	}
	return false
}

// ---------------------------------------------------------------------------
// Key set

const (
	jwksTTL = 10 * time.Minute
	// An unknown kid triggers one refetch; the same unknown kid is then ignored this long.
	missThrottle = time.Minute
	maxMisses    = 1000
	// Tokens with random kids can't force more than one refetch per this interval.
	minRefetchInterval = 5 * time.Second
)

// keySet is an issuer's JWKS, cached for ten minutes, refetched once when a token names
// an unknown kid (key rotation), with unknown kids throttled for a minute so junk tokens
// can't make us hammer the JWKS endpoint. Safe for concurrent use.
type keySet struct {
	provider *provider
	http     *http.Client
	now      func() time.Time

	mu      sync.Mutex
	keys    []*publicKey
	fetched time.Time
	misses  map[string]time.Time
	flight  flight[[]*publicKey]
}

func newKeySet(p *provider, client *http.Client, now func() time.Time) *keySet {
	return &keySet{provider: p, http: client, now: now, misses: make(map[string]time.Time)}
}

func (s *keySet) fetch(ctx context.Context, force bool) ([]*publicKey, error) {
	s.mu.Lock()
	if !force && s.keys != nil && s.now().Sub(s.fetched) < jwksTTL {
		keys := s.keys
		s.mu.Unlock()
		return keys, nil
	}
	s.mu.Unlock()
	return s.flight.do(ctx, "jwks", func(ctx context.Context) ([]*publicKey, error) {
		doc, err := s.provider.discovery(ctx)
		if err != nil {
			return nil, err
		}
		var body struct {
			Keys []jsonWebKey `json:"keys"`
		}
		if err := getJSON(ctx, s.http, doc.JWKSURI, nil, "jwks_unavailable", &body); err != nil {
			if e, ok := err.(*Error); ok && e.Code != "jwks_unavailable" {
				e.Description = e.Code + ": " + e.Description
				e.Code = "jwks_unavailable"
			}
			return nil, err
		}
		keys := make([]*publicKey, 0, len(body.Keys))
		for _, j := range body.Keys {
			// Keys published for something other than signatures are not used.
			if j.Use != "" && j.Use != "sig" {
				continue
			}
			keys = append(keys, parseJWK(j))
		}
		s.mu.Lock()
		s.keys, s.fetched = keys, s.now()
		s.mu.Unlock()
		return keys, nil
	})
}

func findKid(keys []*publicKey, kid string, hasKid bool) *publicKey {
	for _, k := range keys {
		if k.hasKid == hasKid && k.kid == kid {
			return k
		}
	}
	return nil
}

// find returns the key named kid (hasKid false: a token without a kid matches a key
// without one), refetching the JWKS once for an unknown kid. nil when there is none.
func (s *keySet) find(ctx context.Context, kid string, hasKid bool) (*publicKey, error) {
	keys, err := s.fetch(ctx, false)
	if err != nil {
		return nil, err
	}
	if k := findKid(keys, kid, hasKid); k != nil {
		return k, nil
	}
	missKey := kid
	if !hasKid {
		missKey = "\x00none"
	}
	s.mu.Lock()
	missedAt, missed := s.misses[missKey]
	recent := s.now().Sub(s.fetched) < minRefetchInterval
	s.mu.Unlock()
	if missed && s.now().Sub(missedAt) < missThrottle {
		return nil, nil
	}
	if recent {
		// Fetched moments ago (perhaps for another unknown kid): don't fetch again, and
		// don't remember this kid as missing, so it is looked up properly next time.
		return nil, nil
	}
	keys, err = s.fetch(ctx, true)
	if err != nil {
		return nil, err
	}
	if k := findKid(keys, kid, hasKid); k != nil {
		return k, nil
	}
	s.mu.Lock()
	if len(s.misses) >= maxMisses {
		s.misses = make(map[string]time.Time)
	}
	s.misses[missKey] = s.now()
	s.mu.Unlock()
	return nil, nil
}
