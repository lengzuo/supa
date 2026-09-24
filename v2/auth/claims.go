package auth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKSCacheTTL is how long a fetched JWKS is reused before it is fetched
// again (auth-js JWKS_TTL).
const JWKSCacheTTL = 10 * time.Minute

// JWK is a JSON Web Key as served by /.well-known/jwks.json.
type JWK struct {
	Kty    string   `json:"kty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	Kid    string   `json:"kid,omitempty"`
	Use    string   `json:"use,omitempty"`
	// RSA public key members.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC public key members.
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// GetClaimsOptions configure GetClaims.
type GetClaimsOptions struct {
	// AllowExpired skips the exp check (the signature is still verified).
	AllowExpired bool
	// Keys are trusted signing keys to try before the project's JWKS, e.g.
	// keys bundled with the application to avoid a network round trip.
	Keys []JWK
}

// ClaimsResult is a verified JWT.
type ClaimsResult struct {
	Claims    Claims
	Header    JWTHeader
	Signature []byte
}

// jwksCache caches JWKS per endpoint URL across Clients in the process, so
// servers that create a Client per request still reuse fetched keys.
var jwksCache = struct {
	sync.Mutex
	m map[string]jwksEntry
}{m: map[string]jwksEntry{}}

type jwksEntry struct {
	keys      []JWK
	fetchedAt time.Time
}

// GetClaims verifies a JWT and returns its claims. With jwt == "" the
// stored session's access token is used (ErrSessionMissing if none).
//
// Tokens signed with an asymmetric key (RS256, ES256) are verified locally
// against the project's JWKS (GET /.well-known/jwks.json, cached for
// JWKSCacheTTL). Symmetric (HS256) tokens, tokens without a kid, and tokens
// whose kid is not in the JWKS are validated by the Auth server via GetUser
// instead, as in auth-js. Expired tokens are rejected unless
// opts.AllowExpired. Errors from local verification match ErrInvalidJWT.
func (c *Client) GetClaims(ctx context.Context, jwt string, opts *GetClaimsOptions) (*ClaimsResult, error) {
	if opts == nil {
		opts = &GetClaimsOptions{}
	}
	token := jwt
	if token == "" {
		s, err := c.GetSession(ctx)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, ErrSessionMissing
		}
		token = s.AccessToken
	}
	d, err := decodeJWT(token)
	if err != nil {
		return nil, err
	}
	if !opts.AllowExpired {
		if d.Claims.ExpiresAt == 0 {
			return nil, invalidJWT("missing exp claim")
		}
		if d.Claims.ExpiresAt <= c.now().Unix() {
			return nil, invalidJWT("JWT has expired")
		}
	}
	result := &ClaimsResult{Claims: d.Claims, Header: d.Header, Signature: d.Signature}

	var key *JWK
	if d.Header.Alg != "" && !strings.HasPrefix(d.Header.Alg, "HS") && d.Header.Kid != "" {
		if key, err = c.fetchJWK(ctx, d.Header.Kid, opts.Keys); err != nil {
			return nil, err
		}
	}
	if key == nil {
		// The server validates the token; if it accepts it the claims can
		// be trusted.
		if _, err := c.fetchUser(ctx, token); err != nil {
			return nil, err
		}
		return result, nil
	}
	if err := verifyJWTSignature(d, key); err != nil {
		return nil, err
	}
	return result, nil
}

// fetchJWK finds the key with kid in supplied keys, then the cached JWKS,
// then a freshly fetched JWKS. It returns nil when no key matches.
func (c *Client) fetchJWK(ctx context.Context, kid string, supplied []JWK) (*JWK, error) {
	for i := range supplied {
		if supplied[i].Kid == kid {
			k := supplied[i]
			return &k, nil
		}
	}
	endpoint := c.t.URL("/.well-known/jwks.json", nil)
	now := c.now()

	jwksCache.Lock()
	entry, ok := jwksCache.m[endpoint]
	jwksCache.Unlock()
	if ok && now.Sub(entry.fetchedAt) < JWKSCacheTTL {
		if k := findJWK(entry.keys, kid); k != nil {
			return k, nil
		}
	}

	var out struct {
		Keys []JWK `json:"keys"`
	}
	if err := c.call(ctx, http.MethodGet, "/.well-known/jwks.json", nil, "", nil, &out); err != nil {
		return nil, err
	}
	if len(out.Keys) == 0 {
		return nil, nil
	}
	jwksCache.Lock()
	jwksCache.m[endpoint] = jwksEntry{keys: out.Keys, fetchedAt: now}
	jwksCache.Unlock()
	return findJWK(out.Keys, kid), nil
}

func findJWK(keys []JWK, kid string) *JWK {
	for i := range keys {
		if keys[i].Kid == kid {
			k := keys[i]
			return &k
		}
	}
	return nil
}

// verifyJWTSignature checks d's signature with key for RS256 and ES256.
func verifyJWTSignature(d *decodedJWT, key *JWK) error {
	digest := sha256.Sum256([]byte(d.SigningInput))
	switch d.Header.Alg {
	case "RS256":
		pub, err := rsaPublicKey(key)
		if err != nil {
			return err
		}
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], d.Signature) != nil {
			return invalidJWT("invalid JWT signature")
		}
		return nil
	case "ES256":
		pub, err := ecP256PublicKey(key)
		if err != nil {
			return err
		}
		if len(d.Signature) != 64 {
			return invalidJWT("invalid JWT signature")
		}
		r := new(big.Int).SetBytes(d.Signature[:32])
		s := new(big.Int).SetBytes(d.Signature[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return invalidJWT("invalid JWT signature")
		}
		return nil
	default:
		return invalidJWT("unsupported JWT alg " + d.Header.Alg)
	}
}

func rsaPublicKey(k *JWK) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, invalidJWT("signing key is not an RSA key")
	}
	n, err1 := base64.RawURLEncoding.DecodeString(k.N)
	e, err2 := base64.RawURLEncoding.DecodeString(k.E)
	if err := errors.Join(err1, err2); err != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
		return nil, invalidJWT("malformed RSA signing key")
	}
	exp := 0
	for _, b := range e {
		exp = exp<<8 | int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
	if pub.N.BitLen() < 2048 || exp < 3 {
		return nil, invalidJWT("RSA signing key is too weak")
	}
	return pub, nil
}

func ecP256PublicKey(k *JWK) (*ecdsa.PublicKey, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, invalidJWT("signing key is not a P-256 EC key")
	}
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err := errors.Join(err1, err2); err != nil || len(x) != 32 || len(y) != 32 {
		return nil, invalidJWT("malformed EC signing key")
	}
	// crypto/ecdh validates that the point is on the curve.
	point := append(append([]byte{4}, x...), y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, invalidJWT("malformed EC signing key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}
