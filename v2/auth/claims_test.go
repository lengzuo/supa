package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

func signedJWT(t *testing.T, alg, kid string, claims map[string]any, sign func(digest []byte) []byte) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	p, _ := json.Marshal(claims)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	d := sha256.Sum256([]byte(input))
	return input + "." + b64.EncodeToString(sign(d[:]))
}

func rsaJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{Kty: "RSA", Kid: kid, Alg: "RS256", KeyOps: []string{"verify"},
		N: b64.EncodeToString(pub.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}
}

func ecJWK(kid string, pub *ecdsa.PublicKey) JWK {
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return JWK{Kty: "EC", Kid: kid, Alg: "ES256", Crv: "P-256", X: b64.EncodeToString(x), Y: b64.EncodeToString(y)}
}

// upstream: auth-js src/GoTrueClient.ts getClaims / fetchJwk
func TestGetClaims(t *testing.T) {
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signRSA := func(d []byte) []byte {
		s, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, d)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	signEC := func(d []byte) []byte {
		r, s, err := ecdsa.Sign(rand.Reader, ecKey, d)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/.well-known/jwks.json":
			coreJSON(w, 200, map[string]any{"keys": []JWK{rsaJWK("rsa-1", &rsaKey.PublicKey), ecJWK("ec-1", &ecKey.PublicKey)}})
		case "/auth/v1/user":
			if r.Header.Get("Authorization") == "Bearer "+coreJWT(map[string]any{"sub": "rejected", "exp": 9999999999}) {
				coreJSON(w, 401, map[string]any{"code": "bad_jwt", "msg": "invalid JWT"})
				return
			}
			coreJSON(w, 200, coreUser("user-1"))
		}
	})
	exp := time.Now().Add(time.Hour).Unix()
	claims := map[string]any{"sub": "user-1", "exp": exp, "role": "authenticated", "aal": "aal1",
		"amr": []any{"password"}, "custom": "x"}

	t.Run("RS256 via JWKS with cache", func(t *testing.T) {
		c := srv.client(t)
		tok := signedJWT(t, "RS256", "rsa-1", claims, signRSA)
		res, err := c.GetClaims(ctx, tok, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Claims.Subject != "user-1" || res.Claims.Raw["custom"] != "x" || res.Header.Kid != "rsa-1" || res.Claims.AMR[0].Method != "password" {
			t.Fatalf("claims = %+v", res)
		}
		coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/.well-known/jwks.json", coreAPIKey)
		if _, err := c.GetClaims(ctx, tok, nil); err != nil {
			t.Fatal(err)
		}
		if n := srv.count("/auth/v1/.well-known/jwks.json"); n != 1 {
			t.Fatalf("%d JWKS fetches, want 1 (cached)", n)
		}
		// After the TTL the JWKS is fetched again.
		c.now = func() time.Time { return time.Now().Add(JWKSCacheTTL + time.Minute) }
		c2 := srv.client(t)
		c2.now = c.now
		if _, err := c2.GetClaims(ctx, tok, &GetClaimsOptions{AllowExpired: true}); err != nil {
			t.Fatal(err)
		}
		if n := srv.count("/auth/v1/.well-known/jwks.json"); n != 2 {
			t.Fatalf("%d JWKS fetches after TTL, want 2", n)
		}
		if srv.count("/auth/v1/user") != 0 {
			t.Fatal("asymmetric token fell back to GetUser")
		}
	})
	t.Run("ES256 with supplied keys", func(t *testing.T) {
		c := srv.client(t)
		before := len(srv.requests())
		tok := signedJWT(t, "ES256", "ec-local", claims, signEC)
		if _, err := c.GetClaims(ctx, tok, &GetClaimsOptions{Keys: []JWK{ecJWK("ec-local", &ecKey.PublicKey)}}); err != nil {
			t.Fatal(err)
		}
		if len(srv.requests()) != before {
			t.Fatal("supplied key still triggered a request")
		}
	})
	t.Run("invalid signature", func(t *testing.T) {
		c := srv.client(t)
		tok := signedJWT(t, "ES256", "ec-1", claims, func(d []byte) []byte { return make([]byte, 64) })
		if _, err := c.GetClaims(ctx, tok, nil); !errors.Is(err, ErrInvalidJWT) {
			t.Fatalf("err = %v", err)
		}
		// RS256 header with an EC key is rejected.
		tok = signedJWT(t, "RS256", "ec-1", claims, signRSA)
		if _, err := c.GetClaims(ctx, tok, nil); !errors.Is(err, ErrInvalidJWT) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		c := srv.client(t)
		old := map[string]any{"sub": "user-1", "exp": time.Now().Add(-time.Hour).Unix()}
		tok := signedJWT(t, "RS256", "rsa-1", old, signRSA)
		if _, err := c.GetClaims(ctx, tok, nil); !errors.Is(err, ErrInvalidJWT) {
			t.Fatalf("err = %v", err)
		}
		if _, err := c.GetClaims(ctx, tok, &GetClaimsOptions{AllowExpired: true}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("HS256 and unknown kid fall back to GetUser", func(t *testing.T) {
		c := srv.client(t)
		hs := coreJWT(map[string]any{"sub": "user-1", "exp": exp})
		if _, err := c.GetClaims(ctx, hs, nil); err != nil {
			t.Fatal(err)
		}
		coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", hs)
		tok := signedJWT(t, "RS256", "unknown-kid", claims, signRSA)
		if _, err := c.GetClaims(ctx, tok, nil); err != nil {
			t.Fatal(err)
		}
		coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", tok)
		rejected := coreJWT(map[string]any{"sub": "rejected", "exp": 9999999999})
		if _, err := c.GetClaims(ctx, rejected, nil); !errors.Is(err, &Error{Code: ErrorCodeBadJWT}) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("stored session and errors", func(t *testing.T) {
		c := srv.client(t)
		if _, err := c.GetClaims(ctx, "", nil); !errors.Is(err, ErrSessionMissing) {
			t.Fatalf("err = %v", err)
		}
		tok := signedJWT(t, "RS256", "rsa-1", claims, signRSA)
		coreStoreSession(t, c, tok, "rt", time.Now().Add(time.Hour))
		if res, err := c.GetClaims(ctx, "", nil); err != nil || res.Claims.Subject != "user-1" {
			t.Fatalf("GetClaims = %+v, %v", res, err)
		}
		if _, err := c.GetClaims(ctx, "garbage", nil); !errors.Is(err, ErrInvalidJWT) {
			t.Fatalf("err = %v", err)
		}
	})
}

// upstream: auth-js src/lib/types.ts AMREntry (object or RFC 8176 string form)
func TestAMREntryUnmarshal(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"amr":[{"method":"otp","timestamp":5},"pwd"]}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.AMR[0] != (AMREntry{Method: "otp", Timestamp: 5}) || c.AMR[1].Method != "pwd" {
		t.Fatalf("amr = %+v", c.AMR)
	}
}
