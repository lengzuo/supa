package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// upstream: auth-js src/GoTrueClient.ts exchangeCodeForSession (server use: no shared session)
func TestExchangeCodeForSessionNoStore(t *testing.T) {
	ctx := context.Background()
	srv := pkceExchangeServer(t)
	c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	ev := coreWatch(c)
	flow, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"})
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := c.retrievePKCEVerifier(ctx, flow.FlowID)
	resp, err := c.ExchangeCodeForSession(ctx, "code-1", &ExchangeCodeOptions{FlowID: flow.FlowID, NoStore: true})
	if err != nil || resp.Session == nil || resp.User == nil {
		t.Fatalf("ExchangeCodeForSession = %+v, %v", resp, err)
	}
	if got := srv.last(t).Body["code_verifier"]; got != verifier {
		t.Fatalf("code_verifier = %v", got)
	}
	if coreStored(t, c) != nil {
		t.Fatal("NoStore exchange stored the session")
	}
	coreAssertEvents(t, ev)
	if v, _ := c.retrievePKCEVerifier(ctx, flow.FlowID); v != "" {
		t.Fatal("verifier kept")
	}
	if len(c.pkceIndex(ctx)) != 0 {
		t.Fatal("flow index kept")
	}

	// The verifier is gone even when the exchange fails.
	flow2, _ := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"})
	if _, err := c.ExchangeCodeForSession(ctx, "bad-code", &ExchangeCodeOptions{FlowID: flow2.FlowID, NoStore: true}); err == nil {
		t.Fatal("want error")
	}
	if v, _ := c.retrievePKCEVerifier(ctx, flow2.FlowID); v != "" {
		t.Fatal("verifier kept after failed exchange")
	}
}

// upstream: auth-js src/GoTrueClient.ts _getSessionFromURL (server use: no shared session)
func TestGetSessionFromURLNoStore(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Path == "/auth/v1/user" {
			coreJSON(w, 200, coreUser("user-5"))
			return
		}
		coreJSON(w, 200, coreSession("at", "rt", 3600))
	})
	c := srv.client(t)
	ev := coreWatch(c)
	frag := url.Values{"access_token": {"frag-at"}, "refresh_token": {"frag-rt"}, "expires_in": {"3600"},
		"expires_at": {strconv.FormatInt(time.Now().Unix()+3600, 10)}, "token_type": {"bearer"}}
	resp, err := c.GetSessionFromURL(ctx, "https://app/cb#"+frag.Encode(), &GetSessionFromURLOptions{NoStore: true})
	if err != nil || resp.Session.AccessToken != "frag-at" {
		t.Fatalf("GetSessionFromURL = %+v, %v", resp, err)
	}
	pc := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	if _, err := pc.SignInWithOTP(ctx, SignInWithOTPParams{Email: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	pev := coreWatch(pc)
	if _, err := pc.GetSessionFromURL(ctx, "https://app/cb?code=c", &GetSessionFromURLOptions{NoStore: true}); err != nil {
		t.Fatal(err)
	}
	if coreStored(t, c) != nil || coreStored(t, pc) != nil {
		t.Fatal("NoStore callback stored a session")
	}
	coreAssertEvents(t, ev)
	coreAssertEvents(t, pev)
}

// upstream: auth-js src/GoTrueClient.ts _signOut (only the signed-out session is removed)
func TestSignOutKeepsConcurrentSignIn(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/logout":
			g.wait()
			w.WriteHeader(204)
		default:
			coreJSON(w, 200, coreSession("fresh-at", "fresh-rt", 3600))
		}
	})
	c := srv.client(t)
	coreStoreSession(t, c, "old-at", "old-rt", time.Now().Add(time.Hour))
	ev := coreWatch(c)
	done := make(chan error, 1)
	go func() { done <- c.SignOut(ctx, "", SignOutLocal) }()
	g.await(t)
	if _, err := c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := coreStored(t, c); st == nil || st.AccessToken != "fresh-at" {
		t.Fatalf("concurrent sign-in removed by SignOut: %+v", st)
	}
	coreAssertEvents(t, ev, EventSignedIn)
}

// upstream: auth-js src/GoTrueClient.ts getClaims (JWK use / key_ops, unknown-kid fetch)
func TestGetClaimsKeyUsageAndUnknownKidCache(t *testing.T) {
	ctx := context.Background()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
	claims := map[string]any{"sub": "user-1", "exp": time.Now().Add(time.Hour).Unix()}
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/.well-known/jwks.json":
			coreJSON(w, 200, map[string]any{"keys": []JWK{rsaJWK("known", &rsaKey.PublicKey)}})
		default:
			coreJSON(w, 200, coreUser("user-1"))
		}
	})
	c := srv.client(t)

	enc := rsaJWK("enc", &rsaKey.PublicKey)
	enc.Use = "enc"
	encOps := rsaJWK("encops", &rsaKey.PublicKey)
	encOps.KeyOps = []string{"encrypt"}
	for _, kid := range []string{"enc", "encops"} {
		tok := signedJWT(t, "RS256", kid, claims, signRSA)
		if _, err := c.GetClaims(ctx, tok, &GetClaimsOptions{Keys: []JWK{enc, encOps}}); !errors.Is(err, ErrInvalidJWT) {
			t.Fatalf("kid %s: err = %v", kid, err)
		}
	}
	sig := rsaJWK("sigkey", &rsaKey.PublicKey)
	sig.Use = "sig"
	if _, err := c.GetClaims(ctx, signedJWT(t, "RS256", "sigkey", claims, signRSA), &GetClaimsOptions{Keys: []JWK{sig}}); err != nil {
		t.Fatalf("use=sig, key_ops=[verify]: %v", err)
	}

	// An unknown kid is fetched once, then remembered for a while (the
	// token still falls back to server validation each time).
	unknown := signedJWT(t, "RS256", "not-in-jwks", claims, signRSA)
	for i := 0; i < 3; i++ {
		if _, err := c.GetClaims(ctx, unknown, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := srv.count("/auth/v1/.well-known/jwks.json"); n != 1 {
		t.Fatalf("%d JWKS fetches for an unknown kid, want 1", n)
	}
	if n := srv.count("/auth/v1/user"); n != 3 {
		t.Fatalf("%d GetUser fallbacks, want 3", n)
	}
	// After the negative-cache window the JWKS is fetched again.
	c.now = func() time.Time { return time.Now().Add(jwksMissingTTL + time.Second) }
	if _, err := c.GetClaims(ctx, unknown, &GetClaimsOptions{AllowExpired: true}); err != nil {
		t.Fatal(err)
	}
	if n := srv.count("/auth/v1/.well-known/jwks.json"); n != 2 {
		t.Fatalf("%d JWKS fetches after the window, want 2", n)
	}
}
