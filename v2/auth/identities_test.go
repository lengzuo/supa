package auth

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// upstream: auth-js src/GoTrueClient.ts getUserIdentities
func TestGetUserIdentities(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreUser("user-1")) })
	c := srv.client(t)
	ids, err := c.GetUserIdentities(context.Background(), "jwt")
	if err != nil || len(ids) != 1 || ids[0].IdentityID != "11111111-2222-3333-4444-555555555555" || ids[0].Provider != "email" {
		t.Fatalf("identities = %+v, %v", ids, err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", "jwt")
	if _, err := c.GetUserIdentities(context.Background(), ""); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts linkIdentity / linkIdentityOAuth / linkIdentityIdToken
func TestLinkIdentity(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/user/identities/authorize":
			coreJSON(w, 200, map[string]any{"url": "https://github.com/login/oauth/authorize?x=1"})
		case "/auth/v1/token":
			coreJSON(w, 200, coreSession("linked-at", "linked-rt", 3600))
		}
	})
	t.Run("oauth", func(t *testing.T) {
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		if _, err := c.LinkIdentity(ctx, "", SignInWithOAuthParams{Provider: "github"}); !errors.Is(err, ErrSessionMissing) {
			t.Fatalf("err = %v", err)
		}
		coreStoreSession(t, c, "stored-at", "rt", time.Now().Add(time.Hour))
		resp, err := c.LinkIdentity(ctx, "", SignInWithOAuthParams{Provider: "github", RedirectTo: "https://app/linked", Scopes: "repo"})
		if err != nil {
			t.Fatal(err)
		}
		r := srv.last(t)
		coreAssertCommon(t, r, http.MethodGet, "/auth/v1/user/identities/authorize", "stored-at")
		q := r.Query
		if q.Get("provider") != "github" || q.Get("redirect_to") != "https://app/linked" || q.Get("scopes") != "repo" ||
			q.Get("skip_http_redirect") != "true" || q.Get("code_challenge_method") != "s256" {
			t.Fatalf("query = %v", q)
		}
		if resp.URL != "https://github.com/login/oauth/authorize?x=1" || resp.FlowID == "" || resp.Provider != "github" {
			t.Fatalf("resp = %+v", resp)
		}
	})
	t.Run("id token", func(t *testing.T) {
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "stored-at", "rt", time.Now().Add(time.Hour))
		resp, err := c.LinkIdentityWithIDToken(ctx, "", SignInWithIDTokenParams{Provider: "apple", Token: "idt"})
		if err != nil || resp.Session.AccessToken != "linked-at" {
			t.Fatalf("resp = %+v, %v", resp, err)
		}
		r := srv.last(t)
		coreAssertCommon(t, r, http.MethodPost, "/auth/v1/token", "stored-at")
		if r.Query.Get("grant_type") != "id_token" {
			t.Errorf("grant_type = %q", r.Query.Get("grant_type"))
		}
		coreAssertBody(t, r, map[string]any{"provider": "apple", "id_token": "idt", "link_identity": true, "gotrue_meta_security": map[string]any{}})
		if coreStored(t, c).AccessToken != "linked-at" {
			t.Fatal("linked session not stored")
		}
		coreAssertEvents(t, ev, EventUserUpdated)

		// Explicit token: nothing stored.
		c2 := srv.client(t)
		if _, err := c2.LinkIdentityWithIDToken(ctx, "user-jwt", SignInWithIDTokenParams{Provider: "apple", Token: "idt"}); err != nil {
			t.Fatal(err)
		}
		if coreStored(t, c2) != nil {
			t.Fatal("explicit-token link stored a session")
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts unlinkIdentity
func TestUnlinkIdentity(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if strings.HasSuffix(r.Path, "/last") {
			coreJSON(w, 422, map[string]any{"code": "single_identity_not_deletable", "msg": "User must have at least 1 identity"})
			return
		}
		coreJSON(w, 200, map[string]any{})
	})
	c := srv.client(t)
	if err := c.UnlinkIdentity(context.Background(), "jwt", "ident-1"); err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodDelete, "/auth/v1/user/identities/ident-1", "jwt")
	if err := c.UnlinkIdentity(context.Background(), "jwt", "last"); !errors.Is(err, &Error{Code: "single_identity_not_deletable"}) {
		t.Fatalf("err = %v", err)
	}
	if err := c.UnlinkIdentity(context.Background(), "jwt", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts signInWithWeb3 / signInWithEthereum / signInWithSolana
func TestSignInWithWeb3(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
	c := srv.client(t)
	ev := coreWatch(c)
	sig, _ := hex.DecodeString("ab01ff")
	if _, err := c.SignInWithWeb3(ctx, SignInWithWeb3Params{Chain: Web3ChainEthereum, Message: "msg", Signature: sig}); err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/token", coreAPIKey)
	if r.Query.Get("grant_type") != "web3" {
		t.Errorf("grant_type = %q", r.Query.Get("grant_type"))
	}
	coreAssertBody(t, r, map[string]any{"chain": "ethereum", "message": "msg", "signature": "0xab01ff"})
	if _, err := c.SignInWithWeb3(ctx, SignInWithWeb3Params{Chain: Web3ChainSolana, Message: "m", Signature: []byte{0xfb, 0xff}, CaptchaToken: "cap"}); err != nil {
		t.Fatal(err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"chain": "solana", "message": "m", "signature": "-_8",
		"gotrue_meta_security": map[string]any{"captcha_token": "cap"}})
	coreAssertEvents(t, ev, EventSignedIn, EventSignedIn)
	for _, p := range []SignInWithWeb3Params{{Chain: "bitcoin", Message: "m", Signature: sig}, {Chain: Web3ChainSolana}} {
		if _, err := c.SignInWithWeb3(ctx, p); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v", err)
		}
	}
}

// upstream: auth-js src/lib/web3/ethereum.ts createSiweMessage
func TestCreateSIWEMessage(t *testing.T) {
	issued := time.Date(2024, 1, 2, 3, 4, 5, 6e6, time.UTC)
	msg, err := CreateSIWEMessage(SIWEMessage{
		Domain: "app.example", Address: "0xAbCdEf0123456789abcdef0123456789ABCDEF01", Statement: "Sign in please",
		URI: "https://app.example/login", ChainID: 1, Nonce: "abcdefgh", IssuedAt: issued,
		ExpirationTime: issued.Add(time.Hour), Resources: []string{"https://a", "https://b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "app.example wants you to sign in with your Ethereum account:\n" +
		"0xabcdef0123456789abcdef0123456789abcdef01\n\n" +
		"Sign in please\n\n" +
		"URI: https://app.example/login\nVersion: 1\nChain ID: 1\nNonce: abcdefgh\n" +
		"Issued At: 2024-01-02T03:04:05.006Z\nExpiration Time: 2024-01-02T04:04:05.006Z\n" +
		"Resources:\n- https://a\n- https://b"
	if msg != want {
		t.Fatalf("got\n%s\nwant\n%s", msg, want)
	}
	for _, bad := range []SIWEMessage{
		{Domain: "d", Address: "0x1", URI: "u", ChainID: 1},
		{Domain: "d", Address: "0xabcdef0123456789abcdef0123456789abcdef01", URI: "u", ChainID: 1, Nonce: "short"},
		{Domain: "d", Address: "0xabcdef0123456789abcdef0123456789abcdef01", URI: "u", ChainID: 0},
		{Domain: "d", Address: "0xabcdef0123456789abcdef0123456789abcdef01", URI: "u", ChainID: 1, Statement: "a\nb"},
	} {
		if _, err := CreateSIWEMessage(bad); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("CreateSIWEMessage(%+v) err = %v", bad, err)
		}
	}
}

// upstream: auth-js src/GoTrueClient.ts signInWithSolana (message construction)
func TestCreateSolanaSignInMessage(t *testing.T) {
	issued := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	msg, err := CreateSolanaSignInMessage(SolanaSignInMessage{URI: "https://app.example:8443/login", Address: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
		Statement: "Hi", IssuedAt: issued, Nonce: "n1", Resources: []string{"r1"}})
	if err != nil {
		t.Fatal(err)
	}
	want := "app.example:8443 wants you to sign in with your Solana account:\n9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin\n\nHi\n\n" +
		"Version: 1\nURI: https://app.example:8443/login\nIssued At: 2024-01-02T03:04:05.000Z\nNonce: n1\nResources\n- r1"
	if msg != want {
		t.Fatalf("got\n%q\nwant\n%q", msg, want)
	}
	if _, err := CreateSolanaSignInMessage(SolanaSignInMessage{URI: "relative", Address: "a"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _startPasskeyRegistration / _verifyPasskeyRegistration (registerPasskey)
func TestPasskeyRegistration(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/passkeys/registration/options":
			coreJSON(w, 200, map[string]any{"challenge_id": "ch-1", "expires_at": 1700000000,
				"options": map[string]any{"challenge": "Y2hhbA", "rp": map[string]any{"id": "app.example"}}})
		case "/auth/v1/passkeys/registration/verify":
			coreJSON(w, 200, map[string]any{"id": "pk-1", "friendly_name": "Laptop", "created_at": "2024-01-01T00:00:00Z"})
		}
	})
	c := srv.client(t)
	p := c.Passkey()
	if _, err := p.StartRegistration(ctx, ""); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	ch, err := p.StartRegistration(ctx, "user-jwt")
	if err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/passkeys/registration/options", "user-jwt")
	coreAssertBody(t, r, map[string]any{})
	if ch.ChallengeID != "ch-1" || ch.ExpiresAt != 1700000000 || !json.Valid(ch.Options) || !strings.Contains(string(ch.Options), "app.example") {
		t.Fatalf("challenge = %+v", ch)
	}
	cred := json.RawMessage(`{"id":"cred","rawId":"cred","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"o"}}`)
	pk, err := p.VerifyRegistration(ctx, "user-jwt", VerifyPasskeyRegistrationParams{ChallengeID: ch.ChallengeID, Credential: cred})
	if err != nil {
		t.Fatal(err)
	}
	r = srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/passkeys/registration/verify", "user-jwt")
	var credMap map[string]any
	_ = json.Unmarshal(cred, &credMap)
	coreAssertBody(t, r, map[string]any{"challenge_id": "ch-1", "credential": credMap})
	if pk.ID != "pk-1" || pk.FriendlyName != "Laptop" || pk.CreatedAt.IsZero() {
		t.Fatalf("passkey = %+v", pk)
	}
	if _, err := p.VerifyRegistration(ctx, "user-jwt", VerifyPasskeyRegistrationParams{ChallengeID: "c", Credential: json.RawMessage(`{bad`)}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _startPasskeyAuthentication / _verifyPasskeyAuthentication (signInWithPasskey)
func TestPasskeyAuthentication(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/passkeys/authentication/options":
			coreJSON(w, 200, map[string]any{"challenge_id": "ch-2", "expires_at": 1700000000, "options": map[string]any{"challenge": "YQ"}})
		case "/auth/v1/passkeys/authentication/verify":
			if r.Body["challenge_id"] == "expired" {
				coreJSON(w, 400, map[string]any{"code": "webauthn_challenge_expired", "msg": "expired"})
				return
			}
			coreJSON(w, 200, coreSession("pk-at", "pk-rt", 3600))
		}
	})
	c := srv.client(t)
	ev := coreWatch(c)
	ch, err := c.Passkey().StartAuthentication(ctx, StartPasskeyAuthenticationParams{CaptchaToken: "cap"})
	if err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/passkeys/authentication/options", coreAPIKey)
	coreAssertBody(t, r, map[string]any{"gotrue_meta_security": map[string]any{"captcha_token": "cap"}})
	cred := json.RawMessage(`{"id":"cred","type":"public-key","response":{"signature":"sig"}}`)
	resp, err := c.Passkey().VerifyAuthentication(ctx, VerifyPasskeyAuthenticationParams{ChallengeID: ch.ChallengeID, Credential: cred})
	if err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodPost, "/auth/v1/passkeys/authentication/verify", coreAPIKey)
	if resp.Session.AccessToken != "pk-at" || coreStored(t, c).AccessToken != "pk-at" {
		t.Fatal("session not stored")
	}
	coreAssertEvents(t, ev, EventSignedIn)
	if _, err := c.Passkey().VerifyAuthentication(ctx, VerifyPasskeyAuthenticationParams{ChallengeID: "expired", Credential: cred}); !errors.Is(err, &Error{Code: "webauthn_challenge_expired"}) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _listPasskeys / _updatePasskey / _deletePasskey
func TestPasskeyManagement(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Method {
		case http.MethodGet:
			coreJSON(w, 200, []map[string]any{{"id": "pk-1", "friendly_name": "Laptop", "created_at": "2024-01-01T00:00:00Z", "last_used_at": "2024-02-01T00:00:00Z"}})
		case http.MethodPatch:
			coreJSON(w, 200, map[string]any{"id": "pk-1", "friendly_name": r.Body["friendly_name"], "created_at": "2024-01-01T00:00:00Z"})
		case http.MethodDelete:
			if strings.HasSuffix(r.Path, "/missing") {
				coreJSON(w, 404, map[string]any{"code": "passkey_not_found", "msg": "not found"})
				return
			}
			w.WriteHeader(204)
		}
	})
	c := srv.client(t)
	coreStoreSession(t, c, "stored-at", "rt", time.Now().Add(time.Hour))
	p := c.Passkey()
	list, err := p.List(ctx, "")
	if err != nil || len(list) != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("List = %+v, %v", list, err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/passkeys", "stored-at")
	pk, err := p.Update(ctx, "", PasskeyUpdateParams{PasskeyID: "pk-1", FriendlyName: "Phone"})
	if err != nil || pk.FriendlyName != "Phone" {
		t.Fatalf("Update = %+v, %v", pk, err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPatch, "/auth/v1/passkeys/pk-1", "stored-at")
	coreAssertBody(t, r, map[string]any{"friendly_name": "Phone"})
	if err := p.Delete(ctx, "user-jwt", "pk-1"); err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodDelete, "/auth/v1/passkeys/pk-1", "user-jwt")
	if err := p.Delete(ctx, "user-jwt", "missing"); !errors.Is(err, &Error{Code: "passkey_not_found"}) {
		t.Fatalf("err = %v", err)
	}
	if err := p.Delete(ctx, "user-jwt", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
	if _, err := p.Update(ctx, "", PasskeyUpdateParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}
