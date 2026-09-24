package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// upstream: auth-js src/GoTrueClient.ts signUp
func TestSignUp(t *testing.T) {
	ctx := context.Background()
	t.Run("email returns and stores session", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 200, coreSession("at-1", "rt-1", 3600))
		})
		c := srv.client(t)
		ev := coreWatch(c)
		resp, err := c.SignUp(ctx, SignUpParams{
			Email: "user@example.com", Password: "secret-pw", Data: map[string]any{"name": "A"},
			CaptchaToken: "cap", EmailRedirectTo: "https://app.example/cb",
		})
		if err != nil {
			t.Fatal(err)
		}
		r := srv.last(t)
		coreAssertCommon(t, r, http.MethodPost, "/auth/v1/signup", coreAPIKey)
		if got := r.Query.Get("redirect_to"); got != "https://app.example/cb" {
			t.Errorf("redirect_to = %q", got)
		}
		coreAssertBody(t, r, map[string]any{
			"email": "user@example.com", "password": "secret-pw", "data": map[string]any{"name": "A"},
			"gotrue_meta_security": map[string]any{"captcha_token": "cap"},
			"code_challenge":       nil, "code_challenge_method": nil,
		})
		if resp.Session == nil || resp.Session.AccessToken != "at-1" || resp.User == nil || resp.User.ID != "user-1" {
			t.Fatalf("resp = %+v", resp)
		}
		if s := coreStored(t, c); s == nil || s.RefreshToken != "rt-1" {
			t.Fatalf("stored = %+v", s)
		}
		coreAssertEvents(t, ev, EventSignedIn)
	})
	t.Run("phone defaults channel and data", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 200, coreUser("user-2")) // confirmation pending: user only
		})
		c := srv.client(t)
		ev := coreWatch(c)
		resp, err := c.SignUp(ctx, SignUpParams{Phone: "+15550001", Password: "pw"})
		if err != nil {
			t.Fatal(err)
		}
		coreAssertBody(t, srv.last(t), map[string]any{
			"phone": "+15550001", "password": "pw", "data": map[string]any{}, "channel": "sms",
			"gotrue_meta_security": map[string]any{},
		})
		if resp.Session != nil || resp.User == nil || resp.User.ID != "user-2" {
			t.Fatalf("resp = %+v", resp)
		}
		if coreStored(t, c) != nil {
			t.Fatal("session stored without confirmation")
		}
		coreAssertEvents(t, ev)
	})
	t.Run("weak password error", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 422, map[string]any{"code": "weak_password", "msg": "Password is too weak",
				"weak_password": map[string]any{"reasons": []string{"length"}}})
		})
		_, err := srv.client(t).SignUp(ctx, SignUpParams{Email: "a@b.c", Password: "x"})
		var ae *Error
		if !errors.As(err, &ae) || ae.StatusCode != 422 || ae.Code != ErrorCodeWeakPassword || len(ae.WeakPasswordReasons) != 1 {
			t.Fatalf("err = %#v", err)
		}
	})
	t.Run("requires email or phone", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
		if _, err := srv.client(t).SignUp(ctx, SignUpParams{Password: "x"}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v", err)
		}
		if len(srv.requests()) != 0 {
			t.Fatal("request sent")
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts signUp (pkce) + lib/helpers.ts getCodeChallengeAndMethod
func TestSignUpPKCE(t *testing.T) {
	ctx := context.Background()
	fail := false
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if fail {
			coreJSON(w, 400, map[string]any{"msg": "bad"})
			return
		}
		coreJSON(w, 200, coreUser("user-1"))
	})
	store := NewMemoryStorage()
	c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE; cfg.Storage = store; cfg.StorageKey = "sb-test-auth-token" })
	if _, err := c.SignUp(ctx, SignUpParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	body := srv.last(t).Body
	verifier, _ := c.getJSONString(ctx, "sb-test-auth-token-code-verifier")
	if len(verifier) != 112 {
		t.Fatalf("verifier length = %d", len(verifier))
	}
	if body["code_challenge"] != pkceChallenge(verifier) || body["code_challenge_method"] != "s256" {
		t.Fatalf("challenge = %v %v", body["code_challenge"], body["code_challenge_method"])
	}
	index := c.pkceIndex(ctx)
	if len(index) != 1 {
		t.Fatalf("index = %v", index)
	}
	if slot, _ := c.getJSONString(ctx, c.pkceSlotKey(index[0])); slot != verifier {
		t.Fatalf("slot = %q", slot)
	}
	// A failed request removes the verifier of that flow.
	fail = true
	if _, err := c.SignUp(ctx, SignUpParams{Email: "a@b.c", Password: "pw"}); err == nil {
		t.Fatal("want error")
	}
	if got := c.pkceIndex(ctx); len(got) != 1 || got[0] != index[0] {
		t.Fatalf("index after failure = %v", got)
	}
}

// upstream: auth-js src/GoTrueClient.ts signInWithPassword
func TestSignInWithPassword(t *testing.T) {
	ctx := context.Background()
	t.Run("email with weak password", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			body := coreSession("at", "rt", 3600)
			body["weak_password"] = map[string]any{"reasons": []string{"pwned"}, "message": "pwned"}
			coreJSON(w, 200, body)
		})
		c := srv.client(t)
		ev := coreWatch(c)
		resp, err := c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"})
		if err != nil {
			t.Fatal(err)
		}
		r := srv.last(t)
		coreAssertCommon(t, r, http.MethodPost, "/auth/v1/token", coreAPIKey)
		if r.Query.Get("grant_type") != "password" {
			t.Errorf("grant_type = %q", r.Query.Get("grant_type"))
		}
		coreAssertBody(t, r, map[string]any{"email": "a@b.c", "password": "pw", "gotrue_meta_security": map[string]any{}})
		if resp.WeakPassword == nil || resp.WeakPassword.Reasons[0] != "pwned" {
			t.Fatalf("weak password = %+v", resp.WeakPassword)
		}
		if resp.Session.ExpiresAt == 0 {
			t.Fatal("expires_at not set")
		}
		coreAssertEvents(t, ev, EventSignedIn)
	})
	t.Run("phone", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
		if _, err := srv.client(t).SignInWithPassword(ctx, SignInWithPasswordParams{Phone: "+1", Password: "pw", CaptchaToken: "c"}); err != nil {
			t.Fatal(err)
		}
		coreAssertBody(t, srv.last(t), map[string]any{"phone": "+1", "password": "pw", "gotrue_meta_security": map[string]any{"captcha_token": "c"}})
	})
	t.Run("invalid credentials", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 400, map[string]any{"code": "invalid_credentials", "msg": "Invalid login credentials"})
		})
		c := srv.client(t)
		_, err := c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "bad"})
		if !errors.Is(err, &Error{Code: ErrorCodeInvalidCredentials}) {
			t.Fatalf("err = %v", err)
		}
		if coreStored(t, c) != nil {
			t.Fatal("session stored")
		}
	})
	t.Run("missing session in response", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreUser("u")) })
		if _, err := srv.client(t).SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); !errors.Is(err, ErrInvalidTokenResponse) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("non-JSON 502 is retryable", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			w.WriteHeader(502)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		})
		_, err := srv.client(t).SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"})
		var ae *Error
		if !errors.As(err, &ae) || !ae.Retryable || ae.StatusCode != 502 {
			t.Fatalf("err = %#v", err)
		}
	})
	t.Run("context cancellation", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := srv.client(t).SignInWithPassword(cctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts signInWithOtp
func TestSignInWithOTP(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Body["phone"] != nil {
			coreJSON(w, 200, map[string]any{"message_id": "msg-1"})
			return
		}
		coreJSON(w, 200, map[string]any{})
	})
	c := srv.client(t)
	if _, err := c.SignInWithOTP(ctx, SignInWithOTPParams{Email: "a@b.c", EmailRedirectTo: "https://app/cb"}); err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/otp", coreAPIKey)
	if r.Query.Get("redirect_to") != "https://app/cb" {
		t.Errorf("query = %v", r.Query)
	}
	coreAssertBody(t, r, map[string]any{"email": "a@b.c", "data": map[string]any{}, "create_user": true,
		"gotrue_meta_security": map[string]any{}, "code_challenge": nil, "code_challenge_method": nil})

	no := false
	resp, err := c.SignInWithOTP(ctx, SignInWithOTPParams{Phone: "+1", ShouldCreateUser: &no, Channel: "whatsapp"})
	if err != nil {
		t.Fatal(err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"phone": "+1", "data": map[string]any{}, "create_user": false,
		"gotrue_meta_security": map[string]any{}, "channel": "whatsapp"})
	if resp.MessageID != "msg-1" {
		t.Fatalf("message id = %q", resp.MessageID)
	}
	if _, err := c.SignInWithOTP(ctx, SignInWithOTPParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts verifyOtp
func TestVerifyOTP(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Body["token_hash"] == "expired" {
			coreJSON(w, 403, map[string]any{"code": "otp_expired", "msg": "Token has expired or is invalid"})
			return
		}
		coreJSON(w, 200, coreSession("at", "rt", 3600))
	})
	c := srv.client(t)
	ev := coreWatch(c)
	resp, err := c.VerifyOTP(ctx, VerifyOTPParams{Email: "a@b.c", Token: "123456", Type: OTPTypeRecovery, RedirectTo: "https://app/r", CaptchaToken: "cap"})
	if err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/verify", coreAPIKey)
	if r.Query.Get("redirect_to") != "https://app/r" {
		t.Errorf("query = %v", r.Query)
	}
	coreAssertBody(t, r, map[string]any{"email": "a@b.c", "token": "123456", "type": "recovery",
		"gotrue_meta_security": map[string]any{"captcha_token": "cap"}})
	if resp.Session == nil {
		t.Fatal("no session")
	}
	coreAssertEvents(t, ev, EventPasswordRecovery)

	if _, err := c.VerifyOTP(ctx, VerifyOTPParams{TokenHash: "hash", Type: OTPTypeEmail}); err != nil {
		t.Fatal(err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"token_hash": "hash", "type": "email", "gotrue_meta_security": map[string]any{}})
	coreAssertEvents(t, ev, EventPasswordRecovery, EventSignedIn)

	if _, err := c.VerifyOTP(ctx, VerifyOTPParams{TokenHash: "expired", Type: OTPTypeEmail}); !errors.Is(err, &Error{Code: ErrorCodeOTPExpired}) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.VerifyOTP(ctx, VerifyOTPParams{Email: "a@b.c"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts signInAnonymously
func TestSignInAnonymously(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
	c := srv.client(t)
	ev := coreWatch(c)
	resp, err := c.SignInAnonymously(context.Background(), SignInAnonymouslyParams{Data: map[string]any{"k": "v"}, CaptchaToken: "cap"})
	if err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/signup", coreAPIKey)
	coreAssertBody(t, r, map[string]any{"data": map[string]any{"k": "v"}, "gotrue_meta_security": map[string]any{"captcha_token": "cap"}})
	if resp.Session == nil || coreStored(t, c) == nil {
		t.Fatal("session not stored")
	}
	coreAssertEvents(t, ev, EventSignedIn)
}

// upstream: auth-js src/GoTrueClient.ts signInWithOAuth / _getUrlForProvider
func TestSignInWithOAuth(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
	t.Run("implicit", func(t *testing.T) {
		c := srv.client(t)
		resp, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github", RedirectTo: "https://app/cb?x=1", Scopes: "repo gist",
			QueryParams: map[string]string{"prompt": "consent", "access_type": "offline"}})
		if err != nil {
			t.Fatal(err)
		}
		want := srv.srv.URL + "/auth/v1/authorize?provider=github&redirect_to=https%3A%2F%2Fapp%2Fcb%3Fx%3D1&scopes=repo%20gist&access_type=offline&prompt=consent"
		if resp.URL != want || resp.Provider != "github" || resp.FlowID != "" {
			t.Fatalf("resp = %+v\nwant %s", resp, want)
		}
		if len(srv.requests()) != 0 {
			t.Fatal("request sent")
		}
	})
	t.Run("pkce with flow id redirect", func(t *testing.T) {
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE; cfg.AppendPKCEFlowIDToRedirects = true })
		resp, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "google", RedirectTo: "https://app/cb#frag"})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(resp.URL)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		if q.Get("code_challenge_method") != "s256" || q.Get("code_challenge") == "" {
			t.Fatalf("query = %v", q)
		}
		if want := "https://app/cb?sb_flow_id=" + resp.FlowID + "#frag"; q.Get("redirect_to") != want {
			t.Fatalf("redirect_to = %q, want %q", q.Get("redirect_to"), want)
		}
		verifier, _ := c.retrievePKCEVerifier(ctx, resp.FlowID)
		if pkceChallenge(verifier) != q.Get("code_challenge") {
			t.Fatal("challenge does not match stored verifier")
		}
	})
	t.Run("provider required", func(t *testing.T) {
		if _, err := srv.client(t).SignInWithOAuth(ctx, SignInWithOAuthParams{}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v", err)
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts signInWithIdToken
func TestSignInWithIDToken(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
	c := srv.client(t)
	ev := coreWatch(c)
	if _, err := c.SignInWithIDToken(context.Background(), SignInWithIDTokenParams{Provider: "google", Token: "idtok", Nonce: "n", AccessToken: "pat"}); err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/token", coreAPIKey)
	if r.Query.Get("grant_type") != "id_token" {
		t.Errorf("grant_type = %q", r.Query.Get("grant_type"))
	}
	coreAssertBody(t, r, map[string]any{"provider": "google", "id_token": "idtok", "access_token": "pat", "nonce": "n", "gotrue_meta_security": map[string]any{}})
	coreAssertEvents(t, ev, EventSignedIn)
	if _, err := c.SignInWithIDToken(context.Background(), SignInWithIDTokenParams{Provider: "google"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts signInWithSSO
func TestSignInWithSSO(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Body["domain"] == "missing.example" {
			coreJSON(w, 404, map[string]any{"code": "sso_provider_not_found", "msg": "No SSO provider"})
			return
		}
		coreJSON(w, 200, map[string]any{"url": "https://idp.example/sso"})
	})
	c := srv.client(t)
	resp, err := c.SignInWithSSO(ctx, SignInWithSSOParams{Domain: "company.example", RedirectTo: "https://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/sso", coreAPIKey)
	coreAssertBody(t, r, map[string]any{"domain": "company.example", "redirect_to": "https://app/cb", "skip_http_redirect": true,
		"code_challenge": nil, "code_challenge_method": nil})
	if resp.URL != "https://idp.example/sso" {
		t.Fatalf("url = %q", resp.URL)
	}
	if _, err := c.SignInWithSSO(ctx, SignInWithSSOParams{ProviderID: "p-1", CaptchaToken: "cap"}); err != nil {
		t.Fatal(err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"provider_id": "p-1", "skip_http_redirect": true,
		"gotrue_meta_security": map[string]any{"captcha_token": "cap"}, "code_challenge": nil, "code_challenge_method": nil})

	pc := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	_, err = pc.SignInWithSSO(ctx, SignInWithSSOParams{Domain: "missing.example"})
	if !errors.Is(err, &Error{Code: "sso_provider_not_found"}) {
		t.Fatalf("err = %v", err)
	}
	if v, _ := pc.retrievePKCEVerifier(ctx, ""); v != "" {
		t.Fatal("verifier kept after failure")
	}
	if _, err := c.SignInWithSSO(ctx, SignInWithSSOParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts resend
func TestResend(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 200, map[string]any{"message_id": "m-9"})
	})
	c := srv.client(t)
	if _, err := c.Resend(ctx, ResendParams{Type: OTPTypeSignup, Email: "a@b.c", EmailRedirectTo: "https://app"}); err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/resend", coreAPIKey)
	if r.Query.Get("redirect_to") != "https://app" {
		t.Errorf("query = %v", r.Query)
	}
	coreAssertBody(t, r, map[string]any{"email": "a@b.c", "type": "signup", "gotrue_meta_security": map[string]any{},
		"code_challenge": nil, "code_challenge_method": nil})
	resp, err := c.Resend(ctx, ResendParams{Type: OTPTypeSMS, Phone: "+1"})
	if err != nil {
		t.Fatal(err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"phone": "+1", "type": "sms", "gotrue_meta_security": map[string]any{}})
	if resp.MessageID != "m-9" {
		t.Fatalf("message id = %q", resp.MessageID)
	}
	if _, err := c.Resend(ctx, ResendParams{Type: "signup"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts resetPasswordForEmail
func TestResetPasswordForEmail(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, map[string]any{}) })
	c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	if err := c.ResetPasswordForEmail(ctx, ResetPasswordForEmailParams{Email: "a@b.c", RedirectTo: "https://app/reset", CaptchaToken: "cap"}); err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/recover", coreAPIKey)
	if r.Query.Get("redirect_to") != "https://app/reset" {
		t.Errorf("query = %v", r.Query)
	}
	stored, _ := c.retrievePKCEVerifier(ctx, "")
	verifier, marker, _ := strings.Cut(stored, "/")
	if marker != "recovery" {
		t.Fatalf("stored verifier %q lacks recovery marker", stored)
	}
	coreAssertBody(t, r, map[string]any{"email": "a@b.c", "code_challenge": pkceChallenge(verifier), "code_challenge_method": "s256",
		"gotrue_meta_security": map[string]any{"captcha_token": "cap"}})
	if err := c.ResetPasswordForEmail(ctx, ResetPasswordForEmailParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts reauthenticate
func TestReauthenticate(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, map[string]any{}) })
	c := srv.client(t)
	if err := c.Reauthenticate(ctx, ""); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	coreStoreSession(t, c, "stored-at", "rt", time.Now().Add(time.Hour))
	if err := c.Reauthenticate(ctx, ""); err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/reauthenticate", "stored-at")
	if err := c.Reauthenticate(ctx, "explicit-at"); err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/reauthenticate", "explicit-at")
}
