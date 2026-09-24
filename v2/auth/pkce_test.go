package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func pkceExchangeServer(t *testing.T) *coreServer {
	return newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch {
		case r.Path == "/auth/v1/token" && r.Body["auth_code"] == "bad-code":
			coreJSON(w, 400, map[string]any{"code": "flow_state_not_found", "msg": "invalid flow state"})
		case r.Path == "/auth/v1/token":
			coreJSON(w, 200, coreSession("at", "rt", 3600))
		default:
			coreJSON(w, 200, map[string]any{})
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts exchangeCodeForSession
func TestExchangeCodeForSession(t *testing.T) {
	ctx := context.Background()
	srv := pkceExchangeServer(t)
	c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	ev := coreWatch(c)

	if _, err := c.ExchangeCodeForSession(ctx, "code", nil); !errors.Is(err, ErrPKCEVerifierMissing) {
		t.Fatalf("err = %v", err)
	}
	if err := c.ResetPasswordForEmail(ctx, ResetPasswordForEmailParams{Email: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	stored, _ := c.retrievePKCEVerifier(ctx, "")
	resp, err := c.ExchangeCodeForSession(ctx, "auth-code-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPost, "/auth/v1/token", coreAPIKey)
	if r.Query.Get("grant_type") != "pkce" {
		t.Errorf("grant_type = %q", r.Query.Get("grant_type"))
	}
	coreAssertBody(t, r, map[string]any{"auth_code": "auth-code-1", "code_verifier": stored[:112]})
	if resp.RedirectType != "recovery" || resp.Session == nil {
		t.Fatalf("resp = %+v", resp)
	}
	coreAssertEvents(t, ev, EventPasswordRecovery)
	if v, _ := c.retrievePKCEVerifier(ctx, ""); v != "" {
		t.Fatal("verifier not consumed")
	}

	// A failed exchange consumes the verifier too and maps the error.
	if _, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeCodeForSession(ctx, "bad-code", nil); !errors.Is(err, &Error{Code: "flow_state_not_found"}) {
		t.Fatalf("err = %v", err)
	}
	if v, _ := c.retrievePKCEVerifier(ctx, ""); v != "" {
		t.Fatal("verifier kept after failure")
	}
	if _, err := c.ExchangeCodeForSession(ctx, "", nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js test/GoTrueClient.pkce.test.ts (concurrent PKCE flows)
func TestConcurrentPKCEFlows(t *testing.T) {
	ctx := context.Background()
	t.Run("each flow exchanges its own verifier", func(t *testing.T) {
		srv := pkceExchangeServer(t)
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		a, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"})
		if err != nil {
			t.Fatal(err)
		}
		b, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "google"})
		if err != nil {
			t.Fatal(err)
		}
		if a.FlowID == b.FlowID {
			t.Fatal("flows share an id")
		}
		va, _ := c.retrievePKCEVerifier(ctx, a.FlowID)
		vb, _ := c.retrievePKCEVerifier(ctx, b.FlowID)
		if va == "" || vb == "" || va == vb {
			t.Fatalf("verifiers %q %q", va, vb)
		}
		if _, err := c.ExchangeCodeForSession(ctx, "code-a", &ExchangeCodeOptions{FlowID: a.FlowID}); err != nil {
			t.Fatal(err)
		}
		if got := srv.last(t).Body["code_verifier"]; got != va {
			t.Fatalf("exchange A used %v", got)
		}
		if v, _ := c.retrievePKCEVerifier(ctx, b.FlowID); v != vb {
			t.Fatal("exchanging A removed B's slot")
		}
		if idx := c.pkceIndex(ctx); len(idx) != 1 || idx[0] != b.FlowID {
			t.Fatalf("index = %v", idx)
		}
		// B's callback arrives through a URL carrying sb_flow_id.
		if _, err := c.GetSessionFromURL(ctx, "https://app/cb?code=code-b&"+PKCEFlowIDParam+"="+b.FlowID, nil); err != nil {
			t.Fatal(err)
		}
		if got := srv.last(t).Body["code_verifier"]; got != vb {
			t.Fatalf("exchange B used %v", got)
		}
	})
	t.Run("unknown flow id fails fast", func(t *testing.T) {
		srv := pkceExchangeServer(t)
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		if _, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ExchangeCodeForSession(ctx, "code", &ExchangeCodeOptions{FlowID: "0123456789abcdef"}); !errors.Is(err, ErrPKCEVerifierMissing) {
			t.Fatalf("err = %v", err)
		}
		if _, err := c.ExchangeCodeForSession(ctx, "code", &ExchangeCodeOptions{FlowID: "../bad"}); !errors.Is(err, ErrPKCEVerifierMissing) {
			t.Fatalf("err = %v", err)
		}
		if srv.count("/auth/v1/token") != 0 {
			t.Fatal("code burned with a wrong verifier")
		}
		if v, _ := c.retrievePKCEVerifier(ctx, ""); v == "" {
			t.Fatal("pending flow lost its verifier")
		}
	})
	t.Run("slots are bounded", func(t *testing.T) {
		srv := pkceExchangeServer(t)
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		var ids []string
		for i := 0; i < pkceMaxConcurrentFlows+2; i++ {
			r, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"})
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, r.FlowID)
		}
		idx := c.pkceIndex(ctx)
		if len(idx) != pkceMaxConcurrentFlows || idx[0] != ids[2] {
			t.Fatalf("index = %v", idx)
		}
		if v, _ := c.retrievePKCEVerifier(ctx, ids[0]); v != "" {
			t.Fatal("oldest slot not evicted")
		}
	})
	t.Run("flow id appended to redirect only when enabled", func(t *testing.T) {
		got := appendFlowIDToRedirect("myapp://cb?a=1&sb_flow_id=old&b=2#x", "flow12345")
		if want := "myapp://cb?a=1&b=2&sb_flow_id=flow12345#x"; got != want {
			t.Fatalf("got %q want %q", got, want)
		}
		srv := pkceExchangeServer(t)
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		if _, err := c.SignInWithOTP(ctx, SignInWithOTPParams{Email: "a@b.c", EmailRedirectTo: "https://app/cb"}); err != nil {
			t.Fatal(err)
		}
		if got := srv.last(t).Query.Get("redirect_to"); got != "https://app/cb" {
			t.Fatalf("redirect_to = %q", got)
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts _getSessionFromURL / _initialize (detectSessionInUrl)
func TestGetSessionFromURL(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/user":
			coreJSON(w, 200, coreUser("user-5"))
		default:
			coreJSON(w, 200, coreSession("at", "rt", 3600))
		}
	})
	t.Run("implicit fragment", func(t *testing.T) {
		c := srv.client(t)
		ev := coreWatch(c)
		exp := time.Now().Unix() + 3600
		frag := url.Values{"access_token": {"frag-at"}, "refresh_token": {"frag-rt"}, "expires_in": {"3600"},
			"expires_at": {strconv.FormatInt(exp, 10)}, "token_type": {"bearer"}, "type": {"recovery"}, "provider_token": {"ptok"}}
		resp, err := c.GetSessionFromURL(ctx, "https://app/cb#"+frag.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", "frag-at")
		s := resp.Session
		if s.AccessToken != "frag-at" || s.ExpiresAt != exp || s.ProviderToken != "ptok" || resp.User.ID != "user-5" || resp.RedirectType != "recovery" {
			t.Fatalf("resp = %+v", s)
		}
		if coreStored(t, c).AccessToken != "frag-at" {
			t.Fatal("not stored")
		}
		coreAssertEvents(t, ev, EventPasswordRecovery)
	})
	t.Run("error parameters", func(t *testing.T) {
		c := srv.client(t)
		_, err := c.GetSessionFromURL(ctx, "https://app/cb?error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid", nil)
		var ae *Error
		if !errors.As(err, &ae) || ae.Code != "otp_expired" || ae.Message != "Email link is invalid" {
			t.Fatalf("err = %#v", err)
		}
	})
	t.Run("flow type mismatch", func(t *testing.T) {
		c := srv.client(t)
		if _, err := c.GetSessionFromURL(ctx, "https://app/cb?code=abc", nil); !errors.Is(err, ErrImplicitGrantRedirect) {
			t.Fatalf("err = %v", err)
		}
		pc := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		if _, err := pc.GetSessionFromURL(ctx, "https://app/cb#access_token=x", nil); !errors.Is(err, ErrPKCEGrantCodeExchange) {
			t.Fatalf("err = %v", err)
		}
		if _, err := c.GetSessionFromURL(ctx, "https://app/cb#access_token=x", nil); !errors.Is(err, ErrImplicitGrantRedirect) {
			t.Fatalf("incomplete fragment err = %v", err)
		}
		if _, err := c.GetSessionFromURL(ctx, "https://app/plain", nil); !errors.Is(err, ErrImplicitGrantRedirect) {
			t.Fatalf("plain url err = %v", err)
		}
	})
	t.Run("pkce code in query", func(t *testing.T) {
		pc := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		if _, err := pc.SignInWithOTP(ctx, SignInWithOTPParams{Email: "a@b.c"}); err != nil {
			t.Fatal(err)
		}
		resp, err := pc.GetSessionFromURL(ctx, "https://app/cb?code=the-code", nil)
		if err != nil || resp.Session == nil {
			t.Fatalf("GetSessionFromURL = %+v, %v", resp, err)
		}
		if srv.last(t).Body["auth_code"] != "the-code" {
			t.Fatal("code not exchanged")
		}
	})
}
