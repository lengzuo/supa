package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// upstream: auth-js src/GoTrueClient.ts getSession / __loadSession
func TestGetSession(t *testing.T) {
	ctx := context.Background()
	t.Run("no session", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
		s, err := srv.client(t).GetSession(ctx)
		if s != nil || err != nil {
			t.Fatalf("GetSession = %v, %v", s, err)
		}
	})
	t.Run("fresh session is returned without a request", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
		c := srv.client(t)
		coreStoreSession(t, c, "at", "rt", time.Now().Add(time.Hour))
		s, err := c.GetSession(ctx)
		if err != nil || s == nil || s.AccessToken != "at" {
			t.Fatalf("GetSession = %+v, %v", s, err)
		}
		if n := len(srv.requests()); n != 0 {
			t.Fatalf("%d requests", n)
		}
	})
	t.Run("session within expiry margin is refreshed", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
		})
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(ExpiryMargin-time.Second))
		s, err := c.GetSession(ctx)
		if err != nil || s.AccessToken != "at-2" {
			t.Fatalf("GetSession = %+v, %v", s, err)
		}
		r := srv.last(t)
		coreAssertCommon(t, r, http.MethodPost, "/auth/v1/token", coreAPIKey)
		if r.Query.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.Query.Get("grant_type"))
		}
		coreAssertBody(t, r, map[string]any{"refresh_token": "rt-1"})
		if st := coreStored(t, c); st.RefreshToken != "rt-2" {
			t.Fatalf("stored rt = %q", st.RefreshToken)
		}
		coreAssertEvents(t, ev, EventTokenRefreshed)
	})
	t.Run("concurrent callers share one refresh", func(t *testing.T) {
		release := make(chan struct{})
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			<-release
			coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
		})
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		var wg sync.WaitGroup
		var ok atomic.Int32
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s, err := c.GetSession(ctx); err == nil && s.AccessToken == "at-2" {
					ok.Add(1)
				}
			}()
		}
		time.Sleep(50 * time.Millisecond)
		close(release)
		wg.Wait()
		if ok.Load() != 20 {
			t.Fatalf("%d callers got the refreshed session", ok.Load())
		}
		if n := srv.count("/auth/v1/token"); n != 1 {
			t.Fatalf("%d refresh requests, want 1", n)
		}
		coreAssertEvents(t, ev, EventTokenRefreshed)
	})
	t.Run("retryable failure keeps the session", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 503, map[string]any{"msg": "unavailable"})
		})
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		_, err := c.GetSession(ctx)
		var ae *Error
		if !errors.As(err, &ae) || !ae.Retryable {
			t.Fatalf("err = %v", err)
		}
		if st := coreStored(t, c); st == nil || st.RefreshToken != "rt-1" {
			t.Fatal("session dropped after retryable failure")
		}
		coreAssertEvents(t, ev)
		// The failure is cached for the cooldown: no second request.
		if _, err := c.GetSession(ctx); err == nil {
			t.Fatal("want cached error")
		}
		if n := srv.count("/auth/v1/token"); n != 1 {
			t.Fatalf("%d refresh requests during cooldown, want 1", n)
		}
	})
	t.Run("retryable failure is retried within the budget", func(t *testing.T) {
		var calls atomic.Int32
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			if calls.Add(1) < 3 {
				coreJSON(w, 502, map[string]any{"msg": "bad gateway"})
				return
			}
			coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
		})
		c := srv.client(t)
		c.refreshRetryBudget, c.refreshRetryBase = 5*time.Second, time.Millisecond
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		s, err := c.GetSession(ctx)
		if err != nil || s.AccessToken != "at-2" || calls.Load() != 3 {
			t.Fatalf("GetSession = %+v, %v after %d calls", s, err, calls.Load())
		}
	})
	t.Run("network failure keeps the session", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
		c := srv.client(t)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		srv.srv.Close()
		if _, err := c.GetSession(ctx); err == nil {
			t.Fatal("want error")
		}
		if coreStored(t, c) == nil {
			t.Fatal("session dropped after network failure")
		}
	})
	t.Run("definitive failure on expired token signs out", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 400, map[string]any{"code": "refresh_token_not_found", "msg": "Invalid Refresh Token"})
		})
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		_, err := c.GetSession(ctx)
		if !errors.Is(err, &Error{Code: ErrorCodeRefreshTokenNotFound}) {
			t.Fatalf("err = %v", err)
		}
		if coreStored(t, c) != nil {
			t.Fatal("session kept")
		}
		coreAssertEvents(t, ev, EventSignedOut)
	})
	t.Run("definitive failure on still-valid token keeps it", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 400, map[string]any{"code": "refresh_token_already_used", "msg": "used"})
		})
		c := srv.client(t)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(time.Minute))
		s, err := c.GetSession(ctx)
		if err != nil || s == nil || s.AccessToken != "at-1" {
			t.Fatalf("GetSession = %+v, %v", s, err)
		}
	})
	t.Run("refresh discarded when storage changed in flight", func(t *testing.T) {
		var c *Client
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			// A concurrent sign-in replaced the session mid-refresh.
			coreStoreSession(t, c, "other-at", "other-rt", time.Now().Add(time.Hour))
			coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
		})
		c = srv.client(t)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		s, err := c.GetSession(ctx)
		if err != nil || s.AccessToken != "other-at" {
			t.Fatalf("GetSession = %+v, %v", s, err)
		}
	})
	t.Run("waiter context cancellation", func(t *testing.T) {
		release := make(chan struct{})
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			<-release
			coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
		})
		c := srv.client(t)
		coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
		cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		if _, err := c.GetSession(cctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
		close(release)
		// The detached refresh still commits the rotated tokens.
		deadline := time.Now().Add(2 * time.Second)
		for {
			if st := coreStored(t, c); st != nil && st.RefreshToken == "rt-2" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("refresh result not committed")
			}
			time.Sleep(5 * time.Millisecond)
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts refreshSession
func TestRefreshSession(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 200, coreSession("new-at", "new-rt", 3600))
	})
	c := srv.client(t)
	ev := coreWatch(c)
	if _, err := c.RefreshSession(ctx, ""); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	// Explicit token: stateless.
	resp, err := c.RefreshSession(ctx, "explicit-rt")
	if err != nil || resp.Session.RefreshToken != "new-rt" || resp.User == nil {
		t.Fatalf("RefreshSession = %+v, %v", resp, err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"refresh_token": "explicit-rt"})
	if coreStored(t, c) != nil {
		t.Fatal("explicit refresh stored a session")
	}
	coreAssertEvents(t, ev)
	// Stored session: refreshed even when not expiring.
	coreStoreSession(t, c, "at", "stored-rt", time.Now().Add(time.Hour))
	if _, err := c.RefreshSession(ctx, ""); err != nil {
		t.Fatal(err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"refresh_token": "stored-rt"})
	if coreStored(t, c).RefreshToken != "new-rt" {
		t.Fatal("stored session not updated")
	}
	coreAssertEvents(t, ev, EventTokenRefreshed)
}

// upstream: auth-js src/GoTrueClient.ts setSession
func TestSetSession(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Path == "/auth/v1/user" {
			coreJSON(w, 200, coreUser("user-9"))
			return
		}
		coreJSON(w, 200, coreSession("refreshed-at", "refreshed-rt", 3600))
	})
	c := srv.client(t)
	ev := coreWatch(c)
	exp := time.Now().Add(time.Hour).Unix()
	at := coreJWT(map[string]any{"sub": "user-9", "exp": exp})
	resp, err := c.SetSession(ctx, at, "rt")
	if err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", at)
	if resp.User.ID != "user-9" || resp.Session.ExpiresAt != exp || resp.Session.TokenType != "bearer" {
		t.Fatalf("resp = %+v", resp.Session)
	}
	if st := coreStored(t, c); st.AccessToken != at {
		t.Fatal("not stored")
	}
	coreAssertEvents(t, ev, EventSignedIn)

	expired := coreJWT(map[string]any{"sub": "user-9", "exp": time.Now().Add(-time.Hour).Unix()})
	resp, err = c.SetSession(ctx, expired, "old-rt")
	if err != nil || resp.Session.AccessToken != "refreshed-at" {
		t.Fatalf("SetSession(expired) = %+v, %v", resp, err)
	}
	coreAssertBody(t, srv.last(t), map[string]any{"refresh_token": "old-rt"})
	coreAssertEvents(t, ev, EventSignedIn, EventTokenRefreshed)

	if _, err := c.SetSession(ctx, "", "rt"); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.SetSession(ctx, "not-a-jwt", "rt"); !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts signOut / GoTrueAdminApi.ts signOut
func TestSignOut(t *testing.T) {
	ctx := context.Background()
	t.Run("global by default", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { w.WriteHeader(204) })
		c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
		ev := coreWatch(c)
		coreStoreSession(t, c, "at", "rt", time.Now().Add(time.Hour))
		if _, err := c.startPKCE(ctx, false); err != nil {
			t.Fatal(err)
		}
		if err := c.SignOut(ctx, "", ""); err != nil {
			t.Fatal(err)
		}
		r := srv.last(t)
		coreAssertCommon(t, r, http.MethodPost, "/auth/v1/logout", "at")
		if r.Query.Get("scope") != "global" {
			t.Errorf("scope = %q", r.Query.Get("scope"))
		}
		if coreStored(t, c) != nil || len(c.pkceIndex(ctx)) != 0 {
			t.Fatal("session or verifiers kept")
		}
		if v, _ := c.retrievePKCEVerifier(ctx, ""); v != "" {
			t.Fatal("legacy verifier kept")
		}
		coreAssertEvents(t, ev, EventSignedOut)
	})
	t.Run("401 is ignored", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 401, map[string]any{"msg": "invalid JWT"})
		})
		c := srv.client(t)
		coreStoreSession(t, c, "at", "rt", time.Now().Add(time.Hour))
		if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
			t.Fatal(err)
		}
		if srv.last(t).Query.Get("scope") != "local" || coreStored(t, c) != nil {
			t.Fatal("local sign-out failed")
		}
	})
	t.Run("others keeps session and emits nothing", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { w.WriteHeader(204) })
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "at", "rt", time.Now().Add(time.Hour))
		if err := c.SignOut(ctx, "", SignOutOthers); err != nil {
			t.Fatal(err)
		}
		if coreStored(t, c) == nil {
			t.Fatal("session removed")
		}
		coreAssertEvents(t, ev)
	})
	t.Run("server error still removes local session", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
			coreJSON(w, 500, map[string]any{"msg": "boom"})
		})
		c := srv.client(t)
		coreStoreSession(t, c, "at", "rt", time.Now().Add(time.Hour))
		if err := c.SignOut(ctx, "", SignOutGlobal); err == nil {
			t.Fatal("want error")
		}
		if coreStored(t, c) != nil {
			t.Fatal("session kept")
		}
		c2 := srv.client(t)
		coreStoreSession(t, c2, "at", "rt", time.Now().Add(time.Hour))
		if err := c2.SignOut(ctx, "", SignOutOthers); err == nil {
			t.Fatal("want error")
		}
		if coreStored(t, c2) == nil {
			t.Fatal("others scope removed session on failure")
		}
	})
	t.Run("explicit token is stateless", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { w.WriteHeader(204) })
		c := srv.client(t)
		ev := coreWatch(c)
		coreStoreSession(t, c, "stored", "rt", time.Now().Add(time.Hour))
		if err := c.SignOut(ctx, "user-jwt", SignOutLocal); err != nil {
			t.Fatal(err)
		}
		coreAssertCommon(t, srv.last(t), http.MethodPost, "/auth/v1/logout", "user-jwt")
		if coreStored(t, c) == nil {
			t.Fatal("stored session touched")
		}
		coreAssertEvents(t, ev)
		if err := c.SignOut(ctx, "x", "bogus"); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no session", func(t *testing.T) {
		srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
		c := srv.client(t)
		if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
			t.Fatal(err)
		}
		if len(srv.requests()) != 0 {
			t.Fatal("request sent without a session")
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts getUser
func TestGetUser(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Header.Get("Authorization") == "Bearer gone" {
			coreJSON(w, 403, map[string]any{"code": "session_not_found", "msg": "Session from session_id claim in JWT does not exist"})
			return
		}
		coreJSON(w, 200, coreUser("user-7"))
	})
	c := srv.client(t)
	ev := coreWatch(c)
	u, err := c.GetUser(ctx, "user-jwt")
	if err != nil || u.ID != "user-7" || u.Email != "user@example.com" || len(u.Identities) != 1 {
		t.Fatalf("GetUser = %+v, %v", u, err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", "user-jwt")

	if _, err := c.GetUser(ctx, ""); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	coreStoreSession(t, c, "stored-at", "rt", time.Now().Add(time.Hour))
	if _, err := c.GetUser(ctx, ""); err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", "stored-at")

	// session_not_found with an explicit token does not touch storage.
	if _, err := c.GetUser(ctx, "gone"); !isSessionMissing(err) {
		t.Fatalf("err = %v", err)
	}
	if coreStored(t, c) == nil {
		t.Fatal("stored session removed by explicit-token call")
	}
	coreStoreSession(t, c, "gone", "rt", time.Now().Add(time.Hour))
	if _, err := c.GetUser(ctx, ""); !errors.Is(err, &Error{Code: ErrorCodeSessionNotFound}) {
		t.Fatalf("err = %v", err)
	}
	if coreStored(t, c) != nil {
		t.Fatal("dead session kept")
	}
	coreAssertEvents(t, ev, EventSignedOut)

	// A custom Authorization header can stand in for a session.
	cc := srv.client(t, func(cfg *Config) { cfg.Headers = http.Header{"Authorization": {"Bearer custom"}} })
	if _, err := cc.GetUser(ctx, ""); err != nil {
		t.Fatal(err)
	}
	coreAssertCommon(t, srv.last(t), http.MethodGet, "/auth/v1/user", "custom")
}

// upstream: auth-js src/GoTrueClient.ts updateUser
func TestUpdateUser(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		u := coreUser("user-1")
		u["user_metadata"] = map[string]any{"theme": "dark"}
		coreJSON(w, 200, u)
	})
	c := srv.client(t)
	ev := coreWatch(c)
	params := UpdateUserParams{Password: "new-pw", Nonce: "123456", Data: map[string]any{"theme": "dark"}}
	if _, err := c.UpdateUser(ctx, "", params); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	coreStoreSession(t, c, "at", "rt", time.Now().Add(time.Hour))
	u, err := c.UpdateUser(ctx, "", params)
	if err != nil || u.UserMetadata["theme"] != "dark" {
		t.Fatalf("UpdateUser = %+v, %v", u, err)
	}
	r := srv.last(t)
	coreAssertCommon(t, r, http.MethodPut, "/auth/v1/user", "at")
	coreAssertBody(t, r, map[string]any{"password": "new-pw", "nonce": "123456", "data": map[string]any{"theme": "dark"},
		"code_challenge": nil, "code_challenge_method": nil})
	if st := coreStored(t, c); st.User == nil || st.User.UserMetadata["theme"] != "dark" {
		t.Fatal("stored user not updated")
	}
	coreAssertEvents(t, ev, EventUserUpdated)

	// Explicit token, PKCE email change.
	pc := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	pev := coreWatch(pc)
	if _, err := pc.UpdateUser(ctx, "user-jwt", UpdateUserParams{Email: "new@b.c", EmailRedirectTo: "https://app/changed"}); err != nil {
		t.Fatal(err)
	}
	r = srv.last(t)
	coreAssertCommon(t, r, http.MethodPut, "/auth/v1/user", "user-jwt")
	if r.Query.Get("redirect_to") != "https://app/changed" || r.Body["code_challenge_method"] != "s256" {
		t.Fatalf("request = %v %v", r.Query, r.Body)
	}
	if coreStored(t, pc) != nil {
		t.Fatal("explicit-token update stored a session")
	}
	coreAssertEvents(t, pev)
}

// upstream: auth-js src/GoTrueClient.ts onAuthStateChange
func TestOnAuthStateChange(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
	c := srv.client(t)
	var got []AuthChangeEvent
	var gotSession *Session
	unsubscribe := c.OnAuthStateChange(func(e AuthChangeEvent, s *Session) {
		got = append(got, e)
		gotSession = s
	})
	if _, err := c.SignInAnonymously(context.Background(), SignInAnonymouslyParams{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != EventSignedIn || gotSession == nil || gotSession.AccessToken != "at" {
		t.Fatalf("events = %v session = %+v", got, gotSession)
	}
	unsubscribe()
	if err := c.SignOut(context.Background(), "", SignOutLocal); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("event after unsubscribe: %v", got)
	}
}

// upstream: auth-js src/GoTrueClient.ts startAutoRefresh / _autoRefreshTokenTick
func TestAutoRefresh(t *testing.T) {
	refreshed := make(chan struct{}, 10)
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
		refreshed <- struct{}{}
	})
	c := srv.client(t)
	c.tickDuration = 10 * time.Millisecond
	// Expires within 3 ticks (30ms) -> refreshed on the first tick.
	coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(20*time.Millisecond))
	ev := coreWatch(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.StartAutoRefresh(ctx)
	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("no refresh")
	}
	coreWaitFor(t, func() bool { return len(ev.get()) == 1 })
	c.StopAutoRefresh()
	c.StopAutoRefresh() // idempotent
	if st := coreStored(t, c); st.RefreshToken != "rt-2" {
		t.Fatalf("stored = %+v", st)
	}
	coreAssertEvents(t, ev, EventTokenRefreshed)
	// The fresh session (1h) is far from expiry: no further refreshes.
	c.StartAutoRefresh(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel() // parent cancellation also stops it
	c.StopAutoRefresh()
	if n := srv.count("/auth/v1/token"); n != 1 {
		t.Fatalf("%d refreshes", n)
	}
}

// upstream: auth-js src/GoTrueClient.ts constructor (autoRefreshToken option)
func TestAutoRefreshConfig(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
	c := srv.client(t, func(cfg *Config) { cfg.AutoRefreshToken = true })
	c.autoMu.Lock()
	running := c.autoCancel != nil
	c.autoMu.Unlock()
	if !running {
		t.Fatal("auto refresh not started")
	}
	c.StopAutoRefresh()
	c.autoMu.Lock()
	running = c.autoCancel != nil
	c.autoMu.Unlock()
	if running {
		t.Fatal("auto refresh still running")
	}
}

// upstream: auth-js GoTrueClientOptions.storage (custom SupportedStorage)
func TestCustomStorage(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, coreSession("at", "rt", 3600)) })
	store := &recordingStorage{inner: NewMemoryStorage()}
	c := srv.client(t, func(cfg *Config) { cfg.Storage = store; cfg.StorageKey = "custom-key" })
	if _, err := c.SignInAnonymously(ctx, SignInAnonymouslyParams{}); err != nil {
		t.Fatal(err)
	}
	raw, _ := store.inner.GetItem(ctx, "custom-key")
	if raw == "" {
		t.Fatal("session not written under the configured key")
	}
	// A second client sharing the storage sees the persisted session.
	c2 := srv.client(t, func(cfg *Config) { cfg.Storage = store; cfg.StorageKey = "custom-key" })
	if s, err := c2.GetSession(ctx); err != nil || s == nil || s.AccessToken != "at" {
		t.Fatalf("GetSession = %+v, %v", s, err)
	}
	// Storage errors surface.
	store.mu.Lock()
	store.fail = true
	store.mu.Unlock()
	if _, err := c2.GetSession(ctx); !errors.Is(err, errStorage) {
		t.Fatalf("err = %v", err)
	}
	// Default key derives from the project ref.
	d, err := New(Config{URL: "https://abcdef.supabase.co/auth/v1", APIKey: "k"})
	if err != nil || d.storageKey != "sb-abcdef-auth-token" {
		t.Fatalf("default key = %q, %v", d.storageKey, err)
	}
}

var errStorage = errors.New("storage down")

type recordingStorage struct {
	inner *MemoryStorage
	mu    sync.Mutex
	fail  bool
}

func (s *recordingStorage) failing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fail
}

func (s *recordingStorage) GetItem(ctx context.Context, k string) (string, error) {
	if s.failing() {
		return "", errStorage
	}
	return s.inner.GetItem(ctx, k)
}

func (s *recordingStorage) SetItem(ctx context.Context, k, v string) error {
	if s.failing() {
		return errStorage
	}
	return s.inner.SetItem(ctx, k, v)
}

func (s *recordingStorage) RemoveItem(ctx context.Context, k string) error {
	if s.failing() {
		return errStorage
	}
	return s.inner.RemoveItem(ctx, k)
}
