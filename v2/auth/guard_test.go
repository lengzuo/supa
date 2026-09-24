package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// gate lets a fake-server handler block until the test releases it.
type gate struct {
	entered chan struct{}
	release chan struct{}
}

func newGate() *gate { return &gate{entered: make(chan struct{}, 1), release: make(chan struct{})} }

func (g *gate) wait() {
	g.entered <- struct{}{}
	<-g.release
}

func (g *gate) await(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not arrive")
	}
}

// upstream: auth-js src/GoTrueClient.ts _updateUser (write-back vs concurrent refresh)
func TestUpdateUserConcurrentRefresh(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name        string
		refreshUser string
		wantUser    bool
	}{
		{"same user keeps rotated tokens", "user-1", true},
		{"different user is left alone", "user-2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGate()
			srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
				switch r.Path {
				case "/auth/v1/user":
					g.wait()
					u := coreUser("user-1")
					u["user_metadata"] = map[string]any{"theme": "dark"}
					coreJSON(w, 200, u)
				case "/auth/v1/token":
					s := coreSession("at-2", "rt-2", 3600)
					s["user"] = coreUser(tc.refreshUser)
					coreJSON(w, 200, s)
				}
			})
			c := srv.client(t)
			coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(time.Hour))
			ev := coreWatch(c)
			done := make(chan error, 1)
			go func() {
				_, err := c.UpdateUser(ctx, "", UpdateUserParams{Data: map[string]any{"theme": "dark"}})
				done <- err
			}()
			g.await(t)
			if _, err := c.RefreshSession(ctx, ""); err != nil {
				t.Fatal(err)
			}
			close(g.release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			st := coreStored(t, c)
			if st == nil || st.RefreshToken != "rt-2" || st.AccessToken != "at-2" {
				t.Fatalf("rotated tokens overwritten by stale write-back: %+v", st)
			}
			updated := st.User != nil && st.User.UserMetadata["theme"] == "dark"
			if updated != tc.wantUser {
				t.Fatalf("user updated = %v, want %v", updated, tc.wantUser)
			}
			want := []AuthChangeEvent{EventTokenRefreshed}
			if tc.wantUser {
				want = append(want, EventUserUpdated)
			}
			coreAssertEvents(t, ev, want...)
		})
	}
}

// upstream: auth-js src/GoTrueClient.ts _updateUser (write-back vs concurrent sign-out)
func TestUpdateUserConcurrentSignOut(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/user":
			g.wait()
			coreJSON(w, 200, coreUser("user-1"))
		case "/auth/v1/logout":
			w.WriteHeader(204)
		}
	})
	c := srv.client(t)
	coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(time.Hour))
	ev := coreWatch(c)
	done := make(chan error, 1)
	go func() {
		_, err := c.UpdateUser(ctx, "", UpdateUserParams{Password: "new"})
		done <- err
	}()
	g.await(t)
	if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := coreStored(t, c); st != nil {
		t.Fatalf("signed-out session resurrected: %+v", st)
	}
	coreAssertEvents(t, ev, EventSignedOut)
}

// upstream: auth-js src/GoTrueClient.ts linkIdentityIdToken (write-back vs concurrent sign-out)
func TestLinkIdentityConcurrentSignOut(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/token":
			g.wait()
			coreJSON(w, 200, coreSession("linked-at", "linked-rt", 3600))
		case "/auth/v1/logout":
			w.WriteHeader(204)
		}
	})
	c := srv.client(t)
	coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(time.Hour))
	ev := coreWatch(c)
	done := make(chan error, 1)
	go func() {
		_, err := c.LinkIdentityWithIDToken(ctx, "", SignInWithIDTokenParams{Provider: "google", Token: "idt"})
		done <- err
	}()
	g.await(t)
	if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := coreStored(t, c); st != nil {
		t.Fatalf("signed-out session resurrected: %+v", st)
	}
	coreAssertEvents(t, ev, EventSignedOut)
}

// upstream: auth-js src/GoTrueClient.ts _verify (MFA write-back vs concurrent sign-out)
func TestMFAVerifyConcurrentSignOut(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/factors/f-1/verify", "/auth/v1/factors/recovery-codes/verify":
			g.wait()
			coreJSON(w, 200, coreSession("aal2-at", "aal2-rt", 3600))
		case "/auth/v1/logout":
			w.WriteHeader(204)
		}
	})
	for _, verify := range []struct {
		name string
		fn   func(c *Client) (*Session, error)
	}{
		{"factor", func(c *Client) (*Session, error) {
			return c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "ch", Code: "123456"})
		}},
		{"recovery code", func(c *Client) (*Session, error) {
			return c.MFA().RecoveryCodes().Verify(ctx, MFARecoveryCodesVerifyParams{Code: "abcd-efgh"})
		}},
	} {
		t.Run(verify.name, func(t *testing.T) {
			c := srv.client(t, func(cfg *Config) {})
			coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(time.Hour))
			ev := coreWatch(c)
			type result struct {
				s   *Session
				err error
			}
			done := make(chan result, 1)
			go func() {
				s, err := verify.fn(c)
				done <- result{s, err}
			}()
			g.await(t)
			if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
				t.Fatal(err)
			}
			g.release <- struct{}{}
			res := <-done
			if res.err != nil || res.s == nil || res.s.AccessToken != "aal2-at" {
				t.Fatalf("Verify = %+v, %v", res.s, res.err)
			}
			if st := coreStored(t, c); st != nil {
				t.Fatalf("signed-out session resurrected by MFA verify: %+v", st)
			}
			coreAssertEvents(t, ev, EventSignedOut)
		})
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (commit guard vs _removeSession)
func TestRefreshDiscardedAfterSignOut(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		g.wait()
		coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
	})
	c := srv.client(t)
	ev := coreWatch(c)
	expired := coreJWT(map[string]any{"sub": "user-1", "exp": time.Now().Add(-time.Hour).Unix()})
	done := make(chan error, 1)
	go func() {
		// Empty storage: only the removal epoch can detect the sign-out.
		_, err := c.SetSession(ctx, expired, "rt-1")
		done <- err
	}()
	g.await(t)
	if err := c.clearSession(ctx); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if err := <-done; !errors.Is(err, ErrRefreshDiscarded) {
		t.Fatalf("err = %v, want ErrRefreshDiscarded", err)
	}
	if st := coreStored(t, c); st != nil {
		t.Fatalf("refresh resurrected a signed-out session: %+v", st)
	}
	coreAssertEvents(t, ev, EventSignedOut)
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (lastRefreshFailure caches AuthError only)
func TestRefreshFailureCacheOnlyAuthErrors(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	})
	c := srv.client(t)
	coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
	for i := 0; i < 2; i++ {
		if _, err := c.GetSession(ctx); err == nil {
			t.Fatal("want decode error")
		}
	}
	if n := srv.count("/auth/v1/token"); n != 2 {
		t.Fatalf("%d refresh requests, want 2 (local failures are not cached)", n)
	}
	if coreStored(t, c) == nil {
		t.Fatal("session dropped after a decode failure")
	}
}

// upstream: auth-js src/GoTrueClient.ts _exchangeCodeForSession (invalid flow id fails fast)
func TestGetSessionFromURLInvalidFlowID(t *testing.T) {
	ctx := context.Background()
	srv := pkceExchangeServer(t)
	c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	if _, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"bad!", ""} {
		_, err := c.GetSessionFromURL(ctx, "https://app/cb?code=abc&"+PKCEFlowIDParam+"="+bad)
		if !errors.Is(err, ErrPKCEVerifierMissing) {
			t.Fatalf("flow id %q: err = %v", bad, err)
		}
	}
	if srv.count("/auth/v1/token") != 0 {
		t.Fatal("code exchanged with another flow's verifier")
	}
	if v, _ := c.retrievePKCEVerifier(ctx, ""); v == "" {
		t.Fatal("pending flow lost its verifier")
	}
}

// upstream: auth-js src/GoTrueClient.ts _getSessionFromURL (AuthImplicitGrantRedirectError)
func TestGetSessionFromURLErrorParams(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
	c := srv.client(t)
	_, err := c.GetSessionFromURL(context.Background(), "https://app/cb#error=access_denied&error_code=otp_expired")
	var ae *Error
	if !errors.As(err, &ae) || ae.Message != "Error in URL with unspecified error_description" || ae.Code != "otp_expired" || ae.RedirectError != "access_denied" {
		t.Fatalf("err = %#v", err)
	}
	if !errors.Is(err, ErrImplicitGrantRedirect) || !errors.Is(err, &Error{Code: ErrorCodeOTPExpired}) {
		t.Fatalf("err %v does not match ErrImplicitGrantRedirect and its code", err)
	}
	_, err = c.GetSessionFromURL(context.Background(), "https://app/cb?error_description=Denied")
	if !errors.As(err, &ae) || ae.Message != "Denied" || ae.Code != "unspecified_code" || !errors.Is(err, ErrImplicitGrantRedirect) {
		t.Fatalf("err = %#v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _updateUser (PKCE verifier cleanup on failure)
func TestUpdateUserDecodeFailureRemovesVerifier(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, []int{1}) })
	c := srv.client(t, func(cfg *Config) { cfg.FlowType = FlowPKCE })
	if _, err := c.UpdateUser(ctx, "jwt", UpdateUserParams{Email: "new@b.c"}); err == nil {
		t.Fatal("want decode error")
	}
	if idx := c.pkceIndex(ctx); len(idx) != 0 {
		t.Fatalf("verifier kept: %v", idx)
	}
}

// upstream: auth-js src/lib/helpers.ts getItemAsync (corrupt entries read as absent)
func TestLoadSessionCorruptEntry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStorage()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {})
	c := srv.client(t, func(cfg *Config) { cfg.Storage = store })
	_ = store.SetItem(ctx, c.storageKey, "{corrupt")
	if s, err := c.GetSession(ctx); s != nil || err != nil {
		t.Fatalf("GetSession = %v, %v", s, err)
	}
	if raw, _ := store.GetItem(ctx, c.storageKey); raw != "{corrupt" {
		t.Fatal("corrupt entry deleted without coordination")
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (refreshingDeferred resolved before notify)
func TestRefreshListenerCanRefresh(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
	})
	c := srv.client(t)
	coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
	got := make(chan error, 1)
	var once sync.Once
	c.OnAuthStateChange(func(e AuthChangeEvent, _ *Session) {
		if e == EventTokenRefreshed {
			once.Do(func() {
				// The in-flight call for rt-1 is already finished, so this
				// does not wait on itself.
				_, err := c.callRefreshToken(ctx, "rt-1", c.removalEpoch.Load(), true)
				got <- err
			})
		}
	})
	if _, err := c.GetSession(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("listener deadlocked on the in-flight refresh")
	}
}
