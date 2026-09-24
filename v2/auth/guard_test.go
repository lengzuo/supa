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
		_, err := c.GetSessionFromURL(ctx, "https://app/cb?code=abc&"+PKCEFlowIDParam+"="+bad, nil)
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
	_, err := c.GetSessionFromURL(context.Background(), "https://app/cb#error=access_denied&error_code=otp_expired", nil)
	var ae *Error
	if !errors.As(err, &ae) || ae.Message != "Error in URL with unspecified error_description" || ae.Code != "otp_expired" || ae.RedirectError != "access_denied" {
		t.Fatalf("err = %#v", err)
	}
	if !errors.Is(err, ErrImplicitGrantRedirect) || !errors.Is(err, &Error{Code: ErrorCodeOTPExpired}) {
		t.Fatalf("err %v does not match ErrImplicitGrantRedirect and its code", err)
	}
	_, err = c.GetSessionFromURL(context.Background(), "https://app/cb?error_description=Denied", nil)
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

// A listener may call locking methods: events are delivered after the
// session lock is released.
// upstream: auth-js src/GoTrueClient.ts _notifyAllSubscribers (outside the lock)
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
				_, err := c.RefreshSession(ctx, "")
				got <- err
			})
		}
	})
	if _, err := c.GetSession(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("listener did not run before GetSession returned")
	}
}
