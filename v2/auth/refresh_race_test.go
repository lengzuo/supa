package auth

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// strictRefreshServer is a fake Auth server that, like GoTrue with reuse
// detection, accepts only the current refresh token and flags any reuse.
type strictRefreshServer struct {
	*coreServer
	mu        sync.Mutex
	current   string
	gen       int
	expiresIn int64
	reused    atomic.Bool
	// verifyGate and tokenGate, when set, hold MFA verify and refresh
	// requests until released.
	verifyGate *gate
	tokenGate  *gate
}

func newStrictRefreshServer(t *testing.T, first string, expiresIn int64) *strictRefreshServer {
	s := &strictRefreshServer{current: first, gen: 1, expiresIn: expiresIn}
	s.coreServer = newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/token":
			if g := s.tokenGate; g != nil {
				g.wait()
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if r.Body["refresh_token"] != s.current {
				s.reused.Store(true)
				coreJSON(w, 400, map[string]any{"code": ErrorCodeRefreshTokenReused, "msg": "Invalid Refresh Token: Already Used"})
				return
			}
			s.gen++
			s.current = fmt.Sprintf("rt.1.%d", s.gen)
			coreJSON(w, 200, coreSession(fmt.Sprintf("at.%d", s.gen), s.current, s.expiresIn))
		case "/auth/v1/factors/f-1/verify", "/auth/v1/factors/recovery-codes/verify":
			// Like GoTrue updateMFASessionAndClaims: a successful verify swaps
			// the session's refresh token.
			if g := s.verifyGate; g != nil {
				g.wait()
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.gen++
			s.current = fmt.Sprintf("rt.1.%d", s.gen)
			coreJSON(w, 200, coreSession(fmt.Sprintf("at.%d", s.gen), s.current, s.expiresIn))
		case "/auth/v1/logout":
			w.WriteHeader(204)
		}
	})
	return s
}

func (s *strictRefreshServer) currentToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// pausingStorage pauses the next read of key (after reading it) until
// resumed, simulating a goroutine that read the session just before
// others rotated it.
type pausingStorage struct {
	*MemoryStorage
	key    string
	mu     sync.Mutex
	armed  bool
	paused chan struct{}
	resume chan struct{}
}

func newPausingStorage(key string) *pausingStorage {
	return &pausingStorage{MemoryStorage: NewMemoryStorage(), key: key, paused: make(chan struct{}, 1), resume: make(chan struct{})}
}

func (p *pausingStorage) arm() {
	p.mu.Lock()
	p.armed = true
	p.mu.Unlock()
}

func (p *pausingStorage) GetItem(ctx context.Context, key string) (string, error) {
	v, err := p.MemoryStorage.GetItem(ctx, key)
	p.mu.Lock()
	pause := p.armed && key == p.key
	if pause {
		p.armed = false
	}
	p.mu.Unlock()
	if pause {
		p.paused <- struct{}{}
		<-p.resume
	}
	return v, err
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (never send a rotated refresh token)
func TestRefreshStaleTokenNotSent(t *testing.T) {
	ctx := context.Background()
	srv := newStrictRefreshServer(t, "rt.1.1", 3600)
	store := newPausingStorage("sb-test-auth-token")
	c := srv.client(t, func(cfg *Config) { cfg.Storage = store; cfg.StorageKey = "sb-test-auth-token" })
	coreStoreSession(t, c, "at.1", "rt.1.1", time.Now().Add(time.Hour))

	store.arm()
	type result struct {
		resp *AuthResponse
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := c.RefreshSession(ctx, "") // reads rt.1.1, then pauses
		done <- result{resp, err}
	}()
	<-store.paused
	for i := 0; i < 2; i++ { // rt.1.1 -> rt.1.2 -> rt.1.3
		if _, err := c.RefreshSession(ctx, ""); err != nil {
			t.Fatal(err)
		}
	}
	close(store.resume)
	res := <-done
	if srv.reused.Load() {
		t.Fatal("stale refresh token was sent to the server")
	}
	if res.err != nil || res.resp.Session.RefreshToken != "rt.1.3" {
		t.Fatalf("stale caller got %+v, %v", res.resp, res.err)
	}
	if n := srv.count("/auth/v1/token"); n != 2 {
		t.Fatalf("%d /token requests, want 2", n)
	}
	if st := coreStored(t, c); st.RefreshToken != "rt.1.3" {
		t.Fatalf("stored = %q", st.RefreshToken)
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (stale token, stored session also expiring)
func TestRefreshStaleTokenRefreshesStored(t *testing.T) {
	ctx := context.Background()
	srv := newStrictRefreshServer(t, "rt.1.1", 30) // every session is within the margin
	store := newPausingStorage("sb-test-auth-token")
	c := srv.client(t, func(cfg *Config) { cfg.Storage = store; cfg.StorageKey = "sb-test-auth-token" })
	coreStoreSession(t, c, "at.1", "rt.1.1", time.Now().Add(10*time.Second))

	store.arm()
	done := make(chan error, 1)
	go func() {
		_, err := c.GetSession(ctx)
		done <- err
	}()
	<-store.paused
	if _, err := c.GetSession(ctx); err != nil { // rt.1.1 -> rt.1.2
		t.Fatal(err)
	}
	close(store.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if srv.reused.Load() {
		t.Fatal("stale refresh token was sent to the server")
	}
	if st := coreStored(t, c); st.RefreshToken != srv.currentToken() {
		t.Fatalf("stored %q, server %q", st.RefreshToken, srv.currentToken())
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (concurrent refresh chaos, strict reuse detection)
func TestRefreshChaosStrictServer(t *testing.T) {
	ctx := context.Background()
	// expires_in 60s is inside the 90s margin: every GetSession refreshes.
	srv := newStrictRefreshServer(t, "rt.1.1", 60)
	c := srv.client(t)
	coreStoreSession(t, c, "at.1", "rt.1.1", time.Now().Add(10*time.Second))
	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, seed))
			for i := 0; i < 20; i++ {
				switch rng.IntN(3) {
				case 0:
					_, _ = c.GetSession(ctx)
				case 1:
					_, _ = c.RefreshSession(ctx, "")
				default:
					c.autoRefreshTick(ctx)
				}
			}
		}(uint64(g))
	}
	wg.Wait()
	if srv.reused.Load() {
		t.Fatal("a rotated refresh token was reused")
	}
	st := coreStored(t, c)
	if st == nil || st.RefreshToken != srv.currentToken() {
		t.Fatalf("stored %+v, server current %q", st, srv.currentToken())
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (events delivered before callers resolve)
func TestRefreshEventOrder(t *testing.T) {
	ctx := context.Background()
	srv := newStrictRefreshServer(t, "rt.1.1", 3600)
	for i := 0; i < 30; i++ {
		c := srv.client(t)
		coreStoreSession(t, c, "at", srv.currentToken(), time.Now().Add(time.Hour))
		ev := coreWatch(c)
		if _, err := c.RefreshSession(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if got := ev.get(); len(got) != 1 || got[0] != EventTokenRefreshed {
			t.Fatalf("after RefreshSession: %v", got)
		}
		if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
			t.Fatal(err)
		}
		coreAssertEvents(t, ev, EventTokenRefreshed, EventSignedOut)
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (listener re-entering during SIGNED_OUT)
func TestRefreshFailureListenerReentry(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 400, map[string]any{"code": ErrorCodeRefreshTokenNotFound, "msg": "Invalid Refresh Token"})
	})
	c := srv.client(t)
	coreStoreSession(t, c, "at", "rt-1", time.Now().Add(-time.Minute))
	reentered := make(chan error, 1)
	c.OnAuthStateChange(func(e AuthChangeEvent, _ *Session) {
		if e == EventSignedOut {
			cctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			_, err := c.callRefreshToken(cctx, "rt-1", c.removalEpoch.Load(), false)
			reentered <- err
		}
	})
	if _, err := c.GetSession(ctx); !errors.Is(err, &Error{Code: ErrorCodeRefreshTokenNotFound}) {
		t.Fatalf("err = %v", err)
	}
	select {
	case err := <-reentered:
		if !errors.Is(err, &Error{Code: ErrorCodeRefreshTokenNotFound}) {
			t.Fatalf("re-entrant refresh err = %v (want the cached failure)", err)
		}
	default:
		t.Fatal("SIGNED_OUT not delivered before GetSession returned")
	}
	if n := srv.count("/auth/v1/token"); n != 1 {
		t.Fatalf("%d /token requests, want 1", n)
	}
}

// upstream: auth-js src/GoTrueClient.ts _callRefreshToken (removal only of the failed session)
func TestRefreshFailureKeepsNewerSession(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if r.Query.Get("grant_type") == "password" {
			s := coreSession("fresh-at", "fresh-rt", 3600)
			s["expires_at"] = time.Now().Add(-time.Second).Unix() // already expired access token
			coreJSON(w, 200, s)
			return
		}
		g.wait()
		coreJSON(w, 400, map[string]any{"code": ErrorCodeRefreshTokenNotFound, "msg": "Invalid Refresh Token"})
	})
	c := srv.client(t)
	coreStoreSession(t, c, "old-at", "old-rt", time.Now().Add(-time.Minute))
	ev := coreWatch(c)
	done := make(chan error, 1)
	go func() {
		_, err := c.GetSession(ctx)
		done <- err
	}()
	g.await(t)
	if _, err := c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	<-done
	if st := coreStored(t, c); st == nil || st.RefreshToken != "fresh-rt" {
		t.Fatalf("fresh sign-in removed by a stale refresh failure: %+v", st)
	}
	coreAssertEvents(t, ev, EventSignedIn)
}

// upstream: auth-js src/GoTrueClient.ts _getUser (session_not_found removes only that session)
func TestGetUserSessionNotFoundKeepsNewerSession(t *testing.T) {
	ctx := context.Background()
	g := newGate()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		switch r.Path {
		case "/auth/v1/user":
			g.wait()
			coreJSON(w, 403, map[string]any{"code": ErrorCodeSessionNotFound, "msg": "Session not found"})
		case "/auth/v1/token":
			coreJSON(w, 200, coreSession("fresh-at", "fresh-rt", 3600))
		}
	})
	c := srv.client(t)
	coreStoreSession(t, c, "dead-at", "dead-rt", time.Now().Add(time.Hour))
	done := make(chan error, 1)
	go func() {
		_, err := c.GetUser(ctx, "")
		done <- err
	}()
	g.await(t)
	if _, err := c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if err := <-done; !isSessionMissing(err) {
		t.Fatalf("err = %v", err)
	}
	if st := coreStored(t, c); st == nil || st.AccessToken != "fresh-at" {
		t.Fatalf("fresh sign-in removed: %+v", st)
	}
}

// upstream: auth-js lib/fetch.ts (pre-send failures are not retryable fetch errors)
func TestRefreshPreSendErrorNotRetried(t *testing.T) {
	ctx := context.Background()
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 200, coreSession("at-2", "rt-2", 3600))
	})
	var edits atomic.Int32
	editorErr := errors.New("editor failed")
	c := srv.client(t, func(cfg *Config) {
		cfg.RequestEditors = []func(*http.Request) error{func(r *http.Request) error {
			edits.Add(1)
			return editorErr
		}}
	})
	c.refreshRetryBudget, c.refreshRetryBase = 30*time.Second, 10*time.Millisecond
	coreStoreSession(t, c, "at-1", "rt-1", time.Now().Add(-time.Minute))
	start := time.Now()
	if _, err := c.GetSession(ctx); !errors.Is(err, editorErr) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second || edits.Load() != 1 {
		t.Fatalf("pre-send failure retried: %d attempts in %v", edits.Load(), time.Since(start))
	}
	// Cached for the cooldown: no new attempt.
	if _, err := c.GetSession(ctx); !errors.Is(err, editorErr) {
		t.Fatalf("err = %v", err)
	}
	if edits.Load() != 1 {
		t.Fatalf("%d attempts during cooldown", edits.Load())
	}
	if coreStored(t, c) == nil {
		t.Fatal("session dropped after a local failure")
	}
	if isRetryable(fmt.Errorf("wrapped: %w", editorErr)) != true {
		t.Fatal("plain network-style errors stay retryable")
	}
}

// MemoryStorage's zero value is ready to use.
func TestMemoryStorageZeroValue(t *testing.T) {
	var s MemoryStorage
	ctx := context.Background()
	if err := s.SetItem(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetItem(ctx, "k"); v != "v" {
		t.Fatalf("GetItem = %q", v)
	}
	if err := s.RemoveItem(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if err := (&MemoryStorage{}).RemoveItem(ctx, "missing"); err != nil {
		t.Fatal(err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify + _callRefreshToken share _acquireLock
// (an MFA verify rotating the refresh token must not race a refresh)
func TestMFAVerifyRacingRefresh(t *testing.T) {
	ctx := context.Background()
	t.Run("refresh started during verify", func(t *testing.T) {
		srv := newStrictRefreshServer(t, "rt.1.1", 3600)
		srv.verifyGate = newGate()
		c := srv.client(t)
		coreStoreSession(t, c, "at.1", "rt.1.1", time.Now().Add(time.Hour))
		verified := make(chan error, 1)
		go func() {
			_, err := c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "ch", Code: "123456"})
			verified <- err
		}()
		srv.verifyGate.await(t) // verify sent with at.1 and held
		refreshed := make(chan error, 1)
		go func() {
			_, err := c.RefreshSession(ctx, "") // reads rt.1.1 from storage
			refreshed <- err
		}()
		time.Sleep(20 * time.Millisecond)
		close(srv.verifyGate.release) // server rotates rt.1.1 -> rt.1.2
		if err := <-verified; err != nil {
			t.Fatal(err)
		}
		if err := <-refreshed; err != nil {
			t.Fatal(err)
		}
		// The next refresh must use the live token.
		if _, err := c.RefreshSession(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if srv.reused.Load() {
			t.Fatal("a rotated refresh token was sent")
		}
		if st := coreStored(t, c); st.RefreshToken != srv.currentToken() {
			t.Fatalf("stored %q, server %q", st.RefreshToken, srv.currentToken())
		}
	})
	t.Run("verify started during refresh", func(t *testing.T) {
		srv := newStrictRefreshServer(t, "rt.1.1", 3600)
		srv.tokenGate = newGate()
		c := srv.client(t)
		coreStoreSession(t, c, "at.1", "rt.1.1", time.Now().Add(time.Hour))
		refreshed := make(chan error, 1)
		go func() {
			_, err := c.RefreshSession(ctx, "")
			refreshed <- err
		}()
		srv.tokenGate.await(t) // refresh sent with rt.1.1 and held
		verified := make(chan error, 1)
		go func() {
			_, err := c.MFA().RecoveryCodes().Verify(ctx, MFARecoveryCodesVerifyParams{Code: "abcd-efgh"})
			verified <- err
		}()
		time.Sleep(20 * time.Millisecond)
		close(srv.tokenGate.release)
		if err := <-refreshed; err != nil {
			t.Fatal(err)
		}
		if err := <-verified; err != nil {
			t.Fatal(err)
		}
		if n := srv.count("/auth/v1/factors/recovery-codes/verify"); n != 1 {
			t.Fatalf("%d verify requests", n)
		}
		if got := srv.last(t).Header.Get("Authorization"); got != "Bearer at.2" {
			t.Fatalf("verify used %q, want the refreshed session's token", got)
		}
		if _, err := c.RefreshSession(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if srv.reused.Load() {
			t.Fatal("a rotated refresh token was sent")
		}
		if st := coreStored(t, c); st.RefreshToken != srv.currentToken() {
			t.Fatalf("stored %q, server %q", st.RefreshToken, srv.currentToken())
		}
	})
}

// upstream: auth-js src/GoTrueClient.ts (refresh + MFA verify chaos, strict reuse detection)
func TestRefreshVerifyChaosStrictServer(t *testing.T) {
	ctx := context.Background()
	srv := newStrictRefreshServer(t, "rt.1.1", 60) // inside the margin: GetSession refreshes
	c := srv.client(t)
	coreStoreSession(t, c, "at.1", "rt.1.1", time.Now().Add(10*time.Second))
	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, seed+7))
			for i := 0; i < 20; i++ {
				switch rng.IntN(5) {
				case 0:
					_, _ = c.GetSession(ctx)
				case 1:
					_, _ = c.RefreshSession(ctx, "")
				case 2:
					c.autoRefreshTick(ctx)
				case 3:
					_, _ = c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "ch", Code: "1"})
				default:
					_, _ = c.MFA().RecoveryCodes().Verify(ctx, MFARecoveryCodesVerifyParams{Code: "abcd"})
				}
			}
		}(uint64(g))
	}
	wg.Wait()
	if srv.reused.Load() {
		t.Fatal("a rotated refresh token was reused")
	}
	st := coreStored(t, c)
	if st == nil || st.RefreshToken != srv.currentToken() {
		t.Fatalf("stored %+v, server current %q", st, srv.currentToken())
	}
	if _, err := c.RefreshSession(ctx, ""); err != nil || srv.reused.Load() {
		t.Fatalf("session unusable after chaos: %v", err)
	}
}
