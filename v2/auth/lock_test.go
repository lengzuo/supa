package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// famServer is a strict fake GoTrue that models refresh-token families:
// a refresh and an MFA / recovery-code verify rotate the session's refresh
// token; sending a rotated token is recorded as a violation and revokes
// the session, like GoTrue's reuse detection.
type famServer struct {
	*coreServer
	mu         sync.Mutex
	gen        int
	nsid       int
	rtState    map[string]string // rt -> "active" | "rotated"
	rtSess     map[string]string // rt -> session id
	atSess     map[string]string // at -> session id
	current    map[string]string // session id -> current rt
	revoked    map[string]bool
	violations []string
	expiresIn  atomic.Int64
	gates      sync.Map // path -> *gate
}

func newFamServer(t *testing.T) *famServer {
	s := &famServer{rtState: map[string]string{}, rtSess: map[string]string{}, atSess: map[string]string{},
		current: map[string]string{}, revoked: map[string]bool{}}
	s.expiresIn.Store(3600)
	s.coreServer = newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		if g, ok := s.gates.Load(r.Path); ok {
			g.(*gate).wait()
		}
		s.handle(w, r)
	})
	return s
}

func (s *famServer) issueLocked(sid string) map[string]any {
	s.gen++
	exp := s.expiresIn.Load()
	at := coreJWT(map[string]any{"exp": time.Now().Unix() + exp, "session_id": sid, "n": s.gen, "sub": "user-1"})
	rt := fmt.Sprintf("rt-%s-%d", sid, s.gen)
	if old := s.current[sid]; old != "" {
		s.rtState[old] = "rotated"
	}
	s.current[sid] = rt
	s.rtState[rt] = "active"
	s.rtSess[rt] = sid
	s.atSess[at] = sid
	return coreSession(at, rt, exp)
}

func (s *famServer) newSessionLocked(prefix string) map[string]any {
	s.nsid++
	return s.issueLocked(fmt.Sprintf("%s%d", prefix, s.nsid))
}

func (s *famServer) handle(w http.ResponseWriter, r *coreReq) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch r.Path {
	case "/auth/v1/token":
		switch r.Query.Get("grant_type") {
		case "refresh_token":
			rt, _ := r.Body["refresh_token"].(string)
			sid := s.rtSess[rt]
			if s.rtState[rt] == "rotated" {
				s.violations = append(s.violations, "rotated refresh token sent: "+rt)
				s.revoked[sid] = true
				coreJSON(w, 400, map[string]any{"code": ErrorCodeRefreshTokenReused, "msg": "Invalid Refresh Token: Already Used"})
				return
			}
			if sid == "" || s.revoked[sid] {
				coreJSON(w, 400, map[string]any{"code": ErrorCodeRefreshTokenNotFound, "msg": "Invalid Refresh Token"})
				return
			}
			coreJSON(w, 200, s.issueLocked(sid))
		case "pkce":
			prefix := "s"
			if code, _ := r.Body["auth_code"].(string); strings.HasPrefix(code, "ns") {
				prefix = "ns" // sessions issued to NoStore exchanges
			}
			coreJSON(w, 200, s.newSessionLocked(prefix))
		default:
			coreJSON(w, 200, s.newSessionLocked("s"))
		}
	case "/auth/v1/factors/f-1/verify", "/auth/v1/factors/recovery-codes/verify":
		sid := s.atSess[bearer]
		if sid == "" || s.revoked[sid] {
			coreJSON(w, 403, map[string]any{"code": ErrorCodeSessionNotFound, "msg": "session not found"})
			return
		}
		coreJSON(w, 200, s.issueLocked(sid))
	case "/auth/v1/logout":
		if sid := s.atSess[bearer]; sid != "" {
			switch r.Query.Get("scope") {
			case "local":
				s.revoked[sid] = true
			case "others":
				for k := range s.current {
					if k != sid {
						s.revoked[k] = true
					}
				}
			default:
				for k := range s.current {
					s.revoked[k] = true
				}
			}
		}
		w.WriteHeader(204)
	case "/auth/v1/user":
		sid := s.atSess[bearer]
		if sid == "" || s.revoked[sid] {
			coreJSON(w, 403, map[string]any{"code": ErrorCodeSessionNotFound, "msg": "session not found"})
			return
		}
		coreJSON(w, 200, coreUser("user-1"))
	default:
		coreJSON(w, 404, map[string]any{"msg": "not found " + r.Path})
	}
}

// seed creates a server session and stores it in c.
func (s *famServer) seed(t *testing.T, c *Client) *Session {
	t.Helper()
	s.mu.Lock()
	m := s.newSessionLocked("s")
	s.mu.Unlock()
	sess := &Session{AccessToken: m["access_token"].(string), RefreshToken: m["refresh_token"].(string), TokenType: "bearer",
		ExpiresIn: m["expires_in"].(int64), ExpiresAt: m["expires_at"].(int64), User: &User{ID: "user-1"}}
	if err := c.saveSession(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func (s *famServer) viol() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.violations...)
}

func (s *famServer) assertNoViolations(t *testing.T) {
	t.Helper()
	if v := s.viol(); len(v) > 0 {
		t.Fatalf("rotated refresh tokens sent: %v", v)
	}
}

// startGated installs a gate on path, runs fn in a goroutine and waits until
// its request is held at the server.
func startGated[T any](t *testing.T, srv *famServer, path string, fn func() T) (*gate, <-chan T) {
	t.Helper()
	g := newGate()
	srv.gates.Store(path, g)
	out := make(chan T, 1)
	go func() { out <- fn() }()
	g.await(t)
	srv.gates.Delete(path)
	return g, out
}

// waitBlocked gives a goroutine time to reach (and block on) the session lock.
func waitBlocked() { time.Sleep(30 * time.Millisecond) }

// SignOut racing a refresh / verify of the same session: the other
// operation waits for the session lock, so SignOut's removal is final.
// upstream: auth-js src/GoTrueClient.ts _signOut / _callRefreshToken / _verify (shared _acquireLock)
func TestSignOutSerializedWithRotations(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		op   func(c *Client) error
	}{
		{"refresh", func(c *Client) error { _, err := c.RefreshSession(ctx, ""); return err }},
		{"mfa verify", func(c *Client) error {
			_, err := c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "123456"})
			return err
		}},
		{"recovery verify", func(c *Client) error {
			_, err := c.MFA().RecoveryCodes().Verify(ctx, MFARecoveryCodesVerifyParams{Code: "abcd"})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFamServer(t)
			c := srv.client(t)
			srv.seed(t, c)
			ev := coreWatch(c)
			g, signedOut := startGated(t, srv, "/auth/v1/logout", func() error { return c.SignOut(ctx, "", SignOutGlobal) })
			opDone := make(chan error, 1)
			go func() { opDone <- tc.op(c) }()
			waitBlocked()
			close(g.release)
			if err := <-signedOut; err != nil {
				t.Fatal(err)
			}
			if err := <-opDone; !errors.Is(err, ErrSessionMissing) {
				t.Fatalf("operation after sign-out: err = %v, want ErrSessionMissing", err)
			}
			if st := coreStored(t, c); st != nil {
				t.Fatalf("session left after a successful SignOut: %+v", st)
			}
			coreAssertEvents(t, ev, EventSignedOut)
			srv.assertNoViolations(t)
		})
	}
}

// An in-flight session write followed by SignOut: SignOut waits and wins.
// upstream: auth-js src/GoTrueClient.ts _updateUser / linkIdentityIdToken / _verify then _signOut
func TestSessionWriteThenSignOut(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		path  string
		event AuthChangeEvent
		op    func(c *Client) error
	}{
		{"update user", "/auth/v1/user", EventUserUpdated, func(c *Client) error {
			_, err := c.UpdateUser(ctx, "", UpdateUserParams{Data: map[string]any{"x": 1}})
			return err
		}},
		{"mfa verify", "/auth/v1/factors/f-1/verify", EventMFAChallengeVerified, func(c *Client) error {
			_, err := c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFamServer(t)
			c := srv.client(t)
			srv.seed(t, c)
			ev := coreWatch(c)
			g, opDone := startGated(t, srv, tc.path, func() error { return tc.op(c) })
			signedOut := make(chan error, 1)
			go func() { signedOut <- c.SignOut(ctx, "", SignOutLocal) }()
			waitBlocked()
			close(g.release)
			if err := <-opDone; err != nil {
				t.Fatal(err)
			}
			if err := <-signedOut; err != nil {
				t.Fatal(err)
			}
			if st := coreStored(t, c); st != nil {
				t.Fatalf("session resurrected: %+v", st)
			}
			coreAssertEvents(t, ev, tc.event, EventSignedOut)
			srv.assertNoViolations(t)
		})
	}
}

// A refresh queued behind an UpdateUser uses the session the update
// committed; events follow commit order.
// upstream: auth-js src/GoTrueClient.ts _updateUser / _refreshSession (shared _acquireLock)
func TestUpdateUserThenRefresh(t *testing.T) {
	ctx := context.Background()
	srv := newFamServer(t)
	c := srv.client(t)
	srv.seed(t, c)
	ev := coreWatch(c)
	g, updated := startGated(t, srv, "/auth/v1/user", func() error {
		_, err := c.UpdateUser(ctx, "", UpdateUserParams{Data: map[string]any{"theme": "dark"}})
		return err
	})
	refreshed := make(chan error, 1)
	go func() { _, err := c.RefreshSession(ctx, ""); refreshed <- err }()
	waitBlocked()
	if n := srv.count("/auth/v1/token"); n != 0 {
		t.Fatalf("refresh sent while UpdateUser held the session: %d", n)
	}
	close(g.release)
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	coreAssertEvents(t, ev, EventUserUpdated, EventTokenRefreshed)
	if _, err := c.RefreshSession(ctx, ""); err != nil {
		t.Fatal(err)
	}
	srv.assertNoViolations(t)
}

// A caller that gives up on Verify never loses the rotation the server
// performed: the detached request commits it.
// upstream: auth-js src/GoTrueClient.ts _verify (not cancellable mid-flight)
func TestVerifyCancelledCallerKeepsRotation(t *testing.T) {
	for _, path := range []string{"/auth/v1/factors/f-1/verify", "/auth/v1/factors/recovery-codes/verify"} {
		t.Run(path, func(t *testing.T) {
			srv := newFamServer(t)
			c := srv.client(t)
			seeded := srv.seed(t, c)
			ctx, cancel := context.WithCancel(context.Background())
			g, done := startGated(t, srv, path, func() error {
				var err error
				if strings.Contains(path, "recovery") {
					_, err = c.MFA().RecoveryCodes().Verify(ctx, MFARecoveryCodesVerifyParams{Code: "abcd"})
				} else {
					_, err = c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
				}
				return err
			})
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v", err)
			}
			close(g.release) // the server rotates now
			coreWaitFor(t, func() bool {
				st := coreStored(t, c)
				return st != nil && st.RefreshToken != seeded.RefreshToken
			})
			if _, err := c.RefreshSession(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
			srv.assertNoViolations(t)
		})
	}
}

// Waiting for the session lock honours ctx and Config.LockAcquireTimeout.
// upstream: auth-js src/GoTrueClient.ts _acquireLock (lockAcquireTimeout)
func TestSessionLockWaitHonoursContext(t *testing.T) {
	srv := newFamServer(t)
	c := srv.client(t, func(cfg *Config) { cfg.LockAcquireTimeout = -1 })
	srv.seed(t, c)
	g, held := startGated(t, srv, "/auth/v1/token", func() error {
		_, err := c.RefreshSession(context.Background(), "")
		return err
	})
	defer func() {
		close(g.release)
		<-held
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("Verify = %v after %v", err, time.Since(start))
	}

	c2 := srv.client(t, func(cfg *Config) { cfg.LockAcquireTimeout = 50 * time.Millisecond })
	srv.seed(t, c2)
	g2, held2 := startGated(t, srv, "/auth/v1/logout", func() error { return c2.SignOut(context.Background(), "", SignOutLocal) })
	defer func() {
		close(g2.release)
		<-held2
	}()
	if _, err := c2.RefreshSession(context.Background(), ""); !errors.Is(err, ErrLockAcquireTimeout) {
		t.Fatalf("err = %v, want ErrLockAcquireTimeout", err)
	}
}

// GetSession's refresh path waits for the lock with the caller's ctx; its
// fast path never waits.
// upstream: auth-js src/GoTrueClient.ts getSession
func TestGetSessionWhileLockHeld(t *testing.T) {
	srv := newFamServer(t)
	srv.expiresIn.Store(30) // inside the expiry margin
	c := srv.client(t)
	srv.seed(t, c)
	g, verified := startGated(t, srv, "/auth/v1/factors/f-1/verify", func() error {
		_, err := c.MFA().Verify(context.Background(), MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.GetSession(ctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("GetSession = %v after %v", err, time.Since(start))
	}
	close(g.release)
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
	if s, err := c.GetSession(context.Background()); err != nil || s == nil {
		t.Fatalf("GetSession = %v, %v", s, err)
	}
	srv.assertNoViolations(t)

	// Fast path: a fresh session is returned while the lock is held.
	srv.expiresIn.Store(3600)
	c3 := srv.client(t)
	srv.seed(t, c3)
	g3, held := startGated(t, srv, "/auth/v1/logout", func() error { return c3.SignOut(context.Background(), "", SignOutLocal) })
	if s, err := c3.GetSession(ctx); err != nil || s == nil {
		t.Fatalf("fast path GetSession = %v, %v", s, err)
	}
	close(g3.release)
	<-held
}

// Listeners may call back into the client, including locking methods.
// upstream: auth-js src/GoTrueClient.ts _notifyAllSubscribers
func TestListenerReentrancy(t *testing.T) {
	srv := newFamServer(t)
	c := srv.client(t)
	srv.seed(t, c)
	var depth atomic.Int32
	c.OnAuthStateChange(func(e AuthChangeEvent, _ *Session) {
		if depth.Add(1) > 6 {
			return
		}
		ctx := context.Background()
		switch e {
		case EventTokenRefreshed:
			_, _ = c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
			c.StopAutoRefresh()
			c.StartAutoRefresh(ctx)
		case EventMFAChallengeVerified:
			_, _ = c.RefreshSession(ctx, "")
			_, _ = c.GetSession(ctx)
			c.StopAutoRefresh()
		}
	})
	done := make(chan struct{})
	go func() {
		_, _ = c.RefreshSession(context.Background(), "")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock in listener re-entrancy")
	}
	c.StopAutoRefresh()
	srv.assertNoViolations(t)
}

// A sign-out and a new sign-in between a caller's lock-free read and its
// refresh: the refresh uses the session stored when it holds the lock.
// upstream: auth-js src/GoTrueClient.ts __loadSession (re-read inside the lock)
func TestRefreshAfterStaleRead(t *testing.T) {
	for _, exp := range []int64{3600, 30} {
		t.Run(fmt.Sprint("new session expires in ", exp), func(t *testing.T) {
			ctx := context.Background()
			srv := newFamServer(t)
			store := newPausingStorage("k")
			c := srv.client(t, func(cfg *Config) { cfg.Storage = store; cfg.StorageKey = "k" })
			srv.expiresIn.Store(30)
			srv.seed(t, c) // near expiry: GetSession must refresh
			srv.expiresIn.Store(exp)
			store.arm()
			done := make(chan error, 1)
			go func() { _, err := c.GetSession(ctx); done <- err }() // lock-free read, then paused
			<-store.paused
			if err := c.SignOut(ctx, "", SignOutLocal); err != nil {
				t.Fatal(err)
			}
			if _, err := c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "p"}); err != nil {
				t.Fatal(err)
			}
			close(store.resume)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := c.RefreshSession(ctx, ""); err != nil {
				t.Fatal(err)
			}
			srv.assertNoViolations(t)
		})
	}
}

// NoStore exchanges leave no verifier behind, with or without a flow id,
// and never touch the stored session or events.
// upstream: auth-js src/lib/helpers.ts removePKCEVerifier / retrievePKCEVerifier
func TestNoStoreExchangeLeavesNoVerifier(t *testing.T) {
	ctx := context.Background()
	srv := newFamServer(t)
	store := NewMemoryStorage()
	c := srv.client(t, func(cfg *Config) { cfg.Storage = store; cfg.FlowType = FlowPKCE })
	ev := coreWatch(c)
	for _, withID := range []bool{true, false} {
		o, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"})
		if err != nil {
			t.Fatal(err)
		}
		id := ""
		if withID {
			id = o.FlowID
		}
		if _, err := c.ExchangeCodeForSession(ctx, "ns-1", &ExchangeCodeOptions{FlowID: id, NoStore: true}); err != nil {
			t.Fatal(err)
		}
		if left := verifierKeys(store); len(left) > 0 {
			t.Fatalf("withFlowID=%v: verifiers left: %v", withID, left)
		}
	}
	// Stored mode without a flow id cleans up the slot too.
	if _, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExchangeCodeForSession(ctx, "code", nil); err != nil {
		t.Fatal(err)
	}
	if left := verifierKeys(store); len(left) > 0 {
		t.Fatalf("stored mode: verifiers left: %v", left)
	}
	coreAssertEvents(t, ev, EventSignedIn)
}

func verifierKeys(s *MemoryStorage) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for k := range s.m {
		if strings.Contains(k, "verifier") {
			out = append(out, k)
		}
	}
	return out
}
