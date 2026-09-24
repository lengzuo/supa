package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// writeLogStorage records every write of the session key (the refresh
// token written, or "" for a removal) in order.
type writeLogStorage struct {
	*MemoryStorage
	key string
	mu  sync.Mutex
	seq []string
}

func (l *writeLogStorage) SetItem(ctx context.Context, k, v string) error {
	if k != l.key {
		return l.MemoryStorage.SetItem(ctx, k, v)
	}
	var s Session
	_ = json.Unmarshal([]byte(v), &s)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq = append(l.seq, s.RefreshToken)
	return l.MemoryStorage.SetItem(ctx, k, v)
}

func (l *writeLogStorage) RemoveItem(ctx context.Context, k string) error {
	if k != l.key {
		return l.MemoryStorage.RemoveItem(ctx, k)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq = append(l.seq, "")
	return l.MemoryStorage.RemoveItem(ctx, k)
}

func (l *writeLogStorage) writes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seq...)
}

// Every stored-session operation, concurrently, against a fake that
// revokes a session on refresh-token reuse; listeners call back into the
// client. Run with -race -cpu 1,4.
// upstream: auth-js src/GoTrueClient.ts (_acquireLock serialization of all session operations)
func TestSessionLockChaos(t *testing.T) {
	for round := 0; round < 6; round++ {
		t.Run(fmt.Sprint(round), func(t *testing.T) { sessionLockChaosRound(t, uint64(round)) })
	}
}

// clientGoroutines counts goroutines running client internals that must
// not outlive their operation.
func clientGoroutines() int {
	buf := make([]byte, 1<<22)
	n := runtime.Stack(buf, true)
	s := string(buf[:n])
	return strings.Count(s, "auth.(*Client).runLocked") + strings.Count(s, "auth.(*Client).StartAutoRefresh")
}

func sessionLockChaosRound(t *testing.T, seed uint64) {
	baseline := clientGoroutines()
	var quiesce atomic.Bool
	srv := newFamServer(t)
	store := &writeLogStorage{MemoryStorage: NewMemoryStorage(), key: "sb-chaos-auth-token"}
	c := srv.client(t, func(cfg *Config) {
		cfg.Storage = store
		cfg.StorageKey = "sb-chaos-auth-token"
		cfg.FlowType = FlowPKCE
	})
	c.tickDuration = 40 * time.Second
	srv.seed(t, c)
	store.mu.Lock()
	store.seq = nil
	store.mu.Unlock()

	var evMu sync.Mutex
	var evSeq []string
	var evNames []AuthChangeEvent
	var noStoreLeak atomic.Value
	var depth atomic.Int32
	c.OnAuthStateChange(func(e AuthChangeEvent, s *Session) {
		rt := ""
		if s != nil {
			rt = s.RefreshToken
			if strings.HasPrefix(rt, "rt-ns") {
				noStoreLeak.Store("event carries a NoStore session: " + rt)
			}
		}
		evMu.Lock()
		evSeq = append(evSeq, rt)
		evNames = append(evNames, e)
		evMu.Unlock()
		// Re-enter the client from the listener (one level deep).
		if quiesce.Load() {
			return
		}
		if depth.Add(1) > 1 {
			depth.Add(-1)
			return
		}
		defer depth.Add(-1)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		switch rand.IntN(8) {
		case 0:
			_, _ = c.GetSession(ctx)
		case 1:
			_, _ = c.RefreshSession(ctx, "")
		case 2:
			_, _ = c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
		case 3:
			c.StopAutoRefresh()
		case 4:
			c.StartAutoRefresh(context.Background())
		}
	})

	stopExp := make(chan struct{})
	var expWG sync.WaitGroup
	expWG.Add(1)
	go func() { // randomise the lifetime of issued sessions
		defer expWG.Done()
		for {
			select {
			case <-stopExp:
				return
			case <-time.After(time.Millisecond):
				if rand.IntN(2) == 0 {
					srv.expiresIn.Store(30)
				} else {
					srv.expiresIn.Store(3600)
				}
			}
		}
	}()
	freshPair := func() (string, string) {
		srv.mu.Lock()
		defer srv.mu.Unlock()
		m := srv.newSessionLocked("s")
		return m["access_token"].(string), m["refresh_token"].(string)
	}

	var signOuts atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(seed, uint64(w)))
			for i := 0; i < 40; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				switch r.IntN(17) {
				case 0:
					_, _ = c.SignInWithPassword(ctx, SignInWithPasswordParams{Email: "a@b.c", Password: "p"})
				case 1:
					at, rt := freshPair()
					_, _ = c.SetSession(ctx, at, rt)
				case 2:
					_, _ = c.RefreshSession(ctx, "")
				case 3:
					_, _ = c.GetSession(ctx)
				case 4:
					c.autoRefreshTick(ctx)
				case 5:
					_, _ = c.UpdateUser(ctx, "", UpdateUserParams{Data: map[string]any{"x": i}})
				case 6:
					_, _ = c.LinkIdentityWithIDToken(ctx, "", SignInWithIDTokenParams{Provider: "google", Token: "idt"})
				case 7:
					_, _ = c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f-1", ChallengeID: "c", Code: "1"})
				case 8:
					_, _ = c.MFA().RecoveryCodes().Verify(ctx, MFARecoveryCodesVerifyParams{Code: "abc"})
				case 9, 10:
					scope := SignOutLocal
					if r.IntN(2) == 0 {
						scope = SignOutGlobal
					}
					if c.SignOut(ctx, "", scope) == nil {
						signOuts.Add(1)
					}
				case 11:
					_ = c.SignOut(ctx, "", SignOutOthers)
				case 12:
					_, _ = c.GetUser(ctx, "")
				case 13:
					_, _ = c.MFA().ListFactors(ctx)
				case 14:
					if o, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err == nil {
						_, _ = c.ExchangeCodeForSession(ctx, "code", &ExchangeCodeOptions{FlowID: o.FlowID})
					}
				case 15:
					if o, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err == nil {
						_, _ = c.ExchangeCodeForSession(ctx, "ns-code", &ExchangeCodeOptions{FlowID: o.FlowID, NoStore: true})
					}
				case 16:
					if o, err := c.SignInWithOAuth(ctx, SignInWithOAuthParams{Provider: "github"}); err == nil {
						_, _ = c.GetSessionFromURL(ctx, "https://app/cb?code=ns-x&"+PKCEFlowIDParam+"="+url.QueryEscape(o.FlowID),
							&GetSessionFromURLOptions{NoStore: true})
					}
				}
				cancel()
			}
		}(w)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(90 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("deadlock\n%s", buf[:n])
	}
	close(stopExp)
	expWG.Wait()
	// Detached operations finish on their own: wait until the lock is free
	// and every event has been delivered, with listeners no longer
	// re-entering, then stop the refresher they may have started.
	quiesce.Store(true)
	coreWaitFor(t, func() bool {
		if !c.tryAcquireSessionLock() {
			return false
		}
		c.releaseSessionLock()
		c.evMu.Lock()
		idle := !c.delivering && len(c.evQueue) == 0
		c.evMu.Unlock()
		return idle
	})
	c.StopAutoRefresh()

	srv.assertNoViolations(t)
	if v := noStoreLeak.Load(); v != nil {
		t.Error(v)
	}
	writes := store.writes()
	for _, rt := range writes {
		if strings.HasPrefix(rt, "rt-ns") {
			t.Errorf("NoStore session written to storage: %s", rt)
		}
	}
	evMu.Lock()
	events := append([]string(nil), evSeq...)
	names := append([]AuthChangeEvent(nil), evNames...)
	evMu.Unlock()
	if len(writes) < 20 {
		t.Errorf("only %d session writes: the chaos did not exercise the client", len(writes))
	}
	if len(events) != len(writes) {
		t.Errorf("%d events for %d storage writes", len(events), len(writes))
	}
	for i := 0; i < len(events) && i < len(writes); i++ {
		if events[i] != writes[i] {
			t.Errorf("event %d (%s, rt %q) does not match storage write %q", i, names[i], events[i], writes[i])
			break
		}
	}
	signedOut := 0
	for _, e := range names {
		if e == EventSignedOut {
			signedOut++
		}
	}
	if int64(signedOut) < signOuts.Load() {
		t.Errorf("%d successful sign-outs but %d SIGNED_OUT events", signOuts.Load(), signedOut)
	}

	// A successful SignOut leaves no session and no verifier behind.
	if err := c.SignOut(context.Background(), "", SignOutLocal); err != nil {
		t.Fatal(err)
	}
	if st := coreStored(t, c); st != nil {
		t.Errorf("session left after SignOut: %+v", st)
	}
	if left := verifierKeys(store.MemoryStorage); len(left) > 0 {
		t.Errorf("verifiers left after SignOut: %v", left)
	}
	srv.assertNoViolations(t)

	// No leaked client goroutines.
	coreWaitFor(t, func() bool { return clientGoroutines() <= baseline })
}
