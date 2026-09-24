package auth

import (
	"context"
	"time"
)

// Concurrency model
//
// Like auth-js (where every session operation runs inside _acquireLock),
// every operation on the stored session holds one client-wide session lock
// for its whole read -> network -> commit cycle: sign-ins, SetSession,
// RefreshSession(""), GetSession's refresh path, the auto-refresh tick,
// UpdateUser, LinkIdentityWithIDToken, MFA verification, SignOut, code
// exchange in store mode, and session_not_found cleanups. So two such
// operations never interleave, a refresh token is never used twice, and a
// signed-out session is never resurrected. Explicit-token and NoStore calls
// never take the lock, and GetSession's fast path (a session that is not
// near expiry) is a lock-free storage read.
//
// The lock is a one-slot channel, so waiting honours ctx and
// Config.LockAcquireTimeout. Requests that make the server rotate the
// refresh token (token refresh, MFA and recovery-code verification) run in
// a goroutine that owns the lock, detached from the caller's ctx (bounded
// by refreshTimeout): a caller that gives up never loses a rotation the
// server already performed.
//
// Events are queued in commit order while the lock is held and delivered
// after it is released (see OnAuthStateChange), before the operation's
// caller is released. Listeners may therefore call any Client method.
// SessionStorage implementations run while the lock is held and must not
// call back into the Client.

// DefaultLockAcquireTimeout is the default Config.LockAcquireTimeout.
const DefaultLockAcquireTimeout = 10 * time.Second

// ErrLockAcquireTimeout is returned when the session lock could not be
// acquired within Config.LockAcquireTimeout because another session
// operation (typically a slow request) held it.
var ErrLockAcquireTimeout = &Error{Message: "timed out waiting for another auth session operation", Code: "lock_acquire_timeout"}

// acquireSessionLock waits for the session lock, honouring ctx and
// Config.LockAcquireTimeout.
func (c *Client) acquireSessionLock(ctx context.Context) error {
	select {
	case c.sessionLock <- struct{}{}:
		return nil
	default:
	}
	var timeout <-chan time.Time
	if c.lockTimeout > 0 {
		t := time.NewTimer(c.lockTimeout)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case c.sessionLock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timeout:
		return ErrLockAcquireTimeout
	}
}

// tryAcquireSessionLock takes the lock only if it is free.
func (c *Client) tryAcquireSessionLock() bool {
	select {
	case c.sessionLock <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseSessionLock releases the lock and then delivers the events the
// operation queued.
func (c *Client) releaseSessionLock() {
	<-c.sessionLock
	c.deliverEvents()
}

// withSessionLock runs fn holding the session lock, in the caller's
// goroutine and on the caller's ctx.
func (c *Client) withSessionLock(ctx context.Context, fn func() error) error {
	if err := c.acquireSessionLock(ctx); err != nil {
		return err
	}
	defer c.releaseSessionLock()
	return fn()
}

// withSessionLockDetached acquires the session lock (honouring ctx) and
// runs fn in a goroutine that owns the lock, with a ctx detached from the
// caller's and bounded by refreshTimeout. The caller waits for fn or for
// its own ctx; in the latter case fn still completes and commits. Use it
// for requests after which the server rotates the refresh token.
func (c *Client) withSessionLockDetached(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := c.acquireSessionLock(ctx); err != nil {
		return err
	}
	return c.runLocked(ctx, fn)
}

// runLocked runs fn in a new goroutine that owns the (already acquired)
// session lock; see withSessionLockDetached.
func (c *Client) runLocked(ctx context.Context, fn func(ctx context.Context) error) error {
	done := make(chan struct{})
	var err error
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	go func() {
		defer close(done)
		defer cancel()
		defer c.releaseSessionLock()
		err = fn(rctx)
	}()
	select {
	case <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// commitLocked stores s and queues event. The session lock must be held.
func (c *Client) commitLocked(ctx context.Context, s *Session, event AuthChangeEvent) error {
	if err := c.saveSession(ctx, s); err != nil {
		return err
	}
	c.clearRefreshFailure()
	c.enqueueEvent(event, s)
	return nil
}

// signOutLocked removes the stored session and every pending PKCE
// verifier and queues SIGNED_OUT. The session lock must be held.
func (c *Client) signOutLocked(ctx context.Context) error {
	if err := c.removeSession(ctx); err != nil {
		return err
	}
	c.enqueueEvent(EventSignedOut, nil)
	return nil
}

// clearSessionIf removes the stored session and emits SIGNED_OUT if match
// (nil = always) accepts the session stored at that moment. It reports
// whether a removal happened.
func (c *Client) clearSessionIf(ctx context.Context, match func(stored *Session) bool) (bool, error) {
	removed := false
	err := c.withSessionLock(ctx, func() error {
		if match != nil {
			stored, err := c.loadSession(ctx)
			if err != nil || stored == nil || !match(stored) {
				return err
			}
		}
		removed = true
		return c.signOutLocked(ctx)
	})
	return removed, err
}

func (c *Client) clearRefreshFailure() {
	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
}
