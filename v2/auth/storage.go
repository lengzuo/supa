package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// SessionStorage persists the current session and PKCE code verifiers.
//
// The Client calls SetItem and RemoveItem (and some GetItem calls) while it
// holds its internal session lock, so implementations must be fast and
// must not call back into the Client (that would deadlock).
// Implementations must be safe for concurrent use. GetItem returns "" and
// a nil error when the key is absent.
type SessionStorage interface {
	GetItem(ctx context.Context, key string) (string, error)
	SetItem(ctx context.Context, key, value string) error
	RemoveItem(ctx context.Context, key string) error
}

// MemoryStorage is an in-process SessionStorage.
type MemoryStorage struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewMemoryStorage returns an empty MemoryStorage.
func NewMemoryStorage() *MemoryStorage { return &MemoryStorage{m: map[string]string{}} }

// GetItem implements SessionStorage.
func (s *MemoryStorage) GetItem(_ context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[key], nil
}

// SetItem implements SessionStorage.
func (s *MemoryStorage) SetItem(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[key] = value
	return nil
}

// RemoveItem implements SessionStorage.
func (s *MemoryStorage) RemoveItem(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

// loadSession returns the stored session, or nil if there is none.
func (c *Client) loadSession(ctx context.Context) (*Session, error) {
	raw, err := c.storage.GetItem(ctx, c.storageKey)
	if err != nil {
		return nil, fmt.Errorf("auth: load session: %w", err)
	}
	if raw == "" {
		return nil, nil
	}
	var s Session
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		// A corrupt entry is treated as no session, like auth-js. It is
		// not deleted here (that would race with a concurrent writer); the
		// next successful sign-in or sign-out overwrites it.
		return nil, nil
	}
	if s.AccessToken == "" || s.RefreshToken == "" {
		return nil, nil
	}
	return &s, nil
}

// saveSession stores s, filling ExpiresAt from ExpiresIn when absent.
func (c *Client) saveSession(ctx context.Context, s *Session) error {
	if s.ExpiresAt == 0 && s.ExpiresIn > 0 {
		s.ExpiresAt = c.now().Unix() + s.ExpiresIn
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("auth: encode session: %w", err)
	}
	if err := c.storage.SetItem(ctx, c.storageKey, string(data)); err != nil {
		return fmt.Errorf("auth: save session: %w", err)
	}
	return nil
}

// removeSession deletes the stored session and every pending PKCE
// verifier. It does not notify listeners; see clearSession.
func (c *Client) removeSession(ctx context.Context) error {
	c.removalEpoch.Add(1)
	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
	if err := c.storage.RemoveItem(ctx, c.storageKey); err != nil {
		return fmt.Errorf("auth: remove session: %w", err)
	}
	c.removeAllPKCEVerifiers(ctx)
	return nil
}

// commitSession stores s and then notifies listeners with event.
func (c *Client) commitSession(ctx context.Context, s *Session, event AuthChangeEvent) error {
	c.sessionMu.Lock()
	err := c.saveSession(ctx, s)
	if err == nil {
		c.enqueueEvent(event, s)
	}
	c.sessionMu.Unlock()
	if err != nil {
		return err
	}
	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
	c.deliverEvents()
	return nil
}

// clearSession removes the stored session and notifies SIGNED_OUT.
func (c *Client) clearSession(ctx context.Context) error {
	_, err := c.clearSessionIf(ctx, nil)
	return err
}

// clearSessionIf removes the stored session and notifies SIGNED_OUT if
// match (nil = always) accepts the session stored at that moment. The check
// and the removal happen under sessionMu, so a session committed in the
// meantime (e.g. a fresh sign-in) is never removed by a stale decision. It
// reports whether a removal happened.
func (c *Client) clearSessionIf(ctx context.Context, match func(stored *Session) bool) (bool, error) {
	removed, err := c.removeSessionIf(ctx, match)
	if removed {
		c.deliverEvents()
	}
	return removed, err
}

// removeSessionIf is clearSessionIf without delivering the queued
// SIGNED_OUT event; the caller must call deliverEvents.
func (c *Client) removeSessionIf(ctx context.Context, match func(stored *Session) bool) (bool, error) {
	c.sessionMu.Lock()
	if match != nil {
		stored, err := c.loadSession(ctx)
		if err != nil || stored == nil || !match(stored) {
			c.sessionMu.Unlock()
			return false, err
		}
	}
	err := c.removeSession(ctx)
	if err == nil {
		c.enqueueEvent(EventSignedOut, nil)
	}
	c.sessionMu.Unlock()
	if err != nil {
		return false, err
	}
	return true, nil
}

// sessionBasis identifies the stored session a request was made with, so
// its result is only written back if that session is still current.
type sessionBasis struct {
	accessToken  string
	refreshToken string
}

func basisOf(s *Session) sessionBasis {
	if s == nil {
		return sessionBasis{}
	}
	return sessionBasis{accessToken: s.AccessToken, refreshToken: s.RefreshToken}
}

// matches reports whether stored is still the session b was taken from.
func (b sessionBasis) matches(stored *Session) bool {
	if stored == nil {
		return false
	}
	return (b.refreshToken != "" && stored.RefreshToken == b.refreshToken) ||
		(b.accessToken != "" && stored.AccessToken == b.accessToken)
}

// updateStoredUser writes user into the stored session after a user
// update made with basis, then emits USER_UPDATED with the session actually
// stored. It never resurrects a session removed in the meantime: when the
// stored session is gone nothing is written. When the stored session was
// replaced (e.g. refreshed while the request was in flight) the new user is
// swapped in only if it belongs to the same user, keeping the stored
// tokens. It returns the stored session, or nil when nothing was written.
func (c *Client) updateStoredUser(ctx context.Context, basis sessionBasis, user *User) (*Session, error) {
	c.sessionMu.Lock()
	stored, err := c.loadSession(ctx)
	if err != nil || stored == nil {
		c.sessionMu.Unlock()
		return nil, err
	}
	if !basis.matches(stored) && (stored.User == nil || user == nil || stored.User.ID != user.ID) {
		c.sessionMu.Unlock()
		return nil, nil
	}
	stored.User = user
	err = c.saveSession(ctx, stored)
	if err == nil {
		c.enqueueEvent(EventUserUpdated, stored)
	}
	c.sessionMu.Unlock()
	if err != nil {
		return nil, err
	}
	c.deliverEvents()
	return stored, nil
}

// replaceSessionIfCurrent stores next and emits event only if the stored
// session is still the one identified by basis. A session removed or
// replaced while the request was in flight is left alone (never
// resurrected or overwritten with stale tokens). It reports whether next
// was stored.
func (c *Client) replaceSessionIfCurrent(ctx context.Context, basis sessionBasis, next *Session, event AuthChangeEvent) (bool, error) {
	c.sessionMu.Lock()
	stored, err := c.loadSession(ctx)
	if err != nil || !basis.matches(stored) {
		c.sessionMu.Unlock()
		return false, err
	}
	err = c.saveSession(ctx, next)
	if err == nil {
		c.enqueueEvent(event, next)
	}
	c.sessionMu.Unlock()
	if err != nil {
		return false, err
	}
	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
	c.deliverEvents()
	return true, nil
}
