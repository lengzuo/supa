package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// SessionStorage persists the current session and PKCE code verifiers.
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
		// A corrupt entry is treated as no session, like auth-js.
		_ = c.storage.RemoveItem(ctx, c.storageKey)
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
	c.sessionMu.Unlock()
	if err != nil {
		return err
	}
	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
	c.notify(event, s)
	return nil
}

// clearSession removes the stored session and notifies SIGNED_OUT.
func (c *Client) clearSession(ctx context.Context) error {
	c.sessionMu.Lock()
	err := c.removeSession(ctx)
	c.sessionMu.Unlock()
	if err != nil {
		return err
	}
	c.notify(EventSignedOut, nil)
	return nil
}
