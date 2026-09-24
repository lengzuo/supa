package realtime

import (
	"context"
	"fmt"
	"log/slog"
)

// SetAuth sets the JWT used for channel authorization and RLS (upstream
// RealtimeClient.setAuth).
//
// With a non-empty token that token is used; if no AccessToken callback is
// configured the client stays in manual-token mode and no longer refreshes
// the token itself. With an empty token the AccessToken callback is called
// (if configured) to fetch a fresh one; a callback error is returned and
// the current token is kept.
//
// When the token changes, every channel's join payload is updated and
// joined channels receive an access_token push. Concurrent calls are
// ordered: the result of a superseded call is discarded.
func (c *Client) SetAuth(ctx context.Context, token string) error {
	c.mu.Lock()
	c.authGen++
	gen := c.authGen
	done := make(chan struct{})
	c.authDone = done
	cb := c.cfg.AccessToken
	tokenToSend := c.accessToken
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		if c.authDone == done {
			c.authDone = nil
		}
		c.mu.Unlock()
		close(done)
	}()

	manual := false
	fetched := false
	var cbErr error
	switch {
	case token != "":
		tokenToSend = token
		manual = true
	case cb != nil:
		t, err := cb(ctx)
		if err != nil {
			cbErr = fmt.Errorf("realtime: access token callback: %w", err)
			c.mu.Lock()
			c.log(slog.LevelError, "error", "Error fetching access token from callback", slog.String("error", err.Error()))
			c.mu.Unlock()
		} else {
			tokenToSend = t
			fetched = true
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.authGen {
		return cbErr
	}
	if fetched {
		c.authFetched = true
	}
	if cb != nil {
		c.manualToken = false
	} else if manual {
		c.manualToken = true
	}
	if tokenToSend != c.accessToken {
		c.accessToken = tokenToSend
		for _, ch := range append([]*Channel(nil), c.channels...) {
			ch.joinPayload.hasToken = true
			ch.joinPayload.token = tokenToSend
			ch.joinPayload.hasVersion = true
			if ch.joinedOnce && ch.state == ChannelJoined {
				_, _ = ch.pushEvent(eventAccessToken, map[string]any{"access_token": nullableString(tokenToSend)}, ch.timeout)
			}
		}
	}
	return cbErr
}

// waitAuth waits for an in-flight SetAuth (upstream _waitForAuthIfNeeded).
func (c *Client) waitAuth(ctx context.Context) error {
	c.mu.Lock()
	done := c.authDone
	c.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// prepareAuth makes sure a token from the AccessToken callback is known
// before a join is sent, so the join payload carries it.
func (c *Client) prepareAuth(ctx context.Context) error {
	if err := c.waitAuth(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	need := c.cfg.AccessToken != nil && !c.authFetched && c.accessToken == ""
	c.mu.Unlock()
	if need {
		_ = c.SetAuth(ctx, "") // failures are logged; the join proceeds without a token
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

// setAuthSafely refreshes the token from the callback in the background
// unless it was set manually. Requires c.mu.
func (c *Client) setAuthSafely() {
	if c.manualToken || c.cfg.AccessToken == nil {
		return
	}
	c.goBackground(func(bgCtx context.Context) {
		ctx, cancel := context.WithTimeout(bgCtx, c.cfg.Timeout)
		defer cancel()
		_ = c.SetAuth(ctx, "")
	})
}
