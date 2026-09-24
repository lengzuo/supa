package auth

import (
	"context"
	"time"
)

// StartAutoRefresh starts a background goroutine that keeps the stored
// session fresh: every 30 seconds it checks the session and refreshes it
// when it expires within three ticks (90 seconds), like auth-js. The first
// check runs immediately. Calling it again restarts the refresher.
//
// The goroutine stops when ctx is done or StopAutoRefresh is called.
// Refresh failures are logged at debug level and retried on the next tick.
func (c *Client) StartAutoRefresh(ctx context.Context) {
	c.autoMu.Lock()
	defer c.autoMu.Unlock()
	c.stopAutoRefreshLocked()

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.autoCancel, c.autoDone = cancel, done
	interval := c.tickDuration

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			c.autoRefreshTick(runCtx)
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// StopAutoRefresh stops the background refresher started by
// StartAutoRefresh (or by Config.AutoRefreshToken) and waits for it to
// exit. It is safe to call when no refresher is running.
func (c *Client) StopAutoRefresh() {
	c.autoMu.Lock()
	defer c.autoMu.Unlock()
	c.stopAutoRefreshLocked()
}

func (c *Client) stopAutoRefreshLocked() {
	if c.autoCancel != nil {
		c.autoCancel()
		<-c.autoDone
		c.autoCancel, c.autoDone = nil, nil
	}
}

// autoRefreshTick refreshes the stored session when it expires within
// autoRefreshTickThreshold ticks.
func (c *Client) autoRefreshTick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if s, err := c.loadSession(ctx); err != nil || !c.dueForAutoRefresh(s) {
		return
	}
	// Like auth-js, skip the tick when another session operation is in
	// progress instead of queuing behind it.
	if !c.tryAcquireSessionLock() {
		return
	}
	err := c.runLocked(ctx, func(ctx context.Context) error {
		s, err := c.loadSession(ctx)
		if err != nil || !c.dueForAutoRefresh(s) {
			return err
		}
		_, err = c.refreshLocked(ctx, s.RefreshToken)
		return err
	})
	if err != nil {
		c.debug(ctx, "auto refresh tick failed; will retry on the next tick", "error", err.Error())
	}
}

// dueForAutoRefresh reports whether s expires within
// autoRefreshTickThreshold ticks.
func (c *Client) dueForAutoRefresh(s *Session) bool {
	if s == nil || s.RefreshToken == "" || s.ExpiresAt == 0 {
		return false
	}
	tick := c.tickDuration
	left := time.Unix(s.ExpiresAt, 0).Sub(c.now())
	expiresInTicks := int64(left / tick)
	if left < 0 && left%tick != 0 {
		expiresInTicks-- // floor for negative durations, like Math.floor
	}
	return expiresInTicks <= autoRefreshTickThreshold
}
