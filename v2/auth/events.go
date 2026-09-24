package auth

// OnAuthStateChange registers fn to be called after every session change
// made by this Client (sign-in, refresh, update, sign-out, MFA). It returns
// a function that unregisters fn.
//
// Events are delivered one at a time, in the order the changes were
// committed to storage, after the change is stored. The goroutine that made
// a change delivers the pending events before its call returns, unless
// another goroutine is already delivering, in which case that goroutine
// delivers them (still in order). Callbacks must not block for long. A
// callback may call Client methods, including ones that change the session;
// the events those produce are delivered after the callback returns.
func (c *Client) OnAuthStateChange(fn func(event AuthChangeEvent, session *Session)) (unsubscribe func()) {
	c.listenersMu.Lock()
	id := c.nextID
	c.nextID++
	c.listeners[id] = fn
	c.listenersMu.Unlock()
	return func() {
		c.listenersMu.Lock()
		delete(c.listeners, id)
		c.listenersMu.Unlock()
	}
}

// queuedEvent is a committed session change awaiting delivery.
type queuedEvent struct {
	event   AuthChangeEvent
	session *Session
}

// enqueueEvent queues an event. Call it while holding sessionMu, right
// after the storage change, so the queue order is the commit order; call
// deliverEvents after releasing sessionMu.
func (c *Client) enqueueEvent(event AuthChangeEvent, s *Session) {
	c.evMu.Lock()
	c.evQueue = append(c.evQueue, queuedEvent{event, s})
	c.evMu.Unlock()
}

// deliverEvents delivers queued events in order. Only one goroutine
// delivers at a time; a re-entrant call (from a listener) or a concurrent
// one returns at once and its events are delivered by the active deliverer.
func (c *Client) deliverEvents() {
	c.evMu.Lock()
	if c.delivering {
		c.evMu.Unlock()
		return
	}
	c.delivering = true
	defer func() {
		c.evMu.Lock()
		c.delivering = false
		c.evMu.Unlock()
	}()
	for len(c.evQueue) > 0 {
		ev := c.evQueue[0]
		c.evQueue = c.evQueue[1:]
		c.evMu.Unlock()
		c.notify(ev.event, ev.session)
		c.evMu.Lock()
	}
	c.evMu.Unlock()
}

// notify delivers event to every listener.
func (c *Client) notify(event AuthChangeEvent, s *Session) {
	c.listenersMu.RLock()
	fns := make([]func(AuthChangeEvent, *Session), 0, len(c.listeners))
	for _, fn := range c.listeners {
		fns = append(fns, fn)
	}
	c.listenersMu.RUnlock()
	for _, fn := range fns {
		fn(event, s)
	}
}
