package auth

// OnAuthStateChange registers fn to be called after every session change
// made by this Client (sign-in, refresh, update, sign-out, MFA). It returns
// a function that unregisters fn. Callbacks run synchronously on the
// goroutine that changed the session, after the change is stored; they must
// not block for long and must not call methods that change the session.
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
