package realtime

import (
	"fmt"
	"sync"
	"time"
)

// dispatcher runs user callbacks sequentially, in the order they were
// queued, on a goroutine that exists only while the queue is non-empty.
// Callbacks are therefore never invoked while internal locks are held, and
// a callback may call back into the client (even blocking calls such as
// Channel.Unsubscribe) without deadlocking the connection reader.
type dispatcher struct {
	mu      sync.Mutex
	queue   []func()
	running bool
	onPanic func(v any)
}

func (d *dispatcher) enqueue(fn func()) {
	d.mu.Lock()
	d.queue = append(d.queue, fn)
	if !d.running {
		d.running = true
		go d.run()
	}
	d.mu.Unlock()
}

func (d *dispatcher) run() {
	for {
		d.mu.Lock()
		if len(d.queue) == 0 {
			d.running = false
			d.queue = nil
			d.mu.Unlock()
			return
		}
		fn := d.queue[0]
		d.queue[0] = nil
		d.queue = d.queue[1:]
		d.mu.Unlock()
		d.call(fn)
	}
}

func (d *dispatcher) call(fn func()) {
	defer func() {
		if v := recover(); v != nil && d.onPanic != nil {
			d.onPanic(v)
		}
	}()
	fn()
}

// ltimer is a one-shot timer whose callback runs with the client lock held
// and never after stop() (which must also be called with the lock held).
type ltimer struct {
	t       *time.Timer
	stopped bool
}

// after schedules fn to run with c.mu held after d.
func (c *Client) after(d time.Duration, fn func()) *ltimer {
	lt := &ltimer{}
	lt.t = time.AfterFunc(d, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if lt.stopped {
			return
		}
		lt.stopped = true
		fn()
	})
	return lt
}

func (lt *ltimer) stop() {
	if lt == nil {
		return
	}
	lt.stopped = true
	lt.t.Stop()
}

// backoffTimer mirrors phoenix Timer: scheduleTimeout fires fn after
// calc(tries+1); reset clears the tries. All methods require c.mu.
type backoffTimer struct {
	c     *Client
	fn    func()
	calc  func(tries int) time.Duration
	tries int
	t     *ltimer
}

func (b *backoffTimer) reset() {
	b.tries = 0
	b.t.stop()
	b.t = nil
}

func (b *backoffTimer) schedule() {
	b.t.stop()
	d := b.calc(b.tries + 1)
	if d < 0 {
		d = 0
	}
	b.t = b.c.after(d, func() {
		b.t = nil
		b.tries++
		b.fn()
	})
}

func panicError(v any) error {
	if err, ok := v.(error); ok {
		return fmt.Errorf("realtime: callback panicked: %w", err)
	}
	return fmt.Errorf("realtime: callback panicked: %v", v)
}
