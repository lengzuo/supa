package realtime

import (
	"context"
	"log/slog"
	"net/url"
	"reflect"
	"regexp"
	"sync"
)

var reAPIKeyParam = regexp.MustCompile(`(?i)(apikey=)[^&\s"']*`)

func redactString(s string) string {
	return reAPIKeyParam.ReplaceAllString(s, "${1}REDACTED")
}

// redactError hides the apikey query parameter that dial errors (which
// embed the URL) would otherwise expose. Every *url.Error in err's tree is
// redacted in place (as internal/transport does), and every other error
// whose message leaks the key is replaced by a redactedError, so neither
// Error, %+v, errors.Unwrap nor errors.As can reveal the key.
// errors.Is keeps matching the original errors.
func redactError(err error) error {
	if err == nil {
		return nil
	}
	redactURLErrors(err, 0)
	msg := err.Error()
	red := redactString(msg)
	if red == msg {
		return err
	}
	return &redactedError{msg: red, err: err}
}

// redactURLErrors rewrites the URL of every *url.Error in err's tree.
func redactURLErrors(err error, depth int) {
	if err == nil || depth > 100 {
		return
	}
	if ue, ok := err.(*url.Error); ok {
		ue.URL = redactString(ue.URL)
	}
	switch x := err.(type) {
	case interface{ Unwrap() error }:
		redactURLErrors(x.Unwrap(), depth+1)
	case interface{ Unwrap() []error }:
		for _, e := range x.Unwrap() {
			redactURLErrors(e, depth+1)
		}
	}
}

// redactedError stands in for an error whose message contains the API
// key. It exposes only redacted views of the original's wrapped errors.
type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }

// Unwrap returns redacted views of the errors wrapped by the original.
func (e *redactedError) Unwrap() []error {
	var inner []error
	switch x := e.err.(type) {
	case interface{ Unwrap() error }:
		if u := x.Unwrap(); u != nil {
			inner = []error{u}
		}
	case interface{ Unwrap() []error }:
		inner = x.Unwrap()
	}
	out := make([]error, 0, len(inner))
	for _, u := range inner {
		if u != nil {
			out = append(out, redactError(u))
		}
	}
	return out
}

// Is reports whether target is the original (unredacted) error, so that
// errors.Is keeps working without exposing it.
func (e *redactedError) Is(target error) bool {
	if target == nil || !reflect.TypeOf(target).Comparable() || !reflect.TypeOf(e.err).Comparable() {
		return false
	}
	return target == e.err
}

// wsConn is one connection attempt. Fields other than q are guarded by
// Client.mu.
type wsConn struct {
	ws         WebSocketConn
	opened     bool
	detached   bool
	counted    bool
	stop       chan struct{} // closed on detach; stops the writer
	writerDone chan struct{}
	closerDone chan struct{}
	cancelDial context.CancelFunc
	done       chan struct{} // closed once every goroutine of the conn exited
	q          outQueue
}

// outQueue is an unbounded FIFO of encoded frames drained by the writer.
type outQueue struct {
	mu     sync.Mutex
	frames []frame
	notify chan struct{}
}

func (q *outQueue) put(f frame) {
	q.mu.Lock()
	q.frames = append(q.frames, f)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *outQueue) take() []frame {
	q.mu.Lock()
	defer q.mu.Unlock()
	f := q.frames
	q.frames = nil
	return f
}

// runConn dials, then reads until the connection ends. It is the only
// reader of the connection.
func (c *Client) runConn(dialCtx context.Context, conn *wsConn) {
	defer close(conn.done)
	ws, err := c.cfg.Transport.Dial(dialCtx, c.wsURL, c.dialHeader.Clone())
	conn.cancelDial()
	if err != nil {
		err = redactError(err)
	}

	c.mu.Lock()
	if conn.detached {
		c.mu.Unlock()
		if ws != nil {
			_ = ws.Close(wsCloseNormal, "")
		}
		c.finishConn(conn)
		return
	}
	if err != nil {
		c.onConnError(err)
		c.detach(conn, err)
		c.mu.Unlock()
		c.finishConn(conn)
		return
	}
	conn.ws = ws
	conn.opened = true
	conn.writerDone = make(chan struct{})
	c.onConnOpen(conn)
	c.mu.Unlock()

	go c.writeLoop(conn, ws)

	var readErr error
	for {
		typ, data, err := ws.Read(context.Background())
		if err != nil {
			readErr = err
			break
		}
		c.handleFrame(conn, typ, data)
	}

	c.mu.Lock()
	selfClosed := !conn.detached
	if selfClosed {
		c.detach(conn, readErr)
	}
	c.mu.Unlock()
	if selfClosed {
		_ = ws.Close(wsCloseNormal, "")
	}
	<-conn.writerDone
	c.finishConn(conn)
}

// finishConn waits for the closer goroutine and settles the closing count.
func (c *Client) finishConn(conn *wsConn) {
	c.mu.Lock()
	closer := conn.closerDone
	c.mu.Unlock()
	if closer != nil {
		<-closer
	}
	c.mu.Lock()
	if conn.counted {
		conn.counted = false
		c.closing--
	}
	c.mu.Unlock()
}

// writeLoop writes queued frames in order. On stop it flushes what is
// left (bounded) so that e.g. phx_leave pushes reach the server before the
// close handshake.
func (c *Client) writeLoop(conn *wsConn, ws WebSocketConn) {
	defer close(conn.writerDone)
	for {
		select {
		case <-conn.stop:
			ctx, cancel := context.WithTimeout(context.Background(), flushOnCloseTimeout)
			for _, f := range conn.q.take() {
				if ws.Write(ctx, f.typ, f.data) != nil {
					break
				}
			}
			cancel()
			return
		case <-conn.q.notify:
		}
		for _, f := range conn.q.take() {
			ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
			err := ws.Write(ctx, f.typ, f.data)
			cancel()
			if err != nil {
				c.mu.Lock()
				c.log(slog.LevelError, "transport", "write failed", slog.String("error", err.Error()))
				c.mu.Unlock()
				_ = ws.Close(1011, "write failed")
				<-conn.stop
				return
			}
		}
	}
}

// detach makes conn stale: it no longer is the client's connection and
// the close handling (channel errors, reconnect scheduling) runs now.
// Requires c.mu.
func (c *Client) detach(conn *wsConn, cause error) {
	if conn.detached {
		return
	}
	conn.detached = true
	close(conn.stop)
	conn.cancelDial()
	if c.conn == conn {
		c.conn = nil
		c.onConnClose(cause)
	}
}

// teardownConn detaches conn and closes its websocket in the background
// once pending frames are flushed. Requires c.mu.
func (c *Client) teardownConn(conn *wsConn, code int, reason string, cause error) {
	if conn.detached {
		return
	}
	c.closing++
	conn.counted = true
	c.detach(conn, cause)
	if !conn.opened {
		return
	}
	ws, writerDone := conn.ws, conn.writerDone
	done := make(chan struct{})
	conn.closerDone = done
	go func() {
		defer close(done)
		<-writerDone
		_ = ws.Close(code, reason)
	}()
}
