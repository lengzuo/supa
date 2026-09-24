package realtime

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/coder/websocket"
)

// MessageType is the type of a websocket data message.
type MessageType int

// Websocket data message types.
const (
	MessageText   MessageType = 1
	MessageBinary MessageType = 2
)

// WebSocketConn is one websocket connection. Read is only ever called
// from a single goroutine; Write may be called concurrently with Read but
// not with itself; Close may be called from any goroutine and must unblock
// pending Read and Write calls.
type WebSocketConn interface {
	// Read blocks until a data message arrives. When the peer closes the
	// connection it should return a *CloseError.
	Read(ctx context.Context) (MessageType, []byte, error)
	// Write sends one data message.
	Write(ctx context.Context, typ MessageType, data []byte) error
	// Close performs the close handshake with the given status code and
	// reason.
	Close(code int, reason string) error
}

// WebSocketTransport opens websocket connections. Set Config.Transport to
// plug in a custom implementation (upstream `transport` option), e.g. to
// route through a proxy or to test without a network.
type WebSocketTransport interface {
	// Dial opens a connection to url, sending header with the handshake.
	Dial(ctx context.Context, url string, header http.Header) (WebSocketConn, error)
}

// WebSocketTransportFunc adapts a function to WebSocketTransport.
type WebSocketTransportFunc func(ctx context.Context, url string, header http.Header) (WebSocketConn, error)

// Dial calls f.
func (f WebSocketTransportFunc) Dial(ctx context.Context, url string, header http.Header) (WebSocketConn, error) {
	return f(ctx, url, header)
}

// DefaultReadLimit is the maximum size of a received message used by
// DefaultTransport when ReadLimit is zero.
const DefaultReadLimit = 32 << 20

// DefaultTransport is the WebSocketTransport used when Config.Transport is
// nil. It is built on github.com/coder/websocket.
type DefaultTransport struct {
	// HTTPClient performs the handshake. Nil uses http.DefaultClient.
	HTTPClient *http.Client
	// ReadLimit bounds the size of a single received message. Zero means
	// DefaultReadLimit; negative disables the limit.
	ReadLimit int64
}

// Dial implements WebSocketTransport.
func (t *DefaultTransport) Dial(ctx context.Context, url string, header http.Header) (WebSocketConn, error) {
	opts := &websocket.DialOptions{HTTPHeader: header}
	if t != nil && t.HTTPClient != nil {
		opts.HTTPClient = t.HTTPClient
	}
	// coder/websocket manages resp.Body itself; it never needs closing.
	conn, resp, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("realtime: websocket handshake failed with HTTP %d: %w", resp.StatusCode, err)
		}
		return nil, fmt.Errorf("realtime: websocket dial: %w", err)
	}
	limit := int64(DefaultReadLimit)
	if t != nil && t.ReadLimit != 0 {
		limit = t.ReadLimit
	}
	if limit < 0 {
		limit = -1
	}
	conn.SetReadLimit(limit)
	return &coderConn{c: conn}, nil
}

type coderConn struct {
	c *websocket.Conn
}

func (c *coderConn) Read(ctx context.Context) (MessageType, []byte, error) {
	typ, data, err := c.c.Read(ctx)
	if err != nil {
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			return 0, nil, &CloseError{Code: int(ce.Code), Reason: ce.Reason}
		}
		return 0, nil, err
	}
	if typ == websocket.MessageBinary {
		return MessageBinary, data, nil
	}
	return MessageText, data, nil
}

func (c *coderConn) Write(ctx context.Context, typ MessageType, data []byte) error {
	wt := websocket.MessageText
	if typ == MessageBinary {
		wt = websocket.MessageBinary
	}
	return c.c.Write(ctx, wt, data)
}

func (c *coderConn) Close(code int, reason string) error {
	return c.c.Close(websocket.StatusCode(code), reason)
}
