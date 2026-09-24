package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

const httpSend404Message = "httpSend() requires Realtime server v2.97.0 or newer; the endpoint returned 404. " +
	"Update your Supabase CLI to a recent version, or upgrade the Realtime server in your self-hosted setup. " +
	"See https://github.com/supabase/supabase-js/blob/master/packages/core/realtime-js/migrations/httpsend-server-version.md"

// encodeURIComponent mirrors the JavaScript function of the same name.
func encodeURIComponent(s string) string {
	const unreserved = "-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (c *Client) broadcastQuery(private bool) url.Values {
	q := url.Values{}
	for k, v := range c.httpQuery {
		q[k] = append([]string(nil), v...)
	}
	if private {
		q.Set("private", "true")
	}
	return q
}

func (c *Client) tokenSnapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accessToken
}

// HTTPSend sends a broadcast through the REST endpoint
// POST /api/broadcast/<topic>/events/<event> regardless of the websocket
// state (upstream RealtimeChannel.httpSend). A []byte payload is sent as
// application/octet-stream; anything else is JSON-encoded. It returns nil
// when the server accepts the message (HTTP 202) and *HTTPError otherwise.
// The client Timeout bounds the request.
func (ch *Channel) HTTPSend(ctx context.Context, event string, payload any) error {
	if payload == nil {
		return errors.New("realtime: payload is required for HTTPSend")
	}
	c := ch.client
	var body []byte
	contentType := transport.ContentTypeJSON
	switch v := payload.(type) {
	case []byte:
		body = v
		contentType = "application/octet-stream"
	case json.RawMessage:
		body = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("realtime: encode payload: %w", err)
		}
		body = b
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	token := c.tokenSnapshot()
	req := &transport.Request{
		Method:      http.MethodPost,
		Path:        "/" + encodeURIComponent(ch.subTopic) + "/events/" + encodeURIComponent(event),
		Query:       c.broadcastQuery(ch.opts.Private),
		Body:        body,
		ContentType: contentType,
		Token:       token,
		NoRetry:     true,
	}
	resp, err := c.http.Do(ctx, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %w", ErrTimedOut, err)
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch resp.StatusCode {
	case http.StatusAccepted:
		return nil
	case http.StatusNotFound:
		return &HTTPError{StatusCode: resp.StatusCode, Message: httpSend404Message}
	}
	msg := http.StatusText(resp.StatusCode)
	var eb struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &eb) == nil {
		if eb.Error != "" {
			msg = eb.Error
		} else if eb.Message != "" {
			msg = eb.Message
		}
	}
	return &HTTPError{StatusCode: resp.StatusCode, Message: msg}
}

// broadcastFallback is the implicit REST fallback of Channel.Send used when
// the channel is not joined: POST /api/broadcast {"messages":[...]}.
// Upstream deprecates it in favour of HTTPSend.
func (ch *Channel) broadcastFallback(ctx context.Context, args *sendArgs, timeout time.Duration) error {
	c := ch.client
	c.mu.Lock()
	c.log(slog.LevelWarn, "channel", "Realtime send() is automatically falling back to REST API. "+
		"This behavior will be deprecated in the future. Please use httpSend() explicitly for REST delivery.")
	c.mu.Unlock()
	type message struct {
		Topic   string          `json:"topic"`
		Event   string          `json:"event"`
		Payload json.RawMessage `json:"payload,omitempty"`
		Private bool            `json:"private"`
	}
	m := message{Topic: ch.subTopic, Event: args.Event, Private: ch.opts.Private}
	if args.hasPayload {
		raw, ok := args.Payload.(json.RawMessage)
		if !ok {
			return errors.New("realtime: binary payloads cannot be sent through the REST fallback; subscribe first or use HTTPSend")
		}
		m.Payload = raw
	}
	body, err := json.Marshal(struct {
		Messages []message `json:"messages"`
	}{[]message{m}})
	if err != nil {
		return fmt.Errorf("realtime: encode broadcast: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := c.http.Do(ctx, &transport.Request{
		Method:      http.MethodPost,
		Query:       c.broadcastQuery(false),
		Body:        body,
		ContentType: transport.ContentTypeJSON,
		Token:       c.tokenSnapshot(),
		NoRetry:     true,
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %w", ErrTimedOut, err)
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	return nil
}
