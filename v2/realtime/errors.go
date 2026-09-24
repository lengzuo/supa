package realtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrTimedOut is reported when the server does not answer a push
	// (join, broadcast with ack, presence, leave) within the timeout.
	ErrTimedOut = errors.New("realtime: timed out")
	// ErrChannelClosed is reported when a channel is closed (unsubscribed,
	// removed or closed by the server) while an operation waits on it.
	ErrChannelClosed = errors.New("realtime: channel closed")
	// ErrNotSubscribed is returned when pushing a non-broadcast message to
	// a channel that has never been subscribed.
	ErrNotSubscribed = errors.New("realtime: channel is not subscribed; call Subscribe before pushing events")
	// ErrPushDiscarded is reported when a buffered push is dropped because
	// more than 100 pushes were queued while the channel was not joined.
	ErrPushDiscarded = errors.New("realtime: push discarded due to buffer overflow")
	// ErrAlreadySubscribed is returned when Subscribe is called on a channel
	// instance that has already been joined once and then closed. Create a
	// new channel with Client.Channel instead.
	ErrAlreadySubscribed = errors.New("realtime: tried to subscribe multiple times; subscribe can only be called once per channel instance")
)

// SubscribeError describes why a channel did not reach (or left) the
// SUBSCRIBED state. It is returned by Channel.Subscribe and passed to
// status callbacks.
type SubscribeError struct {
	// Status is ChannelError, TimedOut or Closed.
	Status SubscribeStatus
	// Message is a human readable reason, e.g. the server's error reply.
	Message string
	// Response is the raw server reply for join errors, if any.
	Response json.RawMessage
	// Err is the underlying cause (e.g. a *CloseError or dial error).
	Err error
}

func (e *SubscribeError) Error() string {
	var b strings.Builder
	b.WriteString("realtime: ")
	b.WriteString(string(e.Status))
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	} else if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap returns the underlying cause.
func (e *SubscribeError) Unwrap() error { return e.Err }

// Is reports TimedOut as ErrTimedOut and Closed as ErrChannelClosed.
func (e *SubscribeError) Is(target error) bool {
	switch target {
	case ErrTimedOut:
		return e.Status == StatusTimedOut
	case ErrChannelClosed:
		return e.Status == StatusClosed
	}
	return false
}

// PushError is returned when the server replies to a push with status
// "error".
type PushError struct {
	// Response is the raw "response" field of the server reply.
	Response json.RawMessage
}

func (e *PushError) Error() string {
	msg := joinObjectValues(e.Response)
	if msg == "" {
		msg = "error"
	}
	return "realtime: push failed: " + msg
}

// HTTPError is returned by broadcast-over-HTTP calls for unsuccessful
// responses.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("realtime: HTTP %d: %s", e.StatusCode, e.Message)
}

// CloseError reports that the websocket was closed. Custom transports
// should return it from WebSocketConn.Read when the peer closes the
// connection.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("socket closed: %d (%s)", e.Code, e.Reason)
	}
	return fmt.Sprintf("socket closed: %d", e.Code)
}

// normalizeChannelError mirrors realtime-js lib/normalizeChannelError.ts.
func normalizeChannelError(reason error) error {
	if reason == nil {
		return errors.New("channel error: connection lost")
	}
	return reason
}

// joinObjectValues mirrors `Object.values(obj).join(', ')` for a JSON
// object, preserving key order. Non-object input yields its text form.
func joinObjectValues(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	if raw[0] != '{' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return string(raw)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return string(raw)
	}
	var parts []string
	for dec.More() {
		if _, err := dec.Token(); err != nil { // key
			return string(raw)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return string(raw)
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			parts = append(parts, s)
		} else if bytes.Equal(v, []byte("null")) {
			parts = append(parts, "")
		} else {
			parts = append(parts, string(v))
		}
	}
	return strings.Join(parts, ", ")
}
