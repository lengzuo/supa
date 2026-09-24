package realtime

import (
	"encoding/json"
	"time"
)

// ConnectionState is the state of the websocket connection.
type ConnectionState string

// Connection states, as reported by Client.ConnectionState.
const (
	ConnectionConnecting ConnectionState = "connecting"
	ConnectionOpen       ConnectionState = "open"
	ConnectionClosing    ConnectionState = "closing"
	ConnectionClosed     ConnectionState = "closed"
)

// ChannelState is the Phoenix state of a channel.
type ChannelState string

// Channel states.
const (
	ChannelClosed  ChannelState = "closed"
	ChannelErrored ChannelState = "errored"
	ChannelJoined  ChannelState = "joined"
	ChannelJoining ChannelState = "joining"
	ChannelLeaving ChannelState = "leaving"
)

// SubscribeStatus is reported to status callbacks registered with
// Channel.OnStatus (upstream REALTIME_SUBSCRIBE_STATES).
type SubscribeStatus string

// Subscribe statuses.
const (
	StatusSubscribed   SubscribeStatus = "SUBSCRIBED"
	StatusTimedOut     SubscribeStatus = "TIMED_OUT"
	StatusClosed       SubscribeStatus = "CLOSED"
	StatusChannelError SubscribeStatus = "CHANNEL_ERROR"
)

// HeartbeatStatus is reported to heartbeat callbacks.
type HeartbeatStatus string

// Heartbeat statuses.
const (
	HeartbeatSent         HeartbeatStatus = "sent"
	HeartbeatOK           HeartbeatStatus = "ok"
	HeartbeatError        HeartbeatStatus = "error"
	HeartbeatTimeout      HeartbeatStatus = "timeout"
	HeartbeatDisconnected HeartbeatStatus = "disconnected"
)

// ListenType is the kind of message a channel listens to or sends
// (upstream REALTIME_LISTEN_TYPES).
type ListenType string

// Listen types.
const (
	ListenBroadcast       ListenType = "broadcast"
	ListenPresence        ListenType = "presence"
	ListenPostgresChanges ListenType = "postgres_changes"
	ListenSystem          ListenType = "system"
)

// PostgresChangeEvent selects which database changes to receive
// (upstream REALTIME_POSTGRES_CHANGES_LISTEN_EVENT).
type PostgresChangeEvent string

// Postgres change events.
const (
	PostgresChangeAll    PostgresChangeEvent = "*"
	PostgresChangeInsert PostgresChangeEvent = "INSERT"
	PostgresChangeUpdate PostgresChangeEvent = "UPDATE"
	PostgresChangeDelete PostgresChangeEvent = "DELETE"
)

// ChannelOptions configures a channel (upstream RealtimeChannelOptions.config).
// The zero value is a public channel with broadcast self/ack disabled and
// presence enabled only when presence callbacks are registered.
type ChannelOptions struct {
	// Broadcast configures broadcast behaviour.
	Broadcast BroadcastOptions
	// Presence configures presence behaviour.
	Presence PresenceOptions
	// Private makes the channel private: Realtime Authorization (RLS
	// policies on realtime.messages) is enforced for it.
	Private bool
	// PostgresChanges configures how the join waits for postgres_changes
	// subscriptions. Nil leaves the server defaults.
	PostgresChanges *PostgresChangesOptions
}

// BroadcastOptions configures broadcast for a channel.
type BroadcastOptions struct {
	// Self makes the server echo this client's own broadcasts back to it.
	Self bool
	// Ack makes the server acknowledge each broadcast; Channel.Send then
	// waits for the acknowledgement.
	Ack bool
	// Replay asks the server to replay stored broadcast messages on join.
	// Only valid on private channels.
	Replay *ReplayOptions
	// ReplicationReady asks the server to emit a system event once the
	// Postgres replication connection is ready.
	ReplicationReady bool
}

// ReplayOptions configures broadcast replay.
type ReplayOptions struct {
	// Since replays messages sent after this instant (sent as epoch ms).
	Since time.Time
	// Limit caps the number of replayed messages. Zero means server default.
	Limit int
}

// PresenceOptions configures presence for a channel.
type PresenceOptions struct {
	// Key identifies this client in the presence state. Empty lets the
	// server generate one.
	Key string
	// Enabled makes this client receive presence state even without
	// presence callbacks.
	Enabled bool
}

// PostgresChangesOptions configures the join of postgres_changes bindings.
type PostgresChangesOptions struct {
	// Wait holds the SUBSCRIBED status until the server confirms that the
	// postgres_changes subscription is active.
	Wait bool
	// Timeout is how long the server waits for that confirmation. Zero
	// means the server default (15s).
	Timeout time.Duration
}

// SendParams describes a message sent with Channel.Send.
type SendParams struct {
	// Type is the message type. Empty means ListenBroadcast.
	Type ListenType
	// Event is the event name.
	Event string
	// Payload is JSON-encoded unless it is json.RawMessage (sent as-is) or
	// []byte (sent as a binary payload over the websocket; only allowed for
	// broadcasts with protocol VSN2, otherwise Send returns an error). Nil
	// omits the payload; with VSN2 a nil or JSON null broadcast payload is
	// sent as {} like realtime-js.
	Payload any
	// Timeout overrides the client timeout for this push.
	Timeout time.Duration
}

// BroadcastMessage is delivered to broadcast callbacks. It mirrors the
// object realtime-js passes to `on('broadcast', ...)` handlers.
type BroadcastMessage struct {
	// Type is always "broadcast".
	Type string `json:"type"`
	// Event is the broadcast event name.
	Event string `json:"event"`
	// Payload is the JSON payload. It is nil for binary payloads.
	Payload json.RawMessage `json:"payload,omitempty"`
	// Binary is the raw payload of a binary broadcast (protocol VSN2).
	Binary []byte `json:"-"`
	// Meta carries replay metadata when present.
	Meta *BroadcastMeta `json:"meta,omitempty"`
	// Raw is the complete broadcast object as received.
	Raw json.RawMessage `json:"-"`
}

// Decode unmarshals the JSON payload into v.
func (m BroadcastMessage) Decode(v any) error {
	return json.Unmarshal(m.Payload, v)
}

// BroadcastMeta is the metadata attached to replayed broadcasts.
type BroadcastMeta struct {
	Replayed bool   `json:"replayed,omitempty"`
	ID       string `json:"id"`
}

// SystemMessage is delivered to system callbacks (upstream
// RealtimeSystemPayload).
type SystemMessage struct {
	Extension string          `json:"extension"`
	Status    string          `json:"status"`
	Message   string          `json:"message"`
	Channel   string          `json:"channel"`
	Raw       json.RawMessage `json:"-"`
}
