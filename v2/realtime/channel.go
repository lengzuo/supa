package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
)

// Phoenix channel events.
const (
	eventClose       = "phx_close"
	eventError       = "phx_error"
	eventJoin        = "phx_join"
	eventReply       = "phx_reply"
	eventLeave       = "phx_leave"
	eventAccessToken = "access_token"
)

var reRealtimePrefix = regexp.MustCompile(`(?i)^realtime:`)

// Channel is a Realtime channel: a topic on which clients broadcast
// messages, share presence and receive Postgres changes. Create it with
// Client.Channel, register callbacks, then call Subscribe. All methods are
// safe for concurrent use.
type Channel struct {
	client   *Client
	topic    string
	subTopic string
	opts     ChannelOptions

	// Guarded by client.mu.
	state       ChannelState
	joinedOnce  bool
	timeout     time.Duration
	joinPush    *push
	pushBuffer  []*push
	rejoinTimer *backoffTimer
	replies     map[string]*push
	bindings    []*binding
	joinPayload joinPayload
	presence    presenceTracker
	statusFn    func(SubscribeStatus, error)
	subscribed  bool
	waiters     []chan error
	tornDown    bool
}

type binding struct {
	typ   ListenType
	event string // broadcast event or presence event (sync/join/leave)
	pg    *PostgresChangesFilter
	pgID  string
	hasID bool

	onBroadcast     func(BroadcastMessage)
	onPresenceSync  func()
	onPresenceJoin  func(PresenceJoinEvent)
	onPresenceLeave func(PresenceLeaveEvent)
	onPostgres      func(PostgresChangesPayload)
	onSystem        func(SystemMessage)
}

type joinPayload struct {
	config     *joinConfig
	hasToken   bool
	token      string
	hasVersion bool
}

type joinConfig struct {
	Broadcast              broadcastJoin  `json:"broadcast"`
	Presence               presenceJoin   `json:"presence"`
	PostgresChanges        []pgJoin       `json:"postgres_changes"`
	Private                bool           `json:"private"`
	PostgresChangesOptions *pgOptionsJoin `json:"postgres_changes_options,omitempty"`
}

type broadcastJoin struct {
	Ack              bool        `json:"ack"`
	Self             bool        `json:"self"`
	Replay           *replayJoin `json:"replay,omitempty"`
	ReplicationReady bool        `json:"replication_ready,omitempty"`
}

type replayJoin struct {
	Since int64 `json:"since"`
	Limit int   `json:"limit,omitempty"`
}

type presenceJoin struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
}

type pgJoin struct {
	Event  string   `json:"event"`
	Schema string   `json:"schema"`
	Table  string   `json:"table,omitempty"`
	Filter string   `json:"filter,omitempty"`
	Select []string `json:"select,omitempty"`
}

type pgOptionsJoin struct {
	Wait    bool  `json:"wait"`
	Timeout int64 `json:"timeout,omitempty"`
}

func newChannel(c *Client, topic string, opts ChannelOptions) *Channel {
	ch := &Channel{
		client:   c,
		topic:    topic,
		subTopic: reRealtimePrefix.ReplaceAllString(topic, ""),
		opts:     opts,
		state:    ChannelClosed,
		timeout:  c.cfg.Timeout,
		replies:  map[string]*push{},
	}
	ch.presence.ch = ch
	ch.joinPayload.config = ch.buildJoinConfig(opts.Presence.Enabled)
	ch.rejoinTimer = &backoffTimer{c: c, calc: c.cfg.RejoinBackoff, fn: func() {
		if c.isConnected() {
			ch.rejoin(ch.timeout)
		}
	}}
	ch.joinPush = newPush(ch, eventJoin, ch.joinPayloadValue, ch.timeout)
	ch.joinPush.receive("ok", func(json.RawMessage) {
		ch.state = ChannelJoined
		ch.rejoinTimer.reset()
		buf := ch.pushBuffer
		ch.pushBuffer = nil
		for _, p := range buf {
			p.send()
		}
	})
	ch.joinPush.receive("error", func(json.RawMessage) {
		ch.state = ChannelErrored
		c.log(slog.LevelDebug, "channel", "error "+ch.topic)
		if c.isConnected() {
			ch.rejoinTimer.schedule()
		}
	})
	ch.joinPush.receive("timeout", func(json.RawMessage) {
		c.log(slog.LevelDebug, "channel", "timeout "+ch.topic, slog.Duration("timeout", ch.joinPush.timeout))
		leave := newPush(ch, eventLeave, nil, ch.timeout)
		leave.send()
		ch.state = ChannelErrored
		ch.joinPush.reset()
		if c.isConnected() {
			ch.rejoinTimer.schedule()
		}
	})
	return ch
}

// Topic returns the full topic, e.g. "realtime:room1".
func (ch *Channel) Topic() string { return ch.topic }

// State returns the channel state.
func (ch *Channel) State() ChannelState {
	ch.client.mu.Lock()
	defer ch.client.mu.Unlock()
	return ch.state
}

// OnStatus registers fn to observe every subscription status change after
// Subscribe: SUBSCRIBED (also after each automatic rejoin), CHANNEL_ERROR,
// TIMED_OUT and CLOSED. It replaces any previous status callback.
func (ch *Channel) OnStatus(fn func(status SubscribeStatus, err error)) {
	ch.client.mu.Lock()
	ch.statusFn = fn
	ch.client.mu.Unlock()
}

// OnBroadcast registers fn for broadcast messages with the given event
// name; "*" matches every event. Matching is case-insensitive.
func (ch *Channel) OnBroadcast(event string, fn func(BroadcastMessage)) error {
	if fn == nil {
		return errors.New("realtime: nil broadcast callback")
	}
	return ch.addBinding(&binding{typ: ListenBroadcast, event: event, onBroadcast: fn})
}

// OnPresenceSync registers fn to run whenever the presence state changes.
// Registering any presence callback enables presence for the channel. It
// must be called before Subscribe.
func (ch *Channel) OnPresenceSync(fn func()) error {
	if fn == nil {
		return errors.New("realtime: nil presence callback")
	}
	return ch.addBinding(&binding{typ: ListenPresence, event: "sync", onPresenceSync: fn})
}

// OnPresenceJoin registers fn for presences joining. It must be called
// before Subscribe.
func (ch *Channel) OnPresenceJoin(fn func(PresenceJoinEvent)) error {
	if fn == nil {
		return errors.New("realtime: nil presence callback")
	}
	return ch.addBinding(&binding{typ: ListenPresence, event: "join", onPresenceJoin: fn})
}

// OnPresenceLeave registers fn for presences leaving. It must be called
// before Subscribe.
func (ch *Channel) OnPresenceLeave(fn func(PresenceLeaveEvent)) error {
	if fn == nil {
		return errors.New("realtime: nil presence callback")
	}
	return ch.addBinding(&binding{typ: ListenPresence, event: "leave", onPresenceLeave: fn})
}

// OnPostgresChanges registers fn for database changes matching filter. It
// must be called before Subscribe. Registering an identical filter twice
// is a no-op (the server collapses them), matching realtime-js.
func (ch *Channel) OnPostgresChanges(filter PostgresChangesFilter, fn func(PostgresChangesPayload)) error {
	if fn == nil {
		return errors.New("realtime: nil postgres_changes callback")
	}
	if filter.Event == "" {
		filter.Event = PostgresChangeAll
	}
	filter.Select = append([]string(nil), filter.Select...)
	return ch.addBinding(&binding{typ: ListenPostgresChanges, event: string(filter.Event), pg: &filter, onPostgres: fn})
}

// OnSystem registers fn for system messages (e.g. the replication-ready
// notification requested with BroadcastOptions.ReplicationReady).
func (ch *Channel) OnSystem(fn func(SystemMessage)) error {
	if fn == nil {
		return errors.New("realtime: nil system callback")
	}
	return ch.addBinding(&binding{typ: ListenSystem, onSystem: fn})
}

func (ch *Channel) addBinding(b *binding) error {
	c := ch.client
	c.mu.Lock()
	defer c.mu.Unlock()
	if (b.typ == ListenPresence || b.typ == ListenPostgresChanges) &&
		(ch.state == ChannelJoined || ch.state == ChannelJoining) {
		c.log(slog.LevelDebug, "channel", fmt.Sprintf("cannot add `%s` callbacks for %s after `subscribe()`.", b.typ, ch.topic))
		return fmt.Errorf("realtime: cannot add `%s` callbacks for %s after `subscribe()`", b.typ, ch.topic)
	}
	if b.typ == ListenPostgresChanges {
		for _, other := range ch.bindings {
			if other.typ == ListenPostgresChanges && samePostgresFilter(*other.pg, *b.pg) {
				c.log(slog.LevelError, "error", "duplicate `postgres_changes` binding for "+ch.topic+" ignored")
				return nil
			}
		}
	}
	ch.bindings = append(ch.bindings, b)
	return nil
}

func samePostgresFilter(a, b PostgresChangesFilter) bool {
	return a.Event == b.Event && a.Schema == b.Schema && a.Table == b.Table &&
		a.Filter == b.Filter && strings.Join(a.Select, ",") == strings.Join(b.Select, ",") &&
		(a.Select == nil) == (b.Select == nil)
}

func (ch *Channel) hasBindings(typ ListenType) bool {
	for _, b := range ch.bindings {
		if b.typ == typ {
			return true
		}
	}
	return false
}

func (ch *Channel) buildJoinConfig(presenceEnabled bool) *joinConfig {
	o := ch.opts
	cfg := &joinConfig{
		Broadcast: broadcastJoin{
			Ack:              o.Broadcast.Ack,
			Self:             o.Broadcast.Self,
			ReplicationReady: o.Broadcast.ReplicationReady,
		},
		Presence:        presenceJoin{Key: o.Presence.Key, Enabled: presenceEnabled},
		PostgresChanges: []pgJoin{},
		Private:         o.Private,
	}
	if r := o.Broadcast.Replay; r != nil {
		cfg.Broadcast.Replay = &replayJoin{Since: r.Since.UnixMilli(), Limit: r.Limit}
	}
	for _, b := range ch.bindings {
		if b.typ != ListenPostgresChanges {
			continue
		}
		cfg.PostgresChanges = append(cfg.PostgresChanges, pgJoin{
			Event: string(b.pg.Event), Schema: b.pg.Schema, Table: b.pg.Table,
			Filter: b.pg.Filter, Select: b.pg.Select,
		})
	}
	if p := o.PostgresChanges; p != nil {
		cfg.PostgresChangesOptions = &pgOptionsJoin{Wait: p.Wait, Timeout: p.Timeout.Milliseconds()}
	}
	return cfg
}

func (ch *Channel) joinPayloadValue() any {
	m := map[string]any{"config": ch.joinPayload.config}
	if ch.joinPayload.hasToken {
		m["access_token"] = nullableString(ch.joinPayload.token)
	}
	if ch.joinPayload.hasVersion {
		m["version"] = DefaultVersion
	}
	return m
}

// Subscribe joins the channel and waits until it is SUBSCRIBED, the join
// fails, or ctx is done. The client connects first if needed.
//
// A join error, timeout or connection error is returned as a
// *SubscribeError; in those cases (and when ctx is done first) the channel
// keeps retrying in the background like realtime-js does, reporting later
// outcomes to the OnStatus callback. Call Unsubscribe or
// Client.RemoveChannel to stop it.
func (ch *Channel) Subscribe(ctx context.Context) error {
	c := ch.client
	if err := c.prepareAuth(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	if ch.tornDown {
		c.mu.Unlock()
		return &SubscribeError{Status: StatusClosed, Message: "channel was removed"}
	}
	if !c.isConnected() {
		c.connectLocked()
	}
	switch ch.state {
	case ChannelJoined:
		c.mu.Unlock()
		return nil
	case ChannelLeaving:
		c.mu.Unlock()
		return &SubscribeError{Status: StatusClosed, Message: "channel is leaving"}
	case ChannelJoining, ChannelErrored:
		w := ch.addWaiter()
		c.mu.Unlock()
		return ch.waitSubscribe(ctx, w)
	}
	if ch.joinedOnce {
		c.mu.Unlock()
		return ErrAlreadySubscribed
	}

	presenceEnabled := ch.hasBindings(ListenPresence) || ch.opts.Presence.Enabled
	cfg := ch.buildJoinConfig(presenceEnabled)
	ch.subscribed = true
	ch.joinPayload.config = cfg
	if c.accessToken != "" {
		ch.joinPayload.hasToken = true
		ch.joinPayload.token = c.accessToken
	}
	joinTimeout := c.cfg.Timeout
	if o := ch.opts.PostgresChanges; o != nil && o.Wait && len(cfg.PostgresChanges) > 0 {
		wait := o.Timeout
		if wait <= 0 {
			wait = defaultPostgresWaitTimeout
		}
		if wait+postgresWaitErrorGrace > joinTimeout {
			joinTimeout = wait + postgresWaitErrorGrace
		}
	}

	ch.joinPush.receive("ok", func(resp json.RawMessage) {
		if !c.manualToken {
			c.setAuthSafely()
		}
		var r struct {
			PostgresChanges *[]serverPgBinding `json:"postgres_changes"`
		}
		_ = json.Unmarshal(resp, &r)
		if r.PostgresChanges == nil {
			ch.emitStatus(StatusSubscribed, nil)
			return
		}
		ch.updatePostgresBindings(*r.PostgresChanges)
	})
	ch.joinPush.receive("error", func(resp json.RawMessage) {
		ch.state = ChannelErrored
		msg := joinObjectValues(resp)
		if msg == "" {
			msg = "error"
		}
		ch.emitStatus(StatusChannelError, &SubscribeError{Status: StatusChannelError, Message: msg, Response: resp})
	})
	ch.joinPush.receive("timeout", func(json.RawMessage) {
		ch.emitStatus(StatusTimedOut, &SubscribeError{Status: StatusTimedOut, Message: "join timed out", Err: ErrTimedOut})
	})

	w := ch.addWaiter()
	ch.join(joinTimeout)
	c.mu.Unlock()
	return ch.waitSubscribe(ctx, w)
}

// waitSubscribe waits for a Subscribe outcome. A waiter abandoned because
// ctx is done is removed so repeated cancelled Subscribe calls do not
// accumulate.
func (ch *Channel) waitSubscribe(ctx context.Context, w chan error) error {
	select {
	case err := <-w:
		return err
	case <-ctx.Done():
	}
	c := ch.client
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, other := range ch.waiters {
		if other == w {
			ch.waiters = append(ch.waiters[:i], ch.waiters[i+1:]...)
			return ctx.Err()
		}
	}
	// Already resolved while ctx was being cancelled: report the outcome.
	select {
	case err := <-w:
		return err
	default:
		return ctx.Err()
	}
}

func waitErr(ctx context.Context, w chan error) error {
	select {
	case err := <-w:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (ch *Channel) addWaiter() chan error {
	w := make(chan error, 1)
	ch.waiters = append(ch.waiters, w)
	return w
}

// emitStatus resolves Subscribe waiters and notifies the status callback.
func (ch *Channel) emitStatus(status SubscribeStatus, err error) {
	ch.resolveWaiters(err)
	if fn := ch.statusFn; fn != nil {
		ch.client.emit(func() { fn(status, err) })
	}
}

func (ch *Channel) resolveWaiters(err error) {
	for _, w := range ch.waiters {
		w <- err
	}
	ch.waiters = nil
}

type serverPgBinding struct {
	ID     json.RawMessage `json:"id"`
	Event  string          `json:"event"`
	Schema *string         `json:"schema"`
	Table  *string         `json:"table"`
	Filter *string         `json:"filter"`
}

func (ch *Channel) updatePostgresBindings(server []serverPgBinding) {
	var pgBindings []*binding
	for _, b := range ch.bindings {
		if b.typ == ListenPostgresChanges {
			pgBindings = append(pgBindings, b)
		}
	}
	ids := make([]string, len(pgBindings))
	for i, b := range pgBindings {
		if i >= len(server) || !serverBindingMatches(server[i], b.pg) {
			err := &SubscribeError{Status: StatusChannelError, Message: "mismatch between server and client bindings for postgres changes"}
			// Resolve Subscribe first so it reports the mismatch rather than
			// the CLOSED status caused by the leave below.
			ch.resolveWaiters(err)
			ch.leave(ch.timeout)
			ch.state = ChannelErrored
			ch.emitStatus(StatusChannelError, err)
			return
		}
		ids[i] = normalizeID(server[i].ID)
	}
	for i, b := range pgBindings {
		b.pgID, b.hasID = ids[i], true
	}
	if ch.state != ChannelErrored {
		ch.emitStatus(StatusSubscribed, nil)
	}
}

func serverBindingMatches(s serverPgBinding, f *PostgresChangesFilter) bool {
	return s.Event == string(f.Event) && deref(s.Schema) == f.Schema &&
		deref(s.Table) == f.Table && deref(s.Filter) == f.Filter
}

func normalizeID(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

// Unsubscribe leaves the channel. Like realtime-js it resolves as soon as
// the leave is sent (the channel closes locally without waiting for the
// server), and the OnStatus callback receives CLOSED.
func (ch *Channel) Unsubscribe(ctx context.Context) error {
	c := ch.client
	c.mu.Lock()
	p := ch.leave(ch.timeout)
	w := make(chan error, 1)
	deliver := func(err error) {
		select {
		case w <- err:
		default:
		}
	}
	p.receive("ok", func(json.RawMessage) { deliver(nil) })
	p.receive("timeout", func(json.RawMessage) { deliver(ErrTimedOut) })
	p.receive("error", func(r json.RawMessage) { deliver(&PushError{Response: r}) })
	c.mu.Unlock()
	return waitErr(ctx, w)
}

// Send sends a message on the channel (upstream RealtimeChannel.send).
//
// Broadcasts are pushed over the websocket when the channel is joined;
// otherwise they fall back to the HTTP broadcast endpoint (deprecated
// upstream; prefer HTTPSend). Without BroadcastOptions.Ack a websocket
// broadcast returns once queued; with it Send waits for the server's
// acknowledgement. Other message types (presence, postgres_changes) wait
// for the server reply and require Subscribe to have been called; they are
// buffered while the channel is (re)joining.
func (ch *Channel) Send(ctx context.Context, p SendParams) error {
	if p.Type == "" {
		p.Type = ListenBroadcast
	}
	c := ch.client
	args := &sendArgs{Type: string(p.Type), Event: p.Event}
	if p.Payload != nil {
		args.hasPayload = true
		switch v := p.Payload.(type) {
		case []byte:
			if c.cfg.VSN != VSN2 || p.Type != ListenBroadcast {
				return fmt.Errorf("realtime: []byte payloads are only supported for broadcasts with protocol %s (got type %q, protocol %s); use json.RawMessage for JSON", VSN2, p.Type, c.cfg.VSN)
			}
			args.Payload = append([]byte(nil), v...)
		case json.RawMessage:
			if !json.Valid(v) {
				return errors.New("realtime: payload is not valid JSON")
			}
			args.Payload = append(json.RawMessage(nil), v...)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("realtime: encode payload: %w", err)
			}
			args.Payload = json.RawMessage(b)
		}
	}
	timeout := p.Timeout

	c.mu.Lock()
	if timeout <= 0 {
		timeout = ch.timeout
	}
	if !ch.canPush() && p.Type == ListenBroadcast {
		c.mu.Unlock()
		return ch.broadcastFallback(ctx, args, timeout)
	}
	if _, err := c.ser.encode(outMessage{Topic: ch.topic, Event: args.Type, Payload: args, Ref: "0", JoinRef: ch.joinRef()}); err != nil {
		c.mu.Unlock()
		return err
	}
	pu, err := ch.pushEvent(args.Type, args, timeout)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	if p.Type == ListenBroadcast && !ch.opts.Broadcast.Ack {
		c.mu.Unlock()
		return nil
	}
	w := make(chan error, 1)
	deliver := func(err error) {
		select {
		case w <- err:
		default:
		}
	}
	pu.receive("ok", func(json.RawMessage) { deliver(nil) })
	pu.receive("error", func(r json.RawMessage) { deliver(&PushError{Response: r}) })
	pu.receive("timeout", func(json.RawMessage) { deliver(ErrTimedOut) })
	pu.onAbort(deliver)
	c.mu.Unlock()
	return waitErr(ctx, w)
}

// Track shares payload as this client's presence on the channel. It is
// visible to other subscribers regardless of PresenceOptions.Enabled.
func (ch *Channel) Track(ctx context.Context, payload any) error {
	if payload == nil {
		payload = json.RawMessage("{}")
	}
	return ch.Send(ctx, SendParams{Type: ListenPresence, Event: "track", Payload: payload})
}

// Untrack removes this client's presence from the channel.
func (ch *Channel) Untrack(ctx context.Context) error {
	return ch.Send(ctx, SendParams{Type: ListenPresence, Event: "untrack"})
}

// PresenceState returns a snapshot of the channel's presence state keyed
// by presence key.
func (ch *Channel) PresenceState() PresenceState {
	ch.client.mu.Lock()
	defer ch.client.mu.Unlock()
	return ch.presence.snapshot()
}

// --- phoenix Channel internals (require client.mu) ---

func (ch *Channel) joinRef() string { return ch.joinPush.ref }

func (ch *Channel) canPush() bool { return ch.client.isConnected() && ch.state == ChannelJoined }

func (ch *Channel) join(timeout time.Duration) {
	ch.timeout = timeout
	ch.joinedOnce = true
	ch.rejoin(timeout)
}

func (ch *Channel) rejoin(timeout time.Duration) {
	if ch.state == ChannelLeaving || ch.tornDown {
		return
	}
	ch.client.leaveOpenTopic(ch.topic, ch)
	ch.state = ChannelJoining
	ch.joinPush.resend(timeout)
}

func (ch *Channel) leave(timeout time.Duration) *push {
	ch.rejoinTimer.reset()
	ch.joinPush.cancelTimeout()
	ch.state = ChannelLeaving
	onClose := func(json.RawMessage) {
		ch.client.log(slog.LevelDebug, "channel", "leave "+ch.topic)
		ch.onCloseEvent()
	}
	lp := newPush(ch, eventLeave, nil, timeout)
	lp.receive("ok", onClose).receive("timeout", onClose)
	lp.send()
	if !ch.canPush() {
		lp.trigger("ok", json.RawMessage("{}"))
	}
	return lp
}

func (ch *Channel) pushEvent(event string, payload any, timeout time.Duration) (*push, error) {
	if !ch.joinedOnce {
		return nil, fmt.Errorf("realtime: tried to push '%s' to '%s' before joining: %w", event, ch.topic, ErrNotSubscribed)
	}
	p := newPush(ch, event, func() any { return payload }, timeout)
	if ch.canPush() {
		p.send()
	} else {
		p.startTimeout()
		ch.pushBuffer = append(ch.pushBuffer, p)
	}
	if len(ch.pushBuffer) > maxPushBuffer {
		removed := ch.pushBuffer[0]
		ch.pushBuffer[0] = nil
		ch.pushBuffer = ch.pushBuffer[1:]
		removed.cancelTimeout()
		removed.cancelRefEvent()
		removed.abort(ErrPushDiscarded)
		ch.client.log(slog.LevelDebug, "channel", "discarded push due to buffer overflow: "+removed.event)
	}
	return p, nil
}

func (ch *Channel) teardown() {
	for _, p := range ch.pushBuffer {
		p.destroy()
	}
	ch.pushBuffer = nil
	ch.rejoinTimer.reset()
	ch.joinPush.destroy()
	ch.state = ChannelClosed
	ch.bindings = nil
	ch.resolveWaiters(&SubscribeError{Status: StatusClosed, Message: "channel was removed"})
	ch.tornDown = true
	for _, other := range ch.client.channels {
		if other == ch {
			ch.client.removeChannel(ch)
			break
		}
	}
}

func (ch *Channel) isMember(msg inMessage) bool {
	if ch.topic != msg.Topic {
		return false
	}
	if msg.JoinRef != "" && msg.JoinRef != ch.joinRef() {
		ch.client.log(slog.LevelDebug, "channel", "dropping outdated message",
			slog.String("topic", msg.Topic), slog.String("event", msg.Event))
		return false
	}
	return true
}

// onMessage handles a message routed from the socket (phoenix
// Channel.trigger with realtime-js filterBindings/onMessage hooks).
func (ch *Channel) onMessage(msg inMessage) {
	if ch.tornDown {
		return
	}
	switch msg.Event {
	case eventClose, eventError, eventLeave, eventJoin:
		// _notThisChannelEvent: ignore lifecycle events for other joins.
		if msg.Ref != "" && msg.Ref != ch.joinRef() {
			return
		}
	}
	switch msg.Event {
	case eventReply:
		var r struct {
			Status   string          `json:"status"`
			Response json.RawMessage `json:"response"`
		}
		if json.Unmarshal(msg.Payload, &r) != nil {
			return
		}
		if p := ch.replies[msg.Ref]; p != nil {
			p.handleReply(&pushReply{status: r.Status, response: r.Response})
		}
	case eventClose:
		ch.onCloseEvent()
	case eventError:
		ch.onErrorEvent(errors.New("channel error: transport failure"))
	case "presence_state":
		ch.presence.onState(msg.Payload)
	case "presence_diff":
		ch.presence.onDiff(msg.Payload)
	case string(ListenBroadcast):
		ch.dispatchBroadcast(msg)
	case string(ListenPostgresChanges):
		ch.dispatchPostgres(msg)
	case string(ListenSystem):
		ch.dispatchSystem(msg)
	}
}

func (ch *Channel) onCloseEvent() {
	if ch.tornDown {
		return
	}
	ch.rejoinTimer.reset()
	ch.client.log(slog.LevelDebug, "channel", "close "+ch.topic)
	ch.state = ChannelClosed
	ch.client.removeChannel(ch)
	if ch.subscribed {
		ch.emitStatus(StatusClosed, &SubscribeError{Status: StatusClosed})
	}
}

func (ch *Channel) onErrorEvent(reason error) {
	if ch.tornDown {
		return
	}
	attrs := []slog.Attr{}
	if reason != nil {
		attrs = append(attrs, slog.String("reason", reason.Error()))
	}
	ch.client.log(slog.LevelDebug, "channel", "error "+ch.topic, attrs...)
	if ch.state == ChannelJoining {
		ch.joinPush.reset()
	}
	ch.state = ChannelErrored
	if ch.client.isConnected() {
		ch.rejoinTimer.schedule()
	}
	if ch.subscribed {
		err := normalizeChannelError(reason)
		ch.emitStatus(StatusChannelError, &SubscribeError{Status: StatusChannelError, Err: err})
	}
}

func (ch *Channel) dispatchBroadcast(msg inMessage) {
	var bm BroadcastMessage
	_ = json.Unmarshal(msg.Payload, &bm)
	bm.Raw = msg.Payload
	bm.Binary = msg.Binary
	for _, b := range ch.bindings {
		if b.typ != ListenBroadcast {
			continue
		}
		if b.event == "*" || strings.EqualFold(b.event, bm.Event) {
			fn, m := b.onBroadcast, bm
			ch.client.emit(func() { fn(m) })
		}
	}
}

func (ch *Channel) dispatchSystem(msg inMessage) {
	var sm SystemMessage
	_ = json.Unmarshal(msg.Payload, &sm)
	sm.Raw = msg.Payload
	for _, b := range ch.bindings {
		if b.typ == ListenSystem {
			fn := b.onSystem
			ch.client.emit(func() { fn(sm) })
		}
	}
}

func (ch *Channel) dispatchPostgres(msg inMessage) {
	var raw struct {
		IDs  []json.RawMessage `json:"ids"`
		Data json.RawMessage   `json:"data"`
	}
	if json.Unmarshal(msg.Payload, &raw) != nil || raw.IDs == nil {
		return
	}
	var data struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(raw.Data, &data)
	ids := make(map[string]bool, len(raw.IDs))
	for _, id := range raw.IDs {
		ids[normalizeID(id)] = true
	}
	var payload *PostgresChangesPayload
	for _, b := range ch.bindings {
		if b.typ != ListenPostgresChanges {
			continue
		}
		var match bool
		if b.hasID {
			match = ids[b.pgID] && (b.event == "*" || strings.EqualFold(b.event, data.Type))
		} else {
			match = b.event == "*"
		}
		if !match {
			continue
		}
		if payload == nil {
			p := transformPostgresPayload(raw.Data)
			payload = &p
		}
		fn, p := b.onPostgres, *payload
		ch.client.emit(func() { fn(p) })
	}
}

func (ch *Channel) dispatchPresence(event string, join *PresenceJoinEvent, leave *PresenceLeaveEvent) {
	for _, b := range ch.bindings {
		if b.typ != ListenPresence || b.event != event {
			continue
		}
		switch event {
		case "sync":
			fn := b.onPresenceSync
			ch.client.emit(fn)
		case "join":
			fn, ev := b.onPresenceJoin, *join
			ch.client.emit(func() { fn(ev) })
		case "leave":
			fn, ev := b.onPresenceLeave, *leave
			ch.client.emit(func() { fn(ev) })
		}
	}
}
