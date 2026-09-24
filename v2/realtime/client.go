// Package realtime is a Supabase Realtime client: broadcast, presence and
// Postgres changes over the Phoenix channel protocol, ported from
// @supabase/realtime-js.
//
// A Client owns one websocket connection (dialed lazily) and any number
// of channels. Register callbacks on a channel, then Subscribe:
//
//	ch, _ := client.Channel("room1", realtime.ChannelOptions{})
//	_ = ch.OnBroadcast("cursor", func(m realtime.BroadcastMessage) { ... })
//	if err := ch.Subscribe(ctx); err != nil { ... }
//	_ = ch.Send(ctx, realtime.SendParams{Event: "cursor", Payload: pos})
//
// Every method is safe for concurrent use. Callbacks run sequentially on a
// dedicated goroutine, never while internal locks are held, so they may
// call back into the client.
package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Defaults, matching realtime-js.
const (
	// DefaultTimeout bounds pushes (join, leave, acked broadcasts) and
	// HTTP broadcasts.
	DefaultTimeout = 10 * time.Second
	// DefaultHeartbeatInterval is the interval between heartbeats.
	DefaultHeartbeatInterval = 25 * time.Second

	maxPushBuffer              = 100
	defaultPostgresWaitTimeout = 15 * time.Second
	postgresWaitErrorGrace     = 10 * time.Second
	wsCloseNormal              = 1000
	flushOnCloseTimeout        = 1500 * time.Millisecond
)

// DefaultVersion identifies this client in the join payload `version`
// field (upstream `realtime-js/<version>`).
const DefaultVersion = "realtime-go/" + transport.Version

// DefaultReconnectBackoff is the default socket reconnect schedule:
// 1s, 2s, 5s, then 10s.
func DefaultReconnectBackoff(tries int) time.Duration {
	steps := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second}
	if tries >= 1 && tries <= len(steps) {
		return steps[tries-1]
	}
	return 10 * time.Second
}

// DefaultRejoinBackoff is the default channel rejoin schedule (phoenix
// rejoinAfterMs): 1s, 2s, 5s, then 10s.
func DefaultRejoinBackoff(tries int) time.Duration {
	steps := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second}
	if tries >= 1 && tries <= len(steps) {
		return steps[tries-1]
	}
	return 10 * time.Second
}

// Config configures a Client. URL and APIKey are required.
type Config struct {
	// URL is the Realtime endpoint, e.g. wss://<ref>.supabase.co/realtime/v1.
	// http(s) URLs are converted to ws(s). "/websocket" and the apikey,
	// vsn (and log_level) query parameters are appended.
	URL string
	// APIKey is the project API key, sent as the apikey query parameter
	// and header.
	APIKey string
	// AccessToken returns the user JWT used for channel authorization and
	// RLS. It is called on connect, before subscribing, after each join and
	// on every heartbeat unless a token was set manually with SetAuth.
	// Returning "" means "no user token".
	AccessToken func(ctx context.Context) (string, error)
	// Headers are sent with the websocket handshake and with HTTP
	// broadcasts.
	Headers http.Header
	// HTTPClient performs HTTP broadcasts (/api/broadcast).
	HTTPClient *http.Client
	// Logger receives debug logs. Nil disables logging. Payloads and
	// tokens are never logged.
	Logger *slog.Logger
	// Timeout is the default push and HTTP timeout. Zero means DefaultTimeout.
	Timeout time.Duration
	// HeartbeatInterval is the heartbeat period. Zero means
	// DefaultHeartbeatInterval. A heartbeat that is not answered within
	// one interval closes the socket and triggers a reconnect.
	HeartbeatInterval time.Duration
	// HeartbeatCallback observes heartbeats. See also Client.OnHeartbeat.
	HeartbeatCallback func(status HeartbeatStatus, latency time.Duration)
	// ReconnectBackoff returns the delay before reconnect attempt `tries`
	// (1-based). Nil means DefaultReconnectBackoff.
	ReconnectBackoff func(tries int) time.Duration
	// RejoinBackoff returns the delay before channel rejoin attempt `tries`
	// (1-based). Nil means DefaultRejoinBackoff.
	RejoinBackoff func(tries int) time.Duration
	// Transport opens websocket connections. Nil uses DefaultTransport.
	Transport WebSocketTransport
	// VSN selects the wire protocol: VSN1 ("1.0.0", JSON objects) or VSN2
	// ("2.0.0", JSON arrays with binary broadcasts). Empty means DefaultVSN.
	VSN string
	// LogLevel, when set, is sent as the log_level query parameter to make
	// the server log at that level ("info", "warn", "error").
	LogLevel string
	// Params are extra query parameters for the websocket URL.
	Params map[string]string
	// DisconnectOnEmptyChannelsAfter delays the automatic disconnect that
	// happens once the last channel is removed. Zero means twice the
	// heartbeat interval; a negative value disconnects immediately.
	DisconnectOnEmptyChannelsAfter time.Duration
}

// Client is a Supabase Realtime client. Create it with New.
type Client struct {
	cfg          Config
	wsURL        string
	logURL       string
	dialHeader   http.Header
	ser          serializer
	http         *transport.Client
	httpQuery    url.Values
	disconnAfter time.Duration
	disp         dispatcher
	bg           sync.WaitGroup

	mu                    sync.Mutex
	conn                  *wsConn
	closing               int
	connectClock          uint64
	closeWasClean         bool
	ref                   uint64
	sendBuffer            []frame
	channels              []*Channel
	pendingHeartbeatRef   string
	heartbeatSentAt       time.Time
	heartbeatTimer        *ltimer
	heartbeatTimeoutTimer *ltimer
	reconnectTimer        *backoffTimer
	heartbeatCB           func(HeartbeatStatus, time.Duration)
	openWaiters           []chan error
	pendingDisconnect     *ltimer

	accessToken  string
	manualToken  bool
	authFetched  bool
	authGen      uint64
	authDone     chan struct{}
	establishedN int
}

// New validates cfg and returns a Client. No connection is made until
// Connect or Channel.Subscribe is called.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("realtime: API key is required to connect to Realtime")
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil {
		return nil, fmt.Errorf("realtime: invalid URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return nil, fmt.Errorf("realtime: URL %q must use ws, wss, http or https", cfg.URL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("realtime: URL %q must be absolute", cfg.URL)
	}
	if cfg.VSN == "" {
		cfg.VSN = DefaultVSN
	}
	if cfg.VSN != VSN1 && cfg.VSN != VSN2 {
		return nil, fmt.Errorf("realtime: unsupported serializer version: %s", cfg.VSN)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if cfg.ReconnectBackoff == nil {
		cfg.ReconnectBackoff = DefaultReconnectBackoff
	}
	if cfg.RejoinBackoff == nil {
		cfg.RejoinBackoff = DefaultRejoinBackoff
	}
	if cfg.Transport == nil {
		cfg.Transport = &DefaultTransport{}
	}
	cfg.Headers = cfg.Headers.Clone()
	params := make(map[string]string, len(cfg.Params))
	for k, v := range cfg.Params {
		params[k] = v
	}
	cfg.Params = params

	u.Path = strings.TrimRight(u.Path, "/") + "/websocket"
	u.RawPath = ""
	q := u.Query()
	q.Set("apikey", cfg.APIKey)
	for k, v := range cfg.Params {
		q.Set(k, v)
	}
	if cfg.LogLevel != "" {
		q.Set("log_level", cfg.LogLevel)
	}
	q.Set("vsn", cfg.VSN)
	u.RawQuery = q.Encode()
	u.Fragment = ""

	httpURL, err := httpEndpointURL(u.String())
	if err != nil {
		return nil, err
	}
	httpQuery := httpURL.Query()
	httpURL.RawQuery = ""
	hc, err := transport.New(transport.Config{
		BaseURL:    httpURL.String(),
		APIKey:     cfg.APIKey,
		HTTPClient: cfg.HTTPClient,
		Headers:    cfg.Headers,
		Logger:     cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("realtime: %w", err)
	}

	dialHeader := cfg.Headers.Clone()
	if dialHeader == nil {
		dialHeader = http.Header{}
	}
	if dialHeader.Get(transport.HeaderClientInfo) == "" {
		dialHeader.Set(transport.HeaderClientInfo, transport.ClientInfo)
	}

	disconnAfter := cfg.DisconnectOnEmptyChannelsAfter
	if disconnAfter == 0 {
		disconnAfter = 2 * cfg.HeartbeatInterval
	}

	logURL := *u
	logURL.RawQuery = ""
	c := &Client{
		cfg:           cfg,
		wsURL:         u.String(),
		logURL:        logURL.String(),
		dialHeader:    dialHeader,
		ser:           serializer{vsn: cfg.VSN},
		http:          hc,
		httpQuery:     httpQuery,
		disconnAfter:  disconnAfter,
		closeWasClean: true,
		heartbeatCB:   cfg.HeartbeatCallback,
	}
	c.disp.onPanic = func(v any) {
		if c.cfg.Logger != nil {
			c.cfg.Logger.LogAttrs(context.Background(), slog.LevelError, "realtime callback panicked",
				slog.String("kind", "error"), slog.String("error", panicError(v).Error()))
		}
	}
	c.reconnectTimer = &backoffTimer{c: c, calc: cfg.ReconnectBackoff, fn: c.reconnectFire}
	return c, nil
}

var (
	reWSScheme      = regexp.MustCompile(`(?i)^ws`)
	reSocketWSPath  = regexp.MustCompile(`(?i)/socket/websocket$`)
	reSocketPath    = regexp.MustCompile(`(?i)/socket$`)
	reWebsocketPath = regexp.MustCompile(`(?i)/websocket$`)
)

// httpEndpointURL mirrors realtime-js lib/transformers.ts httpEndpointURL:
// it maps the socket URL to the /api/broadcast HTTP endpoint, keeping the
// query string.
func httpEndpointURL(socketURL string) (*url.URL, error) {
	u, err := url.Parse(socketURL)
	if err != nil {
		return nil, fmt.Errorf("realtime: invalid URL: %w", err)
	}
	u.Scheme = reWSScheme.ReplaceAllString(u.Scheme, "http")
	p := strings.TrimRight(u.Path, "/")
	p = reSocketWSPath.ReplaceAllString(p, "")
	p = reSocketPath.ReplaceAllString(p, "")
	p = reWebsocketPath.ReplaceAllString(p, "")
	if p == "" || p == "/" {
		p = "/api/broadcast"
	} else {
		p += "/api/broadcast"
	}
	u.Path, u.RawPath = p, ""
	return u, nil
}

// EndpointURL returns the websocket URL, including the query parameters.
// It contains the API key; do not log it.
func (c *Client) EndpointURL() string { return c.wsURL }

// emit queues a user callback. It may be called with c.mu held.
func (c *Client) emit(fn func()) { c.disp.enqueue(fn) }

// log queues a debug log record. It may be called with c.mu held; the
// logger itself is never invoked under the lock.
func (c *Client) log(level slog.Level, kind, msg string, attrs ...slog.Attr) {
	l := c.cfg.Logger
	if l == nil {
		return
	}
	all := append([]slog.Attr{slog.String("kind", kind)}, attrs...)
	c.emit(func() { l.LogAttrs(context.Background(), level, msg, all...) })
}

// Connect opens the websocket connection unless it is already open or
// being opened, and waits until it is open, the first attempt fails, or
// ctx is done. After a failed attempt the client keeps reconnecting with
// ReconnectBackoff until Disconnect is called.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	if c.isConnected() {
		c.mu.Unlock()
		return nil
	}
	w := make(chan error, 1)
	c.openWaiters = append(c.openWaiters, w)
	c.connectLocked()
	c.mu.Unlock()
	select {
	case err := <-w:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// connectLocked mirrors RealtimeClient.connect: start a connection unless
// one exists, refreshing auth from the callback first.
func (c *Client) connectLocked() {
	if c.conn != nil {
		return
	}
	if c.cfg.AccessToken != nil && c.authDone == nil {
		c.setAuthSafely()
	}
	c.transportConnect()
}

func (c *Client) transportConnect() {
	c.connectClock++
	c.closeWasClean = false
	dialCtx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
	conn := &wsConn{
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		cancelDial: cancel,
		q:          outQueue{notify: make(chan struct{}, 1)},
	}
	c.conn = conn
	go c.runConn(dialCtx, conn)
}

// ConnectionState reports the websocket state.
func (c *Client) ConnectionState() ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.conn != nil && c.conn.opened:
		return ConnectionOpen
	case c.conn != nil:
		return ConnectionConnecting
	case c.closing > 0:
		return ConnectionClosing
	default:
		return ConnectionClosed
	}
}

// IsConnected reports whether the websocket is open.
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isConnected()
}

func (c *Client) isConnected() bool { return c.conn != nil && c.conn.opened }

// Disconnect closes the websocket with code 1000 and stops reconnecting.
// Channels stay registered and rejoin on the next Connect or Subscribe.
// It waits until the connection's goroutines have exited or ctx is done.
func (c *Client) Disconnect(ctx context.Context) error {
	return c.DisconnectWithCode(ctx, wsCloseNormal, "")
}

// DisconnectWithCode is Disconnect with an explicit close code and reason.
func (c *Client) DisconnectWithCode(ctx context.Context, code int, reason string) error {
	c.mu.Lock()
	c.cancelPendingDisconnect()
	c.connectClock++
	c.closeWasClean = true
	c.reconnectTimer.reset()
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		return nil
	}
	c.teardownConn(conn, code, reason, &CloseError{Code: code, Reason: reason})
	c.mu.Unlock()
	select {
	case <-conn.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Channel returns the channel for topic, creating it if needed. Topics are
// prefixed with "realtime:". If a channel for the topic already exists it
// is returned and opts are ignored.
func (c *Client) Channel(topic string, opts ChannelOptions) (*Channel, error) {
	full := "realtime:" + topic
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ch := range c.channels {
		if ch.topic == full {
			return ch, nil
		}
	}
	if !opts.Private && opts.Broadcast.Replay != nil {
		return nil, fmt.Errorf("realtime: tried to use replay on public channel '%s'. It must be a private channel", full)
	}
	ch := newChannel(c, full, opts)
	c.cancelPendingDisconnect()
	c.channels = append(c.channels, ch)
	return ch, nil
}

// GetChannels returns the channels currently registered on the client.
func (c *Client) GetChannels() []*Channel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*Channel(nil), c.channels...)
}

// RemoveChannel unsubscribes ch and tears it down. When the last channel
// is removed the client disconnects after DisconnectOnEmptyChannelsAfter.
func (c *Client) RemoveChannel(ctx context.Context, ch *Channel) error {
	if err := ch.Unsubscribe(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	ch.teardown()
	c.mu.Unlock()
	return nil
}

// RemoveAllChannels unsubscribes and tears down every channel, then
// disconnects. The returned error joins any per-channel failures.
func (c *Client) RemoveAllChannels(ctx context.Context) error {
	var errs []error
	for _, ch := range c.GetChannels() {
		if err := ch.Unsubscribe(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ch.topic, err))
		}
		c.mu.Lock()
		ch.teardown()
		c.mu.Unlock()
	}
	if err := c.Disconnect(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// removeChannel mirrors socket.remove + RealtimeClient._remove.
func (c *Client) removeChannel(ch *Channel) {
	out := c.channels[:0]
	for _, other := range c.channels {
		if other != ch {
			out = append(out, other)
		}
	}
	for i := len(out); i < len(c.channels); i++ {
		c.channels[i] = nil
	}
	c.channels = out
	if len(c.channels) == 0 {
		c.log(slog.LevelDebug, "transport", "no channels remaining, scheduling disconnect")
		c.schedulePendingDisconnect()
	}
}

func (c *Client) schedulePendingDisconnect() {
	c.cancelPendingDisconnect()
	if c.disconnAfter < 0 {
		c.disconnectBackground()
		return
	}
	c.pendingDisconnect = c.after(c.disconnAfter, func() {
		c.pendingDisconnect = nil
		if len(c.channels) == 0 {
			c.log(slog.LevelDebug, "transport", "deferred disconnect fired - no channels, disconnecting")
			c.disconnectBackground()
		}
	})
}

func (c *Client) cancelPendingDisconnect() {
	if c.pendingDisconnect != nil {
		c.pendingDisconnect.stop()
		c.pendingDisconnect = nil
	}
}

// disconnectBackground disconnects without blocking the caller (which may
// hold c.mu).
func (c *Client) disconnectBackground() {
	c.bg.Add(1)
	go func() {
		defer c.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
		defer cancel()
		_ = c.Disconnect(ctx)
	}()
}

// leaveOpenTopic leaves any other joined/joining channel on topic.
func (c *Client) leaveOpenTopic(topic string, except *Channel) {
	for _, ch := range append([]*Channel(nil), c.channels...) {
		if ch != except && ch.topic == topic && (ch.state == ChannelJoined || ch.state == ChannelJoining) {
			c.log(slog.LevelDebug, "transport", "leaving duplicate topic", slog.String("topic", topic))
			ch.leave(ch.timeout)
		}
	}
}

func (c *Client) makeRef() string {
	c.ref++
	return strconv.FormatUint(c.ref, 10)
}

// push writes msg, or buffers it until the socket opens.
func (c *Client) push(msg outMessage) {
	c.log(slog.LevelDebug, "push", msg.Topic+" "+msg.Event,
		slog.String("join_ref", msg.JoinRef), slog.String("ref", msg.Ref))
	f, err := c.ser.encode(msg)
	if err != nil {
		c.log(slog.LevelError, "error", "failed to encode message", slog.String("topic", msg.Topic),
			slog.String("event", msg.Event), slog.String("error", err.Error()))
		return
	}
	if c.isConnected() {
		c.conn.q.put(f)
	} else {
		c.sendBuffer = append(c.sendBuffer, f)
	}
}

// OnHeartbeat sets the heartbeat callback, replacing Config.HeartbeatCallback.
func (c *Client) OnHeartbeat(fn func(status HeartbeatStatus, latency time.Duration)) {
	c.mu.Lock()
	c.heartbeatCB = fn
	c.mu.Unlock()
}

// SendHeartbeat sends a heartbeat now if the socket is connected.
func (c *Client) SendHeartbeat() {
	c.mu.Lock()
	c.sendHeartbeat()
	c.mu.Unlock()
}

func (c *Client) heartbeatEvent(status HeartbeatStatus, latency time.Duration) {
	if status == HeartbeatDisconnected {
		return
	}
	if status == HeartbeatSent {
		c.setAuthSafely()
	}
	if cb := c.heartbeatCB; cb != nil {
		c.emit(func() { cb(status, latency) })
	}
}

func (c *Client) clearHeartbeats() {
	c.heartbeatTimer.stop()
	c.heartbeatTimer = nil
	c.heartbeatTimeoutTimer.stop()
	c.heartbeatTimeoutTimer = nil
}

func (c *Client) resetHeartbeat() {
	c.pendingHeartbeatRef = ""
	c.clearHeartbeats()
	c.heartbeatTimer = c.after(c.cfg.HeartbeatInterval, c.sendHeartbeat)
}

func (c *Client) sendHeartbeat() {
	if !c.isConnected() {
		c.heartbeatEvent(HeartbeatDisconnected, 0)
		return
	}
	if c.pendingHeartbeatRef != "" {
		c.heartbeatTimeout()
		return
	}
	c.pendingHeartbeatRef = c.makeRef()
	c.heartbeatSentAt = time.Now()
	c.push(outMessage{Topic: "phoenix", Event: "heartbeat", Payload: json.RawMessage("{}"), Ref: c.pendingHeartbeatRef})
	c.heartbeatEvent(HeartbeatSent, 0)
	c.heartbeatTimeoutTimer.stop()
	c.heartbeatTimeoutTimer = c.after(c.cfg.HeartbeatInterval, c.heartbeatTimeout)
}

func (c *Client) heartbeatTimeout() {
	if c.pendingHeartbeatRef == "" {
		return
	}
	c.pendingHeartbeatRef = ""
	c.heartbeatSentAt = time.Time{}
	c.log(slog.LevelDebug, "transport", "heartbeat timeout. Attempting to re-establish connection")
	c.heartbeatEvent(HeartbeatTimeout, 0)
	cause := errors.New("heartbeat timeout")
	c.triggerChanError(cause)
	c.closeWasClean = false
	if conn := c.conn; conn != nil {
		c.teardownConn(conn, wsCloseNormal, "heartbeat timeout", cause)
	}
}

// reconnectFire runs when the reconnect timer fires: wait for in-flight
// auth (beforeReconnect) and connect.
func (c *Client) reconnectFire() {
	clock := c.connectClock
	c.bg.Add(1)
	go func() {
		defer c.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
		_ = c.waitAuth(ctx)
		cancel()
		c.mu.Lock()
		if c.connectClock == clock && c.conn == nil {
			c.connectLocked()
		}
		c.mu.Unlock()
	}()
}

func (c *Client) onConnOpen(conn *wsConn) {
	c.log(slog.LevelDebug, "transport", "connected to "+c.logURL)
	c.closeWasClean = false
	c.establishedN++
	for _, f := range c.sendBuffer {
		conn.q.put(f)
	}
	c.sendBuffer = nil
	c.reconnectTimer.reset()
	c.resetHeartbeat()
	for _, ch := range append([]*Channel(nil), c.channels...) {
		ch.rejoinTimer.reset()
		if ch.state == ChannelErrored {
			ch.rejoin(ch.timeout)
		}
	}
	if c.authDone == nil && c.cfg.AccessToken != nil && c.accessToken == "" {
		c.setAuthSafely()
	}
	for _, w := range c.openWaiters {
		w <- nil
	}
	c.openWaiters = nil
}

func (c *Client) onConnError(err error) {
	c.log(slog.LevelDebug, "transport", "error", slog.String("error", err.Error()))
	for _, ch := range append([]*Channel(nil), c.channels...) {
		ch.rejoinTimer.reset()
	}
	c.triggerChanError(err)
}

func (c *Client) onConnClose(cause error) {
	attrs := []slog.Attr{}
	if cause != nil {
		attrs = append(attrs, slog.String("reason", cause.Error()))
	}
	c.log(slog.LevelDebug, "transport", "close", attrs...)
	c.triggerChanError(cause)
	c.clearHeartbeats()
	if !c.closeWasClean {
		c.reconnectTimer.schedule()
	}
	if len(c.openWaiters) > 0 {
		err := cause
		if err == nil {
			err = errors.New("realtime: connection closed")
		}
		for _, w := range c.openWaiters {
			w <- err
		}
		c.openWaiters = nil
	}
}

func (c *Client) triggerChanError(reason error) {
	for _, ch := range append([]*Channel(nil), c.channels...) {
		if ch.state != ChannelErrored && ch.state != ChannelLeaving && ch.state != ChannelClosed {
			ch.onErrorEvent(reason)
		}
	}
}

// handleFrame decodes one received message and routes it.
func (c *Client) handleFrame(conn *wsConn, typ MessageType, data []byte) {
	msg, err := c.ser.decode(typ, data)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.log(slog.LevelError, "error", "failed to decode message", slog.String("error", err.Error()))
		return
	}
	if conn.detached {
		return
	}
	if msg.Ref != "" && msg.Ref == c.pendingHeartbeatRef {
		var latency time.Duration
		if !c.heartbeatSentAt.IsZero() {
			latency = time.Since(c.heartbeatSentAt)
		}
		c.clearHeartbeats()
		var reply struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(msg.Payload, &reply)
		status := HeartbeatError
		if reply.Status == "ok" {
			status = HeartbeatOK
		}
		c.heartbeatEvent(status, latency)
		c.pendingHeartbeatRef = ""
		c.heartbeatSentAt = time.Time{}
		c.heartbeatTimer = c.after(c.cfg.HeartbeatInterval, c.sendHeartbeat)
	}
	c.log(slog.LevelDebug, "receive", msg.Topic+" "+msg.Event, slog.String("ref", msg.Ref))
	for _, ch := range append([]*Channel(nil), c.channels...) {
		if ch.isMember(msg) {
			ch.onMessage(msg)
		}
	}
}
