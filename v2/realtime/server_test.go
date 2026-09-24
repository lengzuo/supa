package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// srvMsg is a message decoded by the fake server.
type srvMsg struct {
	JoinRef *string
	Ref     *string
	Topic   string
	Event   string
	Payload json.RawMessage
	// Set for binary user broadcast pushes (kind 3).
	Binary     bool
	UserEvent  string
	Encoding   byte
	RawPayload []byte
}

func (m srvMsg) ref() string     { return deref(m.Ref) }
func (m srvMsg) joinRef() string { return deref(m.JoinRef) }

func (m srvMsg) payloadMap(t *testing.T) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(m.Payload, &v); err != nil {
		t.Fatalf("payload of %s is not an object: %s", m.Event, m.Payload)
	}
	return v
}

// fakeServer speaks the Phoenix channel protocol like the Realtime server.
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	conns chan *serverConn
	all   chan srvMsg

	// Behaviour switches.
	ignoreHeartbeats atomic.Bool
	ignoreJoins      atomic.Bool
	rejectDial       atomic.Bool
	joinReply        func(sc *serverConn, m srvMsg) (status string, response any)
	onMessage        func(sc *serverConn, m srvMsg) bool
	httpHandler      http.HandlerFunc

	mu      sync.Mutex
	current []*serverConn
}

type serverConn struct {
	fs     *fakeServer
	c      *websocket.Conn
	vsn    string
	query  url.Values
	header http.Header
	msgs   chan srvMsg
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	configs map[string]map[string]any // topic -> join config
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{t: t, conns: make(chan *serverConn, 16), all: make(chan srvMsg, 1024)}
	mux := http.NewServeMux()
	mux.HandleFunc("/realtime/v1/websocket", fs.handleWS)
	mux.HandleFunc("/realtime/v1/api/broadcast", fs.handleHTTP)
	mux.HandleFunc("/realtime/v1/api/broadcast/", fs.handleHTTP)
	fs.srv = httptest.NewServer(mux)
	t.Cleanup(fs.close)
	return fs
}

func (fs *fakeServer) close() {
	fs.mu.Lock()
	conns := fs.current
	fs.current = nil
	fs.mu.Unlock()
	for _, sc := range conns {
		sc.cancel()
		_ = sc.c.CloseNow()
	}
	fs.srv.Close()
}

func (fs *fakeServer) wsURL() string {
	return "ws" + strings.TrimPrefix(fs.srv.URL, "http") + "/realtime/v1"
}

func (fs *fakeServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if fs.httpHandler == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	fs.httpHandler(w, r)
}

func (fs *fakeServer) handleWS(w http.ResponseWriter, r *http.Request) {
	if fs.rejectDial.Load() {
		http.Error(w, "nope", http.StatusServiceUnavailable)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(-1)
	ctx, cancel := context.WithCancel(context.Background())
	sc := &serverConn{
		fs: fs, c: c, vsn: r.URL.Query().Get("vsn"), query: r.URL.Query(), header: r.Header.Clone(),
		msgs: make(chan srvMsg, 1024), ctx: ctx, cancel: cancel, configs: map[string]map[string]any{},
	}
	fs.mu.Lock()
	fs.current = append(fs.current, sc)
	fs.mu.Unlock()
	fs.conns <- sc
	defer cancel()
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		m, err := serverDecode(sc.vsn, typ, data)
		if err != nil {
			fs.t.Errorf("server decode: %v (%q)", err, data)
			return
		}
		select {
		case sc.msgs <- m:
		default:
		}
		select {
		case fs.all <- m:
		default:
		}
		fs.respond(sc, m)
	}
}

func (fs *fakeServer) respond(sc *serverConn, m srvMsg) {
	if fs.onMessage != nil && fs.onMessage(sc, m) {
		return
	}
	switch {
	case m.Topic == "phoenix" && m.Event == "heartbeat":
		if !fs.ignoreHeartbeats.Load() {
			sc.reply(m, "ok", map[string]any{})
		}
	case m.Event == "phx_join":
		p := m.payloadMap(fs.t)
		cfg, _ := p["config"].(map[string]any)
		sc.mu.Lock()
		sc.configs[m.Topic] = cfg
		sc.mu.Unlock()
		if fs.ignoreJoins.Load() {
			return
		}
		if fs.joinReply != nil {
			status, resp := fs.joinReply(sc, m)
			if status != "" {
				sc.reply(m, status, resp)
			}
			return
		}
		sc.reply(m, "ok", defaultJoinResponse(cfg))
	case m.Event == "phx_leave":
		sc.reply(m, "ok", map[string]any{})
	case m.Event == "broadcast":
		sc.mu.Lock()
		cfg := sc.configs[m.Topic]
		sc.mu.Unlock()
		b, _ := cfg["broadcast"].(map[string]any)
		if self, _ := b["self"].(bool); self {
			var payload json.RawMessage
			if m.Binary {
				payload = m.RawPayload
			} else {
				var args struct {
					Payload json.RawMessage `json:"payload"`
				}
				_ = json.Unmarshal(m.Payload, &args)
				payload = args.Payload
			}
			ev := m.UserEvent
			if !m.Binary {
				var args struct {
					Event string `json:"event"`
				}
				_ = json.Unmarshal(m.Payload, &args)
				ev = args.Event
			}
			sc.push(m.Topic, "broadcast", map[string]any{"type": "broadcast", "event": ev, "payload": payload})
		}
		if ack, _ := b["ack"].(bool); ack {
			sc.reply(m, "ok", map[string]any{})
		}
	case m.Event == "presence":
		sc.reply(m, "ok", map[string]any{})
	}
}

func defaultJoinResponse(cfg map[string]any) map[string]any {
	pcs, _ := cfg["postgres_changes"].([]any)
	if len(pcs) == 0 {
		return map[string]any{}
	}
	out := make([]any, 0, len(pcs))
	for i, pc := range pcs {
		m, _ := pc.(map[string]any)
		entry := map[string]any{"id": 100 + i}
		for k, v := range m {
			entry[k] = v
		}
		out = append(out, entry)
	}
	return map[string]any{"postgres_changes": out}
}

// nextConn waits for the next accepted websocket connection.
func (fs *fakeServer) nextConn(t *testing.T) *serverConn {
	t.Helper()
	select {
	case sc := <-fs.conns:
		return sc
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a websocket connection")
		return nil
	}
}

// expect waits for a message on sc matching pred.
func (sc *serverConn) expect(t *testing.T, what string, pred func(srvMsg) bool) srvMsg {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-sc.msgs:
			if pred(m) {
				return m
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
			return srvMsg{}
		}
	}
}

func (sc *serverConn) expectEvent(t *testing.T, topic, event string) srvMsg {
	t.Helper()
	return sc.expect(t, topic+" "+event, func(m srvMsg) bool { return m.Topic == topic && m.Event == event })
}

// noMessage asserts no message matching pred arrives within d.
func (sc *serverConn) noMessage(t *testing.T, d time.Duration, pred func(srvMsg) bool) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case m := <-sc.msgs:
			if pred(m) {
				t.Fatalf("unexpected message %s %s %s", m.Topic, m.Event, m.Payload)
			}
		case <-deadline:
			return
		}
	}
}

func (sc *serverConn) send(joinRef, ref any, topic, event string, payload any) {
	p, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	var data []byte
	if sc.vsn == VSN1 {
		data, _ = json.Marshal(map[string]any{"join_ref": joinRef, "ref": ref, "topic": topic, "event": event, "payload": json.RawMessage(p)})
	} else {
		data, _ = json.Marshal([]any{joinRef, ref, topic, event, json.RawMessage(p)})
	}
	ctx, cancel := context.WithTimeout(sc.ctx, 5*time.Second)
	defer cancel()
	_ = sc.c.Write(ctx, websocket.MessageText, data)
}

func (sc *serverConn) reply(m srvMsg, status string, response any) {
	sc.send(nilIfEmpty(m.joinRef()), nilIfEmpty(m.ref()), m.Topic, "phx_reply", map[string]any{"status": status, "response": response})
}

func (sc *serverConn) push(topic, event string, payload any) {
	sc.send(nil, nil, topic, event, payload)
}

// sendUserBroadcast writes a binary kind-4 user broadcast frame.
func (sc *serverConn) sendUserBroadcast(topic, event, meta string, encoding byte, payload []byte) {
	data := []byte{binKindUserBroadcast, byte(len(topic)), byte(len(event)), byte(len(meta)), encoding}
	data = append(data, topic...)
	data = append(data, event...)
	data = append(data, meta...)
	data = append(data, payload...)
	ctx, cancel := context.WithTimeout(sc.ctx, 5*time.Second)
	defer cancel()
	_ = sc.c.Write(ctx, websocket.MessageBinary, data)
}

func (sc *serverConn) config(topic string) map[string]any {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.configs[topic]
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// serverDecode decodes client frames independently of the client code.
func serverDecode(vsn string, typ websocket.MessageType, data []byte) (srvMsg, error) {
	if typ == websocket.MessageBinary {
		if len(data) < 7 || data[0] != 3 {
			return srvMsg{}, fmt.Errorf("unexpected binary frame kind %d", data[0])
		}
		jl, rl, tl, el, ml, enc := int(data[1]), int(data[2]), int(data[3]), int(data[4]), int(data[5]), data[6]
		off := 7
		if len(data) < off+jl+rl+tl+el+ml {
			return srvMsg{}, errors.New("short binary frame")
		}
		joinRef := string(data[off : off+jl])
		off += jl
		ref := string(data[off : off+rl])
		off += rl
		topic := string(data[off : off+tl])
		off += tl
		event := string(data[off : off+el])
		off += el + ml
		m := srvMsg{JoinRef: &joinRef, Ref: &ref, Topic: topic, Event: "broadcast", Binary: true,
			UserEvent: event, Encoding: enc, RawPayload: data[off:]}
		return m, nil
	}
	if vsn == VSN1 {
		var m struct {
			JoinRef *string         `json:"join_ref"`
			Ref     *string         `json:"ref"`
			Topic   string          `json:"topic"`
			Event   string          `json:"event"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(data, &m); err != nil {
			return srvMsg{}, err
		}
		return srvMsg{JoinRef: m.JoinRef, Ref: m.Ref, Topic: m.Topic, Event: m.Event, Payload: m.Payload}, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil || len(arr) != 5 {
		return srvMsg{}, fmt.Errorf("bad array frame: %v", err)
	}
	var m srvMsg
	_ = json.Unmarshal(arr[0], &m.JoinRef)
	_ = json.Unmarshal(arr[1], &m.Ref)
	_ = json.Unmarshal(arr[2], &m.Topic)
	_ = json.Unmarshal(arr[3], &m.Event)
	m.Payload = arr[4]
	return m, nil
}

// testConfig returns a client config pointed at fs with fast timers.
func testConfig(fs *fakeServer) Config {
	return Config{
		URL:               fs.wsURL(),
		APIKey:            "anon-key",
		Timeout:           2 * time.Second,
		HeartbeatInterval: time.Hour,
		ReconnectBackoff:  func(int) time.Duration { return 20 * time.Millisecond },
		RejoinBackoff:     func(int) time.Duration { return 20 * time.Millisecond },
	}
}

func newTestClient(t *testing.T, fs *fakeServer, mutate func(*Config)) *Client {
	t.Helper()
	cfg := testConfig(fs)
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = c.Disconnect(ctx)
	})
	return c
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// subscribeJoined creates a channel, subscribes and returns it with the
// server connection that received the join.
func subscribeJoined(t *testing.T, c *Client, fs *fakeServer, topic string, opts ChannelOptions, setup func(*Channel)) (*Channel, *serverConn, srvMsg) {
	t.Helper()
	ch, err := c.Channel(topic, opts)
	if err != nil {
		t.Fatalf("Channel: %v", err)
	}
	if setup != nil {
		setup(ch)
	}
	errc := make(chan error, 1)
	go func() { errc <- ch.Subscribe(ctxT(t)) }()
	sc := fs.nextConn(t)
	join := sc.expectEvent(t, "realtime:"+topic, "phx_join")
	if err := <-errc; err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	return ch, sc, join
}

// recv waits for a value on ch.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met: %s", what)
}

// leakedGoroutines returns stacks of goroutines running package code (not
// tests) or websocket code.
func leakedGoroutines() []string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	var out []string
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "coder/websocket") {
			out = append(out, g)
			continue
		}
		for _, line := range strings.Split(g, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "/v2/realtime/") && strings.Contains(line, ".go:") && !strings.Contains(line, "_test.go") {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func assertNoLeaks(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var leaked []string
	for time.Now().Before(deadline) {
		leaked = leakedGoroutines()
		if len(leaked) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("leaked goroutines:\n%s", strings.Join(leaked, "\n\n"))
}
