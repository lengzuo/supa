package realtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// upstream: realtime-js src/RealtimeClient.ts constructor (apikey required, vsn validation)
func TestNewValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"missing key", Config{URL: "wss://x.supabase.co/realtime/v1"}, "API key is required"},
		{"bad scheme", Config{URL: "ftp://x/realtime/v1", APIKey: "k"}, "must use ws"},
		{"relative", Config{URL: "/realtime/v1", APIKey: "k"}, "must use ws"},
		{"bad vsn", Config{URL: "wss://x/realtime/v1", APIKey: "k", VSN: "3.0.0"}, "unsupported serializer version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// upstream: realtime-js test/RealtimeClient.config.test.ts endpointURL; RealtimeClient.errors.test.ts log_level
func TestEndpointURL(t *testing.T) {
	c, err := New(Config{URL: "https://ref.supabase.co/realtime/v1/", APIKey: "anon", LogLevel: "warn", Params: map[string]string{"x": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://ref.supabase.co/realtime/v1/websocket?apikey=anon&log_level=warn&vsn=2.0.0&x=1"
	if got := c.EndpointURL(); got != want {
		t.Fatalf("EndpointURL = %s, want %s", got, want)
	}
	c, _ = New(Config{URL: "ws://localhost:4000/realtime/v1", APIKey: "anon", VSN: VSN1})
	if got := c.EndpointURL(); got != "ws://localhost:4000/realtime/v1/websocket?apikey=anon&vsn=1.0.0" {
		t.Fatalf("EndpointURL = %s", got)
	}
}

// upstream: realtime-js test/transformers.test.ts httpEndpointURL
func TestHTTPEndpointURL(t *testing.T) {
	cases := map[string]string{
		"ws://example.com/socket/websocket":             "http://example.com/api/broadcast",
		"wss://example.com/socket/websocket":            "https://example.com/api/broadcast",
		"ws://example.com/socket":                       "http://example.com/api/broadcast",
		"ws://example.com/websocket":                    "http://example.com/api/broadcast",
		"ws://example.com/socket/websocket/":            "http://example.com/api/broadcast",
		"ws://example.com:8080/socket/websocket":        "http://example.com:8080/api/broadcast",
		"ws://example.com/prefix/socket/websocket":      "http://example.com/prefix/api/broadcast",
		"ws://example.com/socket/websocket?apikey=test": "http://example.com/api/broadcast?apikey=test",
		"ws://example.com":                              "http://example.com/api/broadcast",
		"ws://example.com/some/path":                    "http://example.com/some/path/api/broadcast",
		"wss://ref.supabase.co/realtime/v1/websocket":   "https://ref.supabase.co/realtime/v1/api/broadcast",
	}
	for in, want := range cases {
		u, err := httpEndpointURL(in)
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != want {
			t.Errorf("httpEndpointURL(%s) = %s, want %s", in, u, want)
		}
	}
}

// upstream: realtime-js src/RealtimeClient.ts connect/connectionState/disconnect
func TestConnectConnectionStateDisconnect(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.Headers = http.Header{"X-Custom": {"yes"}}
		cfg.LogLevel = "info"
	})
	if s := c.ConnectionState(); s != ConnectionClosed {
		t.Fatalf("initial state = %s", s)
	}
	if err := c.Connect(ctxT(t)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sc := fs.nextConn(t)
	if s := c.ConnectionState(); s != ConnectionOpen || !c.IsConnected() {
		t.Fatalf("state = %s", s)
	}
	if got := sc.query.Get("apikey"); got != "anon-key" {
		t.Errorf("apikey param = %q", got)
	}
	if got := sc.query.Get("vsn"); got != "2.0.0" {
		t.Errorf("vsn param = %q", got)
	}
	if got := sc.query.Get("log_level"); got != "info" {
		t.Errorf("log_level param = %q", got)
	}
	if sc.header.Get("X-Custom") != "yes" || !strings.HasPrefix(sc.header.Get("X-Client-Info"), "supa-go/") {
		t.Errorf("handshake headers = %v", sc.header)
	}
	// Connecting again is a no-op.
	if err := c.Connect(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if err := c.Disconnect(ctxT(t)); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if s := c.ConnectionState(); s != ConnectionClosed {
		t.Fatalf("state after disconnect = %s", s)
	}
	// No reconnect after an explicit disconnect.
	select {
	case <-fs.conns:
		t.Fatal("client reconnected after Disconnect")
	case <-time.After(150 * time.Millisecond):
	}
}

// upstream: realtime-js test/RealtimeClient.lifecycle.test.ts connection failure schedules reconnect
func TestConnectFailureThenReconnect(t *testing.T) {
	fs := newFakeServer(t)
	fs.rejectDial.Store(true)
	var tries []int
	var mu sync.Mutex
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.ReconnectBackoff = func(n int) time.Duration {
			mu.Lock()
			tries = append(tries, n)
			mu.Unlock()
			return 30 * time.Millisecond
		}
	})
	if err := c.Connect(ctxT(t)); err == nil || strings.Contains(err.Error(), "anon-key") {
		t.Fatalf("Connect against a rejecting server: %v", err)
	}
	fs.rejectDial.Store(false)
	fs.nextConn(t)
	eventually(t, "connected", c.IsConnected)
	mu.Lock()
	defer mu.Unlock()
	if len(tries) == 0 || tries[0] != 1 {
		t.Fatalf("reconnect backoff tries = %v", tries)
	}
}

// upstream: realtime-js test/RealtimeClient.channels.test.ts channel reuse & getChannels
func TestChannelReuseAndGetChannels(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	a, _ := c.Channel("room", ChannelOptions{})
	b, _ := c.Channel("room", ChannelOptions{Private: true})
	if a != b {
		t.Fatal("Channel did not reuse the existing topic")
	}
	if a.Topic() != "realtime:room" || a.State() != ChannelClosed {
		t.Fatalf("topic/state = %s/%s", a.Topic(), a.State())
	}
	o, _ := c.Channel("other", ChannelOptions{})
	got := c.GetChannels()
	if len(got) != 2 || got[0] != a || got[1] != o {
		t.Fatalf("GetChannels = %v", got)
	}
	if _, err := c.Channel("replay", ChannelOptions{Broadcast: BroadcastOptions{Replay: &ReplayOptions{}}}); err == nil {
		t.Fatal("replay on a public channel must fail")
	}
}

// upstream: realtime-js test/RealtimeChannel.lifecycle.test.ts join payload / subscribe states
func TestSubscribeJoinPayload(t *testing.T) {
	for _, vsn := range []string{VSN1, VSN2} {
		t.Run(vsn, func(t *testing.T) {
			fs := newFakeServer(t)
			c := newTestClient(t, fs, func(cfg *Config) { cfg.VSN = vsn })
			statuses := make(chan SubscribeStatus, 4)
			ch, sc, join := subscribeJoined(t, c, fs, "room1", ChannelOptions{
				Broadcast: BroadcastOptions{Self: true, Ack: true},
				Presence:  PresenceOptions{Key: "user-1"},
			}, func(ch *Channel) {
				ch.OnStatus(func(s SubscribeStatus, err error) { statuses <- s })
				_ = ch.OnPresenceSync(func() {})
			})
			if sc.vsn != vsn {
				t.Fatalf("vsn = %s", sc.vsn)
			}
			if join.ref() == "" || join.joinRef() != join.ref() {
				t.Fatalf("join refs = %q/%q", join.joinRef(), join.ref())
			}
			var p struct {
				Config json.RawMessage `json:"config"`
			}
			_ = json.Unmarshal(join.Payload, &p)
			want := `{"broadcast":{"ack":true,"self":true},"presence":{"key":"user-1","enabled":true},"postgres_changes":[],"private":false}`
			if string(p.Config) != want {
				t.Fatalf("config = %s\nwant    %s", p.Config, want)
			}
			if strings.Contains(string(join.Payload), "access_token") {
				t.Fatalf("unexpected access_token without auth: %s", join.Payload)
			}
			if s := recv(t, statuses, "status"); s != StatusSubscribed {
				t.Fatalf("status = %s", s)
			}
			if ch.State() != ChannelJoined {
				t.Fatalf("state = %s", ch.State())
			}
			// Subscribing again when joined is a no-op.
			if err := ch.Subscribe(ctxT(t)); err != nil {
				t.Fatal(err)
			}
			// Presence callbacks cannot be added after subscribe.
			if err := ch.OnPresenceJoin(func(PresenceJoinEvent) {}); err == nil {
				t.Fatal("OnPresenceJoin after subscribe must fail")
			}
		})
	}
}

// upstream: realtime-js test/RealtimeChannel.errors.test.ts join error reply
func TestSubscribeJoinErrorAndRejoin(t *testing.T) {
	fs := newFakeServer(t)
	var joins atomic.Int32
	fs.joinReply = func(sc *serverConn, m srvMsg) (string, any) {
		if joins.Add(1) == 1 {
			return "error", map[string]any{"reason": "Unauthorized: no access"}
		}
		return "ok", map[string]any{}
	}
	c := newTestClient(t, fs, nil)
	ch, _ := c.Channel("private-room", ChannelOptions{Private: true})
	statuses := make(chan SubscribeStatus, 4)
	ch.OnStatus(func(s SubscribeStatus, err error) { statuses <- s })
	err := ch.Subscribe(ctxT(t))
	var se *SubscribeError
	if !errors.As(err, &se) || se.Status != StatusChannelError || se.Message != "Unauthorized: no access" {
		t.Fatalf("Subscribe err = %#v", err)
	}
	if !strings.Contains(string(se.Response), "Unauthorized") {
		t.Fatalf("response = %s", se.Response)
	}
	if s := recv(t, statuses, "status"); s != StatusChannelError {
		t.Fatalf("first status = %s", s)
	}
	// The channel rejoins with backoff and succeeds.
	if s := recv(t, statuses, "status"); s != StatusSubscribed {
		t.Fatalf("second status = %s", s)
	}
	if ch.State() != ChannelJoined {
		t.Fatalf("state = %s", ch.State())
	}
}

// upstream: realtime-js test/RealtimeChannel.errors.test.ts join timeout sends phx_leave and rejoins
func TestSubscribeTimeout(t *testing.T) {
	fs := newFakeServer(t)
	fs.ignoreJoins.Store(true)
	c := newTestClient(t, fs, func(cfg *Config) { cfg.Timeout = 100 * time.Millisecond })
	ch, _ := c.Channel("slow", ChannelOptions{})
	err := ch.Subscribe(ctxT(t))
	if !errors.Is(err, ErrTimedOut) {
		t.Fatalf("err = %v, want ErrTimedOut", err)
	}
	sc := fs.nextConn(t)
	sc.expectEvent(t, "realtime:slow", "phx_join")
	sc.expectEvent(t, "realtime:slow", "phx_leave")
	fs.ignoreJoins.Store(false)
	sc.expectEvent(t, "realtime:slow", "phx_join") // rejoin
	eventually(t, "joined after rejoin", func() bool { return ch.State() == ChannelJoined })
}

// upstream: realtime-js src/RealtimeChannel.ts subscribe honours ctx (no upstream equivalent)
func TestSubscribeContextCanceled(t *testing.T) {
	fs := newFakeServer(t)
	fs.ignoreJoins.Store(true)
	c := newTestClient(t, fs, nil)
	ch, _ := c.Channel("x", ChannelOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := ch.Subscribe(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

// upstream: realtime-js test/RealtimeChannel.messaging.test.ts broadcast receive & filters
func TestBroadcastReceive(t *testing.T) {
	for _, vsn := range []string{VSN1, VSN2} {
		t.Run(vsn, func(t *testing.T) {
			fs := newFakeServer(t)
			c := newTestClient(t, fs, func(cfg *Config) { cfg.VSN = vsn })
			cursor := make(chan BroadcastMessage, 8)
			all := make(chan BroadcastMessage, 8)
			_, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
				_ = ch.OnBroadcast("Cursor-Pos", func(m BroadcastMessage) { cursor <- m })
				_ = ch.OnBroadcast("*", func(m BroadcastMessage) { all <- m })
			})
			sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "cursor-pos", "payload": map[string]any{"x": 1}})
			m := recv(t, cursor, "cursor broadcast")
			var pos struct{ X int }
			if err := m.Decode(&pos); err != nil || pos.X != 1 || m.Event != "cursor-pos" || m.Type != "broadcast" {
				t.Fatalf("message = %+v (%v)", m, err)
			}
			recv(t, all, "wildcard broadcast")

			sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "other", "payload": map[string]any{}})
			if m := recv(t, all, "other broadcast"); m.Event != "other" {
				t.Fatalf("event = %s", m.Event)
			}
			select {
			case m := <-cursor:
				t.Fatalf("cursor callback received %s", m.Event)
			case <-time.After(50 * time.Millisecond):
			}
			// Messages for other topics are not delivered.
			sc.push("realtime:elsewhere", "broadcast", map[string]any{"type": "broadcast", "event": "cursor-pos"})
			select {
			case <-all:
				t.Fatal("received broadcast for another topic")
			case <-time.After(50 * time.Millisecond):
			}
		})
	}
}

// upstream: realtime-js test/serializer.test.ts decode userBroadcast (kind 4) JSON and binary
func TestBroadcastReceiveBinaryFrames(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	got := make(chan BroadcastMessage, 4)
	_, sc, _ := subscribeJoined(t, c, fs, "bin", ChannelOptions{}, func(ch *Channel) {
		_ = ch.OnBroadcast("*", func(m BroadcastMessage) { got <- m })
	})
	sc.sendUserBroadcast("realtime:bin", "json-ev", `{"replayed":true,"id":"abc"}`, binEncodingJSON, []byte(`{"a":"é"}`))
	m := recv(t, got, "json user broadcast")
	if m.Event != "json-ev" || string(m.Payload) != `{"a":"é"}` || m.Meta == nil || !m.Meta.Replayed || m.Meta.ID != "abc" {
		t.Fatalf("message = %+v", m)
	}
	sc.sendUserBroadcast("realtime:bin", "raw-ev", "", binEncodingBinary, []byte{0, 1, 2, 255})
	m = recv(t, got, "binary user broadcast")
	if m.Event != "raw-ev" || !bytes.Equal(m.Binary, []byte{0, 1, 2, 255}) || m.Payload != nil || m.Meta != nil {
		t.Fatalf("message = %+v", m)
	}
}

// upstream: realtime-js test/RealtimeChannel.messaging.test.ts send via websocket (no ack resolves ok)
func TestBroadcastSendNoAck(t *testing.T) {
	for _, vsn := range []string{VSN1, VSN2} {
		t.Run(vsn, func(t *testing.T) {
			fs := newFakeServer(t)
			c := newTestClient(t, fs, func(cfg *Config) { cfg.VSN = vsn })
			ch, sc, join := subscribeJoined(t, c, fs, "room", ChannelOptions{}, nil)
			if err := ch.Send(ctxT(t), SendParams{Event: "cursor", Payload: map[string]int{"x": 2}}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			m := sc.expectEvent(t, "realtime:room", "broadcast")
			if m.joinRef() != join.ref() || m.ref() == "" {
				t.Fatalf("refs = %q/%q", m.joinRef(), m.ref())
			}
			if vsn == VSN2 {
				if !m.Binary || m.UserEvent != "cursor" || m.Encoding != binEncodingJSON || string(m.RawPayload) != `{"x":2}` {
					t.Fatalf("binary push = %+v", m)
				}
			} else {
				if m.Binary || string(m.Payload) != `{"type":"broadcast","event":"cursor","payload":{"x":2}}` {
					t.Fatalf("json push = %s", m.Payload)
				}
			}
			// Raw binary payloads use the binary encoding.
			if vsn == VSN2 {
				if err := ch.Send(ctxT(t), SendParams{Event: "blob", Payload: []byte{9, 8, 7}}); err != nil {
					t.Fatal(err)
				}
				m := sc.expectEvent(t, "realtime:room", "broadcast")
				if m.Encoding != binEncodingBinary || !bytes.Equal(m.RawPayload, []byte{9, 8, 7}) {
					t.Fatalf("binary payload push = %+v", m)
				}
			}
		})
	}
}

// upstream: realtime-js test/RealtimeChannel.messaging.test.ts send with ack (ok / error / timed out)
func TestBroadcastAck(t *testing.T) {
	fs := newFakeServer(t)
	var mode atomic.Value
	mode.Store("ok")
	fs.onMessage = func(sc *serverConn, m srvMsg) bool {
		if m.Event != "broadcast" {
			return false
		}
		switch mode.Load().(string) {
		case "ok":
			sc.reply(m, "ok", map[string]any{})
		case "error":
			sc.reply(m, "error", map[string]any{"reason": "rate limited"})
		}
		return true
	}
	c := newTestClient(t, fs, func(cfg *Config) { cfg.Timeout = 200 * time.Millisecond })
	ch, _, join := subscribeJoined(t, c, fs, "acked", ChannelOptions{Broadcast: BroadcastOptions{Ack: true}}, nil)
	if !strings.Contains(string(join.Payload), `"ack":true`) {
		t.Fatalf("join payload = %s", join.Payload)
	}
	if err := ch.Send(ctxT(t), SendParams{Event: "e", Payload: 1}); err != nil {
		t.Fatalf("acked send: %v", err)
	}
	mode.Store("error")
	var pe *PushError
	if err := ch.Send(ctxT(t), SendParams{Event: "e", Payload: 1}); !errors.As(err, &pe) || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("err = %v", err)
	}
	mode.Store("none")
	if err := ch.Send(ctxT(t), SendParams{Event: "e", Payload: 1}); !errors.Is(err, ErrTimedOut) {
		t.Fatalf("err = %v, want ErrTimedOut", err)
	}
}

// upstream: realtime-js RealtimeChannelOptions broadcast.self — server echoes own messages
func TestBroadcastSelf(t *testing.T) {
	for _, vsn := range []string{VSN1, VSN2} {
		t.Run(vsn, func(t *testing.T) {
			fs := newFakeServer(t)
			c := newTestClient(t, fs, func(cfg *Config) { cfg.VSN = vsn })
			got := make(chan BroadcastMessage, 1)
			ch, _, join := subscribeJoined(t, c, fs, "echo", ChannelOptions{Broadcast: BroadcastOptions{Self: true}}, func(ch *Channel) {
				_ = ch.OnBroadcast("ping", func(m BroadcastMessage) { got <- m })
			})
			if !strings.Contains(string(join.Payload), `"self":true`) {
				t.Fatalf("join payload = %s", join.Payload)
			}
			if err := ch.Send(ctxT(t), SendParams{Event: "ping", Payload: map[string]string{"msg": "hi"}}); err != nil {
				t.Fatal(err)
			}
			m := recv(t, got, "self broadcast")
			if string(m.Payload) != `{"msg":"hi"}` {
				t.Fatalf("payload = %s", m.Payload)
			}
		})
	}
}

// upstream: realtime-js RealtimeChannelOptions broadcast.replay (private channels only)
func TestBroadcastReplayConfig(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	since := time.UnixMilli(1700000000123)
	got := make(chan BroadcastMessage, 1)
	_, sc, join := subscribeJoined(t, c, fs, "replay", ChannelOptions{
		Private:   true,
		Broadcast: BroadcastOptions{Replay: &ReplayOptions{Since: since, Limit: 25}, ReplicationReady: true},
	}, func(ch *Channel) { _ = ch.OnBroadcast("*", func(m BroadcastMessage) { got <- m }) })
	var p struct {
		Config struct {
			Broadcast json.RawMessage `json:"broadcast"`
			Private   bool            `json:"private"`
		} `json:"config"`
	}
	_ = json.Unmarshal(join.Payload, &p)
	if string(p.Config.Broadcast) != `{"ack":false,"self":false,"replay":{"since":1700000000123,"limit":25},"replication_ready":true}` || !p.Config.Private {
		t.Fatalf("config = %s private=%v", p.Config.Broadcast, p.Config.Private)
	}
	sc.push("realtime:replay", "broadcast", map[string]any{"type": "broadcast", "event": "old", "payload": map[string]any{}, "meta": map[string]any{"replayed": true, "id": "m1"}})
	m := recv(t, got, "replayed broadcast")
	if m.Meta == nil || !m.Meta.Replayed || m.Meta.ID != "m1" {
		t.Fatalf("meta = %+v", m.Meta)
	}
}

// upstream: realtime-js test/RealtimeChannel.messaging.test.ts 'sends message via HTTP when not subscribed'
func TestSendFallsBackToHTTP(t *testing.T) {
	fs := newFakeServer(t)
	type captured struct {
		method, path, query, apikey, auth, ctype string
		body                                     []byte
	}
	reqs := make(chan captured, 2)
	status := atomic.Int32{}
	status.Store(200)
	fs.httpHandler = func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		reqs <- captured{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("apikey"), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b.Bytes()}
		w.WriteHeader(int(status.Load()))
	}
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "access_token_123", nil }
	})
	if err := c.SetAuth(ctxT(t), ""); err != nil {
		t.Fatal(err)
	}
	ch, _ := c.Channel("topic", ChannelOptions{Private: true})
	if err := ch.Send(ctxT(t), SendParams{Event: "test"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	r := recv(t, reqs, "fallback request")
	if r.method != http.MethodPost || r.path != "/realtime/v1/api/broadcast" || r.query != "apikey=anon-key&vsn=2.0.0" {
		t.Fatalf("request = %s %s?%s", r.method, r.path, r.query)
	}
	if r.apikey != "anon-key" || r.auth != "Bearer access_token_123" || r.ctype != "application/json" {
		t.Fatalf("headers = %+v", r)
	}
	if string(r.body) != `{"messages":[{"topic":"topic","event":"test","private":true}]}` {
		t.Fatalf("body = %s", r.body)
	}
	status.Store(500)
	var he *HTTPError
	if err := ch.Send(ctxT(t), SendParams{Event: "test", Payload: map[string]int{"a": 1}}); !errors.As(err, &he) || he.StatusCode != 500 {
		t.Fatalf("err = %v", err)
	}
	if r := recv(t, reqs, "fallback request"); string(r.body) != `{"messages":[{"topic":"topic","event":"test","payload":{"a":1},"private":true}]}` {
		t.Fatalf("body = %s", r.body)
	}
}

// upstream: realtime-js test/RealtimeChannel.messaging.test.ts httpSend
func TestHTTPSend(t *testing.T) {
	fs := newFakeServer(t)
	type captured struct {
		path, rawPath, query, auth, ctype string
		body                              []byte
	}
	reqs := make(chan captured, 8)
	var respond atomic.Value
	respond.Store(func(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) })
	fs.httpHandler = func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		_, _ = b.ReadFrom(r.Body)
		reqs <- captured{r.URL.Path, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b.Bytes()}
		respond.Load().(func(http.ResponseWriter))(w)
	}
	c := newTestClient(t, fs, nil)

	pub, _ := c.Channel("room:42", ChannelOptions{})
	if err := pub.HTTPSend(ctxT(t), "user/joined", map[string]int{"id": 1}); err != nil {
		t.Fatalf("HTTPSend: %v", err)
	}
	r := recv(t, reqs, "request")
	if r.rawPath != "/realtime/v1/api/broadcast/room%3A42/events/user%2Fjoined" || r.query != "apikey=anon-key&vsn=2.0.0" {
		t.Fatalf("url = %s?%s", r.rawPath, r.query)
	}
	if r.auth != "" || r.ctype != "application/json" || string(r.body) != `{"id":1}` {
		t.Fatalf("request = %+v", r)
	}

	if err := c.SetAuth(ctxT(t), "token123"); err != nil {
		t.Fatal(err)
	}
	priv, _ := c.Channel("topic", ChannelOptions{Private: true})
	if err := priv.HTTPSend(ctxT(t), "bin", []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	r = recv(t, reqs, "request")
	if r.path != "/realtime/v1/api/broadcast/topic/events/bin" || r.query != "apikey=anon-key&private=true&vsn=2.0.0" ||
		r.auth != "Bearer token123" || r.ctype != "application/octet-stream" || !bytes.Equal(r.body, []byte{1, 2, 3, 4}) {
		t.Fatalf("request = %+v", r)
	}

	if err := priv.HTTPSend(ctxT(t), "x", nil); err == nil {
		t.Fatal("nil payload must fail")
	}

	cases := []struct {
		status int
		body   string
		want   string
	}{
		{404, "", "requires Realtime server v2.97.0 or newer"},
		{500, `{"error":"Server error"}`, "Server error"},
		{400, `{"message":"Invalid request"}`, "Invalid request"},
		{503, `not json`, "Service Unavailable"},
		{200, ``, "OK"},
	}
	for _, tc := range cases {
		respond.Store(func(w http.ResponseWriter) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		})
		err := priv.HTTPSend(ctxT(t), "x", map[string]any{})
		<-reqs
		var he *HTTPError
		if !errors.As(err, &he) || he.StatusCode != tc.status || !strings.Contains(he.Message, tc.want) {
			t.Errorf("status %d: err = %v", tc.status, err)
		}
	}

	// Timeout.
	respond.Store(func(w http.ResponseWriter) { time.Sleep(300 * time.Millisecond); w.WriteHeader(202) })
	c2 := newTestClient(t, fs, func(cfg *Config) { cfg.Timeout = 50 * time.Millisecond })
	ch2, _ := c2.Channel("t", ChannelOptions{})
	if err := ch2.HTTPSend(ctxT(t), "x", 1); !errors.Is(err, ErrTimedOut) {
		t.Fatalf("err = %v, want ErrTimedOut", err)
	}
}

// upstream: realtime-js test/RealtimeClient.test.ts heartbeat + onHeartbeat
func TestHeartbeat(t *testing.T) {
	fs := newFakeServer(t)
	statuses := make(chan HeartbeatStatus, 16)
	c := newTestClient(t, fs, func(cfg *Config) { cfg.HeartbeatInterval = 40 * time.Millisecond })
	c.OnHeartbeat(func(s HeartbeatStatus, latency time.Duration) { statuses <- s })
	if err := c.Connect(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	sc := fs.nextConn(t)
	hb := sc.expectEvent(t, "phoenix", "heartbeat")
	if hb.ref() == "" || hb.JoinRef != nil || string(hb.Payload) != "{}" {
		t.Fatalf("heartbeat = %+v", hb)
	}
	if s := recv(t, statuses, "sent"); s != HeartbeatSent {
		t.Fatalf("status = %s", s)
	}
	if s := recv(t, statuses, "ok"); s != HeartbeatOK {
		t.Fatalf("status = %s", s)
	}
	// SendHeartbeat sends immediately.
	c.SendHeartbeat()
	sc.expectEvent(t, "phoenix", "heartbeat")
}

// upstream: realtime-js test/RealtimeClient.resilience.test.ts heartbeat timeout -> reconnect & rejoin
func TestHeartbeatTimeoutReconnects(t *testing.T) {
	fs := newFakeServer(t)
	statuses := make(chan HeartbeatStatus, 64)
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.HeartbeatInterval = 50 * time.Millisecond
		cfg.HeartbeatCallback = func(s HeartbeatStatus, _ time.Duration) { statuses <- s }
	})
	subStatus := make(chan SubscribeStatus, 16)
	fs.ignoreHeartbeats.Store(true)
	_, sc1, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		ch.OnStatus(func(s SubscribeStatus, _ error) { subStatus <- s })
	})
	if s := recv(t, subStatus, "subscribed"); s != StatusSubscribed {
		t.Fatalf("status = %s", s)
	}
	for s := range statuses {
		if s == HeartbeatTimeout {
			break
		}
	}
	if s := recv(t, subStatus, "channel error"); s != StatusChannelError {
		t.Fatalf("status = %s", s)
	}
	fs.ignoreHeartbeats.Store(false)
	sc2 := fs.nextConn(t)
	if sc2 == sc1 {
		t.Fatal("expected a new connection")
	}
	sc2.expectEvent(t, "realtime:room", "phx_join")
	if s := recv(t, subStatus, "resubscribed"); s != StatusSubscribed {
		t.Fatalf("status = %s", s)
	}
}

// upstream: realtime-js test/RealtimeClient.resilience.test.ts server close -> reconnect with backoff
func TestServerCloseReconnectsAndRejoins(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	ch, sc1, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, nil)
	_ = sc1.c.Close(4000, "bye")
	sc2 := fs.nextConn(t)
	sc2.expectEvent(t, "realtime:room", "phx_join")
	eventually(t, "rejoined", func() bool { return ch.State() == ChannelJoined })
}

// upstream: realtime-js socket sendBuffer — pushes while disconnected are flushed on open
func TestMessagesBufferedWhileConnecting(t *testing.T) {
	fs := newFakeServer(t)
	fs.joinReply = func(sc *serverConn, m srvMsg) (string, any) {
		go func() {
			time.Sleep(100 * time.Millisecond)
			sc.reply(m, "ok", map[string]any{})
		}()
		return "", nil
	}
	c := newTestClient(t, fs, nil)
	ch, _ := c.Channel("buf", ChannelOptions{})
	errc := make(chan error, 2)
	go func() { errc <- ch.Subscribe(ctxT(t)) }()
	// Track is buffered on the channel until joined.
	eventually(t, "joining", func() bool { return ch.State() == ChannelJoining })
	go func() { errc <- ch.Track(ctxT(t), map[string]string{"user": "a"}) }()
	sc := fs.nextConn(t)
	sc.expectEvent(t, "realtime:buf", "phx_join")
	tr := sc.expectEvent(t, "realtime:buf", "presence")
	if string(tr.Payload) != `{"type":"presence","event":"track","payload":{"user":"a"}}` {
		t.Fatalf("track payload = %s", tr.Payload)
	}
	for i := 0; i < 2; i++ {
		if err := recv(t, errc, "result"); err != nil {
			t.Fatal(err)
		}
	}
}

// upstream: realtime-js test/RealtimeChannel.lifecycle.test.ts unsubscribe; RealtimeClient deferred disconnect
func TestUnsubscribeAndDeferredDisconnect(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, func(cfg *Config) { cfg.DisconnectOnEmptyChannelsAfter = 50 * time.Millisecond })
	statuses := make(chan SubscribeStatus, 4)
	ch, sc, join := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		ch.OnStatus(func(s SubscribeStatus, _ error) { statuses <- s })
	})
	recv(t, statuses, "subscribed")
	if err := ch.Unsubscribe(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	leave := sc.expectEvent(t, "realtime:room", "phx_leave")
	if leave.joinRef() != join.ref() {
		t.Fatalf("leave join_ref = %s", leave.joinRef())
	}
	if s := recv(t, statuses, "closed"); s != StatusClosed {
		t.Fatalf("status = %s", s)
	}
	if ch.State() != ChannelClosed || len(c.GetChannels()) != 0 {
		t.Fatalf("state = %s channels = %d", ch.State(), len(c.GetChannels()))
	}
	eventually(t, "deferred disconnect", func() bool { return c.ConnectionState() == ConnectionClosed })
	if err := ch.Subscribe(ctxT(t)); !errors.Is(err, ErrAlreadySubscribed) {
		t.Fatalf("resubscribe err = %v", err)
	}
}

// upstream: realtime-js deferred disconnect is cancelled by new channel activity
func TestDeferredDisconnectCancelledByNewChannel(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, func(cfg *Config) { cfg.DisconnectOnEmptyChannelsAfter = 100 * time.Millisecond })
	ch, _, _ := subscribeJoined(t, c, fs, "a", ChannelOptions{}, nil)
	if err := c.RemoveChannel(ctxT(t), ch); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Channel("b", ChannelOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if !c.IsConnected() {
		t.Fatal("deferred disconnect was not cancelled")
	}
}

// upstream: realtime-js test/RealtimeClient.channels.test.ts removeChannel / removeAllChannels
func TestRemoveChannelAndRemoveAll(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	a, sc, _ := subscribeJoined(t, c, fs, "a", ChannelOptions{}, nil)
	b, _ := c.Channel("b", ChannelOptions{})
	if err := b.Subscribe(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	cc, _ := c.Channel("c", ChannelOptions{})
	if err := cc.Subscribe(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveChannel(ctxT(t), a); err != nil {
		t.Fatal(err)
	}
	sc.expectEvent(t, "realtime:a", "phx_leave")
	if got := c.GetChannels(); len(got) != 2 {
		t.Fatalf("channels = %d", len(got))
	}
	if err := c.RemoveAllChannels(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	sc.expectEvent(t, "realtime:b", "phx_leave")
	sc.expectEvent(t, "realtime:c", "phx_leave")
	if len(c.GetChannels()) != 0 || c.ConnectionState() != ConnectionClosed {
		t.Fatalf("channels=%d state=%s", len(c.GetChannels()), c.ConnectionState())
	}
	if err := b.Subscribe(ctxT(t)); err == nil {
		t.Fatal("subscribe after removal must fail")
	}
}

// upstream: realtime-js test/RealtimeClient.auth.test.ts setAuth pushes access_token and updates join payloads
func TestSetAuthPropagation(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	joined, sc, _ := subscribeJoined(t, c, fs, "one", ChannelOptions{}, nil)
	idle, _ := c.Channel("two", ChannelOptions{})

	if err := c.SetAuth(ctxT(t), "jwt-1"); err != nil {
		t.Fatal(err)
	}
	m := sc.expectEvent(t, "realtime:one", "access_token")
	if string(m.Payload) != `{"access_token":"jwt-1"}` {
		t.Fatalf("access_token payload = %s", m.Payload)
	}
	// Same token: no push.
	if err := c.SetAuth(ctxT(t), "jwt-1"); err != nil {
		t.Fatal(err)
	}
	sc.noMessage(t, 50*time.Millisecond, func(m srvMsg) bool { return m.Event == "access_token" })

	// The idle channel joins with the token and version.
	if err := idle.Subscribe(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	j := sc.expectEvent(t, "realtime:two", "phx_join")
	p := j.payloadMap(t)
	if p["access_token"] != "jwt-1" || p["version"] != DefaultVersion {
		t.Fatalf("join payload = %s", j.Payload)
	}
	_ = joined
}

// upstream: realtime-js test/RealtimeClient.auth.test.ts accessToken callback used on connect/join and heartbeat
func TestAccessTokenCallback(t *testing.T) {
	fs := newFakeServer(t)
	var calls atomic.Int32
	var token atomic.Value
	token.Store("cb-token-1")
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.HeartbeatInterval = 40 * time.Millisecond
		cfg.AccessToken = func(ctx context.Context) (string, error) {
			calls.Add(1)
			return token.Load().(string), nil
		}
	})
	_, sc, join := subscribeJoined(t, c, fs, "room", ChannelOptions{Private: true}, nil)
	if p := join.payloadMap(t); p["access_token"] != "cb-token-1" {
		t.Fatalf("join payload = %s", join.Payload)
	}
	// Heartbeats refresh the token from the callback and push changes.
	token.Store("cb-token-2")
	m := sc.expectEvent(t, "realtime:room", "access_token")
	if string(m.Payload) != `{"access_token":"cb-token-2"}` {
		t.Fatalf("payload = %s", m.Payload)
	}
	if calls.Load() < 2 {
		t.Fatalf("callback calls = %d", calls.Load())
	}
	// Callback errors are returned and keep the current token.
	c2 := newTestClient(t, fs, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "", errors.New("boom") }
	})
	if err := c2.SetAuth(ctxT(t), ""); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

// upstream: realtime-js test/RealtimeClient.auth.test.ts 'clears joined channels auth payload when the callback returns null'
func TestSetAuthCallbackReturnsEmptyClearsToken(t *testing.T) {
	fs := newFakeServer(t)
	var token atomic.Value
	token.Store("t1")
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return token.Load().(string), nil }
	})
	_, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, nil)
	token.Store("")
	if err := c.SetAuth(ctxT(t), ""); err != nil {
		t.Fatal(err)
	}
	m := sc.expectEvent(t, "realtime:room", "access_token")
	if string(m.Payload) != `{"access_token":null}` {
		t.Fatalf("payload = %s", m.Payload)
	}
}

// upstream: realtime-js test/RealtimeClient.auth.test.ts 'ignores stale access token callback results'
func TestSetAuthStaleResultIgnored(t *testing.T) {
	fs := newFakeServer(t)
	release := make(chan string, 2)
	var n atomic.Int32
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.AccessToken = func(ctx context.Context) (string, error) {
			if n.Add(1) == 1 {
				return <-release, nil // slow, stale
			}
			return "", nil
		}
	})
	if err := c.SetAuth(ctxT(t), "manual"); err != nil {
		t.Fatal(err)
	}
	stale := make(chan error, 1)
	go func() { stale <- c.SetAuth(ctxT(t), "") }()
	eventually(t, "first callback running", func() bool { return n.Load() == 1 })
	if err := c.SetAuth(ctxT(t), ""); err != nil { // newer: signs out
		t.Fatal(err)
	}
	release <- "stale-token"
	if err := recv(t, stale, "stale setAuth"); err != nil {
		t.Fatal(err)
	}
	if got := c.tokenSnapshot(); got != "" {
		t.Fatalf("token = %q, want cleared", got)
	}
}

// upstream: realtime-js custom `transport` option
func TestCustomTransport(t *testing.T) {
	fs := newFakeServer(t)
	var dials atomic.Int32
	var gotURL atomic.Value
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.Transport = WebSocketTransportFunc(func(ctx context.Context, url string, h http.Header) (WebSocketConn, error) {
			dials.Add(1)
			gotURL.Store(url)
			return (&DefaultTransport{}).Dial(ctx, url, h)
		})
	})
	subscribeJoined(t, c, fs, "room", ChannelOptions{}, nil)
	if dials.Load() != 1 || !strings.HasSuffix(gotURL.Load().(string), "/realtime/v1/websocket?apikey=anon-key&vsn=2.0.0") {
		t.Fatalf("dials=%d url=%v", dials.Load(), gotURL.Load())
	}
}

type captureHandler struct {
	mu   sync.Mutex
	recs []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" " + a.Key + "=" + a.Value.String())
		return true
	})
	h.mu.Lock()
	h.recs = append(h.recs, b.String())
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// upstream: realtime-js `logger` option (custom logger) — secrets are never logged
func TestCustomLogger(t *testing.T) {
	fs := newFakeServer(t)
	h := &captureHandler{}
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.APIKey = "secret-api-key"
		cfg.Logger = slog.New(h)
	})
	ch, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, nil)
	if err := c.SetAuth(ctxT(t), "secret-jwt"); err != nil {
		t.Fatal(err)
	}
	sc.expectEvent(t, "realtime:room", "access_token")
	_ = ch.Send(ctxT(t), SendParams{Event: "e", Payload: map[string]string{"pw": "secret-payload"}})
	sc.expectEvent(t, "realtime:room", "broadcast")
	eventually(t, "logs", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return len(h.recs) > 3
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	all := strings.Join(h.recs, "\n")
	for _, secret := range []string{"secret-api-key", "secret-jwt", "secret-payload"} {
		if strings.Contains(all, secret) {
			t.Fatalf("log contains %q:\n%s", secret, all)
		}
	}
	if !strings.Contains(all, "realtime:room phx_join") || !strings.Contains(all, "kind=push") {
		t.Fatalf("expected push logs, got:\n%s", all)
	}
}

// upstream: realtime-js socket.isMember drops messages with an outdated join_ref
func TestOutdatedJoinRefDropped(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	got := make(chan BroadcastMessage, 2)
	_, sc, join := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		_ = ch.OnBroadcast("*", func(m BroadcastMessage) { got <- m })
	})
	sc.send("stale", nil, "realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "old"})
	sc.send(join.ref(), nil, "realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "new"})
	if m := recv(t, got, "broadcast"); m.Event != "new" {
		t.Fatalf("event = %s", m.Event)
	}
}

// upstream: realtime-js server phx_close / phx_error handling on a channel
func TestServerChannelCloseAndError(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	statuses := make(chan SubscribeStatus, 8)
	ch, sc, join := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		ch.OnStatus(func(s SubscribeStatus, _ error) { statuses <- s })
	})
	recv(t, statuses, "subscribed")
	// phx_error: errored then rejoined.
	sc.send(join.ref(), join.ref(), "realtime:room", "phx_error", map[string]any{})
	if s := recv(t, statuses, "error"); s != StatusChannelError {
		t.Fatalf("status = %s", s)
	}
	j2 := sc.expectEvent(t, "realtime:room", "phx_join")
	if s := recv(t, statuses, "resubscribed"); s != StatusSubscribed {
		t.Fatalf("status = %s", s)
	}
	// phx_close for an old join ref is ignored.
	sc.send(join.ref(), join.ref(), "realtime:room", "phx_close", map[string]any{})
	// phx_close for the current join closes the channel.
	sc.send(j2.ref(), j2.ref(), "realtime:room", "phx_close", map[string]any{})
	if s := recv(t, statuses, "closed"); s != StatusClosed {
		t.Fatalf("status = %s", s)
	}
	if ch.State() != ChannelClosed {
		t.Fatalf("state = %s", ch.State())
	}
}

// upstream: realtime-js system events (broadcast.replication_ready)
func TestSystemEvents(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	got := make(chan SystemMessage, 1)
	_, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{Broadcast: BroadcastOptions{ReplicationReady: true}}, func(ch *Channel) {
		_ = ch.OnSystem(func(m SystemMessage) { got <- m })
	})
	sc.push("realtime:room", "system", map[string]any{"extension": "system", "status": "ok", "message": "Replication connection established", "channel": "room"})
	m := recv(t, got, "system")
	if m.Extension != "system" || m.Status != "ok" || m.Channel != "room" || !strings.Contains(m.Message, "Replication") {
		t.Fatalf("system = %+v", m)
	}
}

// Callbacks run outside internal locks: a callback may call blocking client
// methods without deadlocking the reader.
func TestCallbackMayCallClient(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	done := make(chan error, 1)
	var ch *Channel
	ch, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{Broadcast: BroadcastOptions{Ack: true}}, func(x *Channel) {
		_ = x.OnBroadcast("go", func(BroadcastMessage) {
			// Acked send waits for a reply read by the connection reader.
			done <- ch.Send(context.Background(), SendParams{Event: "reply"})
		})
	})
	sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "go"})
	if err := recv(t, done, "send from callback"); err != nil {
		t.Fatal(err)
	}
	// A panicking callback does not kill the dispatcher.
	_ = ch.OnBroadcast("panic", func(BroadcastMessage) { panic("boom") })
	sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "panic"})
	sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "go"})
	if err := recv(t, done, "send after panic"); err != nil {
		t.Fatal(err)
	}
}

// Concurrent use from many goroutines is race-free (run with -race).
func TestConcurrentUse(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	ch, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		_ = ch.OnBroadcast("*", func(BroadcastMessage) {})
	})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = ch.Send(context.Background(), SendParams{Event: "e", Payload: j})
				_ = c.ConnectionState()
				_ = ch.PresenceState()
				_ = c.GetChannels()
				if j%5 == 0 {
					_ = c.SetAuth(context.Background(), "tok")
				}
			}
		}(i)
	}
	for i := 0; i < 20; i++ {
		sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "x"})
	}
	wg.Wait()
}

// Disconnect leaves no goroutines behind.
func TestDisconnectNoGoroutineLeak(t *testing.T) {
	assertNoLeaks(t)
	fs := newFakeServer(t)
	cfg := testConfig(fs)
	cfg.HeartbeatInterval = 30 * time.Millisecond
	cfg.AccessToken = func(context.Context) (string, error) { return "tok", nil }
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{}, 1)
	ch, _ := c.Channel("room", ChannelOptions{})
	_ = ch.OnBroadcast("*", func(BroadcastMessage) {
		select {
		case got <- struct{}{}:
		default:
		}
	})
	_ = ch.OnPresenceSync(func() {})
	if err := ch.Subscribe(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	sc := fs.nextConn(t)
	sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "x"})
	recv(t, got, "broadcast")
	_ = ch.Track(ctxT(t), map[string]int{"a": 1})
	time.Sleep(100 * time.Millisecond) // a few heartbeats
	if err := c.Disconnect(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	fs.close()
	assertNoLeaks(t)
}

// Dial errors embed the URL; the apikey parameter must not leak.
func TestDialErrorRedactsAPIKey(t *testing.T) {
	c, err := New(Config{URL: "ws://127.0.0.1:1/realtime/v1", APIKey: "super-secret-key", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Connect(ctxT(t))
	_ = c.Disconnect(ctxT(t))
	if err == nil || strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("err = %v", err)
	}
	base := errors.New(`Get "http://x/realtime/v1/websocket?apikey=abc&vsn=2.0.0": refused`)
	red := redactError(base)
	if red.Error() != `Get "http://x/realtime/v1/websocket?apikey=REDACTED&vsn=2.0.0": refused` || !errors.Is(red, base) {
		t.Fatalf("redacted = %v", red)
	}
}
