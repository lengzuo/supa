package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Removing the last channel with an immediate auto-disconnect and then
// subscribing a new channel right away must not be torn down by the stale
// disconnect.
// upstream: realtime-js src/RealtimeClient.ts _remove / disconnect-on-empty-channels
func TestAutoDisconnectThenImmediateSubscribe(t *testing.T) {
	for _, remove := range []string{"unsubscribe", "remove_channel"} {
		t.Run(remove, func(t *testing.T) {
			fs := newFakeServer(t)
			c := newTestClient(t, fs, func(cfg *Config) { cfg.DisconnectOnEmptyChannelsAfter = -1 })
			a, _, _ := subscribeJoined(t, c, fs, "a", ChannelOptions{}, nil)
			for i := 0; i < 5; i++ {
				var err error
				if remove == "unsubscribe" {
					err = a.Unsubscribe(ctxT(t))
				} else {
					err = c.RemoveChannel(ctxT(t), a)
				}
				if err != nil {
					t.Fatalf("remove: %v", err)
				}
				b, err := c.Channel(fmt.Sprintf("b%d", i), ChannelOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if err := b.Subscribe(ctxT(t)); err != nil {
					t.Fatalf("iteration %d: Subscribe after auto-disconnect: %v", i, err)
				}
				time.Sleep(20 * time.Millisecond)
				if b.State() != ChannelJoined || !c.IsConnected() {
					t.Fatalf("iteration %d: state = %s connected = %v", i, b.State(), c.IsConnected())
				}
				a = b
			}
		})
	}
}

// Dial errors wrapping a *url.Error must not expose the API key through
// errors.As, errors.Unwrap or %+v.
func TestDialErrorRedactsWrappedURLError(t *testing.T) {
	const secret = "super-secret-key"
	check := func(t *testing.T, err error) {
		t.Helper()
		for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
			if strings.Contains(s, secret) {
				t.Fatalf("formatted error leaks the key: %s", s)
			}
		}
		var ue *url.Error
		if !errors.As(err, &ue) {
			t.Fatalf("errors.As(*url.Error) failed for %v", err)
		}
		if strings.Contains(ue.URL, secret) || strings.Contains(ue.Error(), secret) || strings.Contains(fmt.Sprintf("%+v", ue), secret) {
			t.Fatalf("url.Error leaks the key: %+v", ue)
		}
		// Walk the whole tree.
		var walk func(e error, depth int)
		walk = func(e error, depth int) {
			if e == nil || depth > 20 {
				return
			}
			if strings.Contains(e.Error(), secret) {
				t.Fatalf("wrapped error leaks the key: %T %v", e, e)
			}
			switch x := e.(type) {
			case interface{ Unwrap() error }:
				walk(x.Unwrap(), depth+1)
			case interface{ Unwrap() []error }:
				for _, u := range x.Unwrap() {
					walk(u, depth+1)
				}
			}
		}
		walk(err, 0)
	}

	t.Run("synthetic", func(t *testing.T) {
		cause := errors.New("connection refused")
		ue := &url.Error{Op: "Get", URL: "http://x/realtime/v1/websocket?apikey=" + secret + "&vsn=2.0.0", Err: cause}
		inner := fmt.Errorf("failed to WebSocket dial: %w", ue)
		top := fmt.Errorf("realtime: websocket dial: %w", inner)
		red := redactError(top)
		check(t, red)
		if !errors.Is(red, cause) || !errors.Is(red, top) || !errors.Is(red, inner) {
			t.Fatal("errors.Is lost the original errors")
		}
		if !strings.Contains(red.Error(), "apikey=REDACTED") {
			t.Fatalf("Error() = %s", red)
		}
	})

	t.Run("dial", func(t *testing.T) {
		c, err := New(Config{URL: "ws://127.0.0.1:1/realtime/v1", APIKey: secret, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Connect(ctxT(t))
		_ = c.Disconnect(ctxT(t))
		if err == nil {
			t.Fatal("expected a dial error")
		}
		check(t, err)
	})
}

// Disconnect cancels and waits for in-flight AccessToken callbacks; none
// runs after it returns.
// upstream: realtime-js src/RealtimeClient.ts disconnect / _setAuthSafely
func TestDisconnectWaitsForBackgroundWork(t *testing.T) {
	fs := newFakeServer(t)
	var (
		mu           sync.Mutex
		disconnected bool
		lateCalls    int
		inFlight     atomic.Int32
		block        atomic.Bool
	)
	started := make(chan struct{}, 1)
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.HeartbeatInterval = 10 * time.Millisecond
		cfg.AccessToken = func(ctx context.Context) (string, error) {
			inFlight.Add(1)
			defer inFlight.Add(-1)
			mu.Lock()
			if disconnected {
				lateCalls++
			}
			mu.Unlock()
			if !block.Load() {
				return "tok", nil
			}
			select {
			case started <- struct{}{}:
			default:
			}
			<-ctx.Done() // block until Disconnect cancels us (or the timeout)
			return "", ctx.Err()
		}
	})
	var statusMu sync.Mutex
	var seen []SubscribeStatus
	subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		ch.OnStatus(func(s SubscribeStatus, _ error) {
			time.Sleep(20 * time.Millisecond) // a slow callback
			statusMu.Lock()
			seen = append(seen, s)
			statusMu.Unlock()
		})
	})
	block.Store(true)
	c.SendHeartbeat() // refreshes the token in the background
	recv(t, started, "blocked access token callback")

	start := time.Now()
	if err := c.Disconnect(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("Disconnect took %v; the callback context was not cancelled", time.Since(start))
	}
	mu.Lock()
	disconnected = true
	mu.Unlock()
	if n := inFlight.Load(); n != 0 {
		t.Fatalf("%d AccessToken callbacks still running after Disconnect", n)
	}
	// Status callbacks queued by the teardown already ran.
	statusMu.Lock()
	gotError := false
	for _, s := range seen {
		gotError = gotError || s == StatusChannelError
	}
	statusMu.Unlock()
	if !gotError {
		t.Fatalf("CHANNEL_ERROR status not delivered before Disconnect returned: %v", seen)
	}
	time.Sleep(100 * time.Millisecond) // several heartbeat intervals
	mu.Lock()
	defer mu.Unlock()
	if lateCalls != 0 {
		t.Fatalf("AccessToken called %d times after Disconnect", lateCalls)
	}
}

// Disconnect (and RemoveAllChannels) may be called from a callback without
// deadlocking on the callback queue.
func TestDisconnectFromCallback(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	done := make(chan error, 1)
	_, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, func(ch *Channel) {
		_ = ch.OnBroadcast("stop", func(BroadcastMessage) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done <- c.RemoveAllChannels(ctx)
		})
	})
	sc.push("realtime:room", "broadcast", map[string]any{"type": "broadcast", "event": "stop"})
	if err := recv(t, done, "RemoveAllChannels from callback"); err != nil {
		t.Fatalf("RemoveAllChannels: %v", err)
	}
	if c.IsConnected() {
		t.Fatal("still connected")
	}
}

// []byte payloads are only valid for VSN2 broadcasts.
// upstream: realtime-js src/lib/serializer.ts (binary payloads are VSN2 user broadcasts only)
func TestSendBinaryPayloadValidation(t *testing.T) {
	cases := []struct {
		vsn string
		typ ListenType
	}{
		{VSN1, ListenBroadcast},
		{VSN2, ListenPresence},
		{VSN2, ListenPostgresChanges},
	}
	for _, tc := range cases {
		c, err := New(Config{URL: "ws://127.0.0.1:1/realtime/v1", APIKey: "k", VSN: tc.vsn})
		if err != nil {
			t.Fatal(err)
		}
		ch, _ := c.Channel("room", ChannelOptions{})
		err = ch.Send(context.Background(), SendParams{Type: tc.typ, Event: "e", Payload: []byte{1, 2}})
		if err == nil || !strings.Contains(err.Error(), "[]byte payloads") {
			t.Fatalf("%s/%s: err = %v", tc.vsn, tc.typ, err)
		}
	}
}

// A null broadcast payload is sent as {} (upstream `payload ?? {}`).
// upstream: realtime-js src/lib/serializer.ts _encodeJsonUserBroadcastPush
func TestBroadcastNullPayloadSentAsEmptyObject(t *testing.T) {
	s := serializer{vsn: VSN2}
	for _, p := range []any{json.RawMessage("null"), json.RawMessage(" null "), nil} {
		args := &sendArgs{Type: "broadcast", Event: "e", Payload: p, hasPayload: p != nil}
		f, err := s.encode(outMessage{Topic: "t", Event: "broadcast", Payload: args})
		if err != nil {
			t.Fatal(err)
		}
		m, err := decodeTestPush(f.data)
		if err != nil || m != "{}" {
			t.Fatalf("payload %q encoded as %q (%v)", p, m, err)
		}
	}

	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	ch, sc, _ := subscribeJoined(t, c, fs, "room", ChannelOptions{}, nil)
	if err := ch.Send(ctxT(t), SendParams{Event: "e", Payload: map[string]any(nil)}); err != nil {
		t.Fatal(err)
	}
	m := sc.expectEvent(t, "realtime:room", "broadcast")
	if string(m.RawPayload) != "{}" {
		t.Fatalf("payload = %q", m.RawPayload)
	}
}

// decodeTestPush returns the user payload of a kind-3 binary push.
func decodeTestPush(b []byte) (string, error) {
	if len(b) < 7 || b[0] != binKindUserBroadcastPush {
		return "", errors.New("not a user broadcast push")
	}
	off := 7 + int(b[1]) + int(b[2]) + int(b[3]) + int(b[4]) + int(b[5])
	if off > len(b) {
		return "", errors.New("short frame")
	}
	return string(b[off:]), nil
}

// Subscribe calls abandoned through their context do not leave waiters
// behind.
func TestSubscribeCancelledWaitersPruned(t *testing.T) {
	fs := newFakeServer(t)
	fs.ignoreJoins.Store(true)
	c := newTestClient(t, fs, nil)
	ch, _ := c.Channel("x", ChannelOptions{})
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := ch.Subscribe(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	}
	c.mu.Lock()
	n := len(ch.waiters)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d abandoned waiters", n)
	}
}

// Config.RequestEditors run on HTTP broadcasts (HTTPSend and the REST
// fallback of Send), e.g. for trace propagation.
func TestRequestEditorsApplyToHTTPBroadcasts(t *testing.T) {
	fs := newFakeServer(t)
	got := make(chan string, 4)
	fs.httpHandler = func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path + " " + r.Header.Get("Traceparent")
		w.WriteHeader(http.StatusAccepted)
	}
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.RequestEditors = []func(*http.Request) error{func(r *http.Request) error {
			r.Header.Set("Traceparent", tp)
			return nil
		}}
	})
	ch, _ := c.Channel("room", ChannelOptions{})
	if err := ch.HTTPSend(ctxT(t), "e", map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if g := recv(t, got, "HTTPSend"); g != "/realtime/v1/api/broadcast/room/events/e "+tp {
		t.Fatalf("HTTPSend request = %q", g)
	}
	if err := ch.Send(ctxT(t), SendParams{Event: "e", Payload: map[string]int{"a": 1}}); err != nil {
		t.Fatal(err)
	}
	if g := recv(t, got, "fallback"); g != "/realtime/v1/api/broadcast "+tp {
		t.Fatalf("fallback request = %q", g)
	}

	// An editor error aborts the request.
	boom := errors.New("boom")
	c2 := newTestClient(t, fs, func(cfg *Config) {
		cfg.RequestEditors = []func(*http.Request) error{func(*http.Request) error { return boom }}
	})
	ch2, _ := c2.Channel("room", ChannelOptions{})
	if err := ch2.HTTPSend(ctxT(t), "e", map[string]int{"a": 1}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}
