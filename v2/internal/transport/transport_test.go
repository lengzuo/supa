package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc, mutate func(*Config)) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := Config{BaseURL: srv.URL + "/auth/v1", APIKey: "anon", AllowKeyAsBearer: true, HTTPClient: srv.Client()}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewValidates(t *testing.T) {
	for _, u := range []string{"", "  ", "not a url", "/relative"} {
		if _, err := New(Config{BaseURL: u}); err == nil {
			t.Errorf("New(%q) = nil error, want error", u)
		}
	}
}

func TestDefaultHeadersAndKeyFallback(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apikey"); got != "anon" {
			t.Errorf("apikey = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer anon" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Client-Info"); got != ClientInfo {
			t.Errorf("X-Client-Info = %q", got)
		}
		if r.URL.Path != "/auth/v1/user" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte(`{"id":"u1"}`))
	}, nil)
	var out struct{ ID string }
	if _, err := c.DoJSON(context.Background(), &Request{Path: "/user"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "u1" {
		t.Fatalf("decoded %+v", out)
	}
}

func TestNewAPIKeyNotSentAsBearerWhenLegacyOnly(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty", got)
		}
	}, func(cfg *Config) { cfg.APIKey = "sb_publishable_x"; cfg.KeyAsBearerLegacyOnly = true })
	if _, err := c.DoJSON(context.Background(), &Request{Path: "/"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestHeaderPrecedence(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-A"); got != "request" {
			t.Errorf("X-A = %q", got)
		}
		if got := r.Header.Get("X-B"); got != "global" {
			t.Errorf("X-B = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer per-request" {
			t.Errorf("Authorization = %q", got)
		}
	}, func(cfg *Config) {
		cfg.Headers = http.Header{"X-A": {"global"}, "X-B": {"global"}}
		cfg.Token = func(context.Context) (string, error) { return "session", nil }
	})
	req := &Request{Path: "/", Header: http.Header{"X-A": {"request"}}, Token: "per-request"}
	if _, err := c.DoJSON(context.Background(), req, nil); err != nil {
		t.Fatal(err)
	}
}

// Regression test for the v1 bug where every request shared one header map
// and a user's token could leak into a concurrent request.
func TestConcurrentTokensDoNotLeak(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		want := "Bearer " + r.URL.Query().Get("u")
		if got := r.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization = %q, want %q", got, want)
		}
	}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := fmt.Sprintf("tok%d", i)
			req := &Request{Path: "/?u=" + tok, Token: tok}
			if _, err := c.DoJSON(context.Background(), req, nil); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
}

func TestConfigIsCopied(t *testing.T) {
	h := http.Header{"X-A": {"1"}}
	c, err := New(Config{BaseURL: "https://x.supabase.co", Headers: h})
	if err != nil {
		t.Fatal(err)
	}
	h.Set("X-A", "2")
	if got := c.Config().Headers.Get("X-A"); got != "1" {
		t.Fatalf("client headers changed with caller map: %q", got)
	}
	d, err := c.With(func(cfg *Config) { cfg.Headers.Set("X-A", "3") })
	if err != nil {
		t.Fatal(err)
	}
	if c.Config().Headers.Get("X-A") != "1" || d.Config().Headers.Get("X-A") != "3" {
		t.Fatal("With mutated the receiver")
	}
}

func TestURL(t *testing.T) {
	c, _ := New(Config{BaseURL: "https://x.supabase.co/storage/v1/"})
	got := c.URL("object/b/"+PathEscape("a dir/f#1.png")+"?download=1", map[string][]string{"x": {"y"}})
	want := "https://x.supabase.co/storage/v1/object/b/a%20dir/f%231.png?download=1&x=y"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
}

func TestHTTPError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"msg":"bad"}`))
	}, nil)
	_, err := c.DoJSON(context.Background(), &Request{Path: "/"}, nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != 400 || string(he.Body) != `{"msg":"bad"}` {
		t.Fatalf("err = %v", err)
	}
}

func TestJSONBodyAndRawBody(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write([]byte(r.Header.Get("Content-Type") + "|" + string(b)))
	}, nil)
	var out []byte
	if _, err := c.DoJSON(context.Background(), &Request{Method: "POST", Path: "/", Body: map[string]int{"a": 1}}, &out); err != nil {
		t.Fatal(err)
	}
	if string(out) != `application/json|{"a":1}` {
		t.Fatalf("got %s", out)
	}
	req := &Request{Method: "POST", Path: "/", Body: strings.NewReader("raw"), ContentType: "text/plain"}
	if _, err := c.DoJSON(context.Background(), req, &out); err != nil {
		t.Fatal(err)
	}
	if string(out) != "text/plain|raw" {
		t.Fatalf("got %s", out)
	}
}

func TestRetry(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{}`))
	}, func(cfg *Config) { cfg.Retry = &RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond} })
	if _, err := c.DoJSON(context.Background(), &Request{Path: "/"}, nil); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
	calls.Store(0)
	_, err := c.DoJSON(context.Background(), &Request{Method: "POST", Path: "/"}, nil)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("POST retried: calls=%d err=%v", calls.Load(), err)
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}, func(cfg *Config) { cfg.Timeout = 20 * time.Millisecond })
	if _, err := c.DoJSON(context.Background(), &Request{Path: "/"}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
}

func TestLogsAreRedacted(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {}, func(cfg *Config) {
		cfg.Logger = logger
		cfg.APIKey = "secret-key"
	})
	req := &Request{Method: "POST", Path: "/token?refresh_token=secret-refresh", Body: map[string]string{"password": "secret-pw"}}
	if _, err := c.DoJSON(context.Background(), req, nil); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"secret-key", "secret-refresh", "secret-pw"} {
		if strings.Contains(buf.String(), s) {
			t.Errorf("log contains %q: %s", s, buf.String())
		}
	}
	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("log missing status: %s", buf.String())
	}
}
