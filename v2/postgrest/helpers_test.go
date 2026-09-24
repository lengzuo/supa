package postgrest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

const testKey = "test-anon-key"

// recorded is one request seen by the fake server.
type recorded struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   string
}

// fakeServer records requests and replies with handler.
type fakeServer struct {
	mu   sync.Mutex
	reqs []recorded
	srv  *httptest.Server
}

func (f *fakeServer) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

func (f *fakeServer) last(t *testing.T) recorded {
	t.Helper()
	rs := f.requests()
	if len(rs) == 0 {
		t.Fatal("no request recorded")
	}
	return rs[len(rs)-1]
}

// newFake starts a server and a client pointed at <srv>/rest/v1. The
// client's sleep is instant and delays are recorded in *delays.
func newFake(t *testing.T, handler http.HandlerFunc, mutate ...func(*Config)) (*Client, *fakeServer, *[]time.Duration) {
	t.Helper()
	f := &fakeServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: string(body)})
		f.mu.Unlock()
		if handler != nil {
			handler(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	cfg := Config{URL: f.srv.URL + "/rest/v1", APIKey: testKey}
	for _, m := range mutate {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var mu sync.Mutex
	delays := &[]time.Duration{}
	c.sleepFunc = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		*delays = append(*delays, d)
		mu.Unlock()
		return ctx.Err()
	}
	return c, f, delays
}

func jsonReply(status int, body string, headers ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func assertEq[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %#v, want %#v", name, got, want)
	}
}
