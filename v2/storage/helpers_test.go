package storage

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

const testKey = "test-anon-key"

// captured is one request seen by the fake server.
type captured struct {
	Method string
	Path   string // escaped path
	Query  string // raw query
	Header http.Header
	Body   []byte
}

type fakeServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []captured
}

func (s *fakeServer) last(t *testing.T) captured {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		t.Fatal("no request received")
	}
	return s.reqs[len(s.reqs)-1]
}

func (s *fakeServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

// newFake starts a server that records requests and replies with status
// and body (JSON content type).
func newFake(t *testing.T, status int, body string) *fakeServer {
	t.Helper()
	return newFakeHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func newFakeHandler(t *testing.T, h http.HandlerFunc) *fakeServer {
	t.Helper()
	fs := &fakeServer{}
	fs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fs.mu.Lock()
		fs.reqs = append(fs.reqs, captured{
			Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
			Header: r.Header.Clone(), Body: b,
		})
		fs.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(fs.Close)
	return fs
}

func newTestClient(t *testing.T, fs *fakeServer, mut ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{URL: fs.URL + "/storage/v1", APIKey: testKey}
	for _, m := range mut {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func assertReq(t *testing.T, got captured, method, path, query string) {
	t.Helper()
	if got.Method != method {
		t.Errorf("method = %q, want %q", got.Method, method)
	}
	if got.Path != path {
		t.Errorf("path = %q, want %q", got.Path, path)
	}
	if got.Query != query {
		t.Errorf("query = %q, want %q", got.Query, query)
	}
	if k := got.Header.Get("apikey"); k != testKey {
		t.Errorf("apikey = %q, want %q", k, testKey)
	}
	if a := got.Header.Get("Authorization"); a != "Bearer "+testKey {
		t.Errorf("Authorization = %q", a)
	}
}

func assertJSONBody(t *testing.T, got captured, want string) {
	t.Helper()
	if ct := got.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var g, w any
	if err := json.Unmarshal(got.Body, &g); err != nil {
		t.Fatalf("request body %q is not JSON: %v", got.Body, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad want JSON: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("body = %s, want %s", got.Body, want)
	}
}

func assertAPIError(t *testing.T, err error, status int, code, msg string) {
	t.Helper()
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("err = %T %v, want *Error", err, err)
	}
	if e.Status != status || e.Code != code || e.Message != msg {
		t.Errorf("err = %+v, want status %d code %q message %q", e, status, code, msg)
	}
}

const notFoundBody = `{"statusCode":"404","error":"not_found","message":"Object not found","code":"NoSuchKey"}`
