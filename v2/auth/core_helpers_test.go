package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

const coreAPIKey = "anon-key"

// coreReq is one request received by the fake Auth server.
type coreReq struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Raw    []byte
	Body   map[string]any
}

// coreServer is an httptest server that records requests and answers with
// the handler under test.
type coreServer struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []coreReq
}

func newCoreServer(t *testing.T, handler func(w http.ResponseWriter, r *coreReq)) *coreServer {
	t.Helper()
	f := &coreServer{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec := coreReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Raw: raw}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Body)
		}
		f.mu.Lock()
		f.got = append(f.got, rec)
		f.mu.Unlock()
		handler(w, &rec)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *coreServer) requests() []coreReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]coreReq(nil), f.got...)
}

func (f *coreServer) count(path string) int {
	n := 0
	for _, r := range f.requests() {
		if r.Path == path {
			n++
		}
	}
	return n
}

func (f *coreServer) last(t *testing.T) coreReq {
	t.Helper()
	reqs := f.requests()
	if len(reqs) == 0 {
		t.Fatal("no request received")
	}
	return reqs[len(reqs)-1]
}

func (f *coreServer) client(t *testing.T, mods ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{URL: f.srv.URL + "/auth/v1", APIKey: coreAPIKey}
	for _, m := range mods {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.refreshRetryBudget = 0
	t.Cleanup(c.StopAutoRefresh)
	return c
}

func coreJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(APIVersionHeader, APIVersion)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// coreJWT builds an unsigned (alg HS256) token with the given claims.
func coreJWT(claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "." + enc.EncodeToString([]byte("sig"))
}

func coreUser(id string) map[string]any {
	return map[string]any{
		"id": id, "aud": "authenticated", "role": "authenticated", "email": "user@example.com",
		"app_metadata": map[string]any{"provider": "email"}, "user_metadata": map[string]any{},
		"identities": []any{map[string]any{"id": "ident-1", "identity_id": "11111111-2222-3333-4444-555555555555", "user_id": id, "provider": "email"}},
		"created_at": "2024-01-01T00:00:00Z", "is_anonymous": false,
	}
}

// coreSession is a realistic GoTrue token response.
func coreSession(access, refresh string, expiresIn int64) map[string]any {
	return map[string]any{
		"access_token": access, "refresh_token": refresh, "token_type": "bearer",
		"expires_in": expiresIn, "expires_at": time.Now().Unix() + expiresIn,
		"user": coreUser("user-1"),
	}
}

// coreStoreSession writes a session directly into c's storage.
func coreStoreSession(t *testing.T, c *Client, access, refresh string, expiresAt time.Time) {
	t.Helper()
	s := &Session{AccessToken: access, RefreshToken: refresh, TokenType: "bearer", ExpiresIn: 3600,
		ExpiresAt: expiresAt.Unix(), User: &User{ID: "user-1"}}
	if err := c.saveSession(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// coreEventLog records auth events.
type coreEventLog struct {
	mu     sync.Mutex
	events []AuthChangeEvent
}

func coreWatch(c *Client) *coreEventLog {
	l := &coreEventLog{}
	c.OnAuthStateChange(func(e AuthChangeEvent, _ *Session) {
		l.mu.Lock()
		l.events = append(l.events, e)
		l.mu.Unlock()
	})
	return l
}

func (l *coreEventLog) get() []AuthChangeEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]AuthChangeEvent(nil), l.events...)
}

func coreAssertEvents(t *testing.T, l *coreEventLog, want ...AuthChangeEvent) {
	t.Helper()
	got := l.get()
	if len(want) == 0 && len(got) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// coreAssertCommon checks method, path and the headers every call carries.
func coreAssertCommon(t *testing.T, r coreReq, method, path, bearer string) {
	t.Helper()
	if r.Method != method || r.Path != path {
		t.Fatalf("request = %s %s, want %s %s", r.Method, r.Path, method, path)
	}
	if got := r.Header.Get("apikey"); got != coreAPIKey {
		t.Errorf("apikey = %q", got)
	}
	if got := r.Header.Get(APIVersionHeader); got != APIVersion {
		t.Errorf("%s = %q", APIVersionHeader, got)
	}
	if got, want := r.Header.Get("Authorization"), "Bearer "+bearer; got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
	if len(r.Raw) > 0 {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
	}
}

// coreAssertBody compares the decoded JSON body with want.
func coreAssertBody(t *testing.T, r coreReq, want map[string]any) {
	t.Helper()
	var wantNorm map[string]any
	b, _ := json.Marshal(want)
	_ = json.Unmarshal(b, &wantNorm)
	if !reflect.DeepEqual(r.Body, wantNorm) {
		t.Fatalf("body = %s\nwant   %s", r.Raw, b)
	}
}

func coreStored(t *testing.T, c *Client) *Session {
	t.Helper()
	s, err := c.loadSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// coreWaitFor polls cond for up to two seconds.
func coreWaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
