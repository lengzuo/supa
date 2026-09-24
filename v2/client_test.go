package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lengzuo/supa/v2/auth"
)

// fakeProject records every request and answers the few endpoints the
// root client tests touch.
type fakeProject struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
}

func newFakeProject(t *testing.T) *fakeProject {
	t.Helper()
	fp := &fakeProject{}
	fp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fp.mu.Lock()
		fp.reqs = append(fp.reqs, r.Clone(context.Background()))
		fp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/auth/v1/token":
			exp := time.Now().Add(time.Hour).Unix()
			_, _ = w.Write([]byte(`{"access_token":"user-jwt","refresh_token":"rt","token_type":"bearer","expires_in":3600,"expires_at":` +
				jsonInt(exp) + `,"user":{"id":"u1","aud":"authenticated","created_at":"2024-01-01T00:00:00Z"}}`))
		case r.URL.Path == "/auth/v1/logout":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/rest/v1/todos":
			_, _ = w.Write([]byte(`[{"id":1}]`))
		case r.URL.Path == "/storage/v1/bucket":
			_, _ = w.Write([]byte(`[]`))
		case strings.HasPrefix(r.URL.Path, "/functions/v1/"):
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fp.Close)
	return fp
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func (fp *fakeProject) last(path string) *http.Request {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for i := len(fp.reqs) - 1; i >= 0; i-- {
		if fp.reqs[i].URL.Path == path {
			return fp.reqs[i]
		}
	}
	return nil
}

// exercise sends one request to each HTTP service.
func exercise(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	var rows []map[string]any
	if _, err := c.From("todos").Select("*").ExecuteInto(ctx, &rows); err != nil {
		t.Fatalf("db: %v", err)
	}
	if _, err := c.Storage.ListBuckets(ctx, nil); err != nil {
		t.Fatalf("storage: %v", err)
	}
	resp, err := c.Functions.Invoke(ctx, "hello", nil)
	if err != nil {
		t.Fatalf("functions: %v", err)
	}
	_ = resp.Close()
}

func TestNewValidation(t *testing.T) {
	for _, u := range []string{"", "not a url", "ftp://x.supabase.co", "https://x.supabase.co?a=1", "/relative"} {
		if _, err := New(u, "key", nil); err == nil {
			t.Errorf("New(%q) accepted an invalid URL", u)
		}
	}
	if _, err := New("https://x.supabase.co", " ", nil); err == nil {
		t.Error("New accepted an empty key")
	}
	c, err := New("https://x.supabase.co/", "key", nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth == nil || c.Storage == nil || c.Functions == nil || c.Realtime == nil || c.DB() == nil {
		t.Fatal("service client missing")
	}
	if got := c.Realtime.EndpointURL(); !strings.HasPrefix(got, "wss://x.supabase.co/realtime/v1/websocket") {
		t.Errorf("realtime endpoint = %q", got)
	}
	if ProjectURL("abc") != "https://abc.supabase.co" {
		t.Error("ProjectURL")
	}
}

// Features: client.request_configuration.custom_http_client and global_headers.
func TestCustomHTTPClientAndGlobalHeaders(t *testing.T) {
	fp := newFakeProject(t)
	var calls atomic.Int32
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return http.DefaultTransport.RoundTrip(r)
	})}
	c, err := New(fp.URL, "anon", &Options{HTTPClient: hc, Headers: http.Header{"x-app": {"demo"}}})
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, c)
	if _, err := c.Auth.SignInWithPassword(context.Background(), auth.SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/rest/v1/todos", "/storage/v1/bucket", "/functions/v1/hello", "/auth/v1/token"} {
		r := fp.last(p)
		if r == nil {
			t.Fatalf("no request to %s", p)
		}
		if got := r.Header.Values("X-App"); len(got) != 1 || got[0] != "demo" {
			t.Errorf("%s: X-App = %q", p, got)
		}
		if r.Header.Get("apikey") != "anon" {
			t.Errorf("%s: apikey = %q", p, r.Header.Get("apikey"))
		}
	}
	if calls.Load() < 4 {
		t.Errorf("custom HTTP client used %d times, want >= 4", calls.Load())
	}
}

// Without a session the key is the bearer; after sign-in every service sends
// the session's access token; after sign-out the key again.
func TestSessionTokenFlowsToServices(t *testing.T) {
	fp := newFakeProject(t)
	c, err := New(fp.URL, "anon", nil)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, c)
	if got := fp.last("/rest/v1/todos").Header.Get("Authorization"); got != "Bearer anon" {
		t.Fatalf("before sign-in Authorization = %q", got)
	}
	ctx := context.Background()
	if _, err := c.Auth.SignInWithPassword(ctx, auth.SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	exercise(t, c)
	for _, p := range []string{"/rest/v1/todos", "/storage/v1/bucket", "/functions/v1/hello"} {
		if got := fp.last(p).Header.Get("Authorization"); got != "Bearer user-jwt" {
			t.Errorf("%s: Authorization = %q", p, got)
		}
	}
	if err := c.Auth.SignOut(ctx, "", auth.SignOutLocal); err != nil {
		t.Fatal(err)
	}
	exercise(t, c)
	if got := fp.last("/rest/v1/todos").Header.Get("Authorization"); got != "Bearer anon" {
		t.Errorf("after sign-out Authorization = %q", got)
	}
}

// Feature: client.authentication_integration.third_party_auth.
func TestThirdPartyAccessToken(t *testing.T) {
	fp := newFakeProject(t)
	c, err := New(fp.URL, "anon", &Options{AccessToken: func(context.Context) (string, error) { return "clerk-jwt", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth != nil {
		t.Fatal("Auth must be disabled with a third-party AccessToken")
	}
	exercise(t, c)
	for _, p := range []string{"/rest/v1/todos", "/storage/v1/bucket", "/functions/v1/hello"} {
		if got := fp.last(p).Header.Get("Authorization"); got != "Bearer clerk-jwt" {
			t.Errorf("%s: Authorization = %q", p, got)
		}
	}
	tok, err := c.realtimeToken(context.Background())
	if err != nil || tok != "clerk-jwt" {
		t.Errorf("realtime token = %q, %v", tok, err)
	}
	wantErr := errors.New("boom")
	c2, _ := New(fp.URL, "anon", &Options{AccessToken: func(context.Context) (string, error) { return "", wantErr }})
	if _, err := c2.From("todos").Select("*").Execute(context.Background()); !errors.Is(err, wantErr) {
		t.Errorf("token error not propagated: %v", err)
	}
}

// Feature: client.observability.trace_propagation.
func TestTracePropagation(t *testing.T) {
	fp := newFakeProject(t)
	type ctxKey struct{}
	inject := PropagateTrace(func(r *http.Request) {
		if tp, ok := r.Context().Value(ctxKey{}).(string); ok {
			r.Header.Set("traceparent", tp)
		}
	})
	c, err := New(fp.URL, "anon", &Options{RequestEditors: []func(*http.Request) error{inject}})
	if err != nil {
		t.Fatal(err)
	}
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	ctx := context.WithValue(context.Background(), ctxKey{}, tp)
	if _, err := c.From("todos").Select("*").Execute(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Storage.ListBuckets(ctx, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/rest/v1/todos", "/storage/v1/bucket"} {
		if got := fp.last(p).Header.Get("traceparent"); got != tp {
			t.Errorf("%s: traceparent = %q", p, got)
		}
	}
	// An explicit traceparent is not overwritten.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fp.URL, nil)
	req.Header.Set("traceparent", "explicit")
	_ = inject(req)
	if req.Header.Get("traceparent") != "explicit" {
		t.Error("existing traceparent overwritten")
	}
}

// Feature: client.authentication_integration.cross_client_token_sync.
func TestCrossClientTokenSync(t *testing.T) {
	fp := newFakeProject(t)
	c, err := New(fp.URL, "anon", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if tok, _ := c.realtimeToken(ctx); tok != "anon" {
		t.Fatalf("realtime token before sign-in = %q, want API key", tok)
	}
	if _, err := c.Auth.SignInWithPassword(ctx, auth.SignInWithPasswordParams{Email: "a@b.c", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	c.tokenMu.Lock()
	last := c.lastToken
	c.tokenMu.Unlock()
	if last != "user-jwt" {
		t.Fatalf("auth event not propagated: lastToken = %q", last)
	}
	if tok, _ := c.realtimeToken(ctx); tok != "user-jwt" {
		t.Fatalf("realtime token after sign-in = %q", tok)
	}
	if err := c.Auth.SignOut(ctx, "", auth.SignOutLocal); err != nil {
		t.Fatal(err)
	}
	c.tokenMu.Lock()
	last = c.lastToken
	c.tokenMu.Unlock()
	if last != "" {
		t.Fatalf("sign-out not propagated: lastToken = %q", last)
	}
	if tok, _ := c.realtimeToken(ctx); tok != "anon" {
		t.Fatalf("realtime token after sign-out = %q, want API key", tok)
	}
	// Close stops background work and is safe to call.
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPerServiceConfigOverrides(t *testing.T) {
	fp := newFakeProject(t)
	opts := &Options{Headers: http.Header{"X-A": {"global"}}}
	opts.DB.Headers = http.Header{"X-A": {"db"}}
	opts.DB.Schema = "private"
	c, err := New(fp.URL, "anon", opts)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, c)
	r := fp.last("/rest/v1/todos")
	if r.Header.Get("X-A") != "db" || r.Header.Get("Accept-Profile") != "private" {
		t.Errorf("db overrides not applied: X-A=%q Accept-Profile=%q", r.Header.Get("X-A"), r.Header.Get("Accept-Profile"))
	}
	if got := fp.last("/storage/v1/bucket").Header.Get("X-A"); got != "global" {
		t.Errorf("storage X-A = %q", got)
	}
	if opts.DB.URL != "" {
		t.Error("New mutated the caller's Options")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
