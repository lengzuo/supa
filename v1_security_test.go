package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// syncBuffer is a goroutine-safe io.Writer for capturing log output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureDebugLogs enables debug logging into a buffer for the duration of
// the test and restores the previous package logger afterwards.
func captureDebugLogs(t *testing.T) *syncBuffer {
	t.Helper()
	prev := logger
	buf := &syncBuffer{}
	newLogger(true)
	logger.setOutput(buf)
	t.Cleanup(func() { logger = prev })
	return buf
}

// echoAuthServer replies with the Authorization header(s) it received.
func echoAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		vals := r.Header.Values("Authorization")
		if strings.HasPrefix(r.URL.Path, "/auth/v1/user") {
			auth := ""
			if len(vals) == 1 {
				auth = vals[0]
			} else {
				auth = fmt.Sprintf("unexpected %d values: %q", len(vals), vals)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id": auth})
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string][]string{{"auth": vals}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConcurrentRequestsDoNotShareAuthHeaders(t *testing.T) {
	srv := echoAuthServer(t)
	shared := map[string]string{"X-Shared": "1"}

	auth := NewAuth("anon-key", srv.URL+"/auth/v1", WithAuthClient(srv.Client(), shared))
	db := NewPostgres("example", WithPostgresClient(srv.Client(), shared))
	base, err := url.Parse(srv.URL + restAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	db.baseURL = *base

	const workers = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			token := fmt.Sprintf("user-token-%d", i)
			u, err := auth.User(context.Background(), token)
			if err != nil {
				errs <- err
				return
			}
			if want := "Bearer " + token; u.ID != want {
				errs <- fmt.Errorf("auth.User: server saw Authorization %q, want %q", u.ID, want)
			}
		}()
		go func() {
			defer wg.Done()
			token := fmt.Sprintf("pg-token-%d", i)
			var res []map[string][]string
			if err := db.From("items", AuthToken(token)).Select("*").Execute(context.Background(), &res); err != nil {
				errs <- err
				return
			}
			want := []string{"Bearer " + token}
			if len(res) != 1 || fmt.Sprint(res[0]["auth"]) != fmt.Sprint(want) {
				errs <- fmt.Errorf("postgres: server saw Authorization %v, want %v", res, want)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// The requesters' shared default headers must be untouched.
	for name, s := range map[string]Sender{"auth": auth.httpClient, "postgres": db.httpClient} {
		h := s.(*requester).customHeader
		if len(h) != 1 || h.Get("X-Shared") != "1" {
			t.Errorf("%s requester default headers were mutated: %v", name, h)
		}
	}
}

func TestUploadDoesNotMutateSharedHeaders(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Header.Get("Content-Type")]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	st := NewStorage("service-key", srv.URL+"/storage/v1", "bucket",
		WithStorageClient(srv.Client(), map[string]string{"X-Shared": "1"}))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			mime := fmt.Sprintf("image/type-%d", i%2)
			if err := st.UploadFile(context.Background(), "f.bin", mime, strings.NewReader("data")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if seen["image/type-0"] != 10 || seen["image/type-1"] != 10 {
		t.Errorf("unexpected content types seen by server: %v", seen)
	}
	if h := st.httpClient.(*requester).customHeader; len(h) != 1 {
		t.Errorf("storage requester default headers were mutated: %v", h)
	}
}

func TestDebugLoggingRedactsSecrets(t *testing.T) {
	const (
		apiKey       = "apikey-SECRET-111"
		password     = "password-SECRET-222"
		userToken    = "user-token-SECRET-333"
		refreshToken = "refresh-token-SECRET-444"
		respAccess   = "resp-access-SECRET-555"
		respRefresh  = "resp-refresh-SECRET-666"
		pgToken      = "pg-token-SECRET-777"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/rest/") {
			_, _ = w.Write([]byte(`[{"access_token":"` + respAccess + `"}]`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"user":{"id":"u1"},"id":"u1"}`, respAccess, respRefresh)
	}))
	t.Cleanup(srv.Close)

	logs := captureDebugLogs(t)
	ctx := context.Background()

	auth := NewAuth(apiKey, srv.URL+"/auth/v1", WithAuthClient(srv.Client(), nil))
	if _, err := auth.SignInWithPassword(ctx, SignInRequest{Email: "a@example.com", Password: password}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.User(ctx, userToken); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.RefreshToken(ctx, refreshToken); err != nil {
		t.Fatal(err)
	}

	db := NewPostgres("example", WithToken(pgToken), With(authorizationHeader, apiKey),
		WithPostgresClient(srv.Client(), nil))
	base, err := url.Parse(srv.URL + restAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	db.baseURL = *base
	var rows []map[string]string
	if err := db.From("items").Select("*").Execute(ctx, &rows); err != nil {
		t.Fatal(err)
	}

	st := NewStorage(apiKey, srv.URL+"/storage/v1", "bucket", WithStorageClient(srv.Client(), nil))
	if err := st.UploadFile(ctx, "f.bin", "application/octet-stream", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}

	out := logs.String()
	if !strings.Contains(out, redacted) || !strings.Contains(out, "200") {
		t.Fatalf("expected redacted debug logs with status codes, got:\n%s", out)
	}
	for _, secret := range []string{apiKey, password, userToken, refreshToken, respAccess, respRefresh, pgToken} {
		if strings.Contains(out, secret) {
			t.Errorf("debug log leaked %q:\n%s", secret, out)
		}
	}
}

func TestPrintURLRedactsSensitiveQueryParams(t *testing.T) {
	got := printURL("https://u:pw@x.supabase.co/auth/v1/verify?token=abc123&type=signup&Access_Token=zzz&select=*")
	for _, secret := range []string{"abc123", "zzz", "pw"} {
		if strings.Contains(got, secret) {
			t.Errorf("printURL leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "type=signup") || !strings.Contains(got, "select=") {
		t.Errorf("printURL dropped non-sensitive params: %s", got)
	}
}

func TestTransportErrorRedactsURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := srv.URL
	srv.Close() // connection refused from here on

	r := newRequester(&http.Client{}, nil)
	_, err := r.Call(context.Background(), addr+"/auth/v1/verify?token=tok-SECRET", http.MethodGet, nil, func(*http.Request) {})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "tok-SECRET") {
		t.Errorf("transport error leaked token: %v", err)
	}
}

func TestNewPostgresInvalidRefDoesNotPanic(t *testing.T) {
	db := NewPostgres("bad ref")
	if db == nil {
		t.Fatal("NewPostgres returned nil")
	}
	if err := db.From("items").Select("*").Execute(context.Background(), nil); err == nil {
		t.Fatal("expected an error executing against an invalid project ref")
	}
}
