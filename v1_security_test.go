package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	prev := logger.load()
	buf := &syncBuffer{}
	l := buildLogger(true)
	l.setOutput(buf)
	logger.store(l)
	t.Cleanup(func() { logger.store(prev) })
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

func TestPrintURLRedactsAllQueryValues(t *testing.T) {
	got := printURL("https://u:pw@x.supabase.co/rest/v1/users?token=abc123&email=eq.alice%40example.com&Access_Token=zzz#frag-secret")
	for _, secret := range []string{"abc123", "alice", "zzz", "pw", "frag-secret"} {
		if strings.Contains(got, secret) {
			t.Errorf("printURL leaked %q: %s", secret, got)
		}
	}
	want := "https://%5BREDACTED%5D@x.supabase.co/rest/v1/users?Access_Token=[REDACTED]&email=[REDACTED]&token=[REDACTED]"
	if got != want {
		t.Errorf("printURL = %s, want %s", got, want)
	}
}

func TestPrintHeaderLogsNamesOnly(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer tok-SECRET")
	h.Set("apikey", "key-SECRET")
	h.Set("X-Custom", "custom-SECRET")
	got := printHeader(h)
	if got != "[Apikey,Authorization,X-Custom]" {
		t.Errorf("printHeader = %s", got)
	}
}

func TestErrorResponseBodiesAreNotLogged(t *testing.T) {
	// Bodies modelled on real PostgREST / GoTrue / Storage errors whose
	// free-text fields echo row data and input values.
	bodies := map[string]string{
		// PostgREST 23505 unique_violation
		"/rest/v1/users": `{"code":"23505","details":"Key (email)=(alice-SECRET@example.com) already exists.","hint":null,"message":"duplicate key value violates unique constraint \"users_email_key\""}`,
		// PostgREST 23514 check_violation
		"/rest/v1/orders": `{"code":"23514","details":"Failing row contains (42, card-SECRET-4242, -1).","hint":null,"message":"new row for relation \"orders\" violates check constraint \"orders_amount_check\""}`,
		// PostgREST 22P02 invalid_text_representation, via RPC
		"/rest/v1/rpc/lookup": `{"code":"22P02","details":null,"hint":null,"message":"invalid input syntax for type uuid: \"ssn-SECRET-123\""}`,
		// GoTrue
		"/auth/v1/signup": `{"code":422,"error_code":"weak_password","msg":"Password pwd-SECRET is too weak"}`,
		// Storage echoing the object key
		"/storage/v1/object/bucket/private/key-SECRET.pdf": `{"statusCode":"409","code":"Duplicate","error":"Duplicate","message":"The resource private/key-SECRET.pdf already exists"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	logs := captureDebugLogs(t)
	ctx := context.Background()

	db := NewPostgres("example", WithPostgresClient(srv.Client(), nil))
	base, err := url.Parse(srv.URL + restAPIPath)
	if err != nil {
		t.Fatal(err)
	}
	db.baseURL = *base
	for table, code := range map[string]string{"users": "23505", "orders": "23514"} {
		err := db.From(table).Insert(struct {
			X string `json:"x"`
		}{"y"}).Execute(ctx, nil)
		var pgErr *PostgresError
		if !errors.As(err, &pgErr) || pgErr.Code != code || !strings.Contains(pgErr.Details, "SECRET") {
			t.Errorf("%s: want full PostgresError with code %s returned, got %v", table, code, err)
		}
	}
	if err := db.RPC("lookup", struct {
		ID string `json:"id"`
	}{"x"}).Execute(ctx, nil); err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Errorf("rpc: want full error returned, got %v", err)
	}

	auth := NewAuth("anon", srv.URL+"/auth/v1", WithAuthClient(srv.Client(), nil))
	if _, err := auth.SignUp(ctx, SignUpRequest{Email: "a@example.com", Password: "p"}); err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Errorf("signup: want full error body returned, got %v", err)
	}

	st := NewStorage("anon", srv.URL+"/storage/v1", "bucket", WithStorageClient(srv.Client(), nil))
	if err := st.UploadFile(ctx, "private/key-SECRET.pdf", "application/pdf", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "SECRET") {
		t.Errorf("storage: want full error body returned, got %v", err)
	}

	out := logs.String()
	for _, code := range []string{"23505", "23514", "22P02", "weak_password", "Duplicate"} {
		if !strings.Contains(out, code) {
			t.Errorf("expected error code %q in logs:\n%s", code, out)
		}
	}
	for _, secret := range []string{"alice-SECRET", "card-SECRET", "ssn-SECRET", "pwd-SECRET", "already exists", "Failing row", "invalid input syntax"} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaked %q:\n%s", secret, out)
		}
	}
	// The storage object key legitimately appears in the debug request URL
	// (it is the request path), but never in the logged error.
	warnings := 0
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `"level":"warn"`) {
			continue
		}
		warnings++
		if strings.Contains(line, "SECRET") {
			t.Errorf("warning leaked response body: %s", line)
		}
	}
	if warnings != 5 {
		t.Errorf("expected 5 warnings, got %d:\n%s", warnings, out)
	}
}

func TestNewRequestErrorRedactsURL(t *testing.T) {
	logs := captureDebugLogs(t)
	r := newRequester(&http.Client{}, nil)
	bad := "http://example.com/\x7f?token=tok-SECRET"
	_, err := r.Call(context.Background(), bad, http.MethodGet, nil, func(*http.Request) {})
	if err == nil {
		t.Fatal("expected an error for an invalid URL")
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("error type changed: %T", err)
	}
	if strings.Contains(err.Error(), "tok-SECRET") {
		t.Errorf("Call error leaked token: %v", err)
	}
	_, err = r.Upload(context.Background(), bad, http.MethodPost, strings.NewReader("x"), func(*http.Request) {})
	if err == nil || strings.Contains(err.Error(), "tok-SECRET") {
		t.Errorf("Upload error missing or leaked token: %v", err)
	}
	if out := logs.String(); strings.Contains(out, "tok-SECRET") || !strings.Contains(out, "failed in new request") {
		t.Errorf("unexpected logs:\n%s", out)
	}
}

// TestNewConcurrentWithRequests reproduces the race between New swapping the
// package logger and in-flight requests reading it.
func TestNewConcurrentWithRequests(t *testing.T) {
	prev := logger.load()
	t.Cleanup(func() { logger.store(prev) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"x"}`))
	}))
	t.Cleanup(srv.Close)
	auth := NewAuth("anon", srv.URL+"/auth/v1", WithAuthClient(srv.Client(), nil))

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if _, err := New(Config{ApiKey: "k", ProjectRef: "p"}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			_ = auth.SignOut(context.Background(), "t")
		}()
	}
	close(start)
	wg.Wait()
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
