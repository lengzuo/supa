package functions

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const legacyKey = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig"

// captured is one request seen by the test server.
type captured struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   string
}

func newServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, <-chan captured) {
	t.Helper()
	ch := make(chan captured, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- captured{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.Query(), Header: r.Header.Clone(), Body: string(b)}
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

func newClient(t *testing.T, srv *httptest.Server, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{URL: srv.URL + "/functions/v1", APIKey: legacyKey}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func mustInvoke(t *testing.T, c *Client, name string, opts *InvokeOptions) *Response {
	t.Helper()
	resp, err := c.Invoke(context.Background(), name, opts)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	return resp
}

func TestNew(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
	if _, err := New(Config{URL: "not a url"}); err == nil {
		t.Fatal("expected error for relative URL")
	}
	c, err := New(Config{URL: "https://ref.supabase.co/functions/v1"})
	if err != nil || c.region != RegionAny {
		t.Fatalf("New: %v, region %q", err, c.region)
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (JSON body, default POST, response parsing)
func TestInvoke(t *testing.T) {
	srv, reqs := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Application/JSON; charset=utf-8")
		_, _ = io.WriteString(w, `{"message":"Hello Ada!"}`)
	})
	c := newClient(t, srv, func(cfg *Config) {
		cfg.Headers = http.Header{"x-custom-client": {"c1"}}
	})
	resp := mustInvoke(t, c, "hello", &InvokeOptions{
		Body:    map[string]string{"name": "Ada"},
		Headers: http.Header{"my-custom-header": {"v"}},
	})
	if resp.StatusCode != http.StatusOK || resp.MediaType() != "application/json" {
		t.Fatalf("status %d media %q", resp.StatusCode, resp.MediaType())
	}
	var out struct {
		Message string `json:"message"`
	}
	if err := resp.DecodeJSON(&out); err != nil || out.Message != "Hello Ada!" {
		t.Fatalf("DecodeJSON: %v %+v", err, out)
	}

	got := <-reqs
	if got.Method != http.MethodPost || got.Path != "/functions/v1/hello" {
		t.Fatalf("got %s %s", got.Method, got.Path)
	}
	if len(got.Query) != 0 {
		t.Fatalf("unexpected query %v", got.Query)
	}
	checks := map[string]string{
		"Apikey":           legacyKey,
		"Authorization":    "Bearer " + legacyKey,
		"Content-Type":     "application/json",
		"My-Custom-Header": "v",
		"X-Custom-Client":  "c1",
		"X-Region":         "",
	}
	for k, want := range checks {
		if v := got.Header.Get(k); v != want {
			t.Errorf("header %s = %q, want %q", k, v, want)
		}
	}
	if !strings.HasPrefix(got.Header.Get("X-Client-Info"), "supa-go/") {
		t.Errorf("X-Client-Info = %q", got.Header.Get("X-Client-Info"))
	}
	if got.Body != `{"name":"Ada"}` {
		t.Errorf("body = %q", got.Body)
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (body type -> Content-Type)
func TestInvoke_BodyContentType(t *testing.T) {
	srv, reqs := newServer(t, nil)
	c := newClient(t, srv, nil)
	tests := []struct {
		name     string
		body     any
		headers  http.Header
		wantCT   string
		wantBody string
	}{
		{"nil", nil, nil, "", ""},
		{"empty string", "", nil, "", ""},
		{"string", "hi there", nil, "text/plain", "hi there"},
		{"bytes", []byte{0x01, 0x02}, nil, "application/octet-stream", "\x01\x02"},
		{"reader", strings.NewReader("streamed"), nil, "application/octet-stream", "streamed"},
		{"form", url.Values{"a": {"1"}, "b": {"x y"}}, nil, "application/x-www-form-urlencoded", "a=1&b=x+y"},
		{"json", struct {
			N int `json:"n"`
		}{7}, nil, "application/json", `{"n":7}`},
		{"caller content-type lowercase", map[string]int{"n": 1}, http.Header{"content-type": {"application/vnd.custom+json"}}, "application/vnd.custom+json", `{"n":1}`},
		{"caller content-type on string", "<x/>", http.Header{"Content-Type": {"application/xml"}}, "application/xml", "<x/>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mustInvoke(t, c, "mirror", &InvokeOptions{Body: tt.body, Headers: tt.headers})
			_ = resp.Close()
			got := <-reqs
			if ct := got.Header.Values("Content-Type"); strings.Join(ct, ",") != tt.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, tt.wantCT)
			}
			if got.Body != tt.wantBody {
				t.Errorf("body = %q, want %q", got.Body, tt.wantBody)
			}
		})
	}

	if _, err := c.Invoke(context.Background(), "mirror", &InvokeOptions{Body: func() {}}); err == nil {
		t.Fatal("expected encode error for unmarshalable body")
	}
}

// upstream: supabase-js src/lib/fetch.ts fetchWithAuth (omitApiKeyAsBearer for functions)
func TestInvoke_NewAPIKeyNotSentAsBearer(t *testing.T) {
	srv, reqs := newServer(t, nil)
	for _, key := range []string{"sb_publishable_abc", "sb_secret_abc"} {
		c := newClient(t, srv, func(cfg *Config) { cfg.APIKey = key })
		_ = mustInvoke(t, c, "hello", nil).Close()
		got := <-reqs
		if got.Header.Get("Apikey") != key {
			t.Errorf("apikey = %q", got.Header.Get("Apikey"))
		}
		if a := got.Header.Get("Authorization"); a != "" {
			t.Errorf("%s: Authorization = %q, want empty", key, a)
		}
	}

	c := newClient(t, srv, func(cfg *Config) {
		cfg.APIKey = "sb_publishable_abc"
		cfg.AccessToken = func(context.Context) (string, error) { return "user-jwt", nil }
	})
	_ = mustInvoke(t, c, "hello", nil).Close()
	if a := (<-reqs).Header.Get("Authorization"); a != "Bearer user-jwt" {
		t.Errorf("Authorization = %q", a)
	}

	c = newClient(t, srv, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "", errors.New("boom") }
	})
	_, err := c.Invoke(context.Background(), "hello", nil)
	var fe *FetchError
	if !errors.As(err, &fe) {
		t.Fatalf("want *FetchError, got %T %v", err, err)
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (options.method)
func TestInvoke_MethodOverride(t *testing.T) {
	srv, reqs := newServer(t, nil)
	c := newClient(t, srv, nil)
	for _, tc := range []struct{ in, want string }{
		{"", http.MethodPost},
		{"GET", http.MethodGet},
		{"put", http.MethodPut},
		{http.MethodPatch, http.MethodPatch},
		{http.MethodDelete, http.MethodDelete},
	} {
		opts := &InvokeOptions{Method: tc.in}
		if tc.want != http.MethodGet {
			opts.Body = map[string]string{"foo": "bar"}
		}
		_ = mustInvoke(t, c, "hello", opts).Close()
		got := <-reqs
		if got.Method != tc.want {
			t.Errorf("method %q: got %s, want %s", tc.in, got.Method, tc.want)
		}
		if tc.want != http.MethodGet && got.Body != `{"foo":"bar"}` {
			t.Errorf("method %q: body %q", tc.in, got.Body)
		}
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (x-region header and forceFunctionRegion)
func TestInvoke_RegionSelection(t *testing.T) {
	srv, reqs := newServer(t, nil)

	check := func(t *testing.T, got captured, want string) {
		t.Helper()
		if h := got.Header.Get("X-Region"); h != want {
			t.Errorf("x-region = %q, want %q", h, want)
		}
		if q := got.Query.Get("forceFunctionRegion"); q != want {
			t.Errorf("forceFunctionRegion = %q, want %q", q, want)
		}
	}

	t.Run("client default", func(t *testing.T) {
		c := newClient(t, srv, func(cfg *Config) { cfg.Region = RegionEuWest1 })
		_ = mustInvoke(t, c, "hello", nil).Close()
		check(t, <-reqs, "eu-west-1")
	})
	t.Run("per call override", func(t *testing.T) {
		c := newClient(t, srv, func(cfg *Config) { cfg.Region = RegionEuWest1 })
		_ = mustInvoke(t, c, "hello", &InvokeOptions{Region: RegionUsEast1}).Close()
		check(t, <-reqs, "us-east-1")
	})
	t.Run("per call any disables client region", func(t *testing.T) {
		c := newClient(t, srv, func(cfg *Config) { cfg.Region = RegionEuWest1 })
		_ = mustInvoke(t, c, "hello", &InvokeOptions{Region: RegionAny}).Close()
		check(t, <-reqs, "")
	})
	t.Run("default any", func(t *testing.T) {
		c := newClient(t, srv, nil)
		_ = mustInvoke(t, c, "hello", nil).Close()
		check(t, <-reqs, "")
	})
	t.Run("merges with name query", func(t *testing.T) {
		c := newClient(t, srv, nil)
		_ = mustInvoke(t, c, "hello?page=2&forceFunctionRegion=x", &InvokeOptions{Region: RegionApSouth1}).Close()
		got := <-reqs
		check(t, got, "ap-south-1")
		if got.Query.Get("page") != "2" || len(got.Query["forceFunctionRegion"]) != 1 {
			t.Errorf("query = %v", got.Query)
		}
	})
	t.Run("header priority", func(t *testing.T) {
		c := newClient(t, srv, func(cfg *Config) { cfg.Headers = http.Header{"x-region": {"client"}} })
		_ = mustInvoke(t, c, "hello", &InvokeOptions{Region: RegionSaEast1}).Close()
		if h := (<-reqs).Header.Get("X-Region"); h != "client" {
			t.Errorf("client header should win over default, got %q", h)
		}
		_ = mustInvoke(t, c, "hello", &InvokeOptions{Region: RegionSaEast1, Headers: http.Header{"X-Region": {"call"}}}).Close()
		if h := (<-reqs).Header.Get("X-Region"); h != "call" {
			t.Errorf("call header should win, got %q", h)
		}
	})
}

func TestRegionValues(t *testing.T) {
	want := []Region{RegionAny, RegionApNortheast1, RegionApNortheast2, RegionApSouth1, RegionApSoutheast1,
		RegionApSoutheast2, RegionCaCentral1, RegionEuCentral1, RegionEuWest1, RegionEuWest2, RegionEuWest3,
		RegionSaEast1, RegionUsEast1, RegionUsWest1, RegionUsWest2}
	names := "any ap-northeast-1 ap-northeast-2 ap-south-1 ap-southeast-1 ap-southeast-2 ca-central-1 eu-central-1 eu-west-1 eu-west-2 eu-west-3 sa-east-1 us-east-1 us-west-1 us-west-2"
	got := make([]string, len(want))
	for i, r := range want {
		got[i] = r.String()
	}
	if strings.Join(got, " ") != names {
		t.Fatalf("regions = %v", got)
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (options.signal)
func TestInvoke_RequestCancellation(t *testing.T) {
	release := make(chan struct{})
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	c := newClient(t, srv, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := c.Invoke(ctx, "slow", nil)
	var fe *FetchError
	if !errors.As(err, &fe) || !errors.Is(err, context.Canceled) {
		t.Fatalf("want *FetchError wrapping context.Canceled, got %T %v", err, err)
	}

	// Already-cancelled context never reaches the server.
	_, err = c.Invoke(ctx, "slow", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

// upstream: functions-js src/FunctionsClient.ts setAuth
func TestSetAuth(t *testing.T) {
	srv, reqs := newServer(t, nil)
	c := newClient(t, srv, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "session-jwt", nil }
	})

	_ = mustInvoke(t, c, "hello", nil).Close()
	if a := (<-reqs).Header.Get("Authorization"); a != "Bearer session-jwt" {
		t.Fatalf("before SetAuth: %q", a)
	}

	c.SetAuth("custom-jwt")
	_ = mustInvoke(t, c, "hello", nil).Close()
	if a := (<-reqs).Header.Get("Authorization"); a != "Bearer custom-jwt" {
		t.Fatalf("after SetAuth: %q", a)
	}

	_ = mustInvoke(t, c, "hello", &InvokeOptions{Headers: http.Header{"authorization": {"Bearer per-call"}}}).Close()
	if a := (<-reqs).Header.Values("Authorization"); len(a) != 1 || a[0] != "Bearer per-call" {
		t.Fatalf("per-call header should win: %q", a)
	}

	c.SetAuth("")
	_ = mustInvoke(t, c, "hello", nil).Close()
	if a := (<-reqs).Header.Get("Authorization"); a != "Bearer session-jwt" {
		t.Fatalf("after clearing: %q", a)
	}
}

func TestSetAuth_Concurrent(t *testing.T) {
	srv, reqs := newServer(t, nil)
	allowed := map[string]bool{"Bearer tok-init": true}
	for i := 0; i < 8; i++ {
		allowed[fmt.Sprintf("Bearer tok-%d", i)] = true
	}
	c := newClient(t, srv, nil)
	c.SetAuth("tok-init")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			c.SetAuth(fmt.Sprintf("tok-%d", i))
		}(i)
		go func() {
			defer wg.Done()
			resp, err := c.Invoke(context.Background(), "hello", nil)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Close()
		}()
	}
	wg.Wait()
	// Every request was captured (buffered) before its response was sent.
	for i := 0; i < 8; i++ {
		r := <-reqs
		if a := r.Header.Values("Authorization"); len(a) != 1 || !allowed[a[0]] {
			t.Errorf("request %d: Authorization = %q, want one of the tokens set", i, a)
		}
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (text/event-stream returns the raw response)
func TestInvoke_StreamingResponse(t *testing.T) {
	next := make(chan struct{})
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		for i := 1; i <= 3; i++ {
			_, _ = fmt.Fprintf(w, "data: event-%d\n\n", i)
			fl.Flush()
			select {
			case <-next:
			case <-r.Context().Done():
				return
			}
		}
	})
	c := newClient(t, srv, nil)
	resp := mustInvoke(t, c, "stream", &InvokeOptions{Timeout: 5 * time.Second})
	defer func() { _ = resp.Close() }()
	if resp.MediaType() != "text/event-stream" {
		t.Fatalf("media type %q", resp.MediaType())
	}
	sc := bufio.NewScanner(resp.Body)
	for i := 1; i <= 3; i++ {
		// Each event must be readable before the server sends the next,
		// proving the body is streamed rather than buffered.
		var line string
		for sc.Scan() {
			if line = sc.Text(); line != "" {
				break
			}
		}
		if want := fmt.Sprintf("data: event-%d", i); line != want {
			t.Fatalf("event %d: got %q (err %v)", i, line, sc.Err())
		}
		next <- struct{}{}
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (options.timeout); test/spec/timeout.spec.ts
func TestInvoke_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("partial") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "start")
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	c := newClient(t, srv, nil)

	start := time.Now()
	_, err := c.Invoke(context.Background(), "slow", &InvokeOptions{Timeout: 50 * time.Millisecond})
	var fe *FetchError
	if !errors.As(err, &fe) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want *FetchError wrapping DeadlineExceeded, got %T %v", err, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not applied")
	}

	// The timeout also bounds reading the streamed body.
	resp := mustInvoke(t, c, "slow?partial=1", &InvokeOptions{Timeout: 100 * time.Millisecond})
	data, err := resp.Bytes()
	if string(data) != "start" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("body %q err %v", data, err)
	}

	// A fast response within the timeout succeeds.
	fast, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") })
	fc := newClient(t, fast, nil)
	txt, err := mustInvoke(t, fc, "hello", &InvokeOptions{Timeout: time.Second}).Text()
	if err != nil || txt != "ok" {
		t.Fatalf("text %q err %v", txt, err)
	}
}

// upstream: functions-js src/types.ts FunctionsHttpError; test/spec/errors.spec.ts
func TestInvoke_HTTPError(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"bad input"}`)
	})
	c := newClient(t, srv, nil)
	resp, err := c.Invoke(context.Background(), "hello", nil)
	if resp != nil {
		t.Fatal("response should be nil on error")
	}
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("want *HTTPError, got %T %v", err, err)
	}
	if he.StatusCode != http.StatusBadRequest || he.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("got %+v", he)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := he.DecodeJSON(&body); err != nil || body.Error != "bad input" {
		t.Fatalf("DecodeJSON %v %+v", err, body)
	}
	if !strings.Contains(he.Error(), "non-2xx") {
		t.Fatalf("message %q", he.Error())
	}
}

// upstream: functions-js src/types.ts FunctionsRelayError; test/spec/errors.spec.ts
func TestInvoke_RelayError(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-relay-error", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"message":"relay failed"}`)
	})
	c := newClient(t, srv, nil)
	_, err := c.Invoke(context.Background(), "hello", nil)
	var re *RelayError
	if !errors.As(err, &re) {
		t.Fatalf("want *RelayError, got %T %v", err, err)
	}
	var body map[string]string
	if err := re.DecodeJSON(&body); err != nil || body["message"] != "relay failed" || re.StatusCode != 200 {
		t.Fatalf("got %v %+v", err, re)
	}
	var he *HTTPError
	if errors.As(err, &he) {
		t.Fatal("relay error must not match HTTPError")
	}
}

// upstream: functions-js src/types.ts FunctionsFetchError
func TestInvoke_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	c, err := New(Config{URL: u + "/functions/v1", APIKey: legacyKey})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Invoke(context.Background(), "hello", nil)
	var fe *FetchError
	if !errors.As(err, &fe) || fe.Unwrap() == nil {
		t.Fatalf("want *FetchError, got %T %v", err, err)
	}
	if strings.Contains(err.Error(), legacyKey) {
		t.Fatal("error leaks API key")
	}
}

func TestInvoke_FunctionName(t *testing.T) {
	srv, reqs := newServer(t, nil)
	c := newClient(t, srv, nil)

	_ = mustInvoke(t, c, "api/users/a b?x=1", nil).Close()
	got := <-reqs
	if got.Path != "/functions/v1/api/users/a%20b" || got.Query.Get("x") != "1" {
		t.Fatalf("path %q query %v", got.Path, got.Query)
	}

	for _, bad := range []string{"", "  ", "/abs", "../rest/v1/users", "fn/./x", "fn/..", "?x=1", "fn?%zz"} {
		if _, err := c.Invoke(context.Background(), bad, nil); err == nil {
			t.Errorf("name %q: expected error", bad)
		}
	}
	//nolint:staticcheck // deliberately passing a nil context
	if _, err := c.Invoke(nil, "hello", nil); err == nil {
		t.Error("expected error for nil context")
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (application/json response parsed into data)
func TestInvokeJSON(t *testing.T) {
	srv, reqs := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/functions/v1/empty" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":42,"tags":["a"]}`)
	})
	c := newClient(t, srv, nil)
	type out struct {
		ID   int      `json:"id"`
		Tags []string `json:"tags"`
	}
	v, err := InvokeJSON[out](context.Background(), c, "thing", &InvokeOptions{Body: map[string]int{"id": 42}})
	if err != nil || v.ID != 42 || len(v.Tags) != 1 {
		t.Fatalf("got %+v %v", v, err)
	}
	<-reqs

	v, err = InvokeJSON[out](context.Background(), c, "empty", nil)
	if err != nil || v.ID != 0 {
		t.Fatalf("empty: %+v %v", v, err)
	}
	<-reqs

	bad, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "not json") })
	if _, err := InvokeJSON[out](context.Background(), newClient(t, bad, nil), "x", nil); err == nil {
		t.Fatal("expected decode error")
	}
	if _, err := InvokeJSON[out](context.Background(), c, "", nil); err == nil {
		t.Fatal("expected invoke error")
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (default text response)
func TestResponseHelpers(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = io.WriteString(w, "plain")
	})
	c := newClient(t, srv, func(cfg *Config) {
		cfg.RequestEditors = []func(*http.Request) error{func(r *http.Request) error {
			r.Header.Set("Traceparent", "00-abc-def-01")
			return nil
		}}
	})
	resp := mustInvoke(t, c, "hello", nil)
	if resp.MediaType() != "text/plain" {
		t.Fatalf("media %q", resp.MediaType())
	}
	txt, err := resp.Text()
	if err != nil || txt != "plain" {
		t.Fatalf("%q %v", txt, err)
	}

	failing, err := New(Config{URL: srv.URL, RequestEditors: []func(*http.Request) error{
		func(*http.Request) error { return errors.New("editor failed") },
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Invoke(context.Background(), "hello", nil); err == nil {
		t.Fatal("expected editor error")
	}
}
