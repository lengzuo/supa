package functions

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// upstream: functions-js src/FunctionsClient.ts invoke (`if (functionArgs && ...)`: falsy bodies are not sent)
func TestInvoke_FalsyBodiesSendNoBody(t *testing.T) {
	srv, reqs := newServer(t, nil)
	c := newClient(t, srv, nil)
	type payload struct{ N int }
	tests := []struct {
		name string
		body any
	}{
		{"nil []byte", []byte(nil)},
		{"empty []byte", []byte{}},
		{"nil struct pointer", (*payload)(nil)},
		{"nil map", map[string]any(nil)},
		{"nil slice", []int(nil)},
		{"nil reader pointer", (*bytes.Buffer)(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = mustInvoke(t, c, "hello", &InvokeOptions{Body: tt.body}).Close()
			got := <-reqs
			if ct := got.Header.Get("Content-Type"); ct != "" {
				t.Errorf("Content-Type = %q, want none", ct)
			}
			if got.Body != "" {
				t.Errorf("body = %q, want none", got.Body)
			}
		})
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (headers: {..._headers, ...this.headers, ...headers})
func TestInvoke_ClientContentTypeOverridesInferred(t *testing.T) {
	srv, reqs := newServer(t, nil)
	c := newClient(t, srv, func(cfg *Config) {
		cfg.Headers = http.Header{"content-type": {"application/vnd.client+json"}}
	})
	_ = mustInvoke(t, c, "hello", &InvokeOptions{Body: map[string]int{"n": 1}}).Close()
	got := <-reqs
	if ct := got.Header.Values("Content-Type"); len(ct) != 1 || ct[0] != "application/vnd.client+json" {
		t.Fatalf("Content-Type = %q, want the client header", ct)
	}
	if got.Body != `{"n":1}` {
		t.Fatalf("body = %q", got.Body)
	}
	// Per-call headers still win over client headers.
	_ = mustInvoke(t, c, "hello", &InvokeOptions{Body: "x", Headers: http.Header{"Content-Type": {"text/csv"}}}).Close()
	if ct := (<-reqs).Header.Values("Content-Type"); len(ct) != 1 || ct[0] != "text/csv" {
		t.Fatalf("Content-Type = %q, want the per-call header", ct)
	}
}

// upstream: functions-js src/FunctionsClient.ts invoke (`isRelayError === 'true'`)
func TestInvoke_RelayErrorExactTrue(t *testing.T) {
	for _, v := range []string{"True", "TRUE", "1", "false"} {
		srv, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("x-relay-error", v)
			_, _ = io.WriteString(w, "ok")
		})
		c := newClient(t, srv, nil)
		txt, err := mustInvoke(t, c, "hello", nil).Text()
		if err != nil || txt != "ok" {
			t.Fatalf("x-relay-error %q: text %q err %v", v, txt, err)
		}
	}
}

// upstream: functions-js src/types.ts FunctionsRelayError message
func TestRelayError_Error(t *testing.T) {
	e := &RelayError{StatusCode: 502, Body: []byte(`{"message":"boom"}`)}
	if got, want := e.Error(), "functions: relay error invoking the Edge Function (status 502)"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	var v struct{ Message string }
	if err := e.DecodeJSON(&v); err != nil || v.Message != "boom" {
		t.Fatalf("DecodeJSON: %v %+v", err, v)
	}
}

// FetchError names the failed stage and keeps the cause inspectable.
// upstream: functions-js src/types.ts FunctionsFetchError
func TestFetchError_Messages(t *testing.T) {
	tokenErr := errors.New("token store unavailable")
	srv, _ := newServer(t, nil)
	c := newClient(t, srv, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "", tokenErr }
	})
	_, err := c.Invoke(context.Background(), "hello", nil)
	var fe *FetchError
	if !errors.As(err, &fe) || !errors.Is(err, tokenErr) {
		t.Fatalf("want *FetchError wrapping the token error, got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "failed to prepare the request") || strings.Contains(err.Error(), "failed to send") {
		t.Fatalf("message = %q", err)
	}

	editorErr := errors.New("tracer down")
	c = newClient(t, srv, func(cfg *Config) {
		cfg.RequestEditors = []func(*http.Request) error{func(*http.Request) error { return editorErr }}
	})
	if _, err := c.Invoke(context.Background(), "hello", nil); !errors.Is(err, editorErr) || !strings.Contains(err.Error(), "failed to prepare the request") {
		t.Fatalf("editor error = %v", err)
	}

	// A body read failure is reported as such.
	partial, _ := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "start")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	pc := newClient(t, partial, nil)
	resp := mustInvoke(t, pc, "slow", &InvokeOptions{Timeout: 50 * time.Millisecond})
	_, err = resp.Bytes()
	if !errors.As(err, &fe) || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "failed to read the Edge Function response body") {
		t.Fatalf("body read error = %v", err)
	}

	// A zero FetchError still formats.
	if got := (&FetchError{}).Error(); got != "functions: failed to send a request to the Edge Function" {
		t.Fatalf("zero FetchError = %q", got)
	}
}

// The configured request editors (e.g. trace propagation) reach the server.
func TestInvoke_RequestEditorTraceparent(t *testing.T) {
	srv, reqs := newServer(t, nil)
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	c := newClient(t, srv, func(cfg *Config) {
		cfg.RequestEditors = []func(*http.Request) error{func(r *http.Request) error {
			r.Header.Set("Traceparent", tp)
			return nil
		}}
	})
	_ = mustInvoke(t, c, "hello", nil).Close()
	if got := (<-reqs).Header.Get("Traceparent"); got != tp {
		t.Fatalf("Traceparent = %q, want %q", got, tp)
	}
}
