package postgrest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// upstream: postgrest-js src/PostgrestBuilder.ts processResponse; test/fetch-errors.test.ts
func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantErr    *Error
		wantStatus int
		wantData   string
	}{
		{"postgrest_error", 400, `{"code":"42703","message":"column users.x does not exist","details":null,"hint":"Perhaps you meant users.id"}`,
			&Error{Code: "42703", Message: "column users.x does not exist", Hint: "Perhaps you meant users.id", Status: 400}, 0, ""},
		{"permission", 401, `{"code":"42501","message":"permission denied for table users","details":"d","hint":"GRANT SELECT ON public.users TO anon;"}`,
			&Error{Code: "42501", Message: "permission denied for table users", Details: "d", Hint: "GRANT SELECT ON public.users TO anon;", Status: 401}, 0, ""},
		{"non_json", 502, `<html>Bad Gateway</html>`, &Error{Message: "<html>Bad Gateway</html>", Status: 502}, 0, ""},
		{"empty_500", 500, ``, &Error{Message: "Internal Server Error", Status: 500}, 0, ""},
		{"not_found_empty", 404, ``, nil, 204, ""},
		{"not_found_array", 404, `[]`, nil, 200, "[]"},
		{"ok_non_json", 200, `not json`, &Error{Message: "not json", Status: 200}, 0, ""},
		{"ok_truncated_json", 200, `[{"id":1`, &Error{Message: `[{"id":1`, Status: 200}, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _, _ := newFake(t, jsonReply(tt.status, tt.body))
			resp, err := c.From("users").Select("*").Execute(context.Background())
			if tt.wantErr != nil {
				var pe *Error
				if !errors.As(err, &pe) {
					t.Fatalf("err = %v", err)
				}
				assertEq(t, "code", pe.Code, tt.wantErr.Code)
				assertEq(t, "message", pe.Message, tt.wantErr.Message)
				assertEq(t, "details", pe.Details, tt.wantErr.Details)
				assertEq(t, "hint", pe.Hint, tt.wantErr.Hint)
				assertEq(t, "status", pe.Status, tt.wantErr.Status)
				if resp != nil {
					t.Error("response should be nil on error")
				}
				if !strings.Contains(pe.Error(), tt.wantErr.Message) {
					t.Errorf("Error() = %q", pe.Error())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertEq(t, "status", resp.Status, tt.wantStatus)
			assertEq(t, "data", string(resp.Data), tt.wantData)
		})
	}
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts abortSignal
func TestRequestCancellation(t *testing.T) {
	release := make(chan struct{})
	c, _, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err := c.From("users").Select("*").Execute(ctx)
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err does not unwrap to context.Canceled: %v", err)
	}
	assertEq(t, "status", pe.Status, 0)
	assertEq(t, "hint", pe.Hint, "Request was aborted (timeout or manual cancellation)")
}

// upstream: postgrest-js src/PostgrestClient.ts constructor (timeout); test/timeout-and-url-length.test.ts
func TestRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	c, f, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, func(cfg *Config) {
		cfg.Timeout = 30 * time.Millisecond
		cfg.URLLengthLimit = 10
	})
	defer close(release)
	start := time.Now()
	_, err := c.From("users").Select("*").Eq("name", strings.Repeat("x", 50)).Execute(context.Background())
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not applied")
	}
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err does not unwrap to DeadlineExceeded: %v", err)
	}
	if !strings.Contains(pe.Hint, "Request was aborted") || !strings.Contains(pe.Hint, "characters") {
		t.Errorf("hint = %q", pe.Hint)
	}
	// Timeouts are never retried.
	assertEq(t, "attempts", len(f.requests()), 1)
}

func retryHandler(failures int, status int, headers ...string) (http.HandlerFunc, *int32) {
	var n int32
	return func(w http.ResponseWriter, r *http.Request) {
		if int(atomic.AddInt32(&n, 1)) <= failures {
			for i := 0; i+1 < len(headers); i += 2 {
				w.Header().Set(headers[i], headers[i+1])
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"code":"PGRST002","message":"schema cache"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"id":1}]`)
	}, &n
}

// upstream: postgrest-js src/fetchWithRetry.ts; test/retry.test.ts
func TestRetry(t *testing.T) {
	t.Run("get_520_retried_with_count_header", func(t *testing.T) {
		h, _ := retryHandler(2, 520)
		c, f, delays := newFake(t, h)
		resp, err := c.From("users").Select("*").Execute(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		assertEq(t, "data", string(resp.Data), `[{"id":1}]`)
		reqs := f.requests()
		assertEq(t, "attempts", len(reqs), 3)
		assertEq(t, "first retry count", reqs[0].Header.Get("X-Retry-Count"), "")
		assertEq(t, "retry 1", reqs[1].Header.Get("X-Retry-Count"), "1")
		assertEq(t, "retry 2", reqs[2].Header.Get("X-Retry-Count"), "2")
		assertEq(t, "delays", fmt.Sprint(*delays), fmt.Sprint([]time.Duration{time.Second, 2 * time.Second}))
	})
	t.Run("exhausted_after_3_retries", func(t *testing.T) {
		h, _ := retryHandler(10, 503)
		c, f, delays := newFake(t, h)
		_, err := c.From("users").Select("*").Execute(context.Background())
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != "PGRST002" || pe.Status != 503 {
			t.Fatalf("err = %v", err)
		}
		assertEq(t, "attempts", len(f.requests()), 4)
		assertEq(t, "delays", fmt.Sprint(*delays), fmt.Sprint([]time.Duration{time.Second, 2 * time.Second, 4 * time.Second}))
	})
	t.Run("retry_after_header", func(t *testing.T) {
		h, _ := retryHandler(1, 503, "Retry-After", "7")
		c, f, delays := newFake(t, h)
		if _, err := c.From("users").Select("*").Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertEq(t, "attempts", len(f.requests()), 2)
		assertEq(t, "delay", fmt.Sprint(*delays), fmt.Sprint([]time.Duration{7 * time.Second}))
	})
	t.Run("post_not_retried", func(t *testing.T) {
		h, _ := retryHandler(10, 520)
		c, f, _ := newFake(t, h)
		if _, err := c.From("users").Insert(map[string]int{"id": 1}).Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "attempts", len(f.requests()), 1)
		if _, err := c.RPC("fn", nil).Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "rpc attempts", len(f.requests()), 2)
	})
	t.Run("rpc_get_retried", func(t *testing.T) {
		h, _ := retryHandler(1, 520)
		c, f, _ := newFake(t, h)
		if _, err := c.RPC("fn", nil, RPCOptions{Get: true}).Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertEq(t, "attempts", len(f.requests()), 2)
	})
	t.Run("other_status_not_retried", func(t *testing.T) {
		h, _ := retryHandler(10, 500)
		c, f, _ := newFake(t, h)
		if _, err := c.From("users").Select("*").Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "attempts", len(f.requests()), 1)
	})
	t.Run("disabled_globally", func(t *testing.T) {
		h, _ := retryHandler(10, 520)
		c, f, _ := newFake(t, h, func(cfg *Config) { cfg.Retry = &RetryPolicy{Disabled: true} })
		if _, err := c.From("users").Select("*").Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "attempts", len(f.requests()), 1)
		// Preserved across Schema.
		if _, err := c.Schema("other").From("users").Select("*").Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "attempts after schema", len(f.requests()), 2)
		// Per-request opt-in overrides the global setting.
		h2, _ := retryHandler(1, 520)
		c2, f2, _ := newFake(t, h2, func(cfg *Config) { cfg.Retry = &RetryPolicy{Disabled: true} })
		if _, err := c2.From("users").Select("*").Retry(true).Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertEq(t, "opt-in attempts", len(f2.requests()), 2)
	})
	t.Run("disabled_per_request", func(t *testing.T) {
		h, _ := retryHandler(10, 520)
		c, f, _ := newFake(t, h)
		if _, err := c.From("users").Select("*").Retry(false).Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "attempts", len(f.requests()), 1)
	})
	t.Run("custom_policy", func(t *testing.T) {
		h, _ := retryHandler(10, 520)
		c, f, delays := newFake(t, h, func(cfg *Config) {
			cfg.Retry = &RetryPolicy{MaxRetries: 1, BaseDelay: 10 * time.Millisecond}
		})
		if _, err := c.From("users").Select("*").Execute(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		assertEq(t, "attempts", len(f.requests()), 2)
		assertEq(t, "delays", fmt.Sprint(*delays), fmt.Sprint([]time.Duration{10 * time.Millisecond}))
	})
	t.Run("network_error_get_retried", func(t *testing.T) {
		var calls int32
		rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if atomic.AddInt32(&calls, 1) == 1 {
				return nil, errors.New("connection reset")
			}
			return http.DefaultTransport.RoundTrip(r)
		})
		c, f, _ := newFake(t, jsonReply(200, `[]`), func(cfg *Config) { cfg.HTTPClient = &http.Client{Transport: rt} })
		if _, err := c.From("users").Select("*").Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertEq(t, "calls", atomic.LoadInt32(&calls), int32(2))
		assertEq(t, "server requests", len(f.requests()), 1)
	})
	t.Run("network_error_post_not_retried", func(t *testing.T) {
		var calls int32
		rt := roundTripFunc(func(*http.Request) (*http.Response, error) {
			atomic.AddInt32(&calls, 1)
			return nil, errors.New("network error")
		})
		c, _, _ := newFake(t, nil, func(cfg *Config) { cfg.HTTPClient = &http.Client{Transport: rt} })
		_, err := c.From("users").Insert(map[string]int{"id": 1}).Execute(context.Background())
		var pe *Error
		if !errors.As(err, &pe) || !strings.Contains(pe.Message, "network error") || pe.Status != 0 {
			t.Fatalf("err = %v", err)
		}
		assertEq(t, "calls", atomic.LoadInt32(&calls), int32(1))
	})
	t.Run("openapi_retried", func(t *testing.T) {
		var n int32
		c, f, _ := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
			if atomic.AddInt32(&n, 1) == 1 {
				w.WriteHeader(520)
				return
			}
			_, _ = io.WriteString(w, `{"swagger":"2.0","info":{},"paths":{}}`)
		})
		if _, err := c.GetOpenAPISpec(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertEq(t, "attempts", len(f.requests()), 2)
	})
}

func TestRetryPolicyDelay(t *testing.T) {
	var p RetryPolicy
	for i, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
		assertEq(t, fmt.Sprintf("delay(%d)", i), p.delay(i), want)
	}
	assertEq(t, "huge attempt", p.delay(1000), 30*time.Second)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestBuilderImmutability checks that builder methods never modify their
// receiver, so partially built queries can be reused.
func TestBuilderImmutability(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	base := c.From("users").Select("*").Eq("status", "ONLINE")

	derived := []FilterBuilder{
		base.Eq("id", 1),
		base.Order("id").Limit(1),
		base.Single(),
		base.CSV(),
		base.SetHeader("X-A", "1"),
		base.Rollback(),
		base.StripNulls(),
		base.Range(1, 2),
		base.MaybeSingle(),
		base.Retry(false),
		base.Select("id"),
	}
	for _, d := range derived {
		if _, err := d.Execute(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := base.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "raw query", fmt.Sprint(r.Query), fmt.Sprint(map[string][]string{"select": {"*"}, "status": {"eq.ONLINE"}}))
	assertEq(t, "accept", r.Header.Get("Accept"), "")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "")
	assertEq(t, "x-a", r.Header.Get("X-A"), "")

	// Appending to a shared prefix must not alias between siblings.
	p := base.Eq("a", 1)
	s1, s2 := p.Eq("b", 1), p.Eq("c", 1)
	if _, err := s1.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	q1 := f.last(t).Query
	if _, err := s2.Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	q2 := f.last(t).Query
	if q1.Has("c") || q2.Has("b") || !q1.Has("b") || !q2.Has("c") {
		t.Errorf("siblings alias: %v / %v", q1, q2)
	}

	// QueryBuilder is reusable too.
	qb := c.From("users")
	_ = qb.Insert(map[string]int{"id": 1}, InsertOptions{Count: CountExact})
	if _, err := qb.Select("*").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "qb prefer", f.last(t).Header.Get("Prefer"), "")
}

// TestBuilderConcurrentUse shares one partially built query between
// goroutines that extend and execute it; run with -race.
func TestBuilderConcurrentUse(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	base := c.From("users").Select("*").Eq("status", "ONLINE").Order("id")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := base.Eq("id", i).Order("name").SetHeader("Authorization", fmt.Sprintf("Bearer token-%d", i))
			if i%2 == 0 {
				q = q.Single()
			}
			if _, err := q.Execute(context.Background()); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	reqs := f.requests()
	assertEq(t, "requests", len(reqs), 32)
	for _, r := range reqs {
		id := strings.TrimPrefix(r.Query.Get("id"), "eq.")
		assertEq(t, "token matches id", r.Header.Get("Authorization"), "Bearer token-"+id)
		assertEq(t, "order", r.Query.Get("order"), "id.asc,name.asc")
		assertEq(t, "status", r.Query.Get("status"), "eq.ONLINE")
		assertEq(t, "one id", len(r.Query["id"]), 1)
	}
}

func TestNilContext(t *testing.T) {
	c, _, _ := newFake(t, jsonReply(200, `[]`))
	//nolint:staticcheck // deliberately passing a nil context
	if _, err := c.From("users").Select("*").Execute(nil); err == nil {
		t.Error("expected error for nil context")
	}
}
