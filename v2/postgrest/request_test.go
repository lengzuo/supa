package postgrest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"testing"
	"time"
)

// upstream: postgrest-js src/PostgrestBuilder.ts (URLSearchParams keeps insertion order)
func TestQueryParamOrder(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	_, err := c.From("users").Select("id, name").
		Eq("z", 1).
		Eq("a", "x y&z").
		Order("name").
		Gt("m", 2).
		Limit(5).
		Match(map[string]any{"k2": 2, "k1": 1}).
		Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "raw query", f.last(t).RawQuery,
		"select=id%2Cname&z=eq.1&a=eq.x+y%26z&order=name.asc&m=gt.2&limit=5&k1=eq.1&k2=eq.2")
}

func TestZeroValueBuilders(t *testing.T) {
	ctx := context.Background()
	var nilClient *Client
	cases := map[string]FilterBuilder{
		"filter_builder":      {},
		"query_builder":       QueryBuilder{}.Select("*").Eq("id", 1),
		"query_builder_write": QueryBuilder{}.Insert(map[string]int{"id": 1}),
		"nil_client_from":     nilClient.From("users").Select("*"),
		"nil_client_rpc":      nilClient.RPC("fn", nil),
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := q.Execute(ctx); err == nil {
				t.Error("Execute: expected error")
			}
			if _, err := q.ExecuteInto(ctx, new(any)); err == nil {
				t.Error("ExecuteInto: expected error")
			}
			if _, _, err := ExecuteTo[[]int](ctx, q); err == nil {
				t.Error("ExecuteTo: expected error")
			}
		})
	}
}

// upstream: postgrest-js src/fetchWithRetry.ts (parseInt(Retry-After, 10))
func TestParseRetryAfter(t *testing.T) {
	tests := map[string]time.Duration{
		"":                          0,
		"7":                         7 * time.Second,
		" 7 ":                       7 * time.Second,
		"1.5":                       time.Second,
		"2s":                        2 * time.Second,
		"+3":                        3 * time.Second,
		"-3":                        0,
		"abc":                       0,
		"Wed, 21 Oct 2015 07:28:00": 0,
		"99999999999999999999999":   time.Duration(math.MaxInt64/int64(time.Second)) * time.Second,
	}
	for in, want := range tests {
		assertEq(t, fmt.Sprintf("parseRetryAfter(%q)", in), parseRetryAfter(in), want)
	}

	h, _ := retryHandler(1, 503, "Retry-After", "1.5")
	c, _, delays := newFake(t, h)
	if _, err := c.From("users").Select("*").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "delay", fmt.Sprint(*delays), fmt.Sprint([]time.Duration{time.Second}))
}

func TestRetryPolicyDelayOverflow(t *testing.T) {
	p := RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Duration(math.MaxInt64)}
	assertEq(t, "attempt 10", p.delay(10), 1024*time.Second)
	for _, attempt := range []int{34, 40, 62, 63, 64, 1000} {
		assertEq(t, fmt.Sprintf("delay(%d)", attempt), p.delay(attempt), time.Duration(math.MaxInt64))
	}
	big := RetryPolicy{BaseDelay: time.Duration(1) << 61, MaxDelay: time.Duration(math.MaxInt64)}
	assertEq(t, "big base attempt 1", big.delay(1), time.Duration(1)<<62)
	assertEq(t, "big base attempt 2", big.delay(2), time.Duration(math.MaxInt64))
	assertEq(t, "negative attempt", RetryPolicy{}.delay(-1), 30*time.Second)
}

func TestSleepCtx(t *testing.T) {
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Errorf("zero sleep: %v", err)
	}
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("short sleep: %v", err)
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if err := sleepCtx(done, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("zero sleep on cancelled ctx: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	start := time.Now()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled sleep: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("sleep not interrupted")
	}
}

// upstream: postgrest-js src/fetchWithRetry.ts sleep (abort during backoff)
func TestRetryCancelledDuringBackoff(t *testing.T) {
	hit := make(chan struct{}, 10)
	c, f, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
		w.WriteHeader(http.StatusServiceUnavailable)
	}, func(cfg *Config) { cfg.Retry = &RetryPolicy{BaseDelay: time.Hour} })
	c.sleepFunc = sleepCtx // the real, context-aware sleep
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-hit
		time.Sleep(10 * time.Millisecond) // let the client enter the backoff sleep
		cancel()
	}()
	start := time.Now()
	_, err := c.From("users").Select("*").Execute(ctx)
	if time.Since(start) > 5*time.Second {
		t.Fatal("backoff sleep not interrupted by cancellation")
	}
	var pe *Error
	if !errors.As(err, &pe) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	assertEq(t, "hint", pe.Hint, "Request was aborted (timeout or manual cancellation)")
	assertEq(t, "attempts", len(f.requests()), 1)
}

// upstream: postgrest-js src/PostgrestBuilder.ts (AbortError hint); test/timeout-and-url-length.test.ts
func TestTimeoutWhileReadingBody(t *testing.T) {
	release := make(chan struct{})
	c, _, _ := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "[")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}, func(cfg *Config) { cfg.Timeout = 50 * time.Millisecond })
	defer close(release)
	_, err := c.From("users").Select("*").Execute(context.Background())
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err does not unwrap to DeadlineExceeded: %v", err)
	}
	assertEq(t, "status", pe.Status, http.StatusOK)
	assertEq(t, "hint", pe.Hint, "Request was aborted (timeout or manual cancellation)")
}

// upstream: postgrest-js src/PostgrestClient.ts getOpenApiSpec (returns the parsed document as-is)
func TestGetOpenAPISpecUntypedDocument(t *testing.T) {
	doc := `{"swagger":2,"info":"custom","paths":[]}`
	c, _, _ := newFake(t, jsonReply(200, doc))
	spec, err := c.GetOpenAPISpec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "raw", string(spec.Raw), doc)
	assertEq(t, "swagger", spec.Swagger, "")
	if spec.Info != nil || spec.Paths != nil {
		t.Errorf("typed fields populated: %+v", spec)
	}
}
