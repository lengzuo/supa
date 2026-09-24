package storage

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
)

// Dot-segments and empty names must be rejected before any request (the
// /v1/config call included), so a normalizing proxy can never turn
// DELETE .../tables/.. into an operation on the parent resource.
func TestIcebergRejectsDotSegments(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{}`)
	})
	cat, err := c.Analytics().From("my-bucket")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ok := IcebergTableIdentifier{Namespace: []string{"ns"}, Name: "events"}
	tbl := func(ns []string, name string) IcebergTableIdentifier {
		return IcebergTableIdentifier{Namespace: ns, Name: name}
	}
	calls := map[string]func() error{
		"DropTable name ..":        func() error { return cat.DropTable(ctx, tbl([]string{"ns"}, ".."), nil) },
		"DropTable name .":         func() error { return cat.DropTable(ctx, tbl([]string{"ns"}, "."), nil) },
		"DropTable ns ..":          func() error { return cat.DropTable(ctx, tbl([]string{".."}, "t"), nil) },
		"DropTable ns level2 ..":   func() error { return cat.DropTable(ctx, tbl([]string{"a", ".."}, "t"), nil) },
		"DropTable ns empty level": func() error { return cat.DropTable(ctx, tbl([]string{"a", ""}, "t"), nil) },
		"LoadTable name ..":        func() error { _, err := cat.LoadTable(ctx, tbl([]string{"ns"}, ".."), nil); return err },
		"TableExists ns .":         func() error { _, err := cat.TableExists(ctx, tbl([]string{"."}, "t")); return err },
		"UpdateTable name ..": func() error {
			_, err := cat.UpdateTable(ctx, tbl([]string{"ns"}, ".."), IcebergCommitTableRequest{})
			return err
		},
		"CreateTable name ..": func() error {
			_, err := cat.CreateTable(ctx, []string{"ns"}, IcebergCreateTableRequest{Name: ".."})
			return err
		},
		"CreateTable ns ..": func() error {
			_, err := cat.CreateTable(ctx, []string{".."}, IcebergCreateTableRequest{Name: "t"})
			return err
		},
		"RegisterTable name .": func() error {
			_, err := cat.RegisterTable(ctx, []string{"ns"}, IcebergRegisterTableRequest{Name: ".", MetadataLocation: "s3://m"})
			return err
		},
		"RegisterTable ns ..": func() error {
			_, err := cat.RegisterTable(ctx, []string{".."}, IcebergRegisterTableRequest{Name: "t", MetadataLocation: "s3://m"})
			return err
		},
		"RenameTable dest name ..": func() error { return cat.RenameTable(ctx, ok, tbl([]string{"ns"}, "..")) },
		"RenameTable dest ns ..":   func() error { return cat.RenameTable(ctx, ok, tbl([]string{".."}, "t")) },
		"RenameTable source .":     func() error { return cat.RenameTable(ctx, tbl([]string{"ns"}, "."), ok) },
		"DropNamespace ..":         func() error { return cat.DropNamespace(ctx, []string{".."}) },
		"CreateNamespace a/..":     func() error { _, err := cat.CreateNamespace(ctx, []string{"a", ".."}, nil); return err },
		"LoadNamespaceMetadata .":  func() error { _, err := cat.LoadNamespaceMetadata(ctx, []string{"."}); return err },
		"NamespaceExists ..":       func() error { _, err := cat.NamespaceExists(ctx, []string{"..", "x"}); return err },
		"UpdateNamespaceProps ..": func() error {
			_, err := cat.UpdateNamespaceProperties(ctx, []string{".."}, IcebergUpdateNamespacePropertiesParams{})
			return err
		},
		"ListTables ..":             func() error { _, err := cat.ListTables(ctx, []string{".."}, nil); return err },
		"Analytics.From ..":         func() error { _, err := c.Analytics().From(".."); return err },
		"Analytics.From .":          func() error { _, err := c.Analytics().From("."); return err },
		"Analytics.DeleteBucket ..": func() error { _, err := c.Analytics().DeleteBucket(ctx, ".."); return err },
		"Analytics.DeleteBucket .":  func() error { _, err := c.Analytics().DeleteBucket(ctx, "."); return err },
		"Analytics.CreateBucket ..": func() error { _, err := c.Analytics().CreateBucket(ctx, ".."); return err },
		"Analytics.CreateBucket #":  func() error { _, err := c.Analytics().CreateBucket(ctx, "bucket#1"); return err },
		"Analytics.CreateBucket /":  func() error { _, err := c.Analytics().CreateBucket(ctx, "a/b"); return err },
		"Analytics.DeleteBucket %":  func() error { _, err := c.Analytics().DeleteBucket(ctx, "a%2Fb"); return err },
		"Analytics.DeleteBucket sp": func() error { _, err := c.Analytics().DeleteBucket(ctx, " a"); return err },
		"DropTable ns 0x1F":         func() error { return cat.DropTable(ctx, tbl([]string{"a\x1fb"}, "t"), nil) },
		"DropTable ns slash":        func() error { return cat.DropTable(ctx, tbl([]string{"a/b"}, "t"), nil) },
		"DropTable ns backslash":    func() error { return cat.DropTable(ctx, tbl([]string{`a\b`}, "t"), nil) },
		"DropTable name slash":      func() error { return cat.DropTable(ctx, tbl([]string{"ns"}, "a/../b"), nil) },
		"CreateTable name bslash": func() error {
			_, err := cat.CreateTable(ctx, []string{"ns"}, IcebergCreateTableRequest{Name: `a\b`})
			return err
		},
		"ListNamespaces parent 0x1F": func() error {
			_, err := cat.ListNamespaces(ctx, &IcebergListNamespacesOptions{Parent: []string{"a\x1fb"}})
			return err
		},
		"ListNamespaces parent ..": func() error {
			_, err := cat.ListNamespaces(ctx, &IcebergListNamespacesOptions{Parent: []string{".."}})
			return err
		},
	}
	for name, call := range calls {
		err := call()
		var ae *AnalyticsArgumentError
		if !errors.As(err, &ae) {
			t.Errorf("%s: err = %T %v, want *AnalyticsArgumentError", name, err, err)
		}
	}
	if n := len(reqs()); n != 0 {
		t.Fatalf("%d requests were sent for invalid arguments: %+v", n, reqs())
	}
}

// Legitimate names that merely contain dots or need escaping reach the
// server with the exact expected request URI.
func TestIcebergRequestURI(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusNoContent)
	})
	ctx := context.Background()
	if err := cat.DropTable(ctx, IcebergTableIdentifier{Namespace: []string{"a b", "c.d"}, Name: "t..1"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := cat.DropNamespace(ctx, []string{"...", "x:y?"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/storage/v1/iceberg/v1/srv-prefix/namespaces/a%20b%1Fc.d/tables/t..1?purgeRequested=false",
		"/storage/v1/iceberg/v1/srv-prefix/namespaces/...%1Fx%3Ay%3F",
	}
	for i, r := range reqs() {
		if r.Request.RequestURI != want[i] {
			t.Errorf("RequestURI = %q, want %q", r.Request.RequestURI, want[i])
		}
	}
}

// upstream: storage-js src/packages/StorageAnalyticsClient.ts deleteBucket (raw URI)
func TestAnalyticsRequestURI(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			analyticsWriteJSON(w, 404, `{"error":{"message":"nope","type":"NotFound","code":404}}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"message":"ok","namespaces":[]}`)
	})
	if _, err := c.Analytics().DeleteBucket(context.Background(), "a..b c"); err != nil {
		t.Fatal(err)
	}
	cat, err := c.Analytics().From("a..b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	want := []string{
		"/storage/v1/iceberg/bucket/a..b%20c",
		"/storage/v1/iceberg/v1/config?warehouse=a..b",
		"/storage/v1/iceberg/v1/a..b/namespaces",
	}
	if len(got) != len(want) {
		t.Fatalf("requests = %d", len(got))
	}
	for i := range want {
		if got[i].Request.RequestURI != want[i] {
			t.Errorf("RequestURI = %q, want %q", got[i].Request.RequestURI, want[i])
		}
	}
}

// The server prefix is used verbatim (it is already URL-encoded); unsafe
// prefixes are rejected and not cached.
func TestIcebergServerPrefix(t *testing.T) {
	var prefix atomic.Value
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			b, _ := json.Marshal(map[string]any{"defaults": map[string]string{}, "overrides": map[string]string{"prefix": prefix.Load().(string)}})
			analyticsWriteJSON(w, 200, string(b))
			return
		}
		analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
	})
	for _, bad := range []string{"../x", "a/%2E%2E", "a/./b", "a?b", "a#b", "a//b", "a b", "a/%zz",
		"x|%2F..%2Fadmin", "café%2F..%2Fadmin", "café%2F..", "a{b}", "..%2F..%2F..%2Fauth%2Fv1%2Fadmin",
		"a%5C..%5Cadmin", `a"b`, "a`b", "a^b", "a\\b", "%2F", "a%2", "a%G0", "a\x00b"} {
		prefix.Store(bad)
		cat, _ := c.Analytics().From("bkt")
		if _, err := cat.ListNamespaces(context.Background(), nil); err == nil {
			t.Errorf("prefix %q: expected error", bad)
		}
	}
	for _, r := range reqs() {
		if r.Path != "/storage/v1/iceberg/v1/config" {
			t.Fatalf("request sent with unsafe prefix: %s", r.Request.RequestURI)
		}
	}
	// An unsafe prefix is not cached: the same catalog refetches config.
	prefix.Store("x|%2F..%2Fadmin")
	unsafe, _ := c.Analytics().From("bkt")
	before := len(reqs())
	for i := 0; i < 2; i++ {
		if _, err := unsafe.ListNamespaces(context.Background(), nil); err == nil {
			t.Fatal("expected error")
		}
	}
	if got := len(reqs()) - before; got != 2 {
		t.Fatalf("config requests = %d, want 2", got)
	}
	n := len(reqs())

	prefix.Store("/a%2Fb/c/")
	cat, _ := c.Analytics().From("bkt")
	for i := 0; i < 2; i++ {
		if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	got := reqs()[n:]
	if len(got) != 3 {
		t.Fatalf("requests = %d, want 3 (config cached)", len(got))
	}
	if uri := got[1].Request.RequestURI; uri != "/storage/v1/iceberg/v1/a%2Fb/c/namespaces" {
		t.Fatalf("RequestURI = %q", uri)
	}
}

// Auth failures on /v1/config are returned and not cached.
func TestIcebergConfigAuthErrorNotCached(t *testing.T) {
	for _, status := range []int{401, 403, 419} {
		var configs atomic.Int32
		c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if r.URL.Path == "/storage/v1/iceberg/v1/config" {
				if configs.Add(1) == 1 {
					analyticsWriteJSON(w, status, `{"error":{"message":"denied","type":"NotAuthorizedException","code":401}}`)
					return
				}
				analyticsWriteJSON(w, 200, `{"defaults":{},"overrides":{"prefix":"p1"}}`)
				return
			}
			analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
		})
		cat, _ := c.Analytics().From("bkt")
		_, err := cat.ListNamespaces(context.Background(), nil)
		var ie *IcebergError
		if !errors.As(err, &ie) || ie.Status != status {
			t.Fatalf("status %d: err = %v", status, err)
		}
		if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		got := reqs()
		if configs.Load() != 2 || got[len(got)-1].Path != "/storage/v1/iceberg/v1/p1/namespaces" {
			t.Fatalf("status %d: configs=%d last=%s", status, configs.Load(), got[len(got)-1].Path)
		}
	}
}

// A hung /v1/config must not block other callers past their own deadline.
func TestIcebergConfigHangHonorsContext(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			once.Do(func() { close(entered) })
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			analyticsWriteJSON(w, 200, `{"defaults":{},"overrides":{"prefix":"p"}}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
	})
	cat, _ := c.Analytics().From("bkt")

	leaderDone := make(chan error, 1)
	go func() {
		_, err := cat.ListNamespaces(context.Background(), nil)
		leaderDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("config request never started")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := cat.ListNamespaces(ctx, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("waiter returned after %v", d)
	}

	close(release)
	select {
	case err := <-leaderDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader never finished")
	}
	if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

// If the leader's own context ends, a waiter retries under its context.
func TestIcebergConfigLeaderCanceled(t *testing.T) {
	entered := make(chan struct{}, 2)
	var configs atomic.Int32
	c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			if configs.Add(1) == 1 {
				entered <- struct{}{}
				<-r.Context().Done()
				return
			}
			analyticsWriteJSON(w, 200, `{"defaults":{},"overrides":{"prefix":"p"}}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
	})
	cat, _ := c.Analytics().From("bkt")
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := cat.ListNamespaces(leaderCtx, nil)
		leaderDone <- err
	}()
	<-entered
	waiterDone := make(chan error, 1)
	go func() {
		_, err := cat.ListNamespaces(context.Background(), nil)
		waiterDone <- err
	}()
	time.Sleep(20 * time.Millisecond) // let the waiter block on the in-flight call
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v", err)
	}
	select {
	case err := <-waiterDone:
		if err != nil {
			t.Fatalf("waiter err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter hung")
	}
}

func TestIcebergStructTypeJSON(t *testing.T) {
	b, err := json.Marshal(IcebergType{Struct: &IcebergStructType{}})
	if err != nil {
		t.Fatal(err)
	}
	analyticsAssertJSON(t, b, `{"type":"struct","fields":[]}`)
	b, err = json.Marshal(IcebergStructType{Fields: []IcebergStructField{
		{ID: 1, Name: "lat", Type: IcebergPrimitive("double"), Required: true, Doc: "latitude", WriteDefault: 0.5},
	}})
	if err != nil {
		t.Fatal(err)
	}
	analyticsAssertJSON(t, b, `{"type":"struct","fields":[{"id":1,"name":"lat","type":"double","required":true,"doc":"latitude","write-default":0.5}]}`)
	var back IcebergType
	if err := json.Unmarshal(b, &back); err != nil || back.Struct == nil || back.Struct.Fields[0].Name != "lat" {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}

// iceberg-js: serverPrefix = overrides?.prefix ?? defaults?.prefix; an
// empty (but present) override falls back to the warehouse.
func TestIcebergConfigPrefixPrecedence(t *testing.T) {
	for _, tc := range []struct{ config, want string }{
		{`{"defaults":{"prefix":"d"},"overrides":{"prefix":""}}`, "/storage/v1/iceberg/v1/bkt/namespaces"},
		{`{"defaults":{"prefix":"d"},"overrides":{}}`, "/storage/v1/iceberg/v1/d/namespaces"},
		{`{"defaults":{"prefix":"d"},"overrides":{"prefix":"o"}}`, "/storage/v1/iceberg/v1/o/namespaces"},
		{`{"defaults":{},"overrides":{"prefix":"/"}}`, "/storage/v1/iceberg/v1/bkt/namespaces"},
		// Documented divergence: null is present-but-empty, so the bucket
		// is used (iceberg-js `??` would pick defaults.prefix).
		{`{"defaults":{"prefix":"d"},"overrides":{"prefix":null}}`, "/storage/v1/iceberg/v1/bkt/namespaces"},
	} {
		c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if r.URL.Path == "/storage/v1/iceberg/v1/config" {
				analyticsWriteJSON(w, 200, tc.config)
				return
			}
			analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
		})
		cat, _ := c.Analytics().From("bkt")
		if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if got := reqs()[1].Request.RequestURI; got != tc.want {
			t.Errorf("config %s: RequestURI = %q, want %q", tc.config, got, tc.want)
		}
	}
}

// The bucket-name fallback is cached only when the server has no usable
// config endpoint (400/404/405/501); transient failures are retried.
func TestIcebergConfigFallbackCaching(t *testing.T) {
	for _, tc := range []struct {
		status int
		cached bool
	}{{400, true}, {404, true}, {405, true}, {501, true}, {429, false}, {500, false}, {502, false}, {503, false}} {
		var configs atomic.Int32
		c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if r.URL.Path == "/storage/v1/iceberg/v1/config" {
				configs.Add(1)
				analyticsWriteJSON(w, tc.status, `{"error":{"message":"x","type":"T","code":0}}`)
				return
			}
			analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
		})
		cat, _ := c.Analytics().From("bkt")
		for i := 0; i < 2; i++ {
			_, err := cat.ListNamespaces(context.Background(), nil)
			if tc.cached && err != nil {
				t.Fatalf("status %d: %v", tc.status, err)
			}
			var ie *IcebergError
			if !tc.cached && (!errors.As(err, &ie) || ie.Status != tc.status) {
				t.Fatalf("status %d: err = %v", tc.status, err)
			}
		}
		want := int32(2)
		if tc.cached {
			want = 1
		}
		if configs.Load() != want {
			t.Errorf("status %d: config requests = %d, want %d", tc.status, configs.Load(), want)
		}
	}
}

// A panic while fetching /v1/config becomes an error and never wedges
// the catalog.
func TestIcebergConfigPanicDoesNotWedge(t *testing.T) {
	var panicking atomic.Bool
	panicking.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			analyticsWriteJSON(w, 200, `{"defaults":{},"overrides":{"prefix":"p"}}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL + "/storage/v1", APIKey: analyticsTestKey,
		RequestEditors: []func(*http.Request) error{func(r *http.Request) error {
			if panicking.Load() && strings.HasSuffix(r.URL.Path, "/v1/config") {
				panic("editor exploded")
			}
			return nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	cat, _ := c.Analytics().From("bkt")
	_, err = cat.ListNamespaces(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v, want panic converted to error", err)
	}
	panicking.Store(false)
	done := make(chan error, 1)
	go func() { _, err := cat.ListNamespaces(context.Background(), nil); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("catalog wedged after panic")
	}
}

// icebergServerPrefix itself (independently of transport's re-escape
// guard) must reject anything outside RFC 3986 pchar and any traversal.
func TestIcebergServerPrefixValidation(t *testing.T) {
	for _, bad := range []string{
		"x|%2F..%2Fadmin", "café%2F..", "café%2F..%2Fadmin", "a{b}", "..%2F..%2F..%2Fauth%2Fv1%2Fadmin",
		"a%5C..", "%2E%2E", "a/%2e", "a`b", `a"b`, "a^b", "a b", "a%2", "a%zz", "a//b", "%2F", "", "/",
		"a?b", "a#b", `a\b`, "a\x7fb",
	} {
		if got, err := icebergServerPrefix(bad); err == nil {
			t.Errorf("icebergServerPrefix(%q) = %q, want error", bad, got)
		}
	}
	for in, want := range map[string]string{
		"a%2Fb": "a%2Fb", "/a%2Fb/c/": "a%2Fb/c", "p-1_x.y~z": "p-1_x.y~z", "a:b@c!$&'()*+,;=": "a:b@c!$&'()*+,;=",
		"..a/b..": "..a/b..", "caf%C3%A9": "caf%C3%A9",
	} {
		if got, err := icebergServerPrefix(in); err != nil || got != want {
			t.Errorf("icebergServerPrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// A server prefix component that some servers or proxies normalize to a
// dot-segment ("..;x" path parameters, trailing NULs) or that decodes to
// invalid UTF-8 is rejected.
func TestIcebergServerPrefixNormalizedDotSegments(t *testing.T) {
	for _, bad := range []string{
		"..;x", "a/..;jsessionid=1", ".;", "%2E%2E%3Bx", "a%2F..%3Bx", "..%00", ".%00%00", "a%2F..%00%3Bx",
		"%FF", "a%C3", "ok/%C0%AF", "..%00x", ".%00.", "a/..%00evil",
	} {
		if got, err := icebergServerPrefix(bad); err == nil {
			t.Errorf("icebergServerPrefix(%q) = %q, want error", bad, got)
		}
	}
	for _, good := range []string{"x;y", "...;x", "a;..", ";x", "a%00b", "caf%C3%A9"} {
		if got, err := icebergServerPrefix(good); err != nil || got != good {
			t.Errorf("icebergServerPrefix(%q) = %q, %v; want it unchanged", good, got, err)
		}
	}
}

// Namespace levels and table names must be valid UTF-8 and at most
// icebergMaxNameBytes long; violations fail before any request.
func TestIcebergRejectsInvalidNames(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{}`)
	})
	cat, err := c.Analytics().From("my-bucket")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	long := strings.Repeat("a", icebergMaxNameBytes+1)
	for name, call := range map[string]func() error{
		"table name invalid UTF-8": func() error {
			return cat.DropTable(ctx, IcebergTableIdentifier{Namespace: []string{"ns"}, Name: "t\xff"}, nil)
		},
		"namespace invalid UTF-8": func() error { return cat.DropNamespace(ctx, []string{"a\xc3"}) },
		"table name too long": func() error {
			return cat.DropTable(ctx, IcebergTableIdentifier{Namespace: []string{"ns"}, Name: long}, nil)
		},
		"namespace too long": func() error { return cat.DropNamespace(ctx, []string{"ok", long}) },
		"create table too long": func() error {
			_, err := cat.CreateTable(ctx, []string{"ns"}, IcebergCreateTableRequest{Name: long})
			return err
		},
	} {
		var ae *AnalyticsArgumentError
		if err := call(); !errors.As(err, &ae) {
			t.Errorf("%s: err = %v, want *AnalyticsArgumentError", name, err)
		}
	}
	if n := len(reqs()); n != 0 {
		t.Errorf("sent %d requests for invalid arguments", n)
	}

	// Exactly the limit, and multi-byte UTF-8, are accepted.
	if err := icebergCheckSegment("table name", strings.Repeat("a", icebergMaxNameBytes)); err != nil {
		t.Errorf("name at limit: %v", err)
	}
	if err := icebergCheckSegment("table name", "café"); err != nil {
		t.Errorf("UTF-8 name: %v", err)
	}
}
