package storage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
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
	if err := cat.DropNamespace(ctx, []string{"...", "x/y"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/storage/v1/iceberg/v1/srv-prefix/namespaces/a%20b%1Fc.d/tables/t..1?purgeRequested=false",
		"/storage/v1/iceberg/v1/srv-prefix/namespaces/...%1Fx%2Fy",
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
	for _, bad := range []string{"../x", "a/%2E%2E", "a/./b", "a?b", "a#b", "a//b", "a b", "a/%zz"} {
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
