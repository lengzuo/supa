package storage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const analyticsTestKey = "test-anon-key"

// analyticsRecorded is one request seen by an analyticsTestServer.
type analyticsRecorded struct {
	Method  string
	Path    string // escaped path
	Query   string // raw query
	Header  http.Header
	Body    []byte
	Request *http.Request
}

// analyticsTestServer starts a server that records requests and delegates
// the response to handle. It returns a Client rooted at /storage/v1 and a
// function returning the recorded requests.
func analyticsTestServer(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body []byte)) (*Client, func() []analyticsRecorded) {
	t.Helper()
	var (
		mu   sync.Mutex
		reqs []analyticsRecorded
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, analyticsRecorded{
			Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
			Header: r.Header.Clone(), Body: body, Request: r,
		})
		mu.Unlock()
		handle(w, r, body)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{URL: srv.URL + "/storage/v1", APIKey: analyticsTestKey})
	if err != nil {
		t.Fatal(err)
	}
	return c, func() []analyticsRecorded {
		mu.Lock()
		defer mu.Unlock()
		return append([]analyticsRecorded(nil), reqs...)
	}
}

func analyticsWriteJSON(w http.ResponseWriter, status int, v string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, v)
}

// analyticsAssertJSON compares got to the JSON document want semantically.
func analyticsAssertJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("request body is not JSON: %v: %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad expected JSON: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("body mismatch\n got: %s\nwant: %s", got, want)
	}
}

func analyticsAssertAuth(t *testing.T, r analyticsRecorded) {
	t.Helper()
	if got := r.Header.Get("apikey"); got != analyticsTestKey {
		t.Errorf("apikey = %q", got)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+analyticsTestKey {
		t.Errorf("Authorization = %q", got)
	}
}

// upstream: storage-js src/packages/StorageAnalyticsClient.ts createBucket
func TestAnalyticsCreateBucket(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"name":"analytics-data","type":"ANALYTICS","format":"iceberg",
			"created_at":"2024-05-22T22:26:05.100Z","updated_at":"2024-05-22T22:26:05.100Z"}`)
	})
	b, err := c.Analytics().CreateBucket(context.Background(), "analytics-data")
	if err != nil {
		t.Fatal(err)
	}
	want := AnalyticsBucket{Name: "analytics-data", Type: "ANALYTICS", Format: "iceberg",
		CreatedAt: "2024-05-22T22:26:05.100Z", UpdatedAt: "2024-05-22T22:26:05.100Z"}
	if *b != want {
		t.Fatalf("bucket = %+v", *b)
	}
	r := reqs()[0]
	if r.Method != http.MethodPost || r.Path != "/storage/v1/iceberg/bucket" {
		t.Fatalf("got %s %s", r.Method, r.Path)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	analyticsAssertAuth(t, r)
	analyticsAssertJSON(t, r.Body, `{"name":"analytics-data"}`)
}

// upstream: storage-js src/packages/StorageAnalyticsClient.ts listBuckets
func TestAnalyticsListBuckets(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `[{"name":"a","type":"ANALYTICS","format":"iceberg","created_at":"x","updated_at":"y"},
			{"name":"b","type":"ANALYTICS","format":"iceberg","created_at":"x","updated_at":"y"}]`)
	})
	limit, offset := 10, 0
	got, err := c.Analytics().ListBuckets(context.Background(), &AnalyticsListBucketsOptions{
		Limit: &limit, Offset: &offset, SortColumn: AnalyticsSortByCreatedAt, SortOrder: AnalyticsSortDesc, Search: "a b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Name != "b" {
		t.Fatalf("buckets = %+v", got)
	}
	r := reqs()[0]
	if r.Method != http.MethodGet || r.Path != "/storage/v1/iceberg/bucket" {
		t.Fatalf("got %s %s", r.Method, r.Path)
	}
	q := r.Request.URL.Query()
	for k, v := range map[string]string{"limit": "10", "offset": "0", "sortColumn": "created_at", "sortOrder": "desc", "search": "a b"} {
		if q.Get(k) != v {
			t.Errorf("query %s = %q, want %q", k, q.Get(k), v)
		}
	}
	analyticsAssertAuth(t, r)

	// No options: no query string.
	if _, err := c.Analytics().ListBuckets(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if r := reqs()[1]; r.Query != "" {
		t.Errorf("query = %q, want empty", r.Query)
	}
}

// upstream: storage-js src/packages/StorageAnalyticsClient.ts deleteBucket
func TestAnalyticsDeleteBucket(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"message":"Successfully deleted"}`)
	})
	res, err := c.Analytics().DeleteBucket(context.Background(), "my bucket")
	if err != nil {
		t.Fatal(err)
	}
	if res.Message != "Successfully deleted" {
		t.Fatalf("message = %q", res.Message)
	}
	r := reqs()[0]
	if r.Method != http.MethodDelete || r.Path != "/storage/v1/iceberg/bucket/my%20bucket" {
		t.Fatalf("got %s %s", r.Method, r.Path)
	}
	analyticsAssertJSON(t, r.Body, `{}`)
	if _, err := c.Analytics().DeleteBucket(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty name")
	}
}

// upstream: storage-js src/lib/common/fetch.ts handleError (storage namespace)
func TestAnalyticsBucketError(t *testing.T) {
	c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 409, `{"statusCode":"409","error":"Duplicate","message":"The resource already exists","code":"ResourceAlreadyExists"}`)
	})
	_, err := c.Analytics().CreateBucket(context.Background(), "dup")
	var se *Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %T %v", err, err)
	}
	if se.Status != 409 || se.StatusCode != "409" || se.Code != "ResourceAlreadyExists" ||
		se.Message != "The resource already exists" || se.Namespace != "storage" {
		t.Fatalf("err = %+v", se)
	}
}

// upstream: storage-js test/analytics-getcatalog.test.ts
func TestAnalyticsFrom(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {})
	a := c.Analytics()
	for _, name := range []string{"analytics-data", "bucket123", "MyBucket", "my-bucket_2024", "data.backup",
		"bucket's-data", "bucket (2024)", "embeddings-prod", strings.Repeat("a", 100)} {
		cat, err := a.From(name)
		if err != nil {
			t.Errorf("From(%q) error: %v", name, err)
			continue
		}
		if cat.Warehouse() != name {
			t.Errorf("Warehouse() = %q", cat.Warehouse())
		}
	}
	for _, name := range []string{"", "../etc/passwd", "bucket/nested", "/bucket", "bucket/", `bucket\nested`,
		" bucket", "bucket ", strings.Repeat("a", 101), "bucket{name}", "bucket[name]", "bucket<name>",
		"bucket#name", "bucket%name", "bucket%2Fnested"} {
		if _, err := a.From(name); err == nil || !strings.Contains(err.Error(), "invalid bucket name") {
			t.Errorf("From(%q) err = %v, want invalid bucket name", name, err)
		}
	}
	c1, _ := a.From("bucket-1")
	c2, _ := a.From("bucket-2")
	if c1 == c2 {
		t.Error("expected distinct catalogs")
	}
	if n := len(reqs()); n != 0 {
		t.Errorf("From performed %d requests", n)
	}
}

// upstream: storage-js src/lib/common/fetch.ts (request cancellation)
func TestAnalyticsContextCanceled(t *testing.T) {
	c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `[]`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Analytics().ListBuckets(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// upstream: storage-js src/packages/StorageAnalyticsClient.ts deleteBucket / from (error paths)
func TestAnalyticsErrorPaths(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 404, `{"statusCode":"404","error":"not_found","message":"Bucket not found","code":"NoSuchBucket"}`)
	})
	_, err := c.Analytics().DeleteBucket(context.Background(), "missing")
	var se *Error
	if !errors.As(err, &se) || se.Status != 404 || se.Code != "NoSuchBucket" || se.Message != "Bucket not found" || se.Namespace != "storage" {
		t.Fatalf("DeleteBucket err = %+v", err)
	}
	if _, err := c.Analytics().ListBuckets(context.Background(), nil); !errors.As(err, &se) || se.Status != 404 {
		t.Fatalf("ListBuckets err = %+v", err)
	}
	n := len(reqs())
	for _, name := range []string{"", ".", "..", "a/b", "a#b"} {
		_, err := c.Analytics().From(name)
		var ae *AnalyticsArgumentError
		if !errors.As(err, &ae) || ae.Argument != "bucket name" || !strings.Contains(err.Error(), "invalid bucket name") {
			t.Errorf("From(%q) err = %v", name, err)
		}
	}
	if len(reqs()) != n {
		t.Fatal("From sent a request")
	}
}
