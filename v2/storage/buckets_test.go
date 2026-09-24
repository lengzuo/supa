package storage

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
)

const bucketJSON = `{"id":"avatars","name":"avatars","owner":"4d56e902","public":false,
"file_size_limit":1048576,"allowed_mime_types":["image/png"],"type":"STANDARD",
"created_at":"2021-02-17T04:43:32.770Z","updated_at":"2021-02-17T04:43:32.770Z",
"versioning_status":"ENABLED"}`

// upstream: storage-js src/packages/StorageBucketApi.ts listBuckets
func TestListBuckets(t *testing.T) {
	fs := newFake(t, 200, "["+bucketJSON+"]")
	c := newTestClient(t, fs)
	got, err := c.ListBuckets(context.Background(), &ListBucketsOptions{
		Limit: 10, Offset: 5, Search: "av", SortColumn: "name", SortOrder: "desc",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodGet, "/storage/v1/bucket", "limit=10&offset=5&search=av&sortColumn=name&sortOrder=desc")
	if len(got) != 1 || got[0].ID != "avatars" || got[0].VersioningStatus != VersioningEnabled ||
		got[0].FileSizeLimit == nil || *got[0].FileSizeLimit != 1048576 || got[0].Type != BucketTypeStandard {
		t.Errorf("got %+v", got)
	}

	if _, err := c.ListBuckets(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/bucket", "")
}

// upstream: storage-js src/packages/StorageBucketApi.ts getBucket
func TestGetBucket(t *testing.T) {
	fs := newFake(t, 200, bucketJSON)
	c := newTestClient(t, fs)
	b, err := c.GetBucket(context.Background(), "my?bucket")
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/bucket/my%3Fbucket", "")
	if b.Name != "avatars" || b.Owner != "4d56e902" || len(b.AllowedMIMETypes) != 1 {
		t.Errorf("got %+v", b)
	}
	if _, err := c.GetBucket(context.Background(), ""); err == nil {
		t.Error("expected error for empty id")
	}
}

// upstream: storage-js src/packages/StorageBucketApi.ts getBucket (error)
func TestGetBucketError(t *testing.T) {
	fs := newFake(t, 400, `{"statusCode":"404","error":"Bucket not found","message":"Bucket not found","code":"NoSuchBucket"}`)
	c := newTestClient(t, fs)
	_, err := c.GetBucket(context.Background(), "missing")
	assertAPIError(t, err, 400, CodeNoSuchBucket, "Bucket not found")
	var se *Error
	if !errors.As(err, &se) || se.StatusCode != "404" {
		t.Errorf("StatusCode = %v", se)
	}
	if !IsErrorCode(err, CodeNoSuchBucket) || IsErrorCode(err, CodeNoSuchKey) {
		t.Error("IsErrorCode mismatch")
	}
}

// upstream: storage-js src/packages/StorageBucketApi.ts createBucket
func TestCreateBucket(t *testing.T) {
	fs := newFake(t, 200, `{"name":"avatars"}`)
	c := newTestClient(t, fs)
	name, err := c.CreateBucket(context.Background(), "avatars", &BucketOptions{
		Public: true, FileSizeLimit: "1024", AllowedMIMETypes: []string{"image/*"},
		Type: BucketTypeStandard, VersioningStatus: VersioningEnabled,
	})
	if err != nil || name != "avatars" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/bucket", "")
	assertJSONBody(t, r, `{"id":"avatars","name":"avatars","type":"STANDARD","public":true,
		"file_size_limit":1024,"allowed_mime_types":["image/*"],"versioning_status":"ENABLED"}`)

	// Defaults: private bucket, nothing else sent; unit sizes are strings.
	if _, err := c.CreateBucket(context.Background(), "b", nil); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"b","name":"b","public":false}`)
	if _, err := c.CreateBucket(context.Background(), "b", &BucketOptions{FileSizeLimit: "20MB"}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"b","name":"b","public":false,"file_size_limit":"20MB"}`)
}

// upstream: storage-js src/packages/StorageBucketApi.ts createBucket (409)
func TestCreateBucketConflict(t *testing.T) {
	fs := newFake(t, 409, `{"statusCode":"409","error":"Duplicate","message":"The resource already exists","code":"ResourceAlreadyExists"}`)
	c := newTestClient(t, fs)
	_, err := c.CreateBucket(context.Background(), "avatars", nil)
	assertAPIError(t, err, 409, CodeResourceAlreadyExists, "The resource already exists")
}

// upstream: storage-js src/packages/StorageBucketApi.ts updateBucket
func TestUpdateBucket(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully updated"}`)
	c := newTestClient(t, fs)
	msg, err := c.UpdateBucket(context.Background(), "avatars", &BucketOptions{
		Public: true, FileSizeLimit: "2048", VersioningStatus: VersioningSuspended, Type: BucketTypeAnalytics,
	})
	if err != nil || msg != "Successfully updated" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPut, "/storage/v1/bucket/avatars", "")
	assertJSONBody(t, r, `{"id":"avatars","name":"avatars","public":true,"file_size_limit":2048,"versioning_status":"SUSPENDED"}`)
}

// upstream: storage-js src/packages/StorageBucketApi.ts emptyBucket
func TestEmptyBucket(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Empty bucket has been queued. Completion may take up to an hour."}`)
	c := newTestClient(t, fs)
	msg, err := c.EmptyBucket(context.Background(), "avatars")
	if err != nil || msg == "" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/bucket/avatars/empty", "")
	assertJSONBody(t, r, `{}`)
}

// upstream: storage-js src/packages/StorageBucketApi.ts deleteBucket
func TestDeleteBucket(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully deleted"}`)
	c := newTestClient(t, fs)
	msg, err := c.DeleteBucket(context.Background(), "avatars")
	if err != nil || msg != "Successfully deleted" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodDelete, "/storage/v1/bucket/avatars", "")
	assertJSONBody(t, r, `{}`)
}

// upstream: storage-js src/packages/StorageBucketApi.ts deleteBucket (non-JSON error)
func TestDeleteBucketNonJSONError(t *testing.T) {
	fs := newFakeHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	})
	c := newTestClient(t, fs)
	_, err := c.DeleteBucket(context.Background(), "avatars")
	assertAPIError(t, err, 502, "", "Bad Gateway")
}

// upstream: storage-js src/packages/StorageBucketApi.ts purgeBucketCache
func TestPurgeBucketCache(t *testing.T) {
	fs := newFake(t, 200, `{"message":"success"}`)
	c := newTestClient(t, fs)
	msg, err := c.PurgeBucketCache(context.Background(), "my bucket", nil)
	if err != nil || msg != "success" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodDelete, "/storage/v1/cdn/my%20bucket", "")
	assertJSONBody(t, r, `{}`)

	if _, err := c.PurgeBucketCache(context.Background(), "avatars", &PurgeCacheOptions{Transformations: true}); err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodDelete, "/storage/v1/cdn/avatars", "transformations=true")
}

const lifecycleJSON = `{"rules":[{"id":"expire-history","status":"Enabled","filter":{},
"noncurrentVersionExpiration":{"noncurrentDays":30,"newerNoncurrentVersions":2}}]}`

// upstream: storage-js src/packages/StorageBucketApi.ts getBucketLifecycle
func TestGetBucketLifecycle(t *testing.T) {
	fs := newFake(t, 200, lifecycleJSON)
	c := newTestClient(t, fs)
	cfg, err := c.GetBucketLifecycle(context.Background(), "my?bucket")
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/bucket/my%3Fbucket/lifecycle", "")
	if len(cfg.Rules) != 1 || cfg.Rules[0].ID != "expire-history" || cfg.Rules[0].Status != LifecycleRuleEnabled ||
		cfg.Rules[0].NoncurrentVersionExpiration.NoncurrentDays != 30 ||
		cfg.Rules[0].NoncurrentVersionExpiration.NewerNoncurrentVersions != 2 {
		t.Errorf("got %+v", cfg)
	}
}

// upstream: storage-js test/storageBucketApi.test.ts NoSuchLifecycleConfiguration
func TestGetBucketLifecycleError(t *testing.T) {
	fs := newFake(t, 400, `{"statusCode":"400","error":"NoSuchLifecycleConfiguration","message":"The lifecycle configuration does not exist","code":"NoSuchLifecycleConfiguration"}`)
	c := newTestClient(t, fs)
	_, err := c.GetBucketLifecycle(context.Background(), "avatars")
	assertAPIError(t, err, 400, CodeNoSuchLifecycleConfiguration, "The lifecycle configuration does not exist")
}

// upstream: storage-js src/packages/StorageBucketApi.ts updateBucketLifecycle
func TestUpdateBucketLifecycle(t *testing.T) {
	fs := newFake(t, 200, lifecycleJSON)
	c := newTestClient(t, fs)
	in := BucketLifecycleConfiguration{Rules: []LifecycleRule{{
		ID: "expire-history", Status: LifecycleRuleEnabled,
		NoncurrentVersionExpiration: NoncurrentVersionExpiration{NoncurrentDays: 30, NewerNoncurrentVersions: 2},
	}}}
	out, err := c.UpdateBucketLifecycle(context.Background(), "avatars", in)
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPut, "/storage/v1/bucket/avatars/lifecycle", "")
	assertJSONBody(t, r, lifecycleJSON)
	if len(out.Rules) != 1 {
		t.Errorf("got %+v", out)
	}
}

// upstream: storage-js src/packages/StorageBucketApi.ts deleteBucketLifecycle
func TestDeleteBucketLifecycle(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully deleted"}`)
	c := newTestClient(t, fs)
	msg, err := c.DeleteBucketLifecycle(context.Background(), "avatars")
	if err != nil || msg != "Successfully deleted" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	assertReq(t, fs.last(t), http.MethodDelete, "/storage/v1/bucket/avatars/lifecycle", "")
}

func TestUseNewHostname(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://abc.supabase.co/storage/v1", "https://abc.storage.supabase.co/storage/v1"},
		{"https://abc.supabase.in/storage/v1", "https://abc.storage.supabase.in/storage/v1"},
		{"https://abc.storage.supabase.co/storage/v1", "https://abc.storage.supabase.co/storage/v1"},
		{"http://localhost:54321/storage/v1", "http://localhost:54321/storage/v1"},
		{"https://example.com/storage/v1", "https://example.com/storage/v1"},
	}
	for _, tt := range tests {
		c, err := New(Config{URL: tt.in, APIKey: testKey, UseNewHostname: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := c.t.BaseURL().String(); got != tt.want {
			t.Errorf("%s -> %s, want %s", tt.in, got, tt.want)
		}
	}
	c, _ := New(Config{URL: "https://abc.supabase.co/storage/v1", APIKey: testKey})
	if got := c.t.BaseURL().String(); got != "https://abc.supabase.co/storage/v1" {
		t.Errorf("without option: %s", got)
	}
}

func TestRetryPolicy(t *testing.T) {
	var n atomic.Int32
	fs := newFakeHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`[]`))
	})
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.Retry = &RetryPolicy{MaxAttempts: 3, BaseDelay: 1, MaxDelay: 2}
	})
	if _, err := c.ListBuckets(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if fs.count() != 3 {
		t.Errorf("attempts = %d, want 3", fs.count())
	}

	// Without a policy there are no retries.
	n.Store(0)
	c2 := newTestClient(t, fs)
	before := fs.count()
	if _, err := c2.ListBuckets(context.Background(), nil); err == nil {
		t.Fatal("expected error")
	}
	if fs.count()-before != 1 {
		t.Errorf("attempts = %d, want 1", fs.count()-before)
	}
}

func TestRequestUsesAccessToken(t *testing.T) {
	fs := newFake(t, 200, `[]`)
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "user-jwt", nil }
	})
	if _, err := c.ListBuckets(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if a := fs.last(t).Header.Get("Authorization"); a != "Bearer user-jwt" {
		t.Errorf("Authorization = %q", a)
	}
}
