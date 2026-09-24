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
		Public: boolPtr(true), FileSizeLimit: "1024", AllowedMIMETypes: []string{"image/*"},
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
		Public: boolPtr(true), FileSizeLimit: "2048", VersioningStatus: VersioningSuspended, Type: BucketTypeAnalytics,
	})
	if err != nil || msg != "Successfully updated" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPut, "/storage/v1/bucket/avatars", "")
	assertJSONBody(t, r, `{"id":"avatars","name":"avatars","public":true,"file_size_limit":2048,"versioning_status":"SUSPENDED"}`)
}

func boolPtr(v bool) *bool { return &v }

// upstream: storage-js src/packages/StorageBucketApi.ts updateBucket
// (fileSizeLimit/allowedMimeTypes: null clears the setting)
func TestUpdateBucketClearLimits(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully updated"}`)
	c := newTestClient(t, fs)
	ctx := context.Background()

	if _, err := c.UpdateBucket(ctx, "avatars", &BucketOptions{
		ClearFileSizeLimit: true, ClearAllowedMIMETypes: true,
	}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"avatars","name":"avatars","file_size_limit":null,"allowed_mime_types":null}`)

	// A non-nil empty slice is sent as [] (not dropped).
	if _, err := c.UpdateBucket(ctx, "avatars", &BucketOptions{AllowedMIMETypes: []string{}}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"avatars","name":"avatars","allowed_mime_types":[]}`)

	// Clearing also works on create.
	if _, err := c.CreateBucket(ctx, "b", &BucketOptions{ClearFileSizeLimit: true}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"b","name":"b","public":false,"file_size_limit":null}`)

	// Conflicting value and Clear flag fail before any request.
	before := fs.count()
	for _, o := range []*BucketOptions{
		{FileSizeLimit: "1", ClearFileSizeLimit: true},
		{AllowedMIMETypes: []string{}, ClearAllowedMIMETypes: true},
	} {
		if _, err := c.UpdateBucket(ctx, "avatars", o); err == nil {
			t.Errorf("UpdateBucket(%+v): expected error", o)
		}
		if _, err := c.CreateBucket(ctx, "avatars", o); err == nil {
			t.Errorf("CreateBucket(%+v): expected error", o)
		}
	}
	if fs.count() != before {
		t.Errorf("sent %d requests for invalid options", fs.count()-before)
	}
}

// upstream: storage-js src/packages/StorageBucketApi.ts updateBucket
// (Go divergence: an unset Public is omitted, so visibility is unchanged)
func TestUpdateBucketPublicOptional(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully updated"}`)
	c := newTestClient(t, fs)
	ctx := context.Background()

	if _, err := c.UpdateBucket(ctx, "avatars", nil); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"avatars","name":"avatars"}`)

	if _, err := c.UpdateBucket(ctx, "avatars", &BucketOptions{FileSizeLimit: "20MB"}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"avatars","name":"avatars","file_size_limit":"20MB"}`)

	if _, err := c.UpdateBucket(ctx, "avatars", &BucketOptions{Public: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"id":"avatars","name":"avatars","public":false}`)
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

// upstream: storage-js src/lib/common/fetch.ts handleError / _getErrorMessage
// (statusCode = err.statusCode || err.code || String(status); message
// falls back to JSON.stringify(err))
func TestErrorBodyShapes(t *testing.T) {
	for _, tt := range []struct {
		name                  string
		status                int
		body                  string
		msg, statusCode, code string
	}{
		{"statusCode wins", 404, `{"statusCode":"409","code":"NoSuchKey","message":"m"}`, "m", "409", "NoSuchKey"},
		{"empty statusCode falls back to code", 404, `{"statusCode":"","code":"NoSuchKey","message":"m"}`, "m", "NoSuchKey", "NoSuchKey"},
		{"empty statusCode and code fall back to status", 404, `{"statusCode":"","code":"","message":"m"}`, "m", "404", ""},
		{"zero statusCode is falsy", 404, `{"statusCode":0,"message":"m"}`, "m", "404", ""},
		{"numeric statusCode", 400, `{"statusCode":413,"message":"m"}`, "m", "413", ""},
		{"numeric code", 400, `{"code":42,"message":"m"}`, "m", "42", "42"},
		{"zero code is falsy", 400, `{"code":0,"message":"m"}`, "m", "400", ""},
		{"array body", 500, `[1, "a"]`, `[1,"a"]`, "500", ""},
		{"string body", 500, `"boom"`, `"boom"`, "500", ""},
		{"null body", 500, `null`, `null`, "500", ""},
		{"object without message", 500, `{"b": 1, "a": 2}`, `{"b":1,"a":2}`, "500", ""},
		{"nested error message", 500, `{"error":{"message":"deep"}}`, "deep", "500", ""},
		{"non-JSON body", 502, `<html>`, "Bad Gateway", "502", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs := newFake(t, tt.status, tt.body)
			c := newTestClient(t, fs)
			_, err := c.GetBucket(context.Background(), "b")
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("err = %T %v", err, err)
			}
			if e.Status != tt.status || e.Message != tt.msg || e.StatusCode != tt.statusCode || e.Code != tt.code {
				t.Errorf("got status=%d msg=%q statusCode=%q code=%q, want %d %q %q %q",
					e.Status, e.Message, e.StatusCode, e.Code, tt.status, tt.msg, tt.statusCode, tt.code)
			}
		})
	}
}

// Wire values of the Code* constants that differ from their Go names, as
// defined by the Storage server ErrorCode enum (src/internal/errors/codes.ts).
func TestErrorCodeWireValues(t *testing.T) {
	for got, want := range map[string]string{
		CodeS3InvalidAccessKeyID:      "InvalidAccessKeyId",
		CodeS3MaximumCredentialsLimit: "MaximumCredentialsLimit",
		CodeInvalidUploadID:           "InvalidUploadId",
	} {
		if got != want {
			t.Errorf("code = %q, want %q", got, want)
		}
	}
	fs := newFake(t, 403, `{"statusCode":"403","error":"Forbidden","message":"bad key","code":"InvalidAccessKeyId"}`)
	c := newTestClient(t, fs)
	_, err := c.GetBucket(context.Background(), "b")
	if !IsErrorCode(err, CodeS3InvalidAccessKeyID) {
		t.Errorf("IsErrorCode(%v, CodeS3InvalidAccessKeyID) = false", err)
	}
}
