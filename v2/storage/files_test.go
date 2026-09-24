package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// upstream: storage-js src/packages/StorageFileApi.ts upload
func TestUpload(t *testing.T) {
	fs := newFake(t, 200, `{"Id":"obj-id","Key":"avatars/folder/cat.png"}`)
	c := newTestClient(t, fs)

	// Stream the body through a pipe to prove it is not pre-buffered.
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "hello ")
		_, _ = io.WriteString(pw, "world")
		_ = pw.Close()
	}()
	res, err := c.From("avatars").Upload(context.Background(), "/folder//cat.png/", pr, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/avatars/folder/cat.png", "")
	if string(r.Body) != "hello world" {
		t.Errorf("body = %q", r.Body)
	}
	for k, want := range map[string]string{
		"x-upsert":      "false",
		"Cache-Control": "max-age=3600",
		"Content-Type":  "text/plain;charset=UTF-8",
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if r.Header.Get("x-metadata") != "" {
		t.Error("unexpected x-metadata")
	}
	want := UploadResponse{ID: "obj-id", Path: "folder/cat.png", FullPath: "avatars/folder/cat.png"}
	if *res != want {
		t.Errorf("res = %+v, want %+v", *res, want)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts upload (FileOptions.metadata)
func TestUploadWithMetadataAndOptions(t *testing.T) {
	fs := newFake(t, 200, `{"Id":"id","Key":"b/a b.png"}`)
	c := newTestClient(t, fs)
	_, err := c.From("b").Upload(context.Background(), "a b.png", strings.NewReader("png"), &FileOptions{
		CacheControl: "60",
		ContentType:  "image/png",
		Upsert:       true,
		Metadata:     map[string]any{"owner": "<me>", "n": 1},
		Headers:      http.Header{"X-Custom": {"1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/b/a%20b.png", "")
	if r.Header.Get("x-upsert") != "true" || r.Header.Get("Cache-Control") != "max-age=60" ||
		r.Header.Get("Content-Type") != "image/png" || r.Header.Get("X-Custom") != "1" {
		t.Errorf("headers = %v", r.Header)
	}
	meta, err := base64.StdEncoding.DecodeString(r.Header.Get("x-metadata"))
	if err != nil {
		t.Fatal(err)
	}
	if string(meta) != `{"n":1,"owner":"<me>"}` {
		t.Errorf("metadata = %s", meta)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts upload (error)
func TestUploadErrors(t *testing.T) {
	fs := newFake(t, 409, `{"statusCode":"409","error":"Duplicate","message":"The resource already exists","code":"ResourceAlreadyExists"}`)
	c := newTestClient(t, fs)
	_, err := c.From("b").Upload(context.Background(), "a.txt", strings.NewReader("x"), nil)
	assertAPIError(t, err, 409, CodeResourceAlreadyExists, "The resource already exists")

	if _, err := c.From("b").Upload(context.Background(), "a.txt", nil, nil); err == nil {
		t.Error("expected error for nil body")
	}
	if _, err := c.From("b").Upload(context.Background(), "/", strings.NewReader("x"), nil); err == nil {
		t.Error("expected error for empty path")
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts update
func TestUpdateFile(t *testing.T) {
	fs := newFake(t, 200, `{"Id":"id2","Key":"b/a.txt"}`)
	c := newTestClient(t, fs)
	res, err := c.From("b").Update(context.Background(), "a.txt", strings.NewReader("new"), &FileOptions{ContentType: "text/csv"})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPut, "/storage/v1/object/b/a.txt", "")
	if r.Header.Get("x-upsert") != "" {
		t.Error("update must not send x-upsert")
	}
	if r.Header.Get("Content-Type") != "text/csv" || string(r.Body) != "new" {
		t.Errorf("headers=%v body=%q", r.Header, r.Body)
	}
	if res.ID != "id2" || res.FullPath != "b/a.txt" || res.Path != "a.txt" {
		t.Errorf("res = %+v", res)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts createSignedUploadUrl
func TestCreateSignedUploadURL(t *testing.T) {
	fs := newFake(t, 200, `{"url":"/object/upload/sign/b/dir/a.txt?token=tok123"}`)
	c := newTestClient(t, fs)
	res, err := c.From("b").CreateSignedUploadURL(context.Background(), "dir/a.txt", &SignedUploadURLOptions{Upsert: true})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/upload/sign/b/dir/a.txt", "")
	assertJSONBody(t, r, `{}`)
	if r.Header.Get("x-upsert") != "true" {
		t.Error("missing x-upsert")
	}
	if res.Token != "tok123" || res.Path != "dir/a.txt" ||
		res.SignedURL != fs.URL+"/storage/v1/object/upload/sign/b/dir/a.txt?token=tok123" {
		t.Errorf("res = %+v", res)
	}

	if _, err := c.From("b").CreateSignedUploadURL(context.Background(), "a.txt", nil); err != nil {
		t.Fatal(err)
	}
	if fs.last(t).Header.Get("x-upsert") != "" {
		t.Error("x-upsert sent without Upsert")
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts createSignedUploadUrl (no token)
func TestCreateSignedUploadURLNoToken(t *testing.T) {
	fs := newFake(t, 200, `{"url":"/object/upload/sign/b/a.txt"}`)
	c := newTestClient(t, fs)
	if _, err := c.From("b").CreateSignedUploadURL(context.Background(), "a.txt", nil); err == nil {
		t.Fatal("expected error")
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts uploadToSignedUrl
func TestUploadToSignedURL(t *testing.T) {
	fs := newFake(t, 200, `{"Key":"b/dir/a.txt"}`)
	c := newTestClient(t, fs)
	res, err := c.From("b").UploadToSignedURL(context.Background(), "dir/a.txt", "tok 1", strings.NewReader("data"), &FileOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPut, "/storage/v1/object/upload/sign/b/dir/a.txt", "token=tok+1")
	if r.Header.Get("x-upsert") != "false" || r.Header.Get("Content-Type") != "text/plain" || string(r.Body) != "data" {
		t.Errorf("headers=%v body=%q", r.Header, r.Body)
	}
	if res.Path != "dir/a.txt" || res.FullPath != "b/dir/a.txt" {
		t.Errorf("res = %+v", res)
	}
	if _, err := c.From("b").UploadToSignedURL(context.Background(), "a", "", strings.NewReader(""), nil); err == nil {
		t.Error("expected error for empty token")
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts move
func TestMove(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully moved"}`)
	c := newTestClient(t, fs)
	msg, err := c.From("b").Move(context.Background(), "a.txt", "c.txt", nil)
	if err != nil || msg != "Successfully moved" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/move", "")
	assertJSONBody(t, r, `{"bucketId":"b","sourceKey":"a.txt","destinationKey":"c.txt"}`)
}

// upstream: storage-js src/packages/StorageFileApi.ts move (DestinationOptions)
func TestMoveCrossBucketVersion(t *testing.T) {
	fs := newFake(t, 200, `{"message":"Successfully moved"}`)
	c := newTestClient(t, fs)
	_, err := c.From("b").Move(context.Background(), "a.txt", "c.txt", &DestinationOptions{DestinationBucket: "other", SourceVersionID: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"bucketId":"b","sourceKey":"a.txt","destinationKey":"c.txt","destinationBucket":"other","sourceVersionId":"v1"}`)
}

// upstream: storage-js src/packages/StorageFileApi.ts copy
func TestCopy(t *testing.T) {
	fs := newFake(t, 200, `{"Key":"b/c.txt"}`)
	c := newTestClient(t, fs)
	key, err := c.From("b").Copy(context.Background(), "a.txt", "c.txt", nil)
	if err != nil || key != "b/c.txt" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/copy", "")
	assertJSONBody(t, r, `{"bucketId":"b","sourceKey":"a.txt","destinationKey":"c.txt"}`)
}

// upstream: storage-js src/packages/StorageFileApi.ts copy (DestinationOptions)
func TestCopyCrossBucketVersion(t *testing.T) {
	fs := newFake(t, 200, `{"Key":"other/c.txt"}`)
	c := newTestClient(t, fs)
	key, err := c.From("b").Copy(context.Background(), "a.txt", "c.txt", &DestinationOptions{DestinationBucket: "other", SourceVersionID: "v1"})
	if err != nil || key != "other/c.txt" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	assertJSONBody(t, fs.last(t), `{"bucketId":"b","sourceKey":"a.txt","destinationKey":"c.txt","destinationBucket":"other","sourceVersionId":"v1"}`)
}

const fileObjectsJSON = `[{"name":"a.txt","id":"1","updated_at":"2024-01-01T00:00:00Z","created_at":"2024-01-01T00:00:00Z",
"last_accessed_at":"2024-01-01T00:00:00Z","metadata":{"size":3,"mimetype":"text/plain"},"bucket_id":"b",
"version":"v1","archived_at":null,"is_delete_marker":false,"is_versioned":true},
{"name":"folder","id":null,"updated_at":null,"created_at":null,"last_accessed_at":null,"metadata":null}]`

// upstream: storage-js src/packages/StorageFileApi.ts remove
func TestRemove(t *testing.T) {
	fs := newFake(t, 200, fileObjectsJSON)
	c := newTestClient(t, fs)
	objs, err := c.From("b").Remove(context.Background(), []string{"a.txt", "dir/b.txt"})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodDelete, "/storage/v1/object/b", "")
	assertJSONBody(t, r, `{"prefixes":["a.txt","dir/b.txt"]}`)
	if len(objs) != 2 || objs[0].BucketID != "b" || objs[0].Metadata["mimetype"] != "text/plain" ||
		objs[0].IsVersioned == nil || !*objs[0].IsVersioned || objs[1].Name != "folder" || objs[1].ID != "" {
		t.Errorf("objs = %+v", objs)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts remove (DeleteObjectEntry)
func TestRemoveVersions(t *testing.T) {
	fs := newFake(t, 200, `[]`)
	c := newTestClient(t, fs)
	_, err := c.From("b").RemoveVersions(context.Background(), []DeleteObjectEntry{
		{Path: "a.txt"}, {Path: "b.txt", VersionID: "v2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"prefixes":["a.txt",{"path":"b.txt","versionId":"v2"}]}`)
}

// upstream: storage-js src/packages/StorageFileApi.ts purgeCache
func TestPurgeCache(t *testing.T) {
	fs := newFake(t, 200, `{"message":"success"}`)
	c := newTestClient(t, fs)
	msg, err := c.From("b").PurgeCache(context.Background(), "/dir/a?b.png", &PurgeCacheOptions{Transformations: true})
	if err != nil || msg != "success" {
		t.Fatalf("msg=%q err=%v", msg, err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodDelete, "/storage/v1/cdn/b/dir/a%3Fb.png", "transformations=true")
	assertJSONBody(t, r, `{}`)
}

const infoJSON = `{"id":"1","version":"v1","name":"a.txt","bucket_id":"b","created_at":"2024-01-01T00:00:00Z",
"size":3,"cache_control":"max-age=3600","content_type":"text/plain","etag":"\"abc\"",
"last_modified":"2024-01-02T00:00:00Z","metadata":{"k":"v"},"archived_at":"2024-01-03T00:00:00Z",
"is_delete_marker":false,"is_versioned":true}`

// upstream: storage-js src/packages/StorageFileApi.ts info
func TestInfo(t *testing.T) {
	fs := newFake(t, 200, infoJSON)
	c := newTestClient(t, fs)
	info, err := c.From("b").Info(context.Background(), "dir/a.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/object/info/b/dir/a.txt", "")
	if info.ID != "1" || info.Size != 3 || info.ETag != `"abc"` || info.ContentType != "text/plain" ||
		info.Metadata["k"] != "v" || !info.IsVersioned || info.ArchivedAt == nil || info.BucketID != "b" {
		t.Errorf("info = %+v", info)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts info (versionId)
func TestInfoVersion(t *testing.T) {
	fs := newFake(t, 200, infoJSON)
	c := newTestClient(t, fs)
	if _, err := c.From("b").Info(context.Background(), "a.txt", &InfoOptions{VersionID: "v1"}); err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/object/info/b/a.txt", "versionId=v1")
}

// upstream: storage-js src/packages/StorageFileApi.ts exists
func TestExists(t *testing.T) {
	status := 200
	var mu sync.Mutex
	fs := newFakeHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
	})
	c := newTestClient(t, fs)
	for _, tt := range []struct {
		status  int
		want    bool
		wantErr bool
	}{{200, true, false}, {404, false, false}, {400, false, false}, {500, false, true}} {
		mu.Lock()
		status = tt.status
		mu.Unlock()
		got, err := c.From("b").Exists(context.Background(), "a.txt")
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("status %d: got %v, %v", tt.status, got, err)
		}
		assertReq(t, fs.last(t), http.MethodHead, "/storage/v1/object/b/a.txt", "")
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts list
func TestList(t *testing.T) {
	fs := newFake(t, 200, fileObjectsJSON)
	c := newTestClient(t, fs)
	objs, err := c.From("b").List(context.Background(), "folder", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/list/b", "")
	assertJSONBody(t, r, `{"limit":100,"offset":0,"sortBy":{"column":"name","order":"asc"},"prefix":"folder"}`)
	if len(objs) != 2 || objs[0].Version != "v1" {
		t.Errorf("objs = %+v", objs)
	}
}

// upstream: storage-js test/list-sortby-defaults.test.ts + SearchOptions version filters
func TestListOptions(t *testing.T) {
	fs := newFake(t, 200, `[]`)
	c := newTestClient(t, fs)
	_, err := c.From("b").List(context.Background(), "", &ListFilesOptions{
		Limit: 10, Offset: 20, SortBy: SortBy{Order: "desc"}, Search: "cat",
		NoncurrentVersions: ListInclude, DeleteMarkers: ListOnly, ExactMatch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"limit":10,"offset":20,"sortBy":{"column":"name","order":"desc"},"search":"cat",
		"noncurrentVersions":"include","deleteMarkers":"only","exactMatch":true,"prefix":""}`)

	if _, err := c.From("b").List(context.Background(), "", &ListFilesOptions{SortBy: SortBy{Column: "updated_at"}}); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"limit":100,"offset":0,"sortBy":{"column":"updated_at","order":"asc"},"prefix":""}`)
}

// upstream: storage-js src/packages/StorageFileApi.ts listV2
func TestListV2(t *testing.T) {
	fs := newFake(t, 200, `{"hasNext":true,"nextCursor":"c2","folders":[{"name":"dir","key":"dir/"}],
		"objects":[{"name":"a.txt","key":"a.txt","id":"1","updated_at":"u","created_at":"c","metadata":null,
		"last_accessed_at":"l","version":"v1","is_versioned":true}]}`)
	c := newTestClient(t, fs)
	res, err := c.From("b").ListV2(context.Background(), &ListFilesV2Options{
		Limit: 50, Prefix: "d", Cursor: "c1", WithDelimiter: true,
		SortBy:             &SortByV2{Column: "created_at", Order: "desc"},
		NoncurrentVersions: ListInclude, DeleteMarkers: ListExclude, ExactMatch: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/list-v2/b", "")
	assertJSONBody(t, r, `{"limit":50,"prefix":"d","cursor":"c1","with_delimiter":true,
		"sortBy":{"column":"created_at","order":"desc"},"noncurrentVersions":"include","deleteMarkers":"exclude","exactMatch":true}`)
	if !res.HasNext || res.NextCursor != "c2" || len(res.Folders) != 1 || res.Folders[0].Key != "dir/" ||
		len(res.Objects) != 1 || res.Objects[0].Version != "v1" || !res.Objects[0].IsVersioned {
		t.Errorf("res = %+v", res)
	}

	if _, err := c.From("b").ListV2(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{}`)
}

// upstream: storage-js src/packages/StorageFileApi.ts list (error)
func TestListError(t *testing.T) {
	fs := newFake(t, 400, `{"statusCode":"404","error":"Bucket not found","message":"Bucket not found","code":"NoSuchBucket"}`)
	c := newTestClient(t, fs)
	_, err := c.From("missing").List(context.Background(), "", nil)
	assertAPIError(t, err, 400, CodeNoSuchBucket, "Bucket not found")
}

// Concurrent use of one Client and FileAPI with different per-call tokens.
func TestConcurrentUse(t *testing.T) {
	fs := newFake(t, 200, `[]`)
	type tokenKey struct{}
	c := newTestClient(t, fs, func(cfg *Config) {
		cfg.AccessToken = func(ctx context.Context) (string, error) {
			s, _ := ctx.Value(tokenKey{}).(string)
			return s, nil
		}
	})
	files := c.From("b")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.WithValue(context.Background(), tokenKey{}, fmt.Sprintf("tok-%d", i))
			if _, err := files.List(ctx, fmt.Sprintf("p%d", i), nil); err != nil {
				t.Error(err)
			}
			_ = files.GetPublicURL("x", &URLOptions{Download: true})
		}(i)
	}
	wg.Wait()
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, r := range fs.reqs {
		var body struct{ Prefix string }
		if err := json.Unmarshal(r.Body, &body); err != nil {
			t.Fatal(err)
		}
		if want := "Bearer tok-" + strings.TrimPrefix(body.Prefix, "p"); r.Header.Get("Authorization") != want {
			t.Errorf("Authorization = %q, want %q", r.Header.Get("Authorization"), want)
		}
	}
}

func TestIsErrorCodeWrapped(t *testing.T) {
	err := fmt.Errorf("ctx: %w", &Error{Code: CodeAccessDenied, Status: 403})
	if !IsErrorCode(err, CodeAccessDenied) {
		t.Error("wrapped code not found")
	}
	if IsErrorCode(errors.New("x"), CodeAccessDenied) {
		t.Error("plain error matched")
	}
}
