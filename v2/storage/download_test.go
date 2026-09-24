package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

// upstream: storage-js src/packages/StorageFileApi.ts download
func TestDownload(t *testing.T) {
	fs := newFakeHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("PNGDATA"))
	})
	c := newTestClient(t, fs)
	data, err := c.From("b").Download(context.Background(), "dir/a b.png", nil)
	if err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/object/b/dir/a%20b.png", "")
	if string(data) != "PNGDATA" {
		t.Errorf("data = %q", data)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts download (versionId, cacheNonce)
func TestDownloadVersion(t *testing.T) {
	fs := newFake(t, 200, "x")
	c := newTestClient(t, fs)
	if _, err := c.From("b").Download(context.Background(), "a.png", &DownloadOptions{VersionID: "v1", CacheNonce: "n1"}); err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/object/b/a.png", "cacheNonce=n1&versionId=v1")
}

// upstream: storage-js src/packages/StorageFileApi.ts download (transform)
func TestDownloadWithTransform(t *testing.T) {
	fs := newFake(t, 200, "x")
	c := newTestClient(t, fs)
	_, err := c.From("b").Download(context.Background(), "a.png", &DownloadOptions{
		Transform:  &TransformOptions{Width: 200, Height: 100, Resize: ResizeContain, Quality: 60, Format: FormatOrigin},
		CacheNonce: "n 1",
		VersionID:  "v/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same key order and URLSearchParams encoding as storage-js.
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/render/image/authenticated/b/a.png",
		"width=200&height=100&resize=contain&format=origin&quality=60&cacheNonce=n+1&versionId=v%2F1")

	// An empty transform uses the plain object endpoint.
	if _, err := c.From("b").Download(context.Background(), "a.png", &DownloadOptions{Transform: &TransformOptions{}}); err != nil {
		t.Fatal(err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/object/b/a.png", "")
}

// upstream: storage-js src/packages/StreamDownloadBuilder.ts (download().asStream())
func TestDownloadStream(t *testing.T) {
	fs := newFakeHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("chunk1"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("chunk2"))
	})
	c := newTestClient(t, fs)
	rc, err := c.From("b").DownloadStream(context.Background(), "a.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil || string(data) != "chunk1chunk2" {
		t.Errorf("data=%q err=%v", data, err)
	}
	assertReq(t, fs.last(t), http.MethodGet, "/storage/v1/object/b/a.bin", "")
}

// upstream: storage-js src/packages/StorageFileApi.ts download (error)
func TestDownloadError(t *testing.T) {
	fs := newFake(t, 400, notFoundBody)
	c := newTestClient(t, fs)
	_, err := c.From("b").Download(context.Background(), "missing.png", nil)
	assertAPIError(t, err, 400, CodeNoSuchKey, "Object not found")
	if _, err := c.From("b").DownloadStream(context.Background(), "missing.png", nil); !IsErrorCode(err, CodeNoSuchKey) {
		t.Errorf("stream err = %v", err)
	}
}

// upstream: storage-js test/storageFileApi.test.ts "download with abort signal"
func TestDownloadCancellation(t *testing.T) {
	release := make(chan struct{})
	fs := newFakeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	defer close(release)
	c := newTestClient(t, fs)

	// Already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.From("b").Download(ctx, "a.png", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}

	// Cancelled while waiting for the response.
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, err := c.From("b").Download(ctx, "a.png", nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// Cancelling the context aborts a stream that is being read.
func TestDownloadStreamCancellation(t *testing.T) {
	fs := newFakeHandler(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	c := newTestClient(t, fs)
	ctx, cancel := context.WithCancel(context.Background())
	rc, err := c.From("b").DownloadStream(ctx, "a.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(rc, buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := io.ReadAll(rc); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
