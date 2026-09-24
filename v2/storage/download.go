package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// DownloadOptions configures Download and DownloadStream.
type DownloadOptions struct {
	// Transform downloads a transformed image (via the
	// render/image/authenticated endpoint).
	Transform *TransformOptions
	// CacheNonce is sent as "cacheNonce=<value>" to bypass stale caches.
	CacheNonce string
	// VersionID downloads a specific object version.
	VersionID string
}

// DownloadStream downloads the object at path and returns its body as a
// stream. The caller must close it. Cancel ctx to abort the download,
// including while the body is being read. opts may be nil.
func (f *FileAPI) DownloadStream(ctx context.Context, path string, opts *DownloadOptions) (io.ReadCloser, error) {
	render := "object"
	q := url.Values{}
	if opts != nil {
		if opts.Transform.isSet() {
			render = "render/image/authenticated"
		}
		var fq formQuery
		opts.Transform.applyTo(&fq)
		for i, k := range fq.keys {
			q.Set(k, fq.values[i])
		}
		if opts.CacheNonce != "" {
			q.Set("cacheNonce", opts.CacheNonce)
		}
		if opts.VersionID != "" {
			q.Set("versionId", opts.VersionID)
		}
	}
	req := &transport.Request{Method: http.MethodGet, Path: "/" + render + "/" + f.finalPath(path), Query: q}
	resp, err := f.c.t.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := transport.CheckResponse(resp); err != nil {
		return nil, toError(err, "storage")
	}
	return resp.Body, nil
}

// Download downloads the object at path into memory. Use DownloadStream
// for large objects. opts may be nil.
func (f *FileAPI) Download(ctx context.Context, path string, opts *DownloadOptions) ([]byte, error) {
	rc, err := f.DownloadStream(ctx, path, opts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("storage: read download: %w", err)
	}
	return data, nil
}
