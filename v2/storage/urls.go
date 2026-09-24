package storage

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Image resize modes for TransformOptions.Resize.
const (
	ResizeCover   = "cover"
	ResizeContain = "contain"
	ResizeFill    = "fill"
)

// FormatOrigin keeps the original image format (TransformOptions.Format).
const FormatOrigin = "origin"

// TransformOptions requests an on-the-fly image transformation. Zero
// fields are not sent.
type TransformOptions struct {
	// Width is the target width in pixels.
	Width int `json:"width,omitempty"`
	// Height is the target height in pixels.
	Height int `json:"height,omitempty"`
	// Resize is ResizeCover (default), ResizeContain or ResizeFill.
	Resize string `json:"resize,omitempty"`
	// Quality is 20 to 100 (server default 80).
	Quality int `json:"quality,omitempty"`
	// Format is FormatOrigin to keep the original format; empty lets the
	// server pick a modern format such as WebP.
	Format string `json:"format,omitempty"`
}

func (t *TransformOptions) isSet() bool {
	return t != nil && *t != TransformOptions{}
}

// applyTo mirrors storage-js applyTransformOptsToQuery (same key order).
func (t *TransformOptions) applyTo(q *formQuery) {
	if t == nil {
		return
	}
	if t.Width != 0 {
		q.set("width", strconv.Itoa(t.Width))
	}
	if t.Height != 0 {
		q.set("height", strconv.Itoa(t.Height))
	}
	if t.Resize != "" {
		q.set("resize", t.Resize)
	}
	if t.Format != "" {
		q.set("format", t.Format)
	}
	if t.Quality != 0 {
		q.set("quality", strconv.Itoa(t.Quality))
	}
}

// URLOptions configures GetPublicURL and CreateSignedURL.
type URLOptions struct {
	// Download makes the browser download the object (adds "download=").
	Download bool
	// DownloadName downloads the object under this file name
	// ("download=<name>"). It implies Download.
	DownloadName string
	// Transform serves a transformed image.
	Transform *TransformOptions
	// CacheNonce is appended as "cacheNonce=<value>" to bypass stale
	// CDN/browser caches (e.g. after overwriting an object).
	CacheNonce string
	// VersionID selects a specific object version.
	VersionID string
}

func setDownload(q *formQuery, download bool, name string) {
	switch {
	case name != "":
		q.set("download", name)
	case download:
		q.set("download", "")
	}
}

// baseURL returns the service root without a trailing slash.
func (f *FileAPI) baseURL() string {
	return f.c.t.BaseURL().String()
}

// GetPublicURL returns the URL of an object in a public bucket. It makes no
// request and does not check that the bucket is public or that the object
// exists. opts may be nil.
func (f *FileAPI) GetPublicURL(path string, opts *URLOptions) string {
	var q formQuery
	render := "object"
	if opts != nil {
		setDownload(&q, opts.Download, opts.DownloadName)
		opts.Transform.applyTo(&q)
		if opts.CacheNonce != "" {
			q.set("cacheNonce", opts.CacheNonce)
		}
		if opts.VersionID != "" {
			q.set("versionId", opts.VersionID)
		}
		if opts.Transform.isSet() {
			render = "render/image"
		}
	}
	u := encodeURI(f.baseURL() + "/" + render + "/public/" + f.rawFinalPath(path))
	if qs := q.encode(); qs != "" {
		u += "?" + qs
	}
	return u
}

// CreateSignedURL creates a URL that grants access to one object for
// expiresIn seconds. opts may be nil.
func (f *FileAPI) CreateSignedURL(ctx context.Context, path string, expiresIn int, opts *URLOptions) (string, error) {
	body := struct {
		ExpiresIn int               `json:"expiresIn"`
		Transform *TransformOptions `json:"transform,omitempty"`
		VersionID string            `json:"versionId,omitempty"`
	}{ExpiresIn: expiresIn}
	var q formQuery
	if opts != nil {
		if opts.Transform.isSet() {
			body.Transform = opts.Transform
		}
		body.VersionID = opts.VersionID
		setDownload(&q, opts.Download, opts.DownloadName)
		if opts.CacheNonce != "" {
			q.set("cacheNonce", opts.CacheNonce)
		}
	}
	var out struct {
		SignedURL string `json:"signedURL"`
	}
	req := &transport.Request{Method: http.MethodPost, Path: "/object/sign/" + f.finalPath(path), Body: body}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return "", err
	}
	if out.SignedURL == "" {
		return "", errors.New("storage: no signed URL returned by API")
	}
	return f.signedURL(out.SignedURL, q.encode()), nil
}

// signedURL mirrors storage-js: encodeURI(url + signedURL + "&" + query).
func (f *FileAPI) signedURL(rel, qs string) string {
	s := f.baseURL() + rel
	if qs != "" {
		s += "&" + qs
	}
	return encodeURI(s)
}

// SignedURLsOptions configures CreateSignedURLs.
type SignedURLsOptions struct {
	// Download makes the browser download the objects ("download=").
	Download bool
	// DownloadName downloads the objects under this file name.
	DownloadName string
	// CacheNonce is appended as "cacheNonce=<value>".
	CacheNonce string
}

// SignedURLResult is one entry of CreateSignedURLs.
type SignedURLResult struct {
	// Path is the object path.
	Path string
	// SignedURL is the absolute signed URL, empty when Error is set.
	SignedURL string
	// Error describes why no URL was created for Path (e.g. the object
	// does not exist).
	Error string
}

// CreateSignedURLs creates signed URLs for several objects, valid for
// expiresIn seconds. Per-object failures are reported in
// SignedURLResult.Error. opts may be nil.
func (f *FileAPI) CreateSignedURLs(ctx context.Context, paths []string, expiresIn int, opts *SignedURLsOptions) ([]SignedURLResult, error) {
	if paths == nil {
		paths = []string{}
	}
	body := struct {
		ExpiresIn int      `json:"expiresIn"`
		Paths     []string `json:"paths"`
	}{expiresIn, paths}
	var q formQuery
	if opts != nil {
		setDownload(&q, opts.Download, opts.DownloadName)
		if opts.CacheNonce != "" {
			q.set("cacheNonce", opts.CacheNonce)
		}
	}
	var out []struct {
		Error     *string `json:"error"`
		Path      *string `json:"path"`
		SignedURL *string `json:"signedURL"`
	}
	req := &transport.Request{Method: http.MethodPost, Path: "/object/sign/" + transport.PathEscape(f.bucketID), Body: body}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	qs := q.encode()
	res := make([]SignedURLResult, len(out))
	for i, d := range out {
		if d.Path != nil {
			res[i].Path = *d.Path
		}
		if d.Error != nil {
			res[i].Error = *d.Error
		}
		if d.SignedURL != nil && *d.SignedURL != "" {
			res[i].SignedURL = f.signedURL(*d.SignedURL, qs)
		}
	}
	return res, nil
}
