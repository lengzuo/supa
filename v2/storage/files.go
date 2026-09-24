package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// FileAPI performs object operations in one bucket. Obtain it with
// Client.From. It is immutable and safe for concurrent use.
type FileAPI struct {
	c        *Client
	bucketID string
}

// From returns the object API for the bucket with the given id.
func (c *Client) From(bucketID string) *FileAPI {
	return &FileAPI{c: c, bucketID: bucketID}
}

// BucketID returns the id of the bucket this FileAPI operates on.
func (f *FileAPI) BucketID() string { return f.bucketID }

// Default upload settings, as in storage-js.
const (
	// DefaultCacheControl is the default max-age, in seconds, for uploads.
	DefaultCacheControl = "3600"
	// DefaultContentType is the default Content-Type for uploads.
	DefaultContentType = "text/plain;charset=UTF-8"
)

// FileOptions configures Upload, Update and UploadToSignedURL.
type FileOptions struct {
	// CacheControl is the number of seconds the object is cached by
	// browsers and the CDN, sent as "Cache-Control: max-age=<value>".
	// Empty means DefaultCacheControl.
	CacheControl string
	// ContentType is the object's MIME type. Empty means
	// DefaultContentType.
	ContentType string
	// Upsert overwrites an existing object instead of failing. It is
	// sent as the x-upsert header by Upload and UploadToSignedURL; Update
	// always overwrites.
	Upsert bool
	// Metadata is arbitrary user metadata stored with the object (sent
	// as base64-encoded JSON in the x-metadata header).
	Metadata map[string]any
	// Headers are extra request headers. They override the headers above.
	Headers http.Header
}

// UploadResponse describes an uploaded object.
type UploadResponse struct {
	// ID is the object id. It is empty for UploadToSignedURL.
	ID string
	// Path is the object path inside the bucket.
	Path string
	// FullPath is the object key including the bucket id.
	FullPath string
}

type objectKeyResponse struct {
	ID  string `json:"Id"`
	Key string `json:"Key"`
}

var (
	errNilBody          = errors.New("storage: upload body is nil")
	errEmptyPath        = errors.New("storage: object path is required")
	errEmptyUploadToken = errors.New("storage: signed upload token is required")
)

// finalPath returns the escaped "<bucket>/<path>" used in object URLs.
func (f *FileAPI) finalPath(p string) string {
	return transport.PathEscape(f.bucketID) + "/" + transport.PathEscape(trimLeadingSlashes(p))
}

// rawFinalPath returns the unescaped "<bucket>/<path>", as storage-js
// _getFinalPath does.
func (f *FileAPI) rawFinalPath(p string) string {
	return f.bucketID + "/" + trimLeadingSlashes(p)
}

func uploadHeaders(opts *FileOptions, withUpsert bool) (http.Header, error) {
	o := FileOptions{}
	if opts != nil {
		o = *opts
	}
	if o.CacheControl == "" {
		o.CacheControl = DefaultCacheControl
	}
	if o.ContentType == "" {
		o.ContentType = DefaultContentType
	}
	h := http.Header{}
	if withUpsert {
		h.Set("x-upsert", fmt.Sprint(o.Upsert))
	}
	h.Set("Cache-Control", "max-age="+o.CacheControl)
	h.Set(transport.HeaderContentType, o.ContentType)
	if o.Metadata != nil {
		meta, err := encodeJSON(o.Metadata)
		if err != nil {
			return nil, fmt.Errorf("storage: encode metadata: %w", err)
		}
		h.Set("x-metadata", base64.StdEncoding.EncodeToString(meta))
	}
	for k, vs := range o.Headers {
		h[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	return h, nil
}

// encodeJSON is json.Marshal without HTML escaping, matching
// JSON.stringify.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Upload stores body at path. The body is streamed, not buffered. If it
// implements io.Closer it is always closed, including when the call fails
// before anything is sent (invalid arguments, metadata encoding, access
// token or request editor failures). The upload fails
// with CodeResourceAlreadyExists (HTTP 409) when the object exists and
// opts.Upsert is false. opts may be nil.
//
// Uploads are never retried because the body cannot be replayed.
func (f *FileAPI) Upload(ctx context.Context, path string, body io.Reader, opts *FileOptions) (*UploadResponse, error) {
	return f.uploadOrUpdate(ctx, http.MethodPost, path, body, opts)
}

// Update replaces the object at path with body. See Upload.
func (f *FileAPI) Update(ctx context.Context, path string, body io.Reader, opts *FileOptions) (*UploadResponse, error) {
	return f.uploadOrUpdate(ctx, http.MethodPut, path, body, opts)
}

func (f *FileAPI) uploadOrUpdate(ctx context.Context, method, path string, body io.Reader, opts *FileOptions) (*UploadResponse, error) {
	if body == nil {
		return nil, errNilBody
	}
	h, err := uploadHeaders(opts, method == http.MethodPost)
	if err != nil {
		closeBody(body)
		return nil, err
	}
	clean := removeEmptyFolders(path)
	if clean == "" {
		closeBody(body)
		return nil, errEmptyPath
	}
	var out objectKeyResponse
	req := &transport.Request{Method: method, Path: "/object/" + f.finalPath(clean), Header: h, Body: body, NoRetry: true}
	if err := f.sendUpload(ctx, req, body, &out); err != nil {
		return nil, err
	}
	return &UploadResponse{ID: out.ID, Path: clean, FullPath: out.Key}, nil
}

// closeBody closes body if it is an io.Closer. It is used on paths where
// the body never reaches net/http, which would otherwise close it.
func closeBody(body io.Reader) {
	if c, ok := body.(io.Closer); ok {
		_ = c.Close()
	}
}

// sendUpload sends a streamed upload. Once the request reaches
// http.Client.Do, net/http closes the body (also on error); every failure
// before that point closes it here, so the body is closed exactly once on
// every path.
func (f *FileAPI) sendUpload(ctx context.Context, req *transport.Request, body io.Reader, out any) error {
	if ctx == nil {
		closeBody(body)
		return errors.New("storage: nil context")
	}
	if _, err := f.c.t.URL(req.Path, req.Query); err != nil {
		closeBody(body)
		return err
	}
	_, err := request(ctx, f.c.t, req, out, "storage")
	if err != nil && transport.IsPreSend(err) {
		closeBody(body)
	}
	return err
}

// SignedUploadURLOptions configures CreateSignedUploadURL.
type SignedUploadURLOptions struct {
	// Upsert allows the signed upload to overwrite an existing object.
	Upsert bool
}

// SignedUploadURL is a URL that lets anyone holding it upload one object
// without further authorization, for two hours.
type SignedUploadURL struct {
	// SignedURL is the absolute upload URL, including the token.
	SignedURL string
	// Token is the upload token, to pass to UploadToSignedURL.
	Token string
	// Path is the object path the URL was created for.
	Path string
}

// CreateSignedUploadURL creates a signed upload URL for path. opts may be
// nil.
func (f *FileAPI) CreateSignedUploadURL(ctx context.Context, path string, opts *SignedUploadURLOptions) (*SignedUploadURL, error) {
	h := http.Header{}
	if opts != nil && opts.Upsert {
		h.Set("x-upsert", "true")
	}
	var out struct {
		URL string `json:"url"`
	}
	req := &transport.Request{Method: http.MethodPost, Path: "/object/upload/sign/" + f.finalPath(path), Header: h, Body: struct{}{}}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	u, err := url.Parse(f.c.t.BaseURL().String() + out.URL)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid signed upload URL: %w", err)
	}
	token := u.Query().Get("token")
	if token == "" {
		return nil, errors.New("storage: no token returned by API")
	}
	return &SignedUploadURL{SignedURL: u.String(), Token: token, Path: path}, nil
}

// UploadToSignedURL uploads body to path using a token from
// CreateSignedUploadURL. The request is authorized by the token. opts may
// be nil. See Upload for body handling.
func (f *FileAPI) UploadToSignedURL(ctx context.Context, path, token string, body io.Reader, opts *FileOptions) (*UploadResponse, error) {
	if body == nil {
		return nil, errNilBody
	}
	if token == "" {
		closeBody(body)
		return nil, errEmptyUploadToken
	}
	h, err := uploadHeaders(opts, true)
	if err != nil {
		closeBody(body)
		return nil, err
	}
	clean := removeEmptyFolders(path)
	if clean == "" {
		closeBody(body)
		return nil, errEmptyPath
	}
	var out objectKeyResponse
	req := &transport.Request{
		Method:  http.MethodPut,
		Path:    "/object/upload/sign/" + f.finalPath(clean),
		Query:   url.Values{"token": {token}},
		Header:  h,
		Body:    body,
		NoRetry: true,
	}
	if err := f.sendUpload(ctx, req, body, &out); err != nil {
		return nil, err
	}
	return &UploadResponse{Path: clean, FullPath: out.Key}, nil
}

// DestinationOptions configures Move and Copy.
type DestinationOptions struct {
	// DestinationBucket moves or copies into another bucket. Empty means
	// the same bucket.
	DestinationBucket string
	// SourceVersionID selects a specific version of the source object
	// (e.g. to restore a previous version).
	SourceVersionID string
}

type moveCopyBody struct {
	BucketID          string `json:"bucketId"`
	SourceKey         string `json:"sourceKey"`
	DestinationKey    string `json:"destinationKey"`
	DestinationBucket string `json:"destinationBucket,omitempty"`
	SourceVersionID   string `json:"sourceVersionId,omitempty"`
}

func (f *FileAPI) moveCopyBody(from, to string, opts *DestinationOptions) moveCopyBody {
	b := moveCopyBody{BucketID: f.bucketID, SourceKey: from, DestinationKey: to}
	if opts != nil {
		b.DestinationBucket = opts.DestinationBucket
		b.SourceVersionID = opts.SourceVersionID
	}
	return b
}

// Move moves (renames) an object and returns the server message. opts may
// be nil.
func (f *FileAPI) Move(ctx context.Context, fromPath, toPath string, opts *DestinationOptions) (string, error) {
	return f.c.message(ctx, http.MethodPost, "/object/move", f.moveCopyBody(fromPath, toPath, opts))
}

// Copy copies an object and returns the new object's key (including the
// destination bucket id). opts may be nil.
func (f *FileAPI) Copy(ctx context.Context, fromPath, toPath string, opts *DestinationOptions) (string, error) {
	var out objectKeyResponse
	req := &transport.Request{Method: http.MethodPost, Path: "/object/copy", Body: f.moveCopyBody(fromPath, toPath, opts)}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return "", err
	}
	return out.Key, nil
}

// DeleteObjectEntry identifies one object for RemoveVersions. With an empty
// VersionID it removes whatever is currently at Path; otherwise it removes
// exactly that version.
type DeleteObjectEntry struct {
	Path      string `json:"path"`
	VersionID string `json:"versionId"`
}

// MarshalJSON encodes an entry without a version as a plain path string,
// as storage-js does.
func (e DeleteObjectEntry) MarshalJSON() ([]byte, error) {
	if e.VersionID == "" {
		return json.Marshal(e.Path)
	}
	type entry DeleteObjectEntry
	return json.Marshal(entry(e))
}

// Remove deletes the objects at paths and returns the deleted objects.
func (f *FileAPI) Remove(ctx context.Context, paths []string) ([]FileObject, error) {
	entries := make([]DeleteObjectEntry, len(paths))
	for i, p := range paths {
		entries[i] = DeleteObjectEntry{Path: p}
	}
	return f.RemoveVersions(ctx, entries)
}

// RemoveVersions deletes the given objects or object versions and returns
// the deleted objects.
func (f *FileAPI) RemoveVersions(ctx context.Context, entries []DeleteObjectEntry) ([]FileObject, error) {
	if entries == nil {
		entries = []DeleteObjectEntry{}
	}
	body := struct {
		Prefixes []DeleteObjectEntry `json:"prefixes"`
	}{entries}
	var out []FileObject
	req := &transport.Request{Method: http.MethodDelete, Path: "/object/" + transport.PathEscape(f.bucketID), Body: body}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return out, nil
}

// PurgeCache purges the CDN cache for one object and returns the server
// message. opts may be nil.
func (f *FileAPI) PurgeCache(ctx context.Context, path string, opts *PurgeCacheOptions) (string, error) {
	return f.c.purge(ctx, f.finalPath(path), opts)
}

// InfoOptions configures Info.
type InfoOptions struct {
	// VersionID selects a specific object version.
	VersionID string
}

// FileInfo is the detailed description of an object returned by Info.
type FileInfo struct {
	ID           string         `json:"id"`
	Version      string         `json:"version"`
	Name         string         `json:"name"`
	BucketID     string         `json:"bucket_id"`
	CreatedAt    string         `json:"created_at"`
	Size         int64          `json:"size,omitempty"`
	CacheControl string         `json:"cache_control,omitempty"`
	ContentType  string         `json:"content_type,omitempty"`
	ETag         string         `json:"etag,omitempty"`
	LastModified string         `json:"last_modified,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	// Deprecated: the API returns LastModified instead.
	UpdatedAt      string  `json:"updated_at,omitempty"`
	ArchivedAt     *string `json:"archived_at,omitempty"`
	IsDeleteMarker bool    `json:"is_delete_marker,omitempty"`
	IsVersioned    bool    `json:"is_versioned,omitempty"`
}

// Info returns details about the object at path. opts may be nil.
func (f *FileAPI) Info(ctx context.Context, path string, opts *InfoOptions) (*FileInfo, error) {
	req := &transport.Request{Method: http.MethodGet, Path: "/object/info/" + f.finalPath(path)}
	if opts != nil && opts.VersionID != "" {
		req.Query = url.Values{"versionId": {opts.VersionID}}
	}
	var out FileInfo
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Exists reports whether an object exists at path. A 400 or 404 response
// yields (false, nil); other failures are returned as errors.
func (f *FileAPI) Exists(ctx context.Context, path string) (bool, error) {
	req := &transport.Request{Method: http.MethodHead, Path: "/object/" + f.finalPath(path)}
	_, err := request(ctx, f.c.t, req, nil, "storage")
	if err == nil {
		return true, nil
	}
	var se *Error
	if errors.As(err, &se) && (se.Status == http.StatusBadRequest || se.Status == http.StatusNotFound) {
		return false, nil
	}
	return false, err
}
