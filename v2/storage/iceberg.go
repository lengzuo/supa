package storage

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// IcebergCatalog is an Apache Iceberg REST catalog client scoped to one
// analytics bucket (the Iceberg "warehouse"). Obtain one with
// AnalyticsAPI.From. It sends the same apikey and Authorization headers as
// the Storage client and is safe for concurrent use.
//
// On first use the catalog calls GET /v1/config?warehouse=<bucket> and
// uses the server-provided "prefix" (overrides, then defaults) for every
// later path, falling back to the bucket name when the server does not
// provide one or answers with an error.
type IcebergCatalog struct {
	t         *transport.Client
	warehouse string

	mu     sync.Mutex
	prefix string // "v1/<prefix>" once resolved
}

// Warehouse returns the analytics bucket name the catalog is scoped to.
func (c *IcebergCatalog) Warehouse() string { return c.warehouse }

// IcebergError is returned by IcebergCatalog operations for non-2xx
// responses. Use errors.As to inspect it.
type IcebergError struct {
	// Message is the server's error message.
	Message string
	// Status is the HTTP status code.
	Status int
	// Type is the Iceberg exception type, e.g. "NoSuchTableException".
	Type string
	// Code is the error code from the response body (usually the HTTP
	// status), or 0.
	Code int
	// Details is the raw JSON error body, if any.
	Details json.RawMessage
}

func (e *IcebergError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("iceberg: %s (status %d, type %s)", e.Message, e.Status, e.Type)
	}
	return fmt.Sprintf("iceberg: %s (status %d)", e.Message, e.Status)
}

// IsNotFound reports whether the error is a 404 Not Found.
func (e *IcebergError) IsNotFound() bool { return e.Status == http.StatusNotFound }

// IsConflict reports whether the error is a 409 Conflict.
func (e *IcebergError) IsConflict() bool { return e.Status == http.StatusConflict }

// IsAuthenticationTimeout reports whether the error is a 419
// Authentication Timeout.
func (e *IcebergError) IsAuthenticationTimeout() bool { return e.Status == 419 }

// IsCommitStateUnknown reports whether a commit may or may not have been
// applied (CommitStateUnknownException); callers must not blindly retry.
func (e *IcebergError) IsCommitStateUnknown() bool {
	return e.Type == "CommitStateUnknownException"
}

// icebergToError converts transport HTTP errors into *IcebergError.
func icebergToError(err error) error {
	var he *transport.HTTPError
	if err == nil || !errors.As(err, &he) {
		return err
	}
	out := &IcebergError{Status: he.StatusCode}
	var body struct {
		Error *struct {
			Message string          `json:"message"`
			Type    string          `json:"type"`
			Code    json.RawMessage `json:"code"`
		} `json:"error"`
	}
	if len(he.Body) > 0 && json.Valid(he.Body) {
		out.Details = append(json.RawMessage(nil), he.Body...)
		if json.Unmarshal(he.Body, &body) == nil && body.Error != nil {
			out.Message = body.Error.Message
			out.Type = body.Error.Type
			var n json.Number
			if json.Unmarshal(body.Error.Code, &n) == nil {
				if v, err := strconv.Atoi(n.String()); err == nil {
					out.Code = v
				}
			}
		}
	}
	if out.Message == "" {
		out.Message = fmt.Sprintf("Request failed with status %d", he.StatusCode)
	}
	return out
}

// icebergIdempotencyKey returns a UUIDv7 for the Idempotency-Key header.
func icebergIdempotencyKey() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	_, _ = rand.Read(b[6:])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// icebergEscape percent-encodes s like JavaScript's encodeURIComponent.
func icebergEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
			strings.IndexByte("-_.!~*'()", c) >= 0 {
			sb.WriteByte(c)
			continue
		}
		fmt.Fprintf(&sb, "%%%02X", c)
	}
	return sb.String()
}

// icebergNamespacePath encodes a multi-level namespace as one path segment
// with levels separated by the unit separator (%1F), per the REST spec.
func icebergNamespacePath(ns []string) (string, error) {
	if len(ns) == 0 {
		return "", errors.New("storage: iceberg namespace must have at least one level")
	}
	parts := make([]string, len(ns))
	for i, p := range ns {
		parts[i] = icebergEscape(p)
	}
	return strings.Join(parts, "%1F"), nil
}

func icebergTablePath(id IcebergTableIdentifier) (string, error) {
	ns, err := icebergNamespacePath(id.Namespace)
	if err != nil {
		return "", err
	}
	if id.Name == "" {
		return "", errors.New("storage: iceberg table name is required")
	}
	return "/namespaces/" + ns + "/tables/" + icebergEscape(id.Name), nil
}

// LoadConfig fetches the catalog configuration (GET /v1/config) for this
// warehouse. The result is not cached.
func (c *IcebergCatalog) LoadConfig(ctx context.Context) (*IcebergCatalogConfig, error) {
	var out IcebergCatalogConfig
	_, err := c.t.DoJSON(ctx, &transport.Request{
		Method: http.MethodGet,
		Path:   "/v1/config",
		Query:  url.Values{"warehouse": {c.warehouse}},
	}, &out)
	if err != nil {
		return nil, icebergToError(err)
	}
	return &out, nil
}

// resolvePrefix returns "/v1/<prefix>", loading it from /v1/config once.
// A definitive HTTP error from /v1/config caches the bucket-name fallback;
// network and context errors are returned and retried on the next call.
func (c *IcebergCatalog) resolvePrefix(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prefix != "" {
		return c.prefix, nil
	}
	fallback := "/v1/" + url.PathEscape(c.warehouse)
	cfg, err := c.LoadConfig(ctx)
	if err != nil {
		var ie *IcebergError
		if !errors.As(err, &ie) {
			return "", err
		}
		c.prefix = fallback
		return c.prefix, nil
	}
	p := cfg.Overrides["prefix"]
	if p == "" {
		p = cfg.Defaults["prefix"]
	}
	if p == "" {
		c.prefix = fallback
	} else {
		c.prefix = "/v1/" + transport.PathEscape(strings.Trim(p, "/"))
	}
	return c.prefix, nil
}

// do sends a catalog request relative to the resolved prefix.
func (c *IcebergCatalog) do(ctx context.Context, req *transport.Request, out any) (http.Header, error) {
	prefix, err := c.resolvePrefix(ctx)
	if err != nil {
		return nil, err
	}
	req.Path = prefix + req.Path
	h, err := c.t.DoJSON(ctx, req, out)
	return h, icebergToError(err)
}

func icebergIdempotencyHeader() http.Header {
	return http.Header{"Idempotency-Key": {icebergIdempotencyKey()}}
}

// ListNamespaces lists namespaces, top-level ones unless opts.Parent is
// set. opts may be nil. Use NextPageToken to page.
func (c *IcebergCatalog) ListNamespaces(ctx context.Context, opts *IcebergListNamespacesOptions) (*IcebergListNamespacesResult, error) {
	q := url.Values{}
	if opts != nil {
		if len(opts.Parent) > 0 {
			q.Set("parent", strings.Join(opts.Parent, "\x1f"))
		}
		if opts.PageToken != "" {
			q.Set("pageToken", opts.PageToken)
		}
		if opts.PageSize > 0 {
			q.Set("pageSize", strconv.Itoa(opts.PageSize))
		}
	}
	var out IcebergListNamespacesResult
	if _, err := c.do(ctx, &transport.Request{Method: http.MethodGet, Path: "/namespaces", Query: q}, &out); err != nil {
		return nil, err
	}
	if out.Namespaces == nil {
		out.Namespaces = [][]string{}
	}
	return &out, nil
}

// CreateNamespace creates namespace with optional properties.
func (c *IcebergCatalog) CreateNamespace(ctx context.Context, namespace []string, properties map[string]string) (*IcebergNamespaceResponse, error) {
	if len(namespace) == 0 {
		return nil, errors.New("storage: iceberg namespace must have at least one level")
	}
	body := struct {
		Namespace  []string          `json:"namespace"`
		Properties map[string]string `json:"properties,omitempty"`
	}{namespace, properties}
	var out IcebergNamespaceResponse
	if _, err := c.do(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   "/namespaces",
		Body:   body,
		Header: icebergIdempotencyHeader(),
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateNamespaceIfNotExists creates namespace, returning (nil, nil) when
// it already exists (409 Conflict).
func (c *IcebergCatalog) CreateNamespaceIfNotExists(ctx context.Context, namespace []string, properties map[string]string) (*IcebergNamespaceResponse, error) {
	res, err := c.CreateNamespace(ctx, namespace, properties)
	var ie *IcebergError
	if errors.As(err, &ie) && ie.IsConflict() {
		return nil, nil
	}
	return res, err
}

// DropNamespace deletes namespace, which must be empty.
func (c *IcebergCatalog) DropNamespace(ctx context.Context, namespace []string) error {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, &transport.Request{
		Method: http.MethodDelete,
		Path:   "/namespaces/" + ns,
		Header: icebergIdempotencyHeader(),
	}, nil)
	return err
}

// LoadNamespaceMetadata returns the properties of namespace.
func (c *IcebergCatalog) LoadNamespaceMetadata(ctx context.Context, namespace []string) (*IcebergNamespaceMetadata, error) {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return nil, err
	}
	var out IcebergNamespaceMetadata
	if _, err := c.do(ctx, &transport.Request{Method: http.MethodGet, Path: "/namespaces/" + ns}, &out); err != nil {
		return nil, err
	}
	if out.Properties == nil {
		out.Properties = map[string]string{}
	}
	return &out, nil
}

// NamespaceExists reports whether namespace exists (HEAD request; 404
// yields false, nil).
func (c *IcebergCatalog) NamespaceExists(ctx context.Context, namespace []string) (bool, error) {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return false, err
	}
	_, err = c.do(ctx, &transport.Request{Method: http.MethodHead, Path: "/namespaces/" + ns}, nil)
	return icebergExists(err)
}

// UpdateNamespaceProperties sets and removes namespace properties
// (POST /v1/{prefix}/namespaces/{namespace}/properties).
func (c *IcebergCatalog) UpdateNamespaceProperties(ctx context.Context, namespace []string, params IcebergUpdateNamespacePropertiesParams) (*IcebergUpdateNamespacePropertiesResponse, error) {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return nil, err
	}
	var out IcebergUpdateNamespacePropertiesResponse
	if _, err := c.do(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   "/namespaces/" + ns + "/properties",
		Body:   params,
		Header: icebergIdempotencyHeader(),
	}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTables lists the tables of namespace. opts may be nil.
func (c *IcebergCatalog) ListTables(ctx context.Context, namespace []string, opts *IcebergListTablesOptions) (*IcebergListTablesResult, error) {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if opts != nil {
		if opts.PageToken != "" {
			q.Set("pageToken", opts.PageToken)
		}
		if opts.PageSize > 0 {
			q.Set("pageSize", strconv.Itoa(opts.PageSize))
		}
	}
	var out IcebergListTablesResult
	if _, err := c.do(ctx, &transport.Request{
		Method: http.MethodGet,
		Path:   "/namespaces/" + ns + "/tables",
		Query:  q,
	}, &out); err != nil {
		return nil, err
	}
	if out.Identifiers == nil {
		out.Identifiers = []IcebergTableIdentifier{}
	}
	return &out, nil
}

// CreateTable creates a table in namespace and returns its metadata.
func (c *IcebergCatalog) CreateTable(ctx context.Context, namespace []string, req IcebergCreateTableRequest) (*IcebergLoadTableResult, error) {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, errors.New("storage: iceberg table name is required")
	}
	return c.loadTableResult(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   "/namespaces/" + ns + "/tables",
		Body:   req,
		Header: icebergIdempotencyHeader(),
	})
}

// CreateTableIfNotExists creates a table, or loads it when it already
// exists (409 Conflict).
func (c *IcebergCatalog) CreateTableIfNotExists(ctx context.Context, namespace []string, req IcebergCreateTableRequest) (*IcebergLoadTableResult, error) {
	res, err := c.CreateTable(ctx, namespace, req)
	var ie *IcebergError
	if errors.As(err, &ie) && ie.IsConflict() {
		return c.LoadTable(ctx, IcebergTableIdentifier{Namespace: namespace, Name: req.Name}, nil)
	}
	return res, err
}

// RegisterTable registers an existing metadata file as a table in
// namespace (POST /v1/{prefix}/namespaces/{namespace}/register).
func (c *IcebergCatalog) RegisterTable(ctx context.Context, namespace []string, req IcebergRegisterTableRequest) (*IcebergLoadTableResult, error) {
	ns, err := icebergNamespacePath(namespace)
	if err != nil {
		return nil, err
	}
	if req.Name == "" || req.MetadataLocation == "" {
		return nil, errors.New("storage: iceberg register table requires a name and metadata location")
	}
	return c.loadTableResult(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   "/namespaces/" + ns + "/register",
		Body:   req,
		Header: icebergIdempotencyHeader(),
	})
}

// LoadTable loads a table's metadata. opts may be nil. When
// opts.IfNoneMatch matches the current ETag the server answers 304 and
// LoadTable returns (nil, nil).
func (c *IcebergCatalog) LoadTable(ctx context.Context, id IcebergTableIdentifier, opts *IcebergLoadTableOptions) (*IcebergLoadTableResult, error) {
	path, err := icebergTablePath(id)
	if err != nil {
		return nil, err
	}
	req := &transport.Request{Method: http.MethodGet, Path: path}
	if opts != nil {
		if opts.IfNoneMatch != "" {
			req.Header = http.Header{"If-None-Match": {opts.IfNoneMatch}}
		}
		if opts.Snapshots != "" {
			req.Query = url.Values{"snapshots": {opts.Snapshots}}
		}
	}
	return c.loadTableResult(ctx, req)
}

// loadTableResult sends req and decodes a LoadTableResult, handling 304.
func (c *IcebergCatalog) loadTableResult(ctx context.Context, req *transport.Request) (*IcebergLoadTableResult, error) {
	prefix, err := c.resolvePrefix(ctx)
	if err != nil {
		return nil, err
	}
	req.Path = prefix + req.Path
	resp, err := c.t.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		return nil, nil
	}
	if err := transport.CheckResponse(resp); err != nil {
		return nil, icebergToError(err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("storage: read iceberg response: %w", err)
	}
	var out IcebergLoadTableResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("storage: decode iceberg response: %w", err)
	}
	out.ETag = resp.Header.Get("ETag")
	return &out, nil
}

// UpdateTable commits requirements and updates to a table (POST
// /v1/{prefix}/namespaces/{namespace}/tables/{table}).
func (c *IcebergCatalog) UpdateTable(ctx context.Context, id IcebergTableIdentifier, req IcebergCommitTableRequest) (*IcebergCommitTableResponse, error) {
	path, err := icebergTablePath(id)
	if err != nil {
		return nil, err
	}
	var out IcebergCommitTableResponse
	if _, err := c.do(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   path,
		Body:   req,
		Header: icebergIdempotencyHeader(),
	}, &out); err != nil {
		return nil, err
	}
	if out.MetadataLocation == "" {
		return nil, errors.New("storage: iceberg commit response is missing metadata-location")
	}
	return &out, nil
}

// RenameTable renames (and possibly moves) a table.
func (c *IcebergCatalog) RenameTable(ctx context.Context, source, destination IcebergTableIdentifier) error {
	body := struct {
		Source      IcebergTableIdentifier `json:"source"`
		Destination IcebergTableIdentifier `json:"destination"`
	}{source, destination}
	_, err := c.do(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   "/tables/rename",
		Body:   body,
		Header: icebergIdempotencyHeader(),
	}, nil)
	return err
}

// DropTable deletes a table. opts may be nil; opts.Purge also deletes the
// table's data.
func (c *IcebergCatalog) DropTable(ctx context.Context, id IcebergTableIdentifier, opts *IcebergDropTableOptions) error {
	path, err := icebergTablePath(id)
	if err != nil {
		return err
	}
	purge := opts != nil && opts.Purge
	_, err = c.do(ctx, &transport.Request{
		Method: http.MethodDelete,
		Path:   path,
		Query:  url.Values{"purgeRequested": {strconv.FormatBool(purge)}},
		Header: icebergIdempotencyHeader(),
	}, nil)
	return err
}

// TableExists reports whether a table exists (HEAD request; 404 yields
// false, nil).
func (c *IcebergCatalog) TableExists(ctx context.Context, id IcebergTableIdentifier) (bool, error) {
	path, err := icebergTablePath(id)
	if err != nil {
		return false, err
	}
	_, err = c.do(ctx, &transport.Request{Method: http.MethodHead, Path: path}, nil)
	return icebergExists(err)
}

func icebergExists(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	var ie *IcebergError
	if errors.As(err, &ie) && ie.IsNotFound() {
		return false, nil
	}
	return false, err
}
