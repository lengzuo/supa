package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// BucketType is the kind of a storage bucket.
type BucketType string

// Bucket types.
const (
	// BucketTypeStandard is a regular file bucket.
	BucketTypeStandard BucketType = "STANDARD"
	// BucketTypeAnalytics is an Iceberg table bucket.
	BucketTypeAnalytics BucketType = "ANALYTICS"
)

// VersioningStatus is a bucket's object-versioning state.
type VersioningStatus string

// Versioning states. A new bucket can be created with VersioningDisabled or
// VersioningEnabled; an existing bucket can be updated to VersioningEnabled
// or VersioningSuspended (there is no way back to VersioningDisabled).
const (
	VersioningDisabled  VersioningStatus = "DISABLED"
	VersioningEnabled   VersioningStatus = "ENABLED"
	VersioningSuspended VersioningStatus = "SUSPENDED"
)

// Bucket is a Storage bucket.
type Bucket struct {
	ID               string           `json:"id"`
	Type             BucketType       `json:"type,omitempty"`
	Name             string           `json:"name"`
	Owner            string           `json:"owner"`
	FileSizeLimit    *int64           `json:"file_size_limit,omitempty"`
	AllowedMIMETypes []string         `json:"allowed_mime_types,omitempty"`
	CreatedAt        string           `json:"created_at"`
	UpdatedAt        string           `json:"updated_at"`
	Public           bool             `json:"public"`
	VersioningStatus VersioningStatus `json:"versioning_status,omitempty"`
}

// ListBucketsOptions filters and paginates ListBuckets.
type ListBucketsOptions struct {
	// Limit is the maximum number of buckets to return. Zero means the
	// server default.
	Limit int
	// Offset is the number of buckets to skip.
	Offset int
	// SortColumn is one of "id", "name", "created_at" or "updated_at".
	SortColumn string
	// SortOrder is "asc" or "desc".
	SortOrder string
	// Search filters buckets by name.
	Search string
}

// BucketOptions are the settings sent by CreateBucket and UpdateBucket.
//
// The zero value of every field means "do not send this setting", so
// UpdateBucket only changes the settings that are set. To remove a limit
// that is already configured, use ClearFileSizeLimit or
// ClearAllowedMIMETypes, which send JSON null as storage-js does for a
// null option.
type BucketOptions struct {
	// Public makes objects readable without authorization. Nil means
	// "not set": CreateBucket then creates a private bucket (it sends
	// "public": false, the storage-js default) and UpdateBucket leaves
	// the bucket's visibility unchanged (the field is omitted).
	Public *bool
	// FileSizeLimit is the maximum object size, either a number of bytes
	// ("1048576") or a size with a unit ("20MB"). Empty leaves it unset
	// (not sent).
	FileSizeLimit string
	// ClearFileSizeLimit sends "file_size_limit": null, removing the
	// bucket's own limit so only the global limit applies. It cannot be
	// combined with a non-empty FileSizeLimit.
	ClearFileSizeLimit bool
	// AllowedMIMETypes restricts uploads to these MIME types (wildcards
	// such as "image/*" are allowed). Nil leaves it unset (not sent); a
	// non-nil empty slice is sent as [].
	AllowedMIMETypes []string
	// ClearAllowedMIMETypes sends "allowed_mime_types": null, removing
	// the restriction so every MIME type is accepted. It cannot be
	// combined with a non-nil AllowedMIMETypes.
	ClearAllowedMIMETypes bool
	// Type is the bucket type (CreateBucket only). Empty means the server
	// default (STANDARD).
	Type BucketType
	// VersioningStatus sets object versioning. Empty leaves it unset.
	VersioningStatus VersioningStatus
}

// fileSizeLimitJSON encodes a limit as a JSON number for plain byte counts
// and as a string for values with a unit, matching storage-js
// (number | string).
func fileSizeLimitJSON(v string) (json.RawMessage, error) {
	s := strings.TrimSpace(v)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return json.RawMessage(strconv.FormatInt(n, 10)), nil
	}
	return json.Marshal(s)
}

var jsonNull = json.RawMessage("null")

// bucketBody is the create/update request body. The RawMessage fields are
// omitted when empty and otherwise carry a value or a literal null.
type bucketBody struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Type             BucketType       `json:"type,omitempty"`
	Public           *bool            `json:"public,omitempty"`
	FileSizeLimit    json.RawMessage  `json:"file_size_limit,omitempty"`
	AllowedMIMETypes json.RawMessage  `json:"allowed_mime_types,omitempty"`
	VersioningStatus VersioningStatus `json:"versioning_status,omitempty"`
}

var (
	errFileSizeLimitConflict = errors.New("storage: FileSizeLimit and ClearFileSizeLimit are mutually exclusive")
	errMIMETypesConflict     = errors.New("storage: AllowedMIMETypes and ClearAllowedMIMETypes are mutually exclusive")
)

// newBucketBody builds the request body. create selects CreateBucket
// semantics: Type is sent and a nil Public is sent as false.
func newBucketBody(id string, opts *BucketOptions, create bool) (bucketBody, error) {
	b := bucketBody{ID: id, Name: id}
	if opts == nil {
		opts = &BucketOptions{}
	}
	if opts.ClearFileSizeLimit && opts.FileSizeLimit != "" {
		return b, errFileSizeLimitConflict
	}
	if opts.ClearAllowedMIMETypes && opts.AllowedMIMETypes != nil {
		return b, errMIMETypesConflict
	}
	if opts.Public != nil {
		v := *opts.Public
		b.Public = &v
	} else if create {
		b.Public = new(bool)
	}
	switch {
	case opts.ClearFileSizeLimit:
		b.FileSizeLimit = jsonNull
	case opts.FileSizeLimit != "":
		raw, err := fileSizeLimitJSON(opts.FileSizeLimit)
		if err != nil {
			return b, fmt.Errorf("storage: encode file size limit: %w", err)
		}
		b.FileSizeLimit = raw
	}
	switch {
	case opts.ClearAllowedMIMETypes:
		b.AllowedMIMETypes = jsonNull
	case opts.AllowedMIMETypes != nil:
		raw, err := json.Marshal(opts.AllowedMIMETypes)
		if err != nil {
			return b, fmt.Errorf("storage: encode allowed MIME types: %w", err)
		}
		b.AllowedMIMETypes = raw
	}
	b.VersioningStatus = opts.VersioningStatus
	if create {
		b.Type = opts.Type
	}
	return b, nil
}

type messageResponse struct {
	Message string `json:"message"`
}

var errEmptyBucketID = errors.New("storage: bucket id is required")

// bucketPath returns "/bucket/<escaped id><suffix>".
func bucketPath(id, suffix string) string {
	return "/bucket/" + transport.PathEscape(id) + suffix
}

// ListBuckets returns the buckets visible to the caller. opts may be nil.
func (c *Client) ListBuckets(ctx context.Context, opts *ListBucketsOptions) ([]Bucket, error) {
	req := &transport.Request{Method: http.MethodGet, Path: "/bucket"}
	if opts != nil {
		q := make(map[string][]string)
		if opts.Limit > 0 {
			q["limit"] = []string{strconv.Itoa(opts.Limit)}
		}
		if opts.Offset > 0 {
			q["offset"] = []string{strconv.Itoa(opts.Offset)}
		}
		if opts.Search != "" {
			q["search"] = []string{opts.Search}
		}
		if opts.SortColumn != "" {
			q["sortColumn"] = []string{opts.SortColumn}
		}
		if opts.SortOrder != "" {
			q["sortOrder"] = []string{opts.SortOrder}
		}
		req.Query = q
	}
	var out []Bucket
	if _, err := request(ctx, c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return out, nil
}

// GetBucket returns the bucket with the given id.
func (c *Client) GetBucket(ctx context.Context, id string) (*Bucket, error) {
	if id == "" {
		return nil, errEmptyBucketID
	}
	var out Bucket
	req := &transport.Request{Method: http.MethodGet, Path: bucketPath(id, "")}
	if _, err := request(ctx, c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateBucket creates a bucket whose id and name are id, and returns its
// name. opts may be nil, which creates a private bucket with no limits.
func (c *Client) CreateBucket(ctx context.Context, id string, opts *BucketOptions) (string, error) {
	if id == "" {
		return "", errEmptyBucketID
	}
	var out struct {
		Name string `json:"name"`
	}
	body, err := newBucketBody(id, opts, true)
	if err != nil {
		return "", err
	}
	req := &transport.Request{Method: http.MethodPost, Path: "/bucket", Body: body}
	if _, err := request(ctx, c.t, req, &out, "storage"); err != nil {
		return "", err
	}
	return out.Name, nil
}

// UpdateBucket updates a bucket's settings and returns the server message.
// Only the settings set in opts are sent; the others keep their current
// values. In particular a nil opts.Public leaves the bucket's visibility
// unchanged (storage-js makes public a required argument and always sends
// it). opts.Type is ignored.
//
// The Storage API requires at least one of public, file_size_limit or
// allowed_mime_types in an update, so UpdateBucket returns an error without
// sending anything unless opts sets Public, FileSizeLimit, AllowedMIMETypes
// (nil vs empty matters: a non-nil empty slice is sent as []) or one of the
// Clear flags. To change only VersioningStatus, also set Public to the
// bucket's current visibility.
func (c *Client) UpdateBucket(ctx context.Context, id string, opts *BucketOptions) (string, error) {
	if id == "" {
		return "", errEmptyBucketID
	}
	if opts == nil || (opts.Public == nil && opts.FileSizeLimit == "" && !opts.ClearFileSizeLimit &&
		opts.AllowedMIMETypes == nil && !opts.ClearAllowedMIMETypes) {
		return "", errors.New("storage: UpdateBucket requires at least one of Public, FileSizeLimit, AllowedMIMETypes or a Clear flag")
	}
	body, err := newBucketBody(id, opts, false)
	if err != nil {
		return "", err
	}
	return c.message(ctx, http.MethodPut, bucketPath(id, ""), body)
}

// EmptyBucket deletes every object in a bucket (asynchronously on the
// server) and returns the server message.
func (c *Client) EmptyBucket(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", errEmptyBucketID
	}
	return c.message(ctx, http.MethodPost, bucketPath(id, "/empty"), struct{}{})
}

// DeleteBucket deletes an empty bucket and returns the server message.
func (c *Client) DeleteBucket(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", errEmptyBucketID
	}
	return c.message(ctx, http.MethodDelete, bucketPath(id, ""), struct{}{})
}

// PurgeCacheOptions configures PurgeCache and PurgeBucketCache.
type PurgeCacheOptions struct {
	// Transformations purges only the cached image transformations
	// (resized/re-encoded variants), keeping the cached original.
	Transformations bool
}

// PurgeBucketCache purges the CDN cache for every object in a bucket and
// returns the server message. opts may be nil.
func (c *Client) PurgeBucketCache(ctx context.Context, id string, opts *PurgeCacheOptions) (string, error) {
	if id == "" {
		return "", errEmptyBucketID
	}
	return c.purge(ctx, transport.PathEscape(id), opts)
}

func (c *Client) purge(ctx context.Context, escapedPath string, opts *PurgeCacheOptions) (string, error) {
	path := "/cdn/" + escapedPath
	if opts != nil && opts.Transformations {
		path += "?transformations=true"
	}
	return c.message(ctx, http.MethodDelete, path, struct{}{})
}

func (c *Client) message(ctx context.Context, method, path string, body any) (string, error) {
	var out messageResponse
	req := &transport.Request{Method: method, Path: path, Body: body}
	if _, err := request(ctx, c.t, req, &out, "storage"); err != nil {
		return "", err
	}
	return out.Message, nil
}

// LifecycleRuleStatus says whether a lifecycle rule is applied.
type LifecycleRuleStatus string

// Lifecycle rule states.
const (
	LifecycleRuleEnabled  LifecycleRuleStatus = "Enabled"
	LifecycleRuleDisabled LifecycleRuleStatus = "Disabled"
)

// NoncurrentVersionExpiration expires previous versions of objects.
type NoncurrentVersionExpiration struct {
	// NoncurrentDays is how old a noncurrent version must be before it
	// can expire.
	NoncurrentDays int `json:"noncurrentDays"`
	// NewerNoncurrentVersions keeps this many of the newest noncurrent
	// versions regardless of age (1 to 100). Zero leaves it unset.
	NewerNoncurrentVersions int `json:"newerNoncurrentVersions,omitempty"`
}

// LifecycleRuleFilter selects the objects a rule applies to. The server
// currently only accepts the empty filter, which is always sent as {}.
type LifecycleRuleFilter struct{}

// LifecycleRule is one bucket lifecycle rule.
type LifecycleRule struct {
	// ID is optional; the server generates one when empty.
	ID                          string                      `json:"id,omitempty"`
	Status                      LifecycleRuleStatus         `json:"status"`
	Filter                      LifecycleRuleFilter         `json:"filter"`
	NoncurrentVersionExpiration NoncurrentVersionExpiration `json:"noncurrentVersionExpiration"`
}

// BucketLifecycleConfiguration is the lifecycle policy of a bucket (1 to
// 1000 rules).
type BucketLifecycleConfiguration struct {
	Rules []LifecycleRule `json:"rules"`
}

// GetBucketLifecycle returns a bucket's lifecycle policy. It fails with
// CodeNoSuchLifecycleConfiguration when the bucket has none.
func (c *Client) GetBucketLifecycle(ctx context.Context, id string) (*BucketLifecycleConfiguration, error) {
	if id == "" {
		return nil, errEmptyBucketID
	}
	var out BucketLifecycleConfiguration
	req := &transport.Request{Method: http.MethodGet, Path: bucketPath(id, "/lifecycle")}
	if _, err := request(ctx, c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateBucketLifecycle replaces a bucket's lifecycle policy and returns
// the stored policy.
func (c *Client) UpdateBucketLifecycle(ctx context.Context, id string, cfg BucketLifecycleConfiguration) (*BucketLifecycleConfiguration, error) {
	if id == "" {
		return nil, errEmptyBucketID
	}
	if cfg.Rules == nil {
		cfg.Rules = []LifecycleRule{}
	}
	var out BucketLifecycleConfiguration
	req := &transport.Request{Method: http.MethodPut, Path: bucketPath(id, "/lifecycle"), Body: cfg}
	if _, err := request(ctx, c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteBucketLifecycle removes a bucket's lifecycle policy and returns the
// server message.
func (c *Client) DeleteBucketLifecycle(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", errEmptyBucketID
	}
	return c.message(ctx, http.MethodDelete, bucketPath(id, "/lifecycle"), struct{}{})
}
