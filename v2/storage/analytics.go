package storage

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// AnalyticsAPI manages analytics buckets: storage buckets backed by an
// Apache Iceberg REST catalog, served under <storage URL>/iceberg.
//
// The analytics API is in public alpha upstream and may not be available
// on every project. An *AnalyticsAPI is safe for concurrent use.
type AnalyticsAPI struct {
	t   *transport.Client
	err error
}

// Analytics returns the analytics-bucket API. The returned value shares the
// client's configuration and is safe for concurrent use.
func (c *Client) Analytics() *AnalyticsAPI {
	t, err := c.sub("/iceberg")
	return &AnalyticsAPI{t: t, err: err}
}

// AnalyticsBucket is an analytics (Iceberg) bucket.
type AnalyticsBucket struct {
	// Name is the bucket name.
	Name string `json:"name"`
	// Type is always "ANALYTICS".
	Type string `json:"type"`
	// Format is the table format, e.g. "iceberg".
	Format string `json:"format"`
	// CreatedAt is the RFC 3339 creation timestamp.
	CreatedAt string `json:"created_at"`
	// UpdatedAt is the RFC 3339 last-update timestamp.
	UpdatedAt string `json:"updated_at"`
}

// AnalyticsSortColumn is a column analytics buckets can be sorted by.
type AnalyticsSortColumn string

// Sort columns accepted by AnalyticsAPI.ListBuckets.
const (
	AnalyticsSortByName      AnalyticsSortColumn = "name"
	AnalyticsSortByCreatedAt AnalyticsSortColumn = "created_at"
	AnalyticsSortByUpdatedAt AnalyticsSortColumn = "updated_at"
)

// AnalyticsSortOrder is a sort direction for AnalyticsAPI.ListBuckets.
type AnalyticsSortOrder string

// Sort directions accepted by AnalyticsAPI.ListBuckets.
const (
	AnalyticsSortAsc  AnalyticsSortOrder = "asc"
	AnalyticsSortDesc AnalyticsSortOrder = "desc"
)

// AnalyticsListBucketsOptions filters and paginates AnalyticsAPI.ListBuckets.
// Zero values are omitted from the request.
type AnalyticsListBucketsOptions struct {
	// Limit is the maximum number of buckets to return. A nil Limit
	// leaves the server default.
	Limit *int
	// Offset is the number of buckets to skip. A nil Offset is omitted.
	Offset *int
	// SortColumn orders the result.
	SortColumn AnalyticsSortColumn
	// SortOrder is the sort direction.
	SortOrder AnalyticsSortOrder
	// Search filters buckets by name.
	Search string
}

// AnalyticsMessageResponse is the confirmation returned by mutating
// analytics-bucket endpoints.
type AnalyticsMessageResponse struct {
	// Message is the server's confirmation, e.g. "Successfully deleted".
	Message string `json:"message"`
}

// CreateBucket creates an analytics bucket named name.
func (a *AnalyticsAPI) CreateBucket(ctx context.Context, name string) (*AnalyticsBucket, error) {
	if a.err != nil {
		return nil, a.err
	}
	if err := analyticsCheckBucketName(name); err != nil {
		return nil, err
	}
	var out AnalyticsBucket
	_, err := request(ctx, a.t, &transport.Request{
		Method: http.MethodPost,
		Path:   "/bucket",
		Body:   map[string]string{"name": name},
	}, &out, "storage")
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListBuckets lists the project's analytics buckets. opts may be nil.
func (a *AnalyticsAPI) ListBuckets(ctx context.Context, opts *AnalyticsListBucketsOptions) ([]AnalyticsBucket, error) {
	if a.err != nil {
		return nil, a.err
	}
	q := url.Values{}
	if opts != nil {
		if opts.Limit != nil {
			q.Set("limit", strconv.Itoa(*opts.Limit))
		}
		if opts.Offset != nil {
			q.Set("offset", strconv.Itoa(*opts.Offset))
		}
		if opts.SortColumn != "" {
			q.Set("sortColumn", string(opts.SortColumn))
		}
		if opts.SortOrder != "" {
			q.Set("sortOrder", string(opts.SortOrder))
		}
		if opts.Search != "" {
			q.Set("search", opts.Search)
		}
	}
	var out []AnalyticsBucket
	_, err := request(ctx, a.t, &transport.Request{
		Method: http.MethodGet,
		Path:   "/bucket",
		Query:  q,
	}, &out, "storage")
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteBucket deletes the analytics bucket name. The bucket must be empty.
func (a *AnalyticsAPI) DeleteBucket(ctx context.Context, name string) (*AnalyticsMessageResponse, error) {
	if a.err != nil {
		return nil, a.err
	}
	if err := analyticsCheckBucketName(name); err != nil {
		return nil, err
	}
	var out AnalyticsMessageResponse
	_, err := request(ctx, a.t, &transport.Request{
		Method: http.MethodDelete,
		Path:   "/bucket/" + url.PathEscape(name),
		Body:   struct{}{},
	}, &out, "storage")
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// From returns an Iceberg REST catalog client for the analytics bucket
// bucketName (the Iceberg "warehouse"). It performs no I/O. It returns an
// error when bucketName does not satisfy the Storage bucket naming rules
// (1-100 characters, no path separators, no leading or trailing
// whitespace, not "." or "..", only letters, digits and the characters
// _ ! - . * ' ( ) space & $ @ = ; : + , ?). The error is an
// *AnalyticsArgumentError.
func (a *AnalyticsAPI) From(bucketName string) (*IcebergCatalog, error) {
	if a.err != nil {
		return nil, a.err
	}
	if err := analyticsCheckBucketName(bucketName); err != nil {
		return nil, err
	}
	return &IcebergCatalog{t: a.t, warehouse: bucketName}, nil
}

// analyticsCheckBucketName returns an *AnalyticsArgumentError when name
// is not a valid bucket name.
func analyticsCheckBucketName(name string) error {
	if analyticsValidBucketName(name) {
		return nil
	}
	return &AnalyticsArgumentError{Argument: "bucket name", Reason: "file, folder, and bucket names must follow " +
		"AWS object key naming guidelines and should avoid the use of any other characters, " +
		`and must not be "." or ".."`}
}

var analyticsBucketNameRE = regexp.MustCompile(`^[\w!.*'() &$@=;:+,?-]+$`)

// analyticsValidBucketName mirrors storage-js isValidBucketName, and additionally rejects the
// dot-segments "." and "..", which would alter the request path.
func analyticsValidBucketName(name string) bool {
	if name == "" || name == "." || name == ".." || utf8.RuneCountInString(name) > 100 {
		return false
	}
	if strings.TrimSpace(name) != name {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	return analyticsBucketNameRE.MatchString(name)
}
