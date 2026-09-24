package storage

import (
	"context"
	"net/http"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Values for ListFilesOptions/ListFilesV2Options NoncurrentVersions and
// DeleteMarkers.
const (
	ListExclude = "exclude"
	ListInclude = "include"
	ListOnly    = "only"
)

// FileObject is an entry returned by List and Remove. For folder entries
// only Name is set.
type FileObject struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
	// UpdatedAt, CreatedAt and LastAccessedAt are RFC 3339 timestamps.
	UpdatedAt string `json:"updated_at,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	// Deprecated: LastAccessedAt is no longer maintained by the server.
	LastAccessedAt string `json:"last_accessed_at,omitempty"`
	// Metadata holds the object's system metadata (eTag, size, mimetype,
	// cacheControl, lastModified, contentLength, httpStatusCode, ...).
	Metadata map[string]any `json:"metadata,omitempty"`
	// BucketID may be set in Remove responses; List does not return it.
	BucketID string `json:"bucket_id,omitempty"`
	// Deprecated: Owner is not returned by List or Remove.
	Owner string `json:"owner,omitempty"`
	// Deprecated: Buckets is not returned by List or Remove.
	Buckets *Bucket `json:"buckets,omitempty"`
	// Version is the object version id (empty for folders or on older
	// servers).
	Version        string  `json:"version,omitempty"`
	ArchivedAt     *string `json:"archived_at,omitempty"`
	IsDeleteMarker *bool   `json:"is_delete_marker,omitempty"`
	IsVersioned    *bool   `json:"is_versioned,omitempty"`
}

// SortBy orders List results.
type SortBy struct {
	// Column is any FileObject column, e.g. "name" (the default),
	// "created_at" or "updated_at".
	Column string `json:"column,omitempty"`
	// Order is "asc" (the default) or "desc".
	Order string `json:"order,omitempty"`
}

// ListFilesOptions configures List.
type ListFilesOptions struct {
	// Limit is the number of entries to return. Zero means 100.
	Limit int
	// Offset is the number of entries to skip.
	Offset int
	// SortBy orders the results. Empty fields default to name asc.
	SortBy SortBy
	// Search filters entries by name.
	Search string
	// NoncurrentVersions is ListExclude (default), ListInclude or ListOnly.
	NoncurrentVersions string
	// DeleteMarkers is ListExclude (default), ListInclude or ListOnly.
	DeleteMarkers string
	// ExactMatch only returns objects whose key equals the prefix.
	ExactMatch bool
}

type listBody struct {
	Limit              int    `json:"limit"`
	Offset             int    `json:"offset"`
	SortBy             SortBy `json:"sortBy"`
	Search             string `json:"search,omitempty"`
	NoncurrentVersions string `json:"noncurrentVersions,omitempty"`
	DeleteMarkers      string `json:"deleteMarkers,omitempty"`
	ExactMatch         bool   `json:"exactMatch,omitempty"`
	Prefix             string `json:"prefix"`
}

// List lists the files and folders directly under prefix ("" for the
// bucket root). opts may be nil.
func (f *FileAPI) List(ctx context.Context, prefix string, opts *ListFilesOptions) ([]FileObject, error) {
	o := ListFilesOptions{}
	if opts != nil {
		o = *opts
	}
	body := listBody{
		Limit:              o.Limit,
		Offset:             o.Offset,
		SortBy:             o.SortBy,
		Search:             o.Search,
		NoncurrentVersions: o.NoncurrentVersions,
		DeleteMarkers:      o.DeleteMarkers,
		ExactMatch:         o.ExactMatch,
		Prefix:             prefix,
	}
	if body.Limit <= 0 {
		body.Limit = 100
	}
	if body.SortBy.Column == "" {
		body.SortBy.Column = "name"
	}
	if body.SortBy.Order == "" {
		body.SortBy.Order = "asc"
	}
	var out []FileObject
	req := &transport.Request{Method: http.MethodPost, Path: "/object/list/" + transport.PathEscape(f.bucketID), Body: body}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return out, nil
}

// SortByV2 orders ListV2 results.
type SortByV2 struct {
	// Column is "name", "updated_at" or "created_at".
	Column string `json:"column"`
	// Order is "asc" or "desc". Empty means the server default.
	Order string `json:"order,omitempty"`
}

// ListFilesV2Options configures ListV2. Zero values are omitted from the
// request so the server defaults apply.
type ListFilesV2Options struct {
	// Limit is the number of entries per page. Zero means the server
	// default (1000).
	Limit int `json:"limit,omitempty"`
	// Prefix filters objects by key prefix.
	Prefix string `json:"prefix,omitempty"`
	// Cursor continues a previous listing; pass ListV2Result.NextCursor.
	Cursor string `json:"cursor,omitempty"`
	// WithDelimiter groups keys by "/" into Folders, emulating a
	// directory listing. False lists all objects flat.
	WithDelimiter bool `json:"with_delimiter,omitempty"`
	// SortBy orders the results (default name asc).
	SortBy *SortByV2 `json:"sortBy,omitempty"`
	// NoncurrentVersions is ListExclude (default), ListInclude or ListOnly.
	NoncurrentVersions string `json:"noncurrentVersions,omitempty"`
	// DeleteMarkers is ListExclude (default), ListInclude or ListOnly.
	DeleteMarkers string `json:"deleteMarkers,omitempty"`
	// ExactMatch only returns objects whose key equals Prefix.
	ExactMatch bool `json:"exactMatch,omitempty"`
}

// ListV2Object is a file entry in a ListV2 result.
type ListV2Object struct {
	Name string `json:"name"`
	// Key is the full object key.
	Key       string         `json:"key,omitempty"`
	ID        string         `json:"id"`
	UpdatedAt string         `json:"updated_at"`
	CreatedAt string         `json:"created_at"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	// Deprecated: LastAccessedAt is no longer maintained by the server.
	LastAccessedAt string  `json:"last_accessed_at,omitempty"`
	Version        string  `json:"version,omitempty"`
	ArchivedAt     *string `json:"archived_at,omitempty"`
	IsDeleteMarker bool    `json:"is_delete_marker,omitempty"`
	IsVersioned    bool    `json:"is_versioned,omitempty"`
}

// ListV2Folder is a folder entry in a ListV2 result (WithDelimiter only).
type ListV2Folder struct {
	Name string `json:"name"`
	Key  string `json:"key,omitempty"`
}

// ListV2Result is one page of ListV2 results.
type ListV2Result struct {
	HasNext    bool           `json:"hasNext"`
	Folders    []ListV2Folder `json:"folders"`
	Objects    []ListV2Object `json:"objects"`
	NextCursor string         `json:"nextCursor,omitempty"`
}

// ListV2 lists objects with cursor-based pagination. opts may be nil.
func (f *FileAPI) ListV2(ctx context.Context, opts *ListFilesV2Options) (*ListV2Result, error) {
	body := ListFilesV2Options{}
	if opts != nil {
		body = *opts
	}
	var out ListV2Result
	req := &transport.Request{Method: http.MethodPost, Path: "/object/list-v2/" + transport.PathEscape(f.bucketID), Body: body}
	if _, err := request(ctx, f.c.t, req, &out, "storage"); err != nil {
		return nil, err
	}
	return &out, nil
}
