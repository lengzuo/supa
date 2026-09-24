package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// VectorsAPI manages vector buckets, indexes and vectors, served under
// <storage URL>/vector. Every call is a JSON POST to an action endpoint
// (e.g. /vector/CreateVectorBucket); errors are *Error with Namespace
// "vectors".
//
// The vectors API is in public alpha upstream and may not be available on
// every project. A *VectorsAPI and the scopes derived from it are
// immutable and safe for concurrent use.
type VectorsAPI struct {
	t   *transport.Client
	err error
}

// Vectors returns the vector-bucket API.
func (c *Client) Vectors() *VectorsAPI {
	t, err := c.sub("/vector")
	return &VectorsAPI{t: t, err: err}
}

// Vector limits enforced client-side, matching storage-js.
const (
	// VectorMaxBatchSize is the maximum number of vectors per PutVectors
	// call and keys per DeleteVectors call.
	VectorMaxBatchSize = 500
	// VectorMaxSegmentCount is the maximum ListVectors segment count.
	VectorMaxSegmentCount = 16
)

// VectorDataType is the element type of an index's vectors.
type VectorDataType string

// VectorDataTypeFloat32 is the only data type currently supported.
const VectorDataTypeFloat32 VectorDataType = "float32"

// VectorDistanceMetric is the similarity metric of an index.
type VectorDistanceMetric string

// Distance metrics supported by vector indexes.
const (
	VectorDistanceCosine     VectorDistanceMetric = "cosine"
	VectorDistanceEuclidean  VectorDistanceMetric = "euclidean"
	VectorDistanceDotProduct VectorDistanceMetric = "dotproduct"
)

// VectorEncryptionConfiguration is a vector bucket's server-side
// encryption configuration.
type VectorEncryptionConfiguration struct {
	KMSKeyARN string `json:"kmsKeyArn,omitempty"`
	SSEType   string `json:"sseType,omitempty"`
}

// VectorBucket is a vector bucket.
type VectorBucket struct {
	VectorBucketName string `json:"vectorBucketName"`
	// CreationTime is the creation time in Unix seconds.
	CreationTime            float64                        `json:"creationTime,omitempty"`
	EncryptionConfiguration *VectorEncryptionConfiguration `json:"encryptionConfiguration,omitempty"`
}

// VectorMetadataConfiguration configures metadata handling of an index.
type VectorMetadataConfiguration struct {
	// NonFilterableMetadataKeys are stored but cannot be used in filters.
	NonFilterableMetadataKeys []string `json:"nonFilterableMetadataKeys,omitempty"`
}

// VectorIndex describes a vector index.
type VectorIndex struct {
	IndexName             string                       `json:"indexName"`
	VectorBucketName      string                       `json:"vectorBucketName"`
	DataType              VectorDataType               `json:"dataType"`
	Dimension             int                          `json:"dimension"`
	DistanceMetric        VectorDistanceMetric         `json:"distanceMetric"`
	MetadataConfiguration *VectorMetadataConfiguration `json:"metadataConfiguration,omitempty"`
	// CreationTime is the creation time in Unix seconds.
	CreationTime float64 `json:"creationTime,omitempty"`
}

// VectorData holds a vector's components.
type VectorData struct {
	Float32 []float32 `json:"float32"`
}

// VectorMetadata is arbitrary JSON metadata attached to a vector.
type VectorMetadata map[string]any

// VectorFilter is a metadata filter expression for QueryVectors, e.g.
// {"category": "shoes"} or {"$and": [...]}.
type VectorFilter map[string]any

// VectorObject is a vector to insert or replace.
type VectorObject struct {
	Key      string         `json:"key"`
	Data     VectorData     `json:"data"`
	Metadata VectorMetadata `json:"metadata,omitempty"`
}

// VectorMatch is a vector returned by get, list or query calls. Data,
// Metadata and Distance are set only when requested.
type VectorMatch struct {
	Key      string         `json:"key"`
	Data     *VectorData    `json:"data,omitempty"`
	Metadata VectorMetadata `json:"metadata,omitempty"`
	Distance *float64       `json:"distance,omitempty"`
}

// VectorListBucketsOptions filters and paginates VectorsAPI.ListBuckets.
type VectorListBucketsOptions struct {
	Prefix     string `json:"prefix,omitempty"`
	MaxResults int    `json:"maxResults,omitempty"`
	NextToken  string `json:"nextToken,omitempty"`
}

// VectorBucketSummary is an entry of VectorListBucketsResponse.
type VectorBucketSummary struct {
	VectorBucketName string `json:"vectorBucketName"`
}

// VectorListBucketsResponse is a page of vector buckets.
type VectorListBucketsResponse struct {
	VectorBuckets []VectorBucketSummary `json:"vectorBuckets"`
	NextToken     string                `json:"nextToken,omitempty"`
}

// VectorCreateIndexOptions describes a new index.
type VectorCreateIndexOptions struct {
	IndexName             string                       `json:"indexName"`
	DataType              VectorDataType               `json:"dataType"`
	Dimension             int                          `json:"dimension"`
	DistanceMetric        VectorDistanceMetric         `json:"distanceMetric"`
	MetadataConfiguration *VectorMetadataConfiguration `json:"metadataConfiguration,omitempty"`
}

// VectorListIndexesOptions filters and paginates ListIndexes.
type VectorListIndexesOptions struct {
	Prefix     string `json:"prefix,omitempty"`
	MaxResults int    `json:"maxResults,omitempty"`
	NextToken  string `json:"nextToken,omitempty"`
}

// VectorIndexSummary is an entry of VectorListIndexesResponse.
type VectorIndexSummary struct {
	IndexName string `json:"indexName"`
}

// VectorListIndexesResponse is a page of indexes.
type VectorListIndexesResponse struct {
	Indexes   []VectorIndexSummary `json:"indexes"`
	NextToken string               `json:"nextToken,omitempty"`
}

// VectorPutVectorsOptions is the input of PutVectors.
type VectorPutVectorsOptions struct {
	// Vectors holds 1 to VectorMaxBatchSize vectors.
	Vectors []VectorObject `json:"vectors"`
}

// VectorGetVectorsOptions is the input of GetVectors.
type VectorGetVectorsOptions struct {
	Keys           []string `json:"keys"`
	ReturnData     bool     `json:"returnData,omitempty"`
	ReturnMetadata bool     `json:"returnMetadata,omitempty"`
}

// VectorGetVectorsResponse is the result of GetVectors.
type VectorGetVectorsResponse struct {
	Vectors []VectorMatch `json:"vectors"`
}

// VectorDeleteVectorsOptions is the input of DeleteVectors.
type VectorDeleteVectorsOptions struct {
	// Keys holds 1 to VectorMaxBatchSize keys.
	Keys []string `json:"keys"`
}

// VectorListVectorsOptions paginates ListVectors and configures parallel
// scans: set SegmentCount (1-16) and SegmentIndex (0..SegmentCount-1) to
// read one disjoint segment of the index.
type VectorListVectorsOptions struct {
	MaxResults     int    `json:"maxResults,omitempty"`
	NextToken      string `json:"nextToken,omitempty"`
	ReturnData     bool   `json:"returnData,omitempty"`
	ReturnMetadata bool   `json:"returnMetadata,omitempty"`
	// SegmentCount is the total number of segments; nil means no
	// segmentation.
	SegmentCount *int `json:"segmentCount,omitempty"`
	// SegmentIndex is the zero-based segment to read.
	SegmentIndex *int `json:"segmentIndex,omitempty"`
}

// VectorListVectorsResponse is a page of vectors.
type VectorListVectorsResponse struct {
	Vectors   []VectorMatch `json:"vectors"`
	NextToken string        `json:"nextToken,omitempty"`
}

// VectorQueryVectorsOptions is the input of QueryVectors.
type VectorQueryVectorsOptions struct {
	QueryVector    VectorData   `json:"queryVector"`
	TopK           int          `json:"topK"`
	NextToken      string       `json:"nextToken,omitempty"`
	Filter         VectorFilter `json:"filter,omitempty"`
	ReturnDistance bool         `json:"returnDistance,omitempty"`
	ReturnMetadata bool         `json:"returnMetadata,omitempty"`
}

// VectorQueryVectorsResponse is the result of QueryVectors.
type VectorQueryVectorsResponse struct {
	Vectors        []VectorMatch        `json:"vectors"`
	DistanceMetric VectorDistanceMetric `json:"distanceMetric,omitempty"`
	NextToken      string               `json:"nextToken,omitempty"`
}

// vectorPost POSTs body to /<action> and decodes a JSON response into out.
// Empty bodies, 204 and non-JSON responses decode to nothing, since the
// S3 Vectors API answers mutations with an empty 200.
func vectorPost(ctx context.Context, t *transport.Client, action string, body, out any) error {
	resp, err := t.Do(ctx, &transport.Request{
		Method: http.MethodPost,
		Path:   "/" + action,
		Body:   body,
	})
	if err != nil {
		return err
	}
	if err := transport.CheckResponse(resp); err != nil {
		return toError(err, "vectors")
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("storage: read vectors response: %w", err)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("storage: decode vectors response: %w", err)
	}
	return nil
}

// CreateBucket creates a vector bucket.
func (v *VectorsAPI) CreateBucket(ctx context.Context, vectorBucketName string) error {
	if v.err != nil {
		return v.err
	}
	return vectorPost(ctx, v.t, "CreateVectorBucket", map[string]string{"vectorBucketName": vectorBucketName}, nil)
}

// GetBucket returns a vector bucket's details.
func (v *VectorsAPI) GetBucket(ctx context.Context, vectorBucketName string) (*VectorBucket, error) {
	if v.err != nil {
		return nil, v.err
	}
	var out struct {
		VectorBucket VectorBucket `json:"vectorBucket"`
	}
	if err := vectorPost(ctx, v.t, "GetVectorBucket", map[string]string{"vectorBucketName": vectorBucketName}, &out); err != nil {
		return nil, err
	}
	return &out.VectorBucket, nil
}

// ListBuckets lists vector buckets. opts may be nil.
func (v *VectorsAPI) ListBuckets(ctx context.Context, opts *VectorListBucketsOptions) (*VectorListBucketsResponse, error) {
	if v.err != nil {
		return nil, v.err
	}
	if opts == nil {
		opts = &VectorListBucketsOptions{}
	}
	var out VectorListBucketsResponse
	if err := vectorPost(ctx, v.t, "ListVectorBuckets", opts, &out); err != nil {
		return nil, err
	}
	if out.VectorBuckets == nil {
		out.VectorBuckets = []VectorBucketSummary{}
	}
	return &out, nil
}

// DeleteBucket deletes a vector bucket. It must contain no indexes.
func (v *VectorsAPI) DeleteBucket(ctx context.Context, vectorBucketName string) error {
	if v.err != nil {
		return v.err
	}
	return vectorPost(ctx, v.t, "DeleteVectorBucket", map[string]string{"vectorBucketName": vectorBucketName}, nil)
}

// From returns a scope for the index operations of vectorBucketName.
func (v *VectorsAPI) From(vectorBucketName string) *VectorBucketScope {
	return &VectorBucketScope{api: v, bucket: vectorBucketName}
}

// VectorBucketScope performs index operations within one vector bucket.
// It is immutable and safe for concurrent use.
type VectorBucketScope struct {
	api    *VectorsAPI
	bucket string
}

// BucketName returns the scoped vector bucket name.
func (s *VectorBucketScope) BucketName() string { return s.bucket }

// CreateIndex creates an index in the bucket.
func (s *VectorBucketScope) CreateIndex(ctx context.Context, opts VectorCreateIndexOptions) error {
	if s.api.err != nil {
		return s.api.err
	}
	body := struct {
		VectorBucketName string `json:"vectorBucketName"`
		VectorCreateIndexOptions
	}{s.bucket, opts}
	return vectorPost(ctx, s.api.t, "CreateIndex", body, nil)
}

// GetIndex returns an index's details.
func (s *VectorBucketScope) GetIndex(ctx context.Context, indexName string) (*VectorIndex, error) {
	if s.api.err != nil {
		return nil, s.api.err
	}
	var out struct {
		Index VectorIndex `json:"index"`
	}
	if err := vectorPost(ctx, s.api.t, "GetIndex", s.indexBody(indexName), &out); err != nil {
		return nil, err
	}
	return &out.Index, nil
}

// ListIndexes lists the bucket's indexes. opts may be nil.
func (s *VectorBucketScope) ListIndexes(ctx context.Context, opts *VectorListIndexesOptions) (*VectorListIndexesResponse, error) {
	if s.api.err != nil {
		return nil, s.api.err
	}
	if opts == nil {
		opts = &VectorListIndexesOptions{}
	}
	body := struct {
		VectorBucketName string `json:"vectorBucketName"`
		*VectorListIndexesOptions
	}{s.bucket, opts}
	var out VectorListIndexesResponse
	if err := vectorPost(ctx, s.api.t, "ListIndexes", body, &out); err != nil {
		return nil, err
	}
	if out.Indexes == nil {
		out.Indexes = []VectorIndexSummary{}
	}
	return &out, nil
}

// DeleteIndex deletes an index and all its vectors.
func (s *VectorBucketScope) DeleteIndex(ctx context.Context, indexName string) error {
	if s.api.err != nil {
		return s.api.err
	}
	return vectorPost(ctx, s.api.t, "DeleteIndex", s.indexBody(indexName), nil)
}

func (s *VectorBucketScope) indexBody(indexName string) any {
	return map[string]string{"vectorBucketName": s.bucket, "indexName": indexName}
}

// Index returns a scope for the vector data operations of indexName.
func (s *VectorBucketScope) Index(indexName string) *VectorIndexScope {
	return &VectorIndexScope{api: s.api, bucket: s.bucket, index: indexName}
}

// VectorIndexScope performs vector data operations within one index. It
// is immutable and safe for concurrent use.
type VectorIndexScope struct {
	api    *VectorsAPI
	bucket string
	index  string
}

// BucketName returns the scoped vector bucket name.
func (s *VectorIndexScope) BucketName() string { return s.bucket }

// IndexName returns the scoped index name.
func (s *VectorIndexScope) IndexName() string { return s.index }

// vectorScoped prefixes a request body with the bucket and index names.
type vectorScoped[T any] struct {
	VectorBucketName string `json:"vectorBucketName"`
	IndexName        string `json:"indexName"`
	Options          T
}

// MarshalJSON flattens Options next to the bucket and index names.
func (b vectorScoped[T]) MarshalJSON() ([]byte, error) {
	head, err := json.Marshal(map[string]string{"vectorBucketName": b.VectorBucketName, "indexName": b.IndexName})
	if err != nil {
		return nil, err
	}
	opts, err := json.Marshal(b.Options)
	if err != nil {
		return nil, err
	}
	inner := bytes.TrimSpace(opts[1 : len(opts)-1])
	if len(inner) == 0 {
		return head, nil
	}
	out := append(head[:len(head)-1:len(head)-1], ',')
	out = append(out, inner...)
	return append(out, '}'), nil
}

func vectorScope[T any](s *VectorIndexScope, opts T) vectorScoped[T] {
	return vectorScoped[T]{VectorBucketName: s.bucket, IndexName: s.index, Options: opts}
}

// PutVectors inserts or replaces 1 to VectorMaxBatchSize vectors.
func (s *VectorIndexScope) PutVectors(ctx context.Context, opts VectorPutVectorsOptions) error {
	if s.api.err != nil {
		return s.api.err
	}
	if n := len(opts.Vectors); n < 1 || n > VectorMaxBatchSize {
		return fmt.Errorf("storage: vector batch size must be between 1 and %d items, got %d", VectorMaxBatchSize, n)
	}
	return vectorPost(ctx, s.api.t, "PutVectors", vectorScope(s, opts), nil)
}

// GetVectors fetches vectors by key.
func (s *VectorIndexScope) GetVectors(ctx context.Context, opts VectorGetVectorsOptions) (*VectorGetVectorsResponse, error) {
	if s.api.err != nil {
		return nil, s.api.err
	}
	if opts.Keys == nil {
		opts.Keys = []string{}
	}
	var out VectorGetVectorsResponse
	if err := vectorPost(ctx, s.api.t, "GetVectors", vectorScope(s, opts), &out); err != nil {
		return nil, err
	}
	if out.Vectors == nil {
		out.Vectors = []VectorMatch{}
	}
	return &out, nil
}

// ListVectors lists a page of vectors. opts may be nil. For a parallel
// scan set SegmentCount and SegmentIndex, or use ParallelScan.
func (s *VectorIndexScope) ListVectors(ctx context.Context, opts *VectorListVectorsOptions) (*VectorListVectorsResponse, error) {
	if s.api.err != nil {
		return nil, s.api.err
	}
	if opts == nil {
		opts = &VectorListVectorsOptions{}
	}
	if err := vectorValidateSegments(opts.SegmentCount, opts.SegmentIndex); err != nil {
		return nil, err
	}
	var out VectorListVectorsResponse
	if err := vectorPost(ctx, s.api.t, "ListVectors", vectorScope(s, opts), &out); err != nil {
		return nil, err
	}
	if out.Vectors == nil {
		out.Vectors = []VectorMatch{}
	}
	return &out, nil
}

func vectorValidateSegments(count, index *int) error {
	if count == nil {
		return nil
	}
	if *count < 1 || *count > VectorMaxSegmentCount {
		return fmt.Errorf("storage: segmentCount must be between 1 and %d", VectorMaxSegmentCount)
	}
	if index != nil && (*index < 0 || *index >= *count) {
		return fmt.Errorf("storage: segmentIndex must be between 0 and %d", *count-1)
	}
	return nil
}

// ParallelScan reads every vector of the index by listing segmentCount
// (1-16) disjoint segments concurrently, following each segment's
// NextToken until it is exhausted. fn is called once per page and may be
// called concurrently from different goroutines (one per segment). opts
// may be nil; its NextToken, SegmentCount and SegmentIndex are ignored.
// The first error from a request or from fn cancels the remaining
// segments and is returned.
func (s *VectorIndexScope) ParallelScan(ctx context.Context, segmentCount int, opts *VectorListVectorsOptions,
	fn func(segmentIndex int, page *VectorListVectorsResponse) error) error {
	if err := vectorValidateSegments(&segmentCount, nil); err != nil {
		return err
	}
	if fn == nil {
		return errors.New("storage: ParallelScan requires a callback")
	}
	base := VectorListVectorsOptions{}
	if opts != nil {
		base = *opts
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
	)
	fail := func(err error) {
		once.Do(func() { firstErr = err; cancel() })
	}
	for seg := 0; seg < segmentCount; seg++ {
		wg.Add(1)
		go func(seg int) {
			defer wg.Done()
			o := base
			count, idx := segmentCount, seg
			o.SegmentCount, o.SegmentIndex, o.NextToken = &count, &idx, ""
			for {
				page, err := s.ListVectors(ctx, &o)
				if err != nil {
					fail(err)
					return
				}
				if err := fn(seg, page); err != nil {
					fail(err)
					return
				}
				if page.NextToken == "" {
					return
				}
				o.NextToken = page.NextToken
			}
		}(seg)
	}
	wg.Wait()
	return firstErr
}

// QueryVectors returns the TopK vectors nearest to QueryVector,
// optionally filtered by metadata.
func (s *VectorIndexScope) QueryVectors(ctx context.Context, opts VectorQueryVectorsOptions) (*VectorQueryVectorsResponse, error) {
	if s.api.err != nil {
		return nil, s.api.err
	}
	var out VectorQueryVectorsResponse
	if err := vectorPost(ctx, s.api.t, "QueryVectors", vectorScope(s, opts), &out); err != nil {
		return nil, err
	}
	if out.Vectors == nil {
		out.Vectors = []VectorMatch{}
	}
	return &out, nil
}

// DeleteVectors deletes 1 to VectorMaxBatchSize vectors by key.
func (s *VectorIndexScope) DeleteVectors(ctx context.Context, opts VectorDeleteVectorsOptions) error {
	if s.api.err != nil {
		return s.api.err
	}
	if n := len(opts.Keys); n < 1 || n > VectorMaxBatchSize {
		return fmt.Errorf("storage: keys batch size must be between 1 and %d items, got %d", VectorMaxBatchSize, n)
	}
	return vectorPost(ctx, s.api.t, "DeleteVectors", vectorScope(s, opts), nil)
}
