package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
)

// vectorServer returns a Client whose vector endpoints answer with resp
// (JSON, status 200) and a recorder of requests.
func vectorServer(t *testing.T, resp string) (*VectorsAPI, func() []analyticsRecorded) {
	t.Helper()
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if resp == "" {
			w.WriteHeader(http.StatusOK) // S3 Vectors: empty 200 for mutations
			return
		}
		analyticsWriteJSON(w, 200, resp)
	})
	return c.Vectors(), reqs
}

func vectorAssertRequest(t *testing.T, r analyticsRecorded, action, wantBody string) {
	t.Helper()
	if r.Method != http.MethodPost || r.Path != "/storage/v1/vector/"+action {
		t.Fatalf("got %s %s, want POST /storage/v1/vector/%s", r.Method, r.Path, action)
	}
	analyticsAssertAuth(t, r)
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	analyticsAssertJSON(t, r.Body, wantBody)
}

// upstream: storage-js src/packages/VectorBucketApi.ts createBucket
func TestVectorsCreateBucket(t *testing.T) {
	v, reqs := vectorServer(t, "")
	if err := v.CreateBucket(context.Background(), "embeddings-prod"); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[0], "CreateVectorBucket", `{"vectorBucketName":"embeddings-prod"}`)
}

// upstream: storage-js src/packages/VectorBucketApi.ts getBucket
func TestVectorsGetBucket(t *testing.T) {
	v, reqs := vectorServer(t, `{"vectorBucket":{"vectorBucketName":"embeddings-prod","creationTime":1700000000,
		"encryptionConfiguration":{"sseType":"aws:kms","kmsKeyArn":"arn:aws:kms:k"}}}`)
	b, err := v.GetBucket(context.Background(), "embeddings-prod")
	if err != nil {
		t.Fatal(err)
	}
	if b.VectorBucketName != "embeddings-prod" || b.CreationTime != 1700000000 ||
		b.EncryptionConfiguration.SSEType != "aws:kms" || b.EncryptionConfiguration.KMSKeyARN != "arn:aws:kms:k" {
		t.Fatalf("bucket = %+v", b)
	}
	vectorAssertRequest(t, reqs()[0], "GetVectorBucket", `{"vectorBucketName":"embeddings-prod"}`)
}

// upstream: storage-js src/packages/VectorBucketApi.ts listBuckets
func TestVectorsListBuckets(t *testing.T) {
	v, reqs := vectorServer(t, `{"vectorBuckets":[{"vectorBucketName":"a"},{"vectorBucketName":"b"}],"nextToken":"n2"}`)
	res, err := v.ListBuckets(context.Background(), &VectorListBucketsOptions{Prefix: "emb", MaxResults: 100, NextToken: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.VectorBuckets) != 2 || res.VectorBuckets[1].VectorBucketName != "b" || res.NextToken != "n2" {
		t.Fatalf("res = %+v", res)
	}
	vectorAssertRequest(t, reqs()[0], "ListVectorBuckets", `{"prefix":"emb","maxResults":100,"nextToken":"n1"}`)
	if _, err := v.ListBuckets(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[1], "ListVectorBuckets", `{}`)
}

// upstream: storage-js src/packages/VectorBucketApi.ts deleteBucket
func TestVectorsDeleteBucket(t *testing.T) {
	v, reqs := vectorServer(t, `{}`)
	if err := v.DeleteBucket(context.Background(), "old"); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[0], "DeleteVectorBucket", `{"vectorBucketName":"old"}`)
}

// upstream: storage-js src/packages/StorageVectorsClient.ts VectorBucketScope.createIndex
func TestVectorsCreateIndex(t *testing.T) {
	v, reqs := vectorServer(t, "")
	err := v.From("emb").CreateIndex(context.Background(), VectorCreateIndexOptions{
		IndexName: "docs", DataType: VectorDataTypeFloat32, Dimension: 1536, DistanceMetric: VectorDistanceCosine,
		MetadataConfiguration: &VectorMetadataConfiguration{NonFilterableMetadataKeys: []string{"raw"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[0], "CreateIndex", `{"vectorBucketName":"emb","indexName":"docs","dataType":"float32",
		"dimension":1536,"distanceMetric":"cosine","metadataConfiguration":{"nonFilterableMetadataKeys":["raw"]}}`)
}

// upstream: storage-js src/packages/StorageVectorsClient.ts VectorBucketScope.getIndex
func TestVectorsGetIndex(t *testing.T) {
	v, reqs := vectorServer(t, `{"index":{"indexName":"docs","vectorBucketName":"emb","dataType":"float32","dimension":3,
		"distanceMetric":"euclidean","creationTime":1700000001}}`)
	idx, err := v.From("emb").GetIndex(context.Background(), "docs")
	if err != nil {
		t.Fatal(err)
	}
	want := VectorIndex{IndexName: "docs", VectorBucketName: "emb", DataType: "float32", Dimension: 3,
		DistanceMetric: VectorDistanceEuclidean, CreationTime: 1700000001}
	if fmt.Sprint(*idx) != fmt.Sprint(want) {
		t.Fatalf("index = %+v", *idx)
	}
	vectorAssertRequest(t, reqs()[0], "GetIndex", `{"vectorBucketName":"emb","indexName":"docs"}`)
}

// upstream: storage-js src/packages/StorageVectorsClient.ts VectorBucketScope.listIndexes
func TestVectorsListIndexes(t *testing.T) {
	v, reqs := vectorServer(t, `{"indexes":[{"indexName":"docs"}],"nextToken":"t"}`)
	res, err := v.From("emb").ListIndexes(context.Background(), &VectorListIndexesOptions{Prefix: "d", MaxResults: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Indexes) != 1 || res.Indexes[0].IndexName != "docs" || res.NextToken != "t" {
		t.Fatalf("res = %+v", res)
	}
	vectorAssertRequest(t, reqs()[0], "ListIndexes", `{"vectorBucketName":"emb","prefix":"d","maxResults":5}`)
	if _, err := v.From("emb").ListIndexes(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[1], "ListIndexes", `{"vectorBucketName":"emb"}`)
}

// upstream: storage-js src/packages/StorageVectorsClient.ts VectorBucketScope.deleteIndex
func TestVectorsDeleteIndex(t *testing.T) {
	v, reqs := vectorServer(t, "")
	if err := v.From("emb").DeleteIndex(context.Background(), "docs"); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[0], "DeleteIndex", `{"vectorBucketName":"emb","indexName":"docs"}`)
}

// upstream: storage-js src/packages/StorageVectorsClient.ts VectorBucketScope.index
func TestVectorsAccessIndex(t *testing.T) {
	v, reqs := vectorServer(t, "")
	b := v.From("emb")
	i1, i2 := b.Index("a"), b.Index("b")
	if b.BucketName() != "emb" || i1.BucketName() != "emb" || i1.IndexName() != "a" || i2.IndexName() != "b" {
		t.Fatal("scopes share or lose state")
	}
	if n := len(reqs()); n != 0 {
		t.Fatalf("scoping performed %d requests", n)
	}
}

// upstream: storage-js src/packages/VectorDataApi.ts putVectors
func TestVectorsPutVectors(t *testing.T) {
	v, reqs := vectorServer(t, "")
	idx := v.From("emb").Index("docs")
	err := idx.PutVectors(context.Background(), VectorPutVectorsOptions{Vectors: []VectorObject{
		{Key: "doc-1", Data: VectorData{Float32: []float32{0.1, 0.2, 0.3}}, Metadata: VectorMetadata{"title": "Intro", "page": 1}},
		{Key: "doc-2", Data: VectorData{Float32: []float32{0.4, 0.5, 0.6}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[0], "PutVectors", `{"vectorBucketName":"emb","indexName":"docs","vectors":[
		{"key":"doc-1","data":{"float32":[0.1,0.2,0.3]},"metadata":{"title":"Intro","page":1}},
		{"key":"doc-2","data":{"float32":[0.4,0.5,0.6]}}]}`)

	for _, n := range []int{0, VectorMaxBatchSize + 1} {
		err := idx.PutVectors(context.Background(), VectorPutVectorsOptions{Vectors: make([]VectorObject, n)})
		if err == nil || !strings.Contains(err.Error(), "between 1 and 500") {
			t.Errorf("n=%d: err = %v", n, err)
		}
	}
	if len(reqs()) != 1 {
		t.Fatal("invalid batch reached the server")
	}
}

// upstream: storage-js src/packages/VectorDataApi.ts getVectors
func TestVectorsGetVectors(t *testing.T) {
	v, reqs := vectorServer(t, `{"vectors":[{"key":"doc-1","data":{"float32":[0.1,0.2]},"metadata":{"title":"Intro"}}]}`)
	res, err := v.From("emb").Index("docs").GetVectors(context.Background(), VectorGetVectorsOptions{
		Keys: []string{"doc-1", "missing"}, ReturnData: true, ReturnMetadata: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vectors) != 1 || res.Vectors[0].Data.Float32[1] != 0.2 || res.Vectors[0].Metadata["title"] != "Intro" || res.Vectors[0].Distance != nil {
		t.Fatalf("res = %+v", res)
	}
	vectorAssertRequest(t, reqs()[0], "GetVectors", `{"vectorBucketName":"emb","indexName":"docs",
		"keys":["doc-1","missing"],"returnData":true,"returnMetadata":true}`)
}

// upstream: storage-js src/packages/VectorDataApi.ts listVectors
func TestVectorsListVectors(t *testing.T) {
	v, reqs := vectorServer(t, `{"vectors":[{"key":"a"},{"key":"b"}],"nextToken":"next"}`)
	idx := v.From("emb").Index("docs")
	res, err := idx.ListVectors(context.Background(), &VectorListVectorsOptions{MaxResults: 2, NextToken: "t", ReturnMetadata: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vectors) != 2 || res.NextToken != "next" {
		t.Fatalf("res = %+v", res)
	}
	vectorAssertRequest(t, reqs()[0], "ListVectors", `{"vectorBucketName":"emb","indexName":"docs","maxResults":2,
		"nextToken":"t","returnMetadata":true}`)

	if _, err := idx.ListVectors(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[1], "ListVectors", `{"vectorBucketName":"emb","indexName":"docs"}`)

	count, zero := 4, 0
	if _, err := idx.ListVectors(context.Background(), &VectorListVectorsOptions{SegmentCount: &count, SegmentIndex: &zero}); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[2], "ListVectors", `{"vectorBucketName":"emb","indexName":"docs","segmentCount":4,"segmentIndex":0}`)

	bad := func(c, i int) *VectorListVectorsOptions {
		return &VectorListVectorsOptions{SegmentCount: &c, SegmentIndex: &i}
	}
	for _, o := range []*VectorListVectorsOptions{bad(0, 0), bad(17, 0), bad(4, 4), bad(4, -1)} {
		if _, err := idx.ListVectors(context.Background(), o); err == nil {
			t.Errorf("expected validation error for count=%d index=%d", *o.SegmentCount, *o.SegmentIndex)
		}
	}
	if len(reqs()) != 3 {
		t.Fatal("invalid segment options reached the server")
	}
}

// upstream: storage-js src/packages/VectorDataApi.ts listVectors (segmentCount/segmentIndex parallel scan)
func TestVectorsParallelScan(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		var in struct {
			SegmentCount int    `json:"segmentCount"`
			SegmentIndex int    `json:"segmentIndex"`
			NextToken    string `json:"nextToken"`
			ReturnData   bool   `json:"returnData"`
		}
		_ = json.Unmarshal(body, &in)
		if in.SegmentCount != 3 || !in.ReturnData {
			analyticsWriteJSON(w, 400, `{"statusCode":"400","error":"Bad","message":"bad segment"}`)
			return
		}
		if in.NextToken == "" {
			analyticsWriteJSON(w, 200, fmt.Sprintf(`{"vectors":[{"key":"s%d-0"}],"nextToken":"p2"}`, in.SegmentIndex))
			return
		}
		analyticsWriteJSON(w, 200, fmt.Sprintf(`{"vectors":[{"key":"s%d-1"}]}`, in.SegmentIndex))
	})
	idx := c.Vectors().From("emb").Index("docs")
	var (
		mu   sync.Mutex
		keys []string
	)
	err := idx.ParallelScan(context.Background(), 3, &VectorListVectorsOptions{ReturnData: true, NextToken: "ignored"},
		func(seg int, page *VectorListVectorsResponse) error {
			mu.Lock()
			defer mu.Unlock()
			for _, v := range page.Vectors {
				if !strings.HasPrefix(v.Key, fmt.Sprintf("s%d-", seg)) {
					t.Errorf("segment %d got key %s", seg, v.Key)
				}
				keys = append(keys, v.Key)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "s0-0,s0-1,s1-0,s1-1,s2-0,s2-1" {
		t.Fatalf("keys = %v", keys)
	}
	if n := len(reqs()); n != 6 {
		t.Fatalf("requests = %d, want 6", n)
	}

	stop := errors.New("stop")
	if err := idx.ParallelScan(context.Background(), 3, &VectorListVectorsOptions{ReturnData: true},
		func(int, *VectorListVectorsResponse) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("err = %v, want callback error", err)
	}
	var se *Error
	if err := idx.ParallelScan(context.Background(), 3, nil,
		func(int, *VectorListVectorsResponse) error { return nil }); !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("err = %v, want API error", err)
	}
	if err := idx.ParallelScan(context.Background(), 17, nil, func(int, *VectorListVectorsResponse) error { return nil }); err == nil {
		t.Fatal("expected segment count validation error")
	}
	if err := idx.ParallelScan(context.Background(), 2, nil, nil); err == nil {
		t.Fatal("expected nil callback error")
	}
}

// upstream: storage-js src/packages/VectorDataApi.ts queryVectors
func TestVectorsQueryVectors(t *testing.T) {
	v, reqs := vectorServer(t, `{"vectors":[{"key":"doc-1","distance":0.1,"metadata":{"category":"shoes"}},
		{"key":"doc-2","distance":0.15}],"distanceMetric":"cosine","nextToken":"q2"}`)
	res, err := v.From("emb").Index("docs").QueryVectors(context.Background(), VectorQueryVectorsOptions{
		QueryVector: VectorData{Float32: []float32{0.5, 0.25}}, TopK: 2, NextToken: "q1",
		Filter:         VectorFilter{"category": "shoes"},
		ReturnDistance: true, ReturnMetadata: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vectors) != 2 || *res.Vectors[0].Distance != 0.1 || res.DistanceMetric != VectorDistanceCosine || res.NextToken != "q2" {
		t.Fatalf("res = %+v", res)
	}
	vectorAssertRequest(t, reqs()[0], "QueryVectors", `{"vectorBucketName":"emb","indexName":"docs",
		"queryVector":{"float32":[0.5,0.25]},"topK":2,"nextToken":"q1","filter":{"category":"shoes"},
		"returnDistance":true,"returnMetadata":true}`)
}

// upstream: storage-js src/packages/VectorDataApi.ts deleteVectors
func TestVectorsDeleteVectors(t *testing.T) {
	v, reqs := vectorServer(t, "")
	idx := v.From("emb").Index("docs")
	if err := idx.DeleteVectors(context.Background(), VectorDeleteVectorsOptions{Keys: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	vectorAssertRequest(t, reqs()[0], "DeleteVectors", `{"vectorBucketName":"emb","indexName":"docs","keys":["a","b"]}`)
	for _, n := range []int{0, 501} {
		if err := idx.DeleteVectors(context.Background(), VectorDeleteVectorsOptions{Keys: make([]string, n)}); err == nil {
			t.Errorf("n=%d: expected validation error", n)
		}
	}
	if len(reqs()) != 1 {
		t.Fatal("invalid batch reached the server")
	}
}

// upstream: storage-js src/lib/common/fetch.ts handleError (vectors namespace), errors.ts StorageVectorsErrorCode
func TestVectorsErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       Error
	}{
		{"statusCode", `{"statusCode":"409","error":"Conflict","message":"Bucket 'x' already exists","code":"S3VectorConflictException"}`, 409,
			Error{Message: "Bucket 'x' already exists", Status: 409, StatusCode: "409", Code: "S3VectorConflictException", Namespace: "vectors"}},
		{"numeric statusCode", `{"statusCode":404,"error":"Not Found","message":"Index not found"}`, 404,
			Error{Message: "Index not found", Status: 404, StatusCode: "404", Namespace: "vectors"}},
		{"non-JSON", `upstream exploded`, 502,
			Error{Message: "Bad Gateway", Status: 502, StatusCode: "502", Namespace: "vectors"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			_, err := c.Vectors().GetBucket(context.Background(), "x")
			var se *Error
			if !errors.As(err, &se) {
				t.Fatalf("err = %T %v", err, err)
			}
			if *se != tc.want {
				t.Fatalf("err = %+v, want %+v", *se, tc.want)
			}
			if !strings.HasPrefix(se.Error(), "vectors: ") {
				t.Errorf("Error() = %q", se.Error())
			}
		})
	}
}

// upstream: storage-js src/lib/common/fetch.ts _handleRequest (vectors: empty / non-JSON 200 => {})
func TestVectorsNonJSONSuccess(t *testing.T) {
	c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("OK"))
	})
	res, err := c.Vectors().ListBuckets(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.VectorBuckets == nil || len(res.VectorBuckets) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

// upstream: storage-js src/lib/types.ts VectorFetchParameters.signal
func TestVectorsContextCanceled(t *testing.T) {
	v, _ := vectorServer(t, `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.CreateBucket(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.From("b").Index("i").QueryVectors(ctx, VectorQueryVectorsOptions{TopK: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// Concurrent use of shared scopes must be race-free.
func TestVectorsConcurrentScopes(t *testing.T) {
	v, reqs := vectorServer(t, `{"vectors":[]}`)
	b := v.From("emb")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			idx := b.Index(fmt.Sprintf("idx-%d", i))
			if _, err := idx.GetVectors(context.Background(), VectorGetVectorsOptions{Keys: []string{"k"}}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, r := range reqs() {
		var in struct {
			IndexName string `json:"indexName"`
		}
		_ = json.Unmarshal(r.Body, &in)
		seen[in.IndexName] = true
	}
	if len(seen) != 16 {
		t.Fatalf("distinct indexes = %d", len(seen))
	}
}
