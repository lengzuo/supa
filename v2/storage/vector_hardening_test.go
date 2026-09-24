package storage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// upstream: storage-js src/packages/VectorDataApi.ts listVectors (parallel scan: first error cancels the rest)
func TestVectorsParallelScanCancelsOnFirstError(t *testing.T) {
	baseline := runtime.NumGoroutine()

	var arrived, canceled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			SegmentIndex int `json:"segmentIndex"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.SegmentIndex == 0 {
			analyticsWriteJSON(w, 500, `{"statusCode":"500","error":"InternalError","message":"boom","code":"InternalError"}`)
			return
		}
		// Other segments hang until their request is canceled.
		arrived.Add(1)
		select {
		case <-r.Context().Done():
			canceled.Add(1)
		case <-time.After(10 * time.Second):
			analyticsWriteJSON(w, 200, `{"vectors":[]}`)
		}
	}))
	tr := &http.Transport{}
	c, err := New(Config{URL: srv.URL + "/storage/v1", APIKey: analyticsTestKey, HTTPClient: &http.Client{Transport: tr}})
	if err != nil {
		t.Fatal(err)
	}
	idx := c.Vectors().From("emb").Index("docs")

	start := time.Now()
	var pages atomic.Int32
	err = idx.ParallelScan(context.Background(), 4, nil, func(int, *VectorListVectorsResponse) error {
		pages.Add(1)
		return nil
	})
	var se *Error
	if !errors.As(err, &se) || se.Status != 500 || se.Code != "InternalError" {
		t.Fatalf("err = %v, want the segment-0 API error", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("ParallelScan returned after %v; other segments were not canceled", d)
	}
	if pages.Load() != 0 {
		t.Fatalf("callback ran %d times", pages.Load())
	}

	// Every hanging segment that reached the server observes cancellation
	// (a segment may also be canceled before its request is sent), and
	// nothing leaks.
	deadline := time.Now().Add(5 * time.Second)
	for canceled.Load() != arrived.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if canceled.Load() != arrived.Load() {
		t.Fatalf("canceled segments = %d, arrived %d", canceled.Load(), arrived.Load())
	}
	tr.CloseIdleConnections()
	srv.Close()
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Fatalf("goroutines = %d, baseline %d: leak", n, baseline)
	}
}

// Canceling the caller's context stops every segment.
func TestVectorsParallelScanContextCanceled(t *testing.T) {
	c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := c.Vectors().From("emb").Index("docs").ParallelScan(ctx, 3, nil,
		func(int, *VectorListVectorsResponse) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestVectorScopedMarshal(t *testing.T) {
	b, err := json.Marshal(vectorScoped[*VectorListVectorsOptions]{VectorBucketName: "b", IndexName: "i"})
	if err != nil {
		t.Fatal(err)
	}
	analyticsAssertJSON(t, b, `{"vectorBucketName":"b","indexName":"i"}`)
	b, err = json.Marshal(vectorScoped[VectorDeleteVectorsOptions]{VectorBucketName: "b", IndexName: "i",
		Options: VectorDeleteVectorsOptions{Keys: []string{"k"}}})
	if err != nil {
		t.Fatal(err)
	}
	analyticsAssertJSON(t, b, `{"vectorBucketName":"b","indexName":"i","keys":["k"]}`)
	if _, err := json.Marshal(vectorScoped[[]string]{Options: []string{"x"}}); err == nil {
		t.Fatal("expected error for non-object options")
	}
}

// upstream: storage-js src/lib/common/fetch.ts handleError (statusCode || code || status)
func TestVectorsErrorEmptyStatusCode(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"statusCode":"","code":"S3VectorNotFoundException","message":"no index"}`, "S3VectorNotFoundException"},
		{`{"statusCode":"","message":"no index"}`, "404"},
	} {
		c, _ := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			analyticsWriteJSON(w, 404, tc.body)
		})
		_, err := c.Vectors().From("b").GetIndex(context.Background(), "i")
		var se *Error
		if !errors.As(err, &se) || se.StatusCode != tc.want || se.Namespace != "vectors" {
			t.Fatalf("body %s: err = %+v, want StatusCode %q", tc.body, err, tc.want)
		}
	}
}

// upstream: storage-js src/lib/common/fetch.ts handleError (vectors namespace, every endpoint)
func TestVectorsMethodErrors(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 404, `{"statusCode":"404","error":"Not Found","message":"missing","code":"S3VectorNotFoundException"}`)
	})
	ctx := context.Background()
	v := c.Vectors()
	b := v.From("emb")
	idx := b.Index("docs")
	calls := map[string]func() error{
		"CreateVectorBucket": func() error { return v.CreateBucket(ctx, "emb") },
		"GetVectorBucket":    func() error { _, err := v.GetBucket(ctx, "emb"); return err },
		"ListVectorBuckets":  func() error { _, err := v.ListBuckets(ctx, nil); return err },
		"DeleteVectorBucket": func() error { return v.DeleteBucket(ctx, "emb") },
		"CreateIndex": func() error {
			return b.CreateIndex(ctx, VectorCreateIndexOptions{IndexName: "docs", DataType: VectorDataTypeFloat32, Dimension: 3, DistanceMetric: VectorDistanceCosine})
		},
		"GetIndex":     func() error { _, err := b.GetIndex(ctx, "docs"); return err },
		"ListIndexes":  func() error { _, err := b.ListIndexes(ctx, nil); return err },
		"DeleteIndex":  func() error { return b.DeleteIndex(ctx, "docs") },
		"PutVectors":   func() error { return idx.PutVectors(ctx, VectorPutVectorsOptions{Vectors: []VectorObject{{Key: "k"}}}) },
		"GetVectors":   func() error { _, err := idx.GetVectors(ctx, VectorGetVectorsOptions{Keys: []string{"k"}}); return err },
		"ListVectors":  func() error { _, err := idx.ListVectors(ctx, nil); return err },
		"QueryVectors": func() error { _, err := idx.QueryVectors(ctx, VectorQueryVectorsOptions{TopK: 1}); return err },
		"DeleteVectors": func() error {
			return idx.DeleteVectors(ctx, VectorDeleteVectorsOptions{Keys: []string{"k"}})
		},
	}
	for action, call := range calls {
		n := len(reqs())
		err := call()
		var se *Error
		if !errors.As(err, &se) || se.Status != 404 || se.StatusCode != "404" || se.Code != "S3VectorNotFoundException" ||
			se.Message != "missing" || se.Namespace != "vectors" {
			t.Errorf("%s: err = %+v", action, err)
		}
		if got := reqs(); len(got) != n+1 || got[n].Path != "/storage/v1/vector/"+action {
			t.Errorf("%s: unexpected requests", action)
		}
	}
}
