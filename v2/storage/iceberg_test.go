package storage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const icebergTableJSON = `{
  "metadata-location": "s3://bucket/meta/00001.json",
  "config": {"s3.endpoint": "https://s3.example"},
  "storage-credentials": [{"prefix": "s3://bucket", "config": {"s3.access-key-id": "AK"}}],
  "metadata": {
    "format-version": 2,
    "table-uuid": "9c12d441-03fe-4693-9a96-a0705ddf69c1",
    "location": "s3://bucket/events",
    "last-updated-ms": 1700000000000,
    "last-column-id": 4,
    "schemas": [{
      "type": "struct", "schema-id": 0, "identifier-field-ids": [1],
      "fields": [
        {"id": 1, "name": "id", "type": "long", "required": true},
        {"id": 2, "name": "tags", "type": {"type": "list", "element-id": 3, "element": "string", "element-required": false}, "required": false},
        {"id": 4, "name": "attrs", "type": {"type": "map", "key-id": 5, "key": "string", "value-id": 6, "value": "decimal(10,2)", "value-required": true}, "required": false},
        {"id": 7, "name": "loc", "type": {"type": "struct", "fields": [{"id": 8, "name": "lat", "type": "double", "required": true}]}, "required": false}
      ]
    }],
    "current-schema-id": 0,
    "partition-specs": [{"spec-id": 0, "fields": [{"source-id": 1, "field-id": 1000, "name": "id_bucket", "transform": "bucket[16]"}]}],
    "default-spec-id": 0,
    "sort-orders": [{"order-id": 0, "fields": []}],
    "properties": {"write.format.default": "parquet"},
    "current-snapshot-id": 3051729675574597004,
    "snapshots": [{"snapshot-id": 3051729675574597004, "timestamp-ms": 1700000000000, "manifest-list": "s3://m.avro", "summary": {"operation": "append"}}],
    "refs": {"main": {"type": "branch", "snapshot-id": 3051729675574597004}}
  }
}`

// icebergServer starts a fake catalog. /v1/config answers with prefix
// "srv-prefix"; every other request is answered by handle.
func icebergServer(t *testing.T, handle func(w http.ResponseWriter, r *http.Request, body []byte)) (*IcebergCatalog, func() []analyticsRecorded) {
	t.Helper()
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			analyticsWriteJSON(w, 200, `{"defaults":{},"overrides":{"prefix":"srv-prefix"}}`)
			return
		}
		handle(w, r, body)
	})
	cat, err := c.Analytics().From("my-bucket")
	if err != nil {
		t.Fatal(err)
	}
	return cat, func() []analyticsRecorded {
		var out []analyticsRecorded
		for _, r := range reqs() {
			if r.Path != "/storage/v1/iceberg/v1/config" {
				out = append(out, r)
			}
		}
		return out
	}
}

var icebergUUIDv7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func icebergAssertRequest(t *testing.T, r analyticsRecorded, method, path string, idempotent bool) {
	t.Helper()
	if r.Method != method || r.Path != path {
		t.Fatalf("got %s %s, want %s %s", r.Method, r.Path, method, path)
	}
	analyticsAssertAuth(t, r)
	key := r.Header.Get("Idempotency-Key")
	if idempotent && !icebergUUIDv7.MatchString(key) {
		t.Errorf("Idempotency-Key = %q, want UUIDv7", key)
	}
	if !idempotent && key != "" {
		t.Errorf("unexpected Idempotency-Key %q", key)
	}
	if len(r.Body) > 0 && r.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
	}
}

// upstream: iceberg-js src/catalog/IcebergRestCatalog.ts loadConfig/resolvePrefix (via StorageAnalyticsClient.from)
func TestIcebergAccessCatalog(t *testing.T) {
	var (
		mu      sync.Mutex
		configs int
	)
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/config" {
			mu.Lock()
			configs++
			mu.Unlock()
			analyticsWriteJSON(w, 200, `{"defaults":{"prefix":"default-prefix"},"overrides":{"prefix":"override/prefix"},
				"endpoints":["GET /v1/{prefix}/namespaces"],"idempotency-key-lifetime":"PT30M"}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
	})
	cat, err := c.Analytics().From("my bucket")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := cat.LoadConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Overrides["prefix"] != "override/prefix" || cfg.IdempotencyKeyLifetime != "PT30M" || len(cfg.Endpoints) != 1 {
		t.Fatalf("config = %+v", cfg)
	}
	r := reqs()[0]
	if r.Method != http.MethodGet || r.Path != "/storage/v1/iceberg/v1/config" || r.Request.URL.Query().Get("warehouse") != "my bucket" {
		t.Fatalf("config request = %s %s?%s", r.Method, r.Path, r.Query)
	}
	analyticsAssertAuth(t, r)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if configs != 2 { // one explicit LoadConfig + one prefix resolution
		t.Errorf("config fetched %d times, want 2", configs)
	}
	for _, r := range reqs()[2:] {
		if r.Path != "/storage/v1/iceberg/v1/override/prefix/namespaces" {
			t.Fatalf("path = %s", r.Path)
		}
	}
}

// upstream: iceberg-js src/catalog/IcebergRestCatalog.ts computePrefix fallback
func TestIcebergPrefixFallback(t *testing.T) {
	c, reqs := analyticsTestServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if strings.HasSuffix(r.URL.Path, "/v1/config") {
			analyticsWriteJSON(w, 404, `{"error":{"message":"no config","type":"NotFound","code":404}}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"namespaces":[["a"]]}`)
	})
	cat, _ := c.Analytics().From("bucket (2024)")
	for i := 0; i < 2; i++ {
		if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	got := reqs()
	if len(got) != 3 {
		t.Fatalf("requests = %d, want 3 (config fetched once)", len(got))
	}
	if got[1].Path != "/storage/v1/iceberg/v1/bucket%20%282024%29/namespaces" {
		t.Fatalf("path = %s", got[1].Path)
	}
}

// upstream: iceberg-js src/catalog/namespaces.ts listNamespaces
func TestIcebergListNamespaces(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"namespaces":[["analytics","prod"],["raw"]],"next-page-token":"tok2"}`)
	})
	res, err := cat.ListNamespaces(context.Background(), &IcebergListNamespacesOptions{
		Parent: []string{"analytics", "x"}, PageToken: "tok1", PageSize: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Namespaces) != 2 || res.Namespaces[0][1] != "prod" || res.NextPageToken != "tok2" {
		t.Fatalf("result = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodGet, "/storage/v1/iceberg/v1/srv-prefix/namespaces", false)
	q := r.Request.URL.Query()
	if q.Get("parent") != "analytics\x1fx" || q.Get("pageToken") != "tok1" || q.Get("pageSize") != "50" {
		t.Fatalf("query = %q", r.Query)
	}
	if !strings.Contains(r.Query, "parent=analytics%1Fx") {
		t.Errorf("raw query = %q", r.Query)
	}
}

// upstream: iceberg-js src/catalog/namespaces.ts createNamespace
func TestIcebergCreateNamespace(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"namespace":["production"],"properties":{"owner":"data-team"}}`)
	})
	res, err := cat.CreateNamespace(context.Background(), []string{"production"}, map[string]string{"owner": "data-team"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Namespace[0] != "production" || res.Properties["owner"] != "data-team" {
		t.Fatalf("res = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodPost, "/storage/v1/iceberg/v1/srv-prefix/namespaces", true)
	analyticsAssertJSON(t, r.Body, `{"namespace":["production"],"properties":{"owner":"data-team"}}`)

	if _, err := cat.CreateNamespace(context.Background(), nil, nil); err == nil {
		t.Fatal("expected error for empty namespace")
	}
}

// upstream: iceberg-js src/catalog/namespaces.ts createNamespaceIfNotExists
func TestIcebergCreateNamespaceIfNotExists(t *testing.T) {
	cat, _ := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 409, `{"error":{"message":"exists","type":"AlreadyExistsException","code":409}}`)
	})
	res, err := cat.CreateNamespaceIfNotExists(context.Background(), []string{"a"}, nil)
	if err != nil || res != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
}

// upstream: iceberg-js src/catalog/namespaces.ts dropNamespace
func TestIcebergDropNamespace(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusNoContent)
	})
	if err := cat.DropNamespace(context.Background(), []string{"a b", "c/d"}); err != nil {
		t.Fatal(err)
	}
	icebergAssertRequest(t, reqs()[0], http.MethodDelete, "/storage/v1/iceberg/v1/srv-prefix/namespaces/a%20b%1Fc%2Fd", true)
}

// upstream: iceberg-js src/catalog/namespaces.ts loadNamespaceMetadata
func TestIcebergLoadNamespaceMetadata(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"namespace":["analytics"],"properties":{"owner":"me"}}`)
	})
	md, err := cat.LoadNamespaceMetadata(context.Background(), []string{"analytics"})
	if err != nil {
		t.Fatal(err)
	}
	if md.Properties["owner"] != "me" {
		t.Fatalf("md = %+v", md)
	}
	icebergAssertRequest(t, reqs()[0], http.MethodGet, "/storage/v1/iceberg/v1/srv-prefix/namespaces/analytics", false)
}

// upstream: iceberg-js src/catalog/namespaces.ts namespaceExists
func TestIcebergNamespaceExists(t *testing.T) {
	var status atomic.Int32
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(int(status.Load()))
	})
	for _, tc := range []struct {
		status  int
		want    bool
		wantErr bool
	}{{200, true, false}, {204, true, false}, {404, false, false}, {500, false, true}} {
		status.Store(int32(tc.status))
		got, err := cat.NamespaceExists(context.Background(), []string{"analytics"})
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("status %d: got %v, %v", tc.status, got, err)
		}
	}
	icebergAssertRequest(t, reqs()[0], http.MethodHead, "/storage/v1/iceberg/v1/srv-prefix/namespaces/analytics", false)
}

// upstream: iceberg-js src/catalog/namespaces.ts updateNamespaceProperties (storage-js: not_implemented)
func TestIcebergUpdateNamespaceProperties(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"updated":["owner"],"removed":["tmp"],"missing":["gone"]}`)
	})
	res, err := cat.UpdateNamespaceProperties(context.Background(), []string{"analytics"},
		IcebergUpdateNamespacePropertiesParams{Removals: []string{"tmp", "gone"}, Updates: map[string]string{"owner": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Updated[0] != "owner" || res.Removed[0] != "tmp" || res.Missing[0] != "gone" {
		t.Fatalf("res = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodPost, "/storage/v1/iceberg/v1/srv-prefix/namespaces/analytics/properties", true)
	analyticsAssertJSON(t, r.Body, `{"removals":["tmp","gone"],"updates":{"owner":"x"}}`)
}

// upstream: iceberg-js src/catalog/tables.ts listTables
func TestIcebergListTables(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"identifiers":[{"namespace":["default"],"name":"events"}],"next-page-token":null}`)
	})
	res, err := cat.ListTables(context.Background(), []string{"default"}, &IcebergListTablesOptions{PageSize: 10, PageToken: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Identifiers) != 1 || res.Identifiers[0].Name != "events" || res.NextPageToken != "" {
		t.Fatalf("res = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodGet, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables", false)
	if q := r.Request.URL.Query(); q.Get("pageSize") != "10" || q.Get("pageToken") != "p" {
		t.Fatalf("query = %q", r.Query)
	}
}

// upstream: iceberg-js src/catalog/tables.ts createTable
func TestIcebergCreateTable(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("ETag", `"v1"`)
		analyticsWriteJSON(w, 200, icebergTableJSON)
	})
	zero := 0
	res, err := cat.CreateTable(context.Background(), []string{"default"}, IcebergCreateTableRequest{
		Name: "events",
		Schema: IcebergSchema{
			SchemaID:           &zero,
			IdentifierFieldIDs: []int{1},
			Fields: []IcebergStructField{
				{ID: 1, Name: "id", Type: IcebergPrimitive("long"), Required: true},
				{ID: 2, Name: "tags", Type: IcebergType{List: &IcebergListType{ElementID: 3, Element: IcebergPrimitive("string")}}},
			},
		},
		PartitionSpec: &IcebergPartitionSpec{SpecID: &zero},
		WriteOrder:    &IcebergSortOrder{},
		Properties:    map[string]string{"write.format.default": "parquet"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodPost, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables", true)
	analyticsAssertJSON(t, r.Body, `{
		"name":"events",
		"schema":{"type":"struct","schema-id":0,"identifier-field-ids":[1],"fields":[
			{"id":1,"name":"id","type":"long","required":true},
			{"id":2,"name":"tags","type":{"type":"list","element-id":3,"element":"string","element-required":false},"required":false}]},
		"partition-spec":{"spec-id":0,"fields":[]},
		"write-order":{"order-id":0,"fields":[]},
		"properties":{"write.format.default":"parquet"}}`)

	if res.ETag != `"v1"` || res.MetadataLocation != "s3://bucket/meta/00001.json" ||
		res.StorageCredentials[0].Config["s3.access-key-id"] != "AK" || res.Config["s3.endpoint"] == "" {
		t.Fatalf("res = %+v", res)
	}
	md := res.Metadata
	if md.FormatVersion != 2 || md.TableUUID == "" || *md.CurrentSnapshotID != 3051729675574597004 ||
		md.Refs["main"].SnapshotID != 3051729675574597004 || md.Snapshots[0].Summary["operation"] != "append" ||
		md.PartitionSpecs[0].Fields[0].Transform != "bucket[16]" {
		t.Fatalf("metadata = %+v", md)
	}
	s := md.CurrentSchema()
	if s == nil || len(s.Fields) != 4 {
		t.Fatalf("schema = %+v", s)
	}
	if s.Fields[0].Type.Primitive != "long" || s.Fields[1].Type.List.Element.Primitive != "string" ||
		s.Fields[2].Type.Map.Value.Primitive != "decimal(10,2)" || s.Fields[3].Type.Struct.Fields[0].Name != "lat" {
		t.Fatalf("field types decoded wrong: %+v", s.Fields)
	}
}

// upstream: iceberg-js src/catalog/tables.ts createTableIfNotExists
func TestIcebergCreateTableIfNotExists(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Method == http.MethodPost {
			analyticsWriteJSON(w, 409, `{"error":{"message":"exists","type":"AlreadyExistsException","code":409}}`)
			return
		}
		analyticsWriteJSON(w, 200, icebergTableJSON)
	})
	res, err := cat.CreateTableIfNotExists(context.Background(), []string{"default"}, IcebergCreateTableRequest{Name: "events"})
	if err != nil || res == nil || res.Metadata.FormatVersion != 2 {
		t.Fatalf("res=%v err=%v", res, err)
	}
	icebergAssertRequest(t, reqs()[1], http.MethodGet, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables/events", false)
}

// upstream: iceberg-js src/catalog/tables.ts loadTable/loadTableResult
func TestIcebergLoadTable(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		analyticsWriteJSON(w, 200, icebergTableJSON)
	})
	id := IcebergTableIdentifier{Namespace: []string{"default"}, Name: "my events"}
	res, err := cat.LoadTable(context.Background(), id, &IcebergLoadTableOptions{Snapshots: "refs"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ETag != `"v1"` || res.Metadata.Location != "s3://bucket/events" {
		t.Fatalf("res = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodGet, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables/my%20events", false)
	if r.Query != "snapshots=refs" {
		t.Errorf("query = %q", r.Query)
	}
	res, err = cat.LoadTable(context.Background(), id, &IcebergLoadTableOptions{IfNoneMatch: res.ETag})
	if err != nil || res != nil {
		t.Fatalf("304: res=%v err=%v", res, err)
	}
	if _, err := cat.LoadTable(context.Background(), IcebergTableIdentifier{Namespace: []string{"a"}}, nil); err == nil {
		t.Fatal("expected error for empty table name")
	}
}

// upstream: iceberg-js src/catalog/tables.ts updateTable
func TestIcebergUpdateTable(t *testing.T) {
	var missing atomic.Bool
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if missing.Load() {
			analyticsWriteJSON(w, 200, `{"metadata":{}}`)
			return
		}
		analyticsWriteJSON(w, 200, `{"metadata-location":"s3://m2.json","metadata":{"format-version":2,"table-uuid":"u",
			"schemas":[],"current-schema-id":0,"partition-specs":[],"sort-orders":[],"properties":{"a":"b"}}}`)
	})
	id := IcebergTableIdentifier{Namespace: []string{"default"}, Name: "events"}
	res, err := cat.UpdateTable(context.Background(), id, IcebergCommitTableRequest{
		Requirements: []IcebergTableRequirement{
			IcebergAssertTableUUID{UUID: "u"},
			IcebergAssertRefSnapshotID{Ref: "main"},
			IcebergAssertCreate{},
		},
		Updates: []IcebergTableUpdate{
			IcebergSetPropertiesUpdate{Updates: map[string]string{"a": "b"}},
			IcebergRemovePropertiesUpdate{Removals: []string{"c"}},
			IcebergSetCurrentSchemaUpdate{SchemaID: -1},
			IcebergSetSnapshotRefUpdate{RefName: "main", IcebergSnapshotReference: IcebergSnapshotReference{Type: "branch", SnapshotID: 7}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.MetadataLocation != "s3://m2.json" || res.Metadata.Properties["a"] != "b" {
		t.Fatalf("res = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodPost, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables/events", true)
	analyticsAssertJSON(t, r.Body, `{
		"requirements":[
			{"type":"assert-table-uuid","uuid":"u"},
			{"type":"assert-ref-snapshot-id","ref":"main","snapshot-id":null},
			{"type":"assert-create"}],
		"updates":[
			{"action":"set-properties","updates":{"a":"b"}},
			{"action":"remove-properties","removals":["c"]},
			{"action":"set-current-schema","schema-id":-1},
			{"action":"set-snapshot-ref","ref-name":"main","type":"branch","snapshot-id":7}]}`)

	// Empty commit encodes empty arrays.
	missing.Store(true)
	_, err = cat.UpdateTable(context.Background(), id, IcebergCommitTableRequest{})
	if err == nil || !strings.Contains(err.Error(), "metadata-location") {
		t.Fatalf("err = %v, want missing metadata-location", err)
	}
	analyticsAssertJSON(t, reqs()[1].Body, `{"requirements":[],"updates":[]}`)
}

// upstream: iceberg-js src/catalog/tables.ts renameTable
func TestIcebergRenameTable(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusNoContent)
	})
	err := cat.RenameTable(context.Background(),
		IcebergTableIdentifier{Namespace: []string{"default"}, Name: "events"},
		IcebergTableIdentifier{Namespace: []string{"archive"}, Name: "events_2024"})
	if err != nil {
		t.Fatal(err)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodPost, "/storage/v1/iceberg/v1/srv-prefix/tables/rename", true)
	analyticsAssertJSON(t, r.Body, `{"source":{"namespace":["default"],"name":"events"},
		"destination":{"namespace":["archive"],"name":"events_2024"}}`)
}

// upstream: iceberg-js src/catalog/tables.ts dropTable
func TestIcebergDropTable(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(http.StatusNoContent)
	})
	id := IcebergTableIdentifier{Namespace: []string{"default"}, Name: "events"}
	if err := cat.DropTable(context.Background(), id, &IcebergDropTableOptions{Purge: true}); err != nil {
		t.Fatal(err)
	}
	if err := cat.DropTable(context.Background(), id, nil); err != nil {
		t.Fatal(err)
	}
	got := reqs()
	icebergAssertRequest(t, got[0], http.MethodDelete, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables/events", true)
	if got[0].Query != "purgeRequested=true" || got[1].Query != "purgeRequested=false" {
		t.Fatalf("queries = %q, %q", got[0].Query, got[1].Query)
	}
}

// upstream: iceberg-js src/catalog/tables.ts registerTable (storage-js: not_implemented)
func TestIcebergRegisterTable(t *testing.T) {
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, icebergTableJSON)
	})
	res, err := cat.RegisterTable(context.Background(), []string{"default"}, IcebergRegisterTableRequest{
		Name: "events", MetadataLocation: "s3://bucket/meta/00001.json", Overwrite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata.TableUUID == "" {
		t.Fatalf("res = %+v", res)
	}
	r := reqs()[0]
	icebergAssertRequest(t, r, http.MethodPost, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/register", true)
	analyticsAssertJSON(t, r.Body, `{"name":"events","metadata-location":"s3://bucket/meta/00001.json","overwrite":true}`)
	if _, err := cat.RegisterTable(context.Background(), []string{"default"}, IcebergRegisterTableRequest{Name: "x"}); err == nil {
		t.Fatal("expected validation error")
	}
}

// upstream: iceberg-js src/catalog/tables.ts tableExists
func TestIcebergTableExists(t *testing.T) {
	var status atomic.Int32
	cat, reqs := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.WriteHeader(int(status.Load()))
	})
	id := IcebergTableIdentifier{Namespace: []string{"default"}, Name: "events"}
	for _, tc := range []struct {
		status  int
		want    bool
		wantErr bool
	}{{200, true, false}, {404, false, false}, {403, false, true}} {
		status.Store(int32(tc.status))
		got, err := cat.TableExists(context.Background(), id)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("status %d: got %v, %v", tc.status, got, err)
		}
	}
	icebergAssertRequest(t, reqs()[0], http.MethodHead, "/storage/v1/iceberg/v1/srv-prefix/namespaces/default/tables/events", false)
}

// upstream: iceberg-js src/http/createFetchClient.ts (IcebergError mapping)
func TestIcebergErrorMapping(t *testing.T) {
	body := `{"error":{"message":"Table does not exist: default.events","type":"NoSuchTableException","code":404}}`
	cat, _ := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == "/storage/v1/iceberg/v1/srv-prefix/namespaces/x" {
			w.WriteHeader(502)
			_, _ = w.Write([]byte("bad gateway"))
			return
		}
		analyticsWriteJSON(w, 404, body)
	})
	_, err := cat.LoadTable(context.Background(), IcebergTableIdentifier{Namespace: []string{"default"}, Name: "events"}, nil)
	var ie *IcebergError
	if !errors.As(err, &ie) {
		t.Fatalf("err = %T %v", err, err)
	}
	if ie.Status != 404 || ie.Code != 404 || ie.Type != "NoSuchTableException" ||
		ie.Message != "Table does not exist: default.events" || !ie.IsNotFound() || ie.IsConflict() ||
		string(ie.Details) != body {
		t.Fatalf("err = %+v", ie)
	}
	if !strings.Contains(ie.Error(), "NoSuchTableException") {
		t.Errorf("Error() = %q", ie.Error())
	}
	_, err = cat.LoadNamespaceMetadata(context.Background(), []string{"x"})
	if !errors.As(err, &ie) || ie.Status != 502 || ie.Message != "Request failed with status 502" || ie.Details != nil {
		t.Fatalf("err = %+v", err)
	}
	for _, e := range []IcebergError{{Status: 409}, {Status: 419}, {Type: "CommitStateUnknownException", Status: 500}} {
		if ok := e.IsConflict() || e.IsAuthenticationTimeout() || e.IsCommitStateUnknown(); !ok {
			t.Errorf("predicate false for %+v", e)
		}
	}
}

// upstream: iceberg-js src/http/createFetchClient.ts (request cancellation)
func TestIcebergContextCanceled(t *testing.T) {
	cat, _ := icebergServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		analyticsWriteJSON(w, 200, `{"namespaces":[]}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cat.ListNamespaces(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	// A canceled prefix resolution is not cached: the next call works.
	if _, err := cat.ListNamespaces(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestIcebergTypeJSON(t *testing.T) {
	in := `{"type":"map","key-id":1,"key":"string","value-id":2,"value":{"type":"list","element-id":3,"element":"fixed[16]","element-required":true},"value-required":false}`
	var typ IcebergType
	if err := json.Unmarshal([]byte(in), &typ); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(typ)
	if err != nil {
		t.Fatal(err)
	}
	analyticsAssertJSON(t, out, in)
	if _, err := json.Marshal(IcebergType{}); err == nil {
		t.Error("expected error for empty type")
	}
	if err := json.Unmarshal([]byte(`{"type":"weird"}`), &typ); err == nil {
		t.Error("expected error for unknown type")
	}
	// Every update and requirement carries its discriminator.
	updates := []IcebergTableUpdate{
		IcebergAssignUUIDUpdate{}, IcebergUpgradeFormatVersionUpdate{}, IcebergAddSchemaUpdate{},
		IcebergSetCurrentSchemaUpdate{}, IcebergAddPartitionSpecUpdate{}, IcebergSetDefaultSpecUpdate{},
		IcebergAddSortOrderUpdate{}, IcebergSetDefaultSortOrderUpdate{}, IcebergAddSnapshotUpdate{},
		IcebergSetSnapshotRefUpdate{}, IcebergRemoveSnapshotsUpdate{}, IcebergRemoveSnapshotRefUpdate{},
		IcebergSetLocationUpdate{}, IcebergSetPropertiesUpdate{}, IcebergRemovePropertiesUpdate{},
		IcebergSetStatisticsUpdate{}, IcebergRemoveStatisticsUpdate{}, IcebergSetPartitionStatisticsUpdate{},
		IcebergRemovePartitionStatisticsUpdate{}, IcebergRemovePartitionSpecsUpdate{}, IcebergRemoveSchemasUpdate{},
		IcebergAddEncryptionKeyUpdate{}, IcebergRemoveEncryptionKeyUpdate{},
	}
	for _, u := range updates {
		b, err := json.Marshal(u)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil || m["action"] != u.IcebergAction() {
			t.Errorf("%T -> %s", u, b)
		}
	}
	reqs := []IcebergTableRequirement{
		IcebergAssertCreate{}, IcebergAssertTableUUID{}, IcebergAssertRefSnapshotID{}, IcebergAssertLastAssignedFieldID{},
		IcebergAssertCurrentSchemaID{}, IcebergAssertLastAssignedPartitionID{}, IcebergAssertDefaultSpecID{},
		IcebergAssertDefaultSortOrderID{},
	}
	for _, r := range reqs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil || m["type"] != r.IcebergRequirementType() {
			t.Errorf("%T -> %s", r, b)
		}
	}
}
