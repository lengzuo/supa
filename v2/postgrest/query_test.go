package postgrest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type user struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{URL: "http://x/rest/v1"}); err == nil {
		t.Error("expected error for missing API key")
	}
	if _, err := New(Config{URL: "not a url", APIKey: "k"}); err == nil {
		t.Error("expected error for relative URL")
	}
	c, err := New(Config{URL: "http://x/rest/v1", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "default schema", c.SchemaName(), "public")
}

// upstream: postgrest-js src/PostgrestClient.ts from, src/PostgrestQueryBuilder.ts select
func TestFromSelect(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[{"id":1,"username":"supabot"}]`))
	var got []user
	resp, err := c.From("users").Select(" id,\n username , \"full name\" ").ExecuteInto(context.Background(), &got)
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "GET")
	assertEq(t, "path", r.Path, "/rest/v1/users")
	assertEq(t, "select", r.Query.Get("select"), `id,username,"full name"`)
	assertEq(t, "apikey", r.Header.Get("apikey"), testKey)
	assertEq(t, "authorization", r.Header.Get("Authorization"), "Bearer "+testKey)
	assertEq(t, "accept-profile", r.Header.Get("Accept-Profile"), "public")
	assertEq(t, "content-type", r.Header.Get("Content-Type"), "")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "")
	assertEq(t, "status", resp.Status, 200)
	assertEq(t, "statusText", resp.StatusText, "OK")
	if resp.Count != nil {
		t.Errorf("count = %v, want nil", *resp.Count)
	}
	if len(got) != 1 || got[0].Username != "supabot" {
		t.Errorf("decoded %+v", got)
	}

	// Default select is "*".
	if _, err := c.From("users").Select("").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "default select", f.last(t).Query.Get("select"), "*")
}

// upstream: postgrest-js src/PostgrestQueryBuilder.ts select (head, count)
func TestSelectHeadCount(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, "", "Content-Range", "*/42"))
	resp, err := c.From("users").Select("*", SelectOptions{Head: true, Count: CountExact}).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "HEAD")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "count=exact")
	if resp.Count == nil || *resp.Count != 42 {
		t.Fatalf("count = %v", resp.Count)
	}
	if resp.Data != nil {
		t.Errorf("data = %s, want nil", resp.Data)
	}

	// Count is only reported when requested.
	resp, err = c.From("users").Select("*").Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Count != nil {
		t.Errorf("count without Count option = %v", *resp.Count)
	}
}

func TestSelectCountRange(t *testing.T) {
	c, _, _ := newFake(t, jsonReply(200, `[{"id":1}]`, "Content-Range", "0-0/3573"))
	resp, err := c.From("users").Select("*", SelectOptions{Count: CountPlanned}).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Count == nil || *resp.Count != 3573 {
		t.Fatalf("count = %v", resp.Count)
	}
}

func TestAccessTokenAndSetHeader(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`), func(cfg *Config) {
		cfg.AccessToken = func(context.Context) (string, error) { return "user-jwt", nil }
		cfg.Headers = http.Header{"x-custom": {"1"}}
	})
	if _, err := c.From("users").Select("*").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "authorization", r.Header.Get("Authorization"), "Bearer user-jwt")
	assertEq(t, "custom", r.Header.Get("X-Custom"), "1")
	assertEq(t, "client info", r.Header.Get("X-Client-Info") != "", true)

	if _, err := c.From("users").Select("*").SetHeader("Authorization", "Bearer other").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "override authorization", f.last(t).Header.Get("Authorization"), "Bearer other")
}

// upstream: postgrest-js src/PostgrestQueryBuilder.ts insert
func TestInsert(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(201, ""))
	resp, err := c.From("users").Insert(user{ID: 1, Username: "bar"}).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "POST")
	assertEq(t, "path", r.Path, "/rest/v1/users")
	assertEq(t, "body", r.Body, `{"id":1,"username":"bar"}`)
	assertEq(t, "content-type", r.Header.Get("Content-Type"), "application/json")
	assertEq(t, "content-profile", r.Header.Get("Content-Profile"), "public")
	assertEq(t, "accept-profile", r.Header.Get("Accept-Profile"), "")
	assertEq(t, "columns", r.Query.Has("columns"), false)
	assertEq(t, "prefer", r.Header.Get("Prefer"), "")
	assertEq(t, "status", resp.Status, 201)
	if resp.Data != nil {
		t.Errorf("data = %s, want nil (return=minimal)", resp.Data)
	}
}

// upstream: postgrest-js src/PostgrestQueryBuilder.ts insert (bulk columns, defaultToNull)
func TestInsertBulk(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(201, ""))
	rows := []map[string]any{{"username": "a"}, {"username": "b", "status": "ONLINE"}}
	_, err := c.From("users").Insert(rows, InsertOptions{Count: CountExact, MissingAsDefault: true}).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "columns", r.Query.Get("columns"), `"username","status"`)
	assertEq(t, "prefer", r.Header.Get("Prefer"), "count=exact, missing=default")
	assertEq(t, "body", r.Body, `[{"username":"a"},{"status":"ONLINE","username":"b"}]`)
}

// upstream: postgrest-js src/PostgrestQueryBuilder.ts upsert
func TestUpsert(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(201, `[{"id":1,"username":"x"}]`))
	var got []user
	_, err := c.From("users").
		Upsert([]user{{ID: 1, Username: "x"}}, UpsertOptions{OnConflict: "username", IgnoreDuplicates: true, Count: CountEstimated, MissingAsDefault: true}).
		Select("*").
		ExecuteInto(context.Background(), &got)
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "POST")
	assertEq(t, "on_conflict", r.Query.Get("on_conflict"), "username")
	assertEq(t, "columns", r.Query.Get("columns"), `"id","username"`)
	assertEq(t, "select", r.Query.Get("select"), "*")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "resolution=ignore-duplicates, count=estimated, missing=default, return=representation")
	if len(got) != 1 || got[0].ID != 1 {
		t.Errorf("decoded %+v", got)
	}

	if _, err := c.From("users").Upsert(user{ID: 2}).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = f.last(t)
	assertEq(t, "default prefer", r.Header.Get("Prefer"), "resolution=merge-duplicates")
	assertEq(t, "no on_conflict", r.Query.Has("on_conflict"), false)
}

// upstream: postgrest-js src/PostgrestQueryBuilder.ts update
func TestUpdate(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(204, ""))
	resp, err := c.From("users").Update(map[string]any{"status": "OFFLINE"}, UpdateOptions{Count: CountExact}).Eq("username", "bob").Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "PATCH")
	assertEq(t, "filter", r.Query.Get("username"), "eq.bob")
	assertEq(t, "body", r.Body, `{"status":"OFFLINE"}`)
	assertEq(t, "prefer", r.Header.Get("Prefer"), "count=exact")
	assertEq(t, "content-profile", r.Header.Get("Content-Profile"), "public")
	assertEq(t, "status", resp.Status, 204)
}

// upstream: postgrest-js src/PostgrestQueryBuilder.ts delete
func TestDelete(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(204, ""))
	if _, err := c.From("users").Delete(DeleteOptions{Count: CountExact}).Eq("id", 3).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "DELETE")
	assertEq(t, "filter", r.Query.Get("id"), "eq.3")
	assertEq(t, "body", r.Body, "")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "count=exact")
	assertEq(t, "content-type", r.Header.Get("Content-Type"), "application/json")
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts select (after mutation);
// test/basic.test.ts "custom prefer headers"
func TestSelectAfterMutation(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[{"id":9,"username":"gone"}]`), func(cfg *Config) {
		cfg.Headers = http.Header{"Prefer": {"tx=rollback"}}
	})
	var got []user
	if _, err := c.From("users").Delete().Eq("id", 9).Select("id, username").ExecuteInto(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "select", r.Query.Get("select"), "id,username")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "tx=rollback, return=representation")
	if len(got) != 1 || got[0].ID != 9 {
		t.Errorf("decoded %+v", got)
	}
}

// upstream: postgrest-js src/PostgrestClient.ts schema
func TestSchemaSelection(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`), func(cfg *Config) { cfg.Schema = "personal" })
	billing := c.Schema("billing")
	assertEq(t, "original schema", c.SchemaName(), "personal")

	if _, err := billing.From("invoices").Select("*").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept-profile", f.last(t).Header.Get("Accept-Profile"), "billing")

	if _, err := billing.From("invoices").Insert(map[string]int{"id": 1}).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "content-profile", r.Header.Get("Content-Profile"), "billing")
	assertEq(t, "accept-profile on POST", r.Header.Get("Accept-Profile"), "")

	if _, err := c.From("users").Select("*").Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "original client profile", f.last(t).Header.Get("Accept-Profile"), "personal")
}

// upstream: postgrest-js src/PostgrestClient.ts getOpenApiSpec; test/openapi-spec.test.ts
func TestGetOpenAPISpec(t *testing.T) {
	spec := `{"swagger":"2.0","info":{"title":"PostgREST API","version":"12.0.0"},"host":"0.0.0.0:3000","basePath":"/","paths":{"/todos":{"get":{}}},"definitions":{"todos":{"properties":{"id":{"type":"integer"}}}},"parameters":{},"x-extra":1}`
	c, f, _ := newFake(t, jsonReply(200, spec))
	got, err := c.Schema("billing").GetOpenAPISpec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "GET")
	assertEq(t, "path", r.Path, "/rest/v1/")
	assertEq(t, "accept", r.Header.Get("Accept"), "application/openapi+json")
	assertEq(t, "accept-profile", r.Header.Get("Accept-Profile"), "billing")
	assertEq(t, "swagger", got.Swagger, "2.0")
	assertEq(t, "host", got.Host, "0.0.0.0:3000")
	assertEq(t, "basePath", got.BasePath, "/")
	if _, ok := got.Paths["/todos"]; !ok {
		t.Errorf("paths = %v", got.Paths)
	}
	if _, ok := got.Definitions["todos"]; !ok {
		t.Errorf("definitions = %v", got.Definitions)
	}
	if !strings.Contains(string(got.Raw), "x-extra") {
		t.Error("raw document missing extra field")
	}
}

func TestGetOpenAPISpecErrors(t *testing.T) {
	c, _, _ := newFake(t, jsonReply(403, `{"code":"42501","message":"permission denied","details":null,"hint":"grant usage"}`))
	_, err := c.GetOpenAPISpec(context.Background())
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	assertEq(t, "code", pe.Code, "42501")
	assertEq(t, "hint", pe.Hint, "grant usage")
	assertEq(t, "status", pe.Status, 403)

	c, _, _ = newFake(t, jsonReply(200, `not json`))
	_, err = c.GetOpenAPISpec(context.Background())
	if !errors.As(err, &pe) || pe.Message != "not json" || pe.Status != 200 {
		t.Fatalf("err = %v", err)
	}
}

// upstream: postgrest-js src/PostgrestClient.ts rpc
func TestRPC(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `"ONLINE"`))
	var status string
	_, err := c.RPC("get_status", map[string]string{"name_param": "supabot"}).ExecuteInto(context.Background(), &status)
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "POST")
	assertEq(t, "path", r.Path, "/rest/v1/rpc/get_status")
	assertEq(t, "body", r.Body, `{"name_param":"supabot"}`)
	assertEq(t, "content-type", r.Header.Get("Content-Type"), "application/json")
	assertEq(t, "content-profile", r.Header.Get("Content-Profile"), "public")
	assertEq(t, "result", status, "ONLINE")

	// nil args send an empty object.
	if _, err := c.RPC("noop", nil).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "empty body", f.last(t).Body, "{}")
}

// upstream: postgrest-js src/PostgrestClient.ts rpc (get/head, count)
func TestRPCGetHead(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[{"id":1}]`, "Content-Range", "0-0/1"))
	args := struct {
		Name string  `json:"name"`
		IDs  []any   `json:"ids"`
		N    float64 `json:"n"`
		Nil  *int    `json:"nil"`
		Skip *int    `json:"skip,omitempty"`
	}{Name: "a b", IDs: []any{1, "x,y", nil}, N: 1.5}
	resp, err := c.RPC("list", args, RPCOptions{Get: true, Count: CountExact}).Eq("id", 1).Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "method", r.Method, "GET")
	assertEq(t, "name", r.Query.Get("name"), "a b")
	assertEq(t, "ids", r.Query.Get("ids"), `{1,"x,y",null}`)
	assertEq(t, "n", r.Query.Get("n"), "1.5")
	assertEq(t, "nil", r.Query.Get("nil"), "null")
	assertEq(t, "skip", r.Query.Has("skip"), false)
	assertEq(t, "filter", r.Query.Get("id"), "eq.1")
	assertEq(t, "prefer", r.Header.Get("Prefer"), "count=exact")
	assertEq(t, "accept-profile", r.Header.Get("Accept-Profile"), "public")
	assertEq(t, "body", r.Body, "")
	if resp.Count == nil || *resp.Count != 1 {
		t.Errorf("count = %v", resp.Count)
	}

	if _, err := c.RPC("list", map[string]int{"a": 1}, RPCOptions{Head: true}).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = f.last(t)
	assertEq(t, "head method", r.Method, "HEAD")
	assertEq(t, "head arg", r.Query.Get("a"), "1")

	// upstream: test/fetch-errors.test.ts "rpc with head: true and object args uses POST with return=minimal"
	if _, err := c.RPC("list", map[string]any{"filter": map[string]int{"a": 1}}, RPCOptions{Head: true, Count: CountExact}).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	r = f.last(t)
	assertEq(t, "object arg method", r.Method, "POST")
	assertEq(t, "object arg prefer", r.Header.Get("Prefer"), "count=exact,return=minimal")
	assertEq(t, "object arg body", r.Body, `{"filter":{"a":1}}`)

	_, err = c.RPC("list", []int{1}, RPCOptions{Get: true}).Execute(context.Background())
	if err == nil {
		t.Error("expected error for non-object GET args")
	}
}

// upstream: postgrest-js test/embeded_functions_join.test.ts, resource-embedding.test.ts
func TestRelationshipEmbed(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[{"name":"general","messages":[{"id":1}]}]`))
	_, err := c.From("channels").
		Select("name, messages!inner ( id, username:users(name) )").
		Eq("messages.id", 1).
		Order("id", OrderOptions{ReferencedTable: "messages", Descending: true}).
		Limit(1, TableOptions{ReferencedTable: "messages"}).
		Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := f.last(t)
	assertEq(t, "select", r.Query.Get("select"), "name,messages!inner(id,username:users(name))")
	assertEq(t, "embedded filter", r.Query.Get("messages.id"), "eq.1")
	assertEq(t, "embedded order", r.Query.Get("messages.order"), "id.desc")
	assertEq(t, "embedded limit", r.Query.Get("messages.limit"), "1")
}

func TestExecuteTo(t *testing.T) {
	c, _, _ := newFake(t, jsonReply(200, `[{"id":1,"username":"a"},{"id":2,"username":"b"}]`))
	users, resp, err := ExecuteTo[[]user](context.Background(), c.From("users").Select("*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || resp.Status != 200 {
		t.Fatalf("users=%v resp=%+v", users, resp)
	}
	var raw json.RawMessage
	if _, err := c.From("users").Select("*").ExecuteInto(context.Background(), &raw); err != nil || !strings.HasPrefix(string(raw), "[") {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
	var bad int
	if _, err := c.From("users").Select("*").ExecuteInto(context.Background(), &bad); err == nil {
		t.Error("expected decode error")
	}
}
