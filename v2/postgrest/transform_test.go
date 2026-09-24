package postgrest

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// upstream: postgrest-js src/PostgrestTransformBuilder.ts order; test/transforms.test.ts
func TestOrder(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	_, err := c.From("users").Select("*").
		Order("id").
		Order("name", OrderOptions{Descending: true, Nulls: NullsFirst}).
		Order("age", OrderOptions{Nulls: NullsLast}).
		Order("id", OrderOptions{ReferencedTable: "messages", Descending: true}).
		Execute(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	q := f.last(t).Query
	assertEq(t, "order", q.Get("order"), "id.asc,name.desc.nullsfirst,age.asc.nullslast")
	assertEq(t, "messages.order", q.Get("messages.order"), "id.desc")
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts limit, range
func TestLimitRange(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	if _, err := c.From("users").Select("*").Limit(5).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "limit", f.last(t).Query.Get("limit"), "5")

	if _, err := c.From("users").Select("*").Limit(5).Range(10, 19).Range(0, 2, TableOptions{ReferencedTable: "messages"}).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	q := f.last(t).Query
	assertEq(t, "offset", q.Get("offset"), "10")
	assertEq(t, "limit", q.Get("limit"), "10")
	assertEq(t, "limit values", len(q["limit"]), 1)
	assertEq(t, "messages.offset", q.Get("messages.offset"), "0")
	assertEq(t, "messages.limit", q.Get("messages.limit"), "3")
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts single
func TestSingle(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `{"id":1,"username":"supabot"}`))
	u, _, err := ExecuteTo[user](context.Background(), c.From("users").Select("*").Eq("id", 1).Single())
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept", f.last(t).Header.Get("Accept"), "application/vnd.pgrst.object+json")
	assertEq(t, "username", u.Username, "supabot")

	c, _, _ = newFake(t, jsonReply(406, `{"code":"PGRST116","details":"The result contains 0 rows","hint":null,"message":"JSON object requested, multiple (or no) rows returned"}`))
	_, err = c.From("users").Select("*").Single().Execute(context.Background())
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v", err)
	}
	assertEq(t, "code", pe.Code, "PGRST116")
	assertEq(t, "status", pe.Status, 406)
	assertEq(t, "details", pe.Details, "The result contains 0 rows")
	assertEq(t, "hint", pe.Hint, "")
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts maybeSingle; test/maybe-single.test.ts
func TestMaybeSingle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantData string
		wantErr  bool
	}{
		{"one", `[{"username":"supabot"}]`, `{"username":"supabot"}`, false},
		{"none", `[]`, "", false},
		{"many", `[{"username":"supabot"},{"username":"kiwicopple"}]`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, f, _ := newFake(t, jsonReply(200, tt.body))
			resp, err := c.From("users").Select("username").MaybeSingle().Execute(context.Background())
			assertEq(t, "accept", f.last(t).Header.Get("Accept"), "")
			if tt.wantErr {
				var pe *Error
				if !errors.As(err, &pe) {
					t.Fatalf("err = %v", err)
				}
				assertEq(t, "code", pe.Code, "PGRST116")
				assertEq(t, "status", pe.Status, 406)
				assertEq(t, "details", pe.Details, "Results contain 2 rows, application/vnd.pgrst.object+json requires 1 row")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertEq(t, "data", string(resp.Data), tt.wantData)
			assertEq(t, "status", resp.Status, 200)
		})
	}

	// Pointer targets distinguish "no row".
	c, _, _ := newFake(t, jsonReply(200, `[]`))
	u, _, err := ExecuteTo[*user](context.Background(), c.From("users").Select("*").MaybeSingle())
	if err != nil || u != nil {
		t.Fatalf("u=%v err=%v", u, err)
	}
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts csv
func TestCSV(t *testing.T) {
	c, f, _ := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("id,username\n1,supabot"))
	})
	var out string
	resp, err := c.From("users").Select("*").CSV().ExecuteInto(context.Background(), &out)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept", f.last(t).Header.Get("Accept"), "text/csv")
	assertEq(t, "csv", out, "id,username\n1,supabot")
	assertEq(t, "data", string(resp.Data), out)

	// StripNulls before CSV leaves the CSV Accept untouched.
	if _, err := c.From("users").Select("*").StripNulls().CSV().Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept after stripnulls", f.last(t).Header.Get("Accept"), "text/csv")
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts geojson
func TestGeoJSON(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `{"type":"FeatureCollection","features":[]}`))
	var fc map[string]any
	if _, err := c.From("shops").Select("*").GeoJSON().ExecuteInto(context.Background(), &fc); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept", f.last(t).Header.Get("Accept"), "application/geo+json")
	assertEq(t, "type", fc["type"], any("FeatureCollection"))
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts explain
func TestExplain(t *testing.T) {
	c, f, _ := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Aggregate  (cost=33.34..33.36 rows=1 width=112)"))
	})
	var plan string
	if _, err := c.From("users").Select("*").Explain().ExecuteInto(context.Background(), &plan); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept", f.last(t).Header.Get("Accept"), `application/vnd.pgrst.plan+text; for="application/json"; options=;`)
	assertEq(t, "plan", plan, "Aggregate  (cost=33.34..33.36 rows=1 width=112)")

	c, f, _ = newFake(t, jsonReply(200, `[{"Plan":{}}]`))
	opts := ExplainOptions{Analyze: true, Verbose: true, Settings: true, Buffers: true, WAL: true, Format: ExplainJSON}
	if _, err := c.From("users").Select("*").Single().Explain(opts).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept json", f.last(t).Header.Get("Accept"),
		`application/vnd.pgrst.plan+json; for="application/vnd.pgrst.object+json"; options=analyze|verbose|settings|buffers|wal;`)
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts rollback
func TestRollback(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(201, `[{"id":1}]`))
	if _, err := c.From("users").Insert(map[string]int{"id": 1}).Select("*").Rollback().Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "prefer", f.last(t).Header.Get("Prefer"), "return=representation, tx=rollback")
}

// upstream: postgrest-js src/PostgrestTransformBuilder.ts maxAffected; test/max-affected.test.ts
func TestMaxAffected(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(204, ""))
	if _, err := c.From("users").Update(map[string]string{"s": "x"}).Eq("id", 1).MaxAffected(5).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "prefer", f.last(t).Header.Get("Prefer"), "handling=strict, max-affected=5")
	if _, err := c.From("users").Delete().Eq("id", 1).MaxAffected(1).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "delete prefer", f.last(t).Header.Get("Prefer"), "handling=strict, max-affected=1")
	if _, err := c.RPC("fn", nil).MaxAffected(2).Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "rpc prefer", f.last(t).Header.Get("Prefer"), "handling=strict, max-affected=2")
	if _, err := c.From("users").Insert(map[string]int{"id": 1}).MaxAffected(1).Execute(context.Background()); err == nil {
		t.Error("expected error for MaxAffected on insert")
	}
}

// upstream: postgrest-js src/PostgrestBuilder.ts stripNulls
func TestStripNulls(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[{"id":1}]`))
	if _, err := c.From("users").Select("*").StripNulls().Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "accept", f.last(t).Header.Get("Accept"), "application/vnd.pgrst.array+json;nulls=stripped")
	if _, err := c.From("users").Select("*").Single().StripNulls().Execute(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertEq(t, "single accept", f.last(t).Header.Get("Accept"), "application/vnd.pgrst.object+json;nulls=stripped")
	if _, err := c.From("users").Select("*").CSV().StripNulls().Execute(context.Background()); err == nil {
		t.Error("expected error for StripNulls after CSV")
	}
}
