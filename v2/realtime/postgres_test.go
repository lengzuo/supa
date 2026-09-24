package realtime

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func pgChange(ids []int, typ string, record, old map[string]any) map[string]any {
	return map[string]any{
		"ids": ids,
		"data": map[string]any{
			"schema": "public", "table": "todos", "commit_timestamp": "2024-01-01T00:00:00Z", "type": typ,
			"errors": nil,
			"columns": []any{
				map[string]any{"name": "id", "type": "int8"},
				map[string]any{"name": "done", "type": "bool"},
				map[string]any{"name": "meta", "type": "jsonb"},
				map[string]any{"name": "tags", "type": "_int4"},
				map[string]any{"name": "at", "type": "timestamp"},
				map[string]any{"name": "title", "type": "text"},
			},
			"record":     record,
			"old_record": old,
		},
	}
}

// upstream: realtime-js test/RealtimeChannel.postgres.test.ts (join payload, server ids, dispatch & transform)
func TestPostgresChanges(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	inserts := make(chan PostgresChangesPayload, 4)
	all := make(chan PostgresChangesPayload, 4)
	deletes := make(chan PostgresChangesPayload, 4)
	ch, sc, join := subscribeJoined(t, c, fs, "db", ChannelOptions{}, func(ch *Channel) {
		_ = ch.OnPostgresChanges(PostgresChangesFilter{Event: PostgresChangeInsert, Schema: "public", Table: "todos"}, func(p PostgresChangesPayload) { inserts <- p })
		_ = ch.OnPostgresChanges(PostgresChangesFilter{Schema: "public", Table: "todos", Filter: "id=eq.1", Select: []string{"id", "title"}}, func(p PostgresChangesPayload) { all <- p })
		_ = ch.OnPostgresChanges(PostgresChangesFilter{Event: PostgresChangeDelete, Schema: "public"}, func(p PostgresChangesPayload) { deletes <- p })
		// Duplicate filters are ignored.
		_ = ch.OnPostgresChanges(PostgresChangesFilter{Event: PostgresChangeDelete, Schema: "public"}, func(p PostgresChangesPayload) { deletes <- p })
	})
	var p struct {
		Config struct {
			PostgresChanges json.RawMessage `json:"postgres_changes"`
		} `json:"config"`
	}
	_ = json.Unmarshal(join.Payload, &p)
	want := `[{"event":"INSERT","schema":"public","table":"todos"},{"event":"*","schema":"public","table":"todos","filter":"id=eq.1","select":["id","title"]},{"event":"DELETE","schema":"public"}]`
	if string(p.Config.PostgresChanges) != want {
		t.Fatalf("postgres_changes = %s\nwant %s", p.Config.PostgresChanges, want)
	}
	if err := ch.OnPostgresChanges(PostgresChangesFilter{Schema: "public"}, func(PostgresChangesPayload) {}); err == nil {
		t.Fatal("OnPostgresChanges after subscribe must fail")
	}

	// Server ids are 100, 101, 102 (see defaultJoinResponse).
	rec := map[string]any{"id": "1", "done": "t", "meta": `{"a":[1,2]}`, "tags": "{1,2,3}", "at": "2024-01-01 10:00:00", "title": "hi"}
	sc.push("realtime:db", "postgres_changes", pgChange([]int{100, 101}, "INSERT", rec, nil))
	ins := recv(t, inserts, "insert")
	if ins.EventType != PostgresChangeInsert || ins.Schema != "public" || ins.Table != "todos" || ins.CommitTimestamp != "2024-01-01T00:00:00Z" {
		t.Fatalf("payload = %+v", ins)
	}
	wantNew := map[string]any{
		"id": json.Number("1"), "done": true, "meta": map[string]any{"a": []any{json.Number("1"), json.Number("2")}},
		"tags": []any{json.Number("1"), json.Number("2"), json.Number("3")}, "at": "2024-01-01T10:00:00", "title": "hi",
	}
	if !reflect.DeepEqual(ins.New, wantNew) || len(ins.Old) != 0 {
		t.Fatalf("new = %#v old = %#v", ins.New, ins.Old)
	}
	var row struct {
		ID    int    `json:"id"`
		Done  bool   `json:"done"`
		Title string `json:"title"`
	}
	if err := ins.DecodeNew(&row); err != nil || row.ID != 1 || !row.Done || row.Title != "hi" {
		t.Fatalf("DecodeNew = %+v %v", row, err)
	}
	recv(t, all, "wildcard")
	select {
	case <-deletes:
		t.Fatal("delete binding received insert")
	case <-time.After(30 * time.Millisecond):
	}

	// Ids select bindings: only 102 gets this DELETE.
	sc.push("realtime:db", "postgres_changes", pgChange([]int{102}, "DELETE", nil, map[string]any{"id": "7"}))
	del := recv(t, deletes, "delete")
	if del.EventType != PostgresChangeDelete || len(del.New) != 0 || del.Old["id"] != json.Number("7") {
		t.Fatalf("delete = %+v", del)
	}
	select {
	case <-all:
		t.Fatal("binding 101 received change for id 102")
	case <-deletes:
		t.Fatal("duplicate binding was registered")
	case <-time.After(30 * time.Millisecond):
	}

	// UPDATE fills both new and old.
	sc.push("realtime:db", "postgres_changes", pgChange([]int{101}, "UPDATE", map[string]any{"id": "1"}, map[string]any{"id": "1", "done": "f"}))
	up := recv(t, all, "update")
	if up.New["id"] != json.Number("1") || up.Old["done"] != false {
		t.Fatalf("update = %+v", up)
	}
}

// upstream: realtime-js test/RealtimeChannel.postgres.test.ts multiple filters on one channel
func TestPostgresChangesMultipleFilters(t *testing.T) {
	fs := newFakeServer(t)
	c := newTestClient(t, fs, nil)
	a := make(chan PostgresChangesPayload, 2)
	b := make(chan PostgresChangesPayload, 2)
	f1 := NewPostgresFilter().Eq("room", "a,b").Gt("id", 10)
	f2 := NewPostgresFilter().In("status", "open", "closed")
	s1, _ := f1.Build()
	s2, _ := f2.Build()
	_, sc, join := subscribeJoined(t, c, fs, "multi", ChannelOptions{}, func(ch *Channel) {
		_ = ch.OnPostgresChanges(PostgresChangesFilter{Event: PostgresChangeUpdate, Schema: "public", Table: "msgs", Filter: s1}, func(p PostgresChangesPayload) { a <- p })
		_ = ch.OnPostgresChanges(PostgresChangesFilter{Event: PostgresChangeUpdate, Schema: "public", Table: "msgs", Filter: s2}, func(p PostgresChangesPayload) { b <- p })
	})
	if !strings.Contains(string(join.Payload), `"filter":"room=eq.\"a,b\",id=gt.10"`) || !strings.Contains(string(join.Payload), `"filter":"status=in.(open,closed)"`) {
		t.Fatalf("join payload = %s", join.Payload)
	}
	sc.push("realtime:multi", "postgres_changes", pgChange([]int{101}, "UPDATE", map[string]any{"id": "1"}, map[string]any{}))
	recv(t, b, "second filter")
	select {
	case <-a:
		t.Fatal("first filter received change")
	case <-time.After(30 * time.Millisecond):
	}
	sc.push("realtime:multi", "postgres_changes", pgChange([]int{100, 101}, "UPDATE", map[string]any{"id": "1"}, map[string]any{}))
	recv(t, a, "first filter")
	recv(t, b, "second filter again")
}

// upstream: realtime-js test/RealtimeChannel.postgres.test.ts 'mismatch between server and client bindings'
func TestPostgresChangesBindingMismatch(t *testing.T) {
	fs := newFakeServer(t)
	fs.joinReply = func(sc *serverConn, m srvMsg) (string, any) {
		return "ok", map[string]any{"postgres_changes": []any{map[string]any{"id": 1, "event": "*", "schema": "public", "table": "other"}}}
	}
	c := newTestClient(t, fs, nil)
	ch, _ := c.Channel("mismatch", ChannelOptions{})
	statuses := make(chan SubscribeStatus, 4)
	ch.OnStatus(func(s SubscribeStatus, _ error) { statuses <- s })
	_ = ch.OnPostgresChanges(PostgresChangesFilter{Schema: "public", Table: "todos"}, func(PostgresChangesPayload) {})
	err := ch.Subscribe(ctxT(t))
	var se *SubscribeError
	if !errors.As(err, &se) || se.Status != StatusChannelError || !strings.Contains(se.Message, "mismatch") {
		t.Fatalf("err = %v", err)
	}
	sc := fs.nextConn(t)
	sc.expectEvent(t, "realtime:mismatch", "phx_leave")
	if s := recv(t, statuses, "closed"); s != StatusClosed {
		t.Fatalf("status = %s", s)
	}
	if s := recv(t, statuses, "error"); s != StatusChannelError {
		t.Fatalf("status = %s", s)
	}
}

// upstream: realtime-js RealtimeChannelOptions postgres_changes_options.wait extends the join timeout
func TestPostgresChangesWaitOption(t *testing.T) {
	fs := newFakeServer(t)
	fs.joinReply = func(sc *serverConn, m srvMsg) (string, any) {
		go func() {
			time.Sleep(300 * time.Millisecond) // longer than the client timeout
			var p struct {
				Config map[string]any `json:"config"`
			}
			_ = json.Unmarshal(m.Payload, &p)
			sc.reply(m, "ok", defaultJoinResponse(p.Config))
		}()
		return "", nil
	}
	c := newTestClient(t, fs, func(cfg *Config) { cfg.Timeout = 100 * time.Millisecond })
	ch, _ := c.Channel("wait", ChannelOptions{PostgresChanges: &PostgresChangesOptions{Wait: true, Timeout: 5 * time.Second}})
	_ = ch.OnPostgresChanges(PostgresChangesFilter{Schema: "public"}, func(PostgresChangesPayload) {})
	if err := ch.Subscribe(ctxT(t)); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	sc := fs.nextConn(t)
	if opts, _ := sc.config("realtime:wait")["postgres_changes_options"].(map[string]any); opts["wait"] != true || opts["timeout"] != float64(5000) {
		t.Fatalf("postgres_changes_options = %v", sc.config("realtime:wait"))
	}
}

// upstream: realtime-js test/RealtimePostgresFilterBuilder.test.ts
func TestPostgresFilterBuilder(t *testing.T) {
	cases := []struct {
		name string
		f    *PostgresFilter
		want string
	}{
		{"eq", NewPostgresFilter().Eq("id", 1), "id=eq.1"},
		{"chain", NewPostgresFilter().Eq("id", 1).Lt("age", 30), "id=eq.1,age=lt.30"},
		{"all ops", NewPostgresFilter().Neq("a", "x").Gt("b", 1.5).Gte("c", 2).Lte("d", -1).Like("e", "%foo%").ILike("f", "%F%").Match("g", "^a").IMatch("h", "^A").IsDistinct("i", nil),
			"a=neq.x,b=gt.1.5,c=gte.2,d=lte.-1,e=like.%foo%,f=ilike.%F%,g=match.^a,h=imatch.^A,i=isdistinct.null"},
		{"quote reserved", NewPostgresFilter().Eq("name", "a,b").Eq("q", `say "hi"`).Eq("p", `back\slash`).Eq("s", " pad"),
			`name=eq."a,b",q=eq."say \"hi\"",p=eq."back\\slash",s=eq." pad"`},
		{"in", NewPostgresFilter().In("status", "active", "pending", "active"), "status=in.(active,pending)"},
		{"in slice", NewPostgresFilter().In("id", []int{1, 2}), "id=in.(1,2)"},
		{"in quoted", NewPostgresFilter().In("tag", "a,b", "c"), `tag=in.("a,b",c)`},
		{"in mixed types", NewPostgresFilter().In("v", 1, "1", true), "v=in.(1,1,true)"},
		{"is", NewPostgresFilter().Is("deleted_at", nil).Is("flag", true).Is("x", "unknown"), "deleted_at=is.null,flag=is.true,x=is.unknown"},
		{"not in", NewPostgresFilter().Not("status", "in", []string{"draft", "archived"}), "status=not.in.(draft,archived)"},
		{"not is", NewPostgresFilter().Not("deleted_at", "is", nil), "deleted_at=not.is.null"},
		{"not eq", NewPostgresFilter().Not("a", "eq", 5), "a=not.eq.5"},
		{"empty", NewPostgresFilter(), ""},
		{"floats", NewPostgresFilter().Eq("a", 1e21).Eq("b", 0.0000001).Eq("c", 100.0), "a=eq.1e+21,b=eq.1e-7,c=eq.100"},
	}
	for _, tc := range cases {
		got, err := tc.f.Build()
		if err != nil || got != tc.want || tc.f.String() != tc.want {
			t.Errorf("%s: got %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := NewPostgresFilter().In("id").Build(); err == nil {
		t.Error("empty in must fail")
	}
	if _, err := NewPostgresFilter().Not("id", "cs", 1).Eq("a", 1).Build(); err == nil {
		t.Error("unsupported operator must fail")
	}
	// Builders are immutable.
	base := NewPostgresFilter().Eq("a", 1)
	_ = base.Eq("b", 2)
	if base.String() != "a=eq.1" {
		t.Errorf("builder mutated: %s", base.String())
	}
}

// upstream: realtime-js test/transformers.test.ts convertChangeData / convertCell / toArray
func TestConvertChangeData(t *testing.T) {
	cols := []pgColumn{{"first_name", "text"}, {"age", "int4"}, {"ok", "bool"}, {"price", "numeric"}, {"arr", "_int4"},
		{"txt", "_text"}, {"j", "json"}, {"ts", "timestamp"}, {"tz", "timestamptz"}, {"bad", "int4"}, {"empty", "_int4"}}
	rec := json.RawMessage(`{"first_name":"Paul","age":"33","ok":"f","price":"1.50","arr":"{1,2,3,4}","txt":"{a,b}",
		"j":"{\"x\":1}","ts":"2019-09-10 00:00:00","tz":"2019-09-10 00:00:00+00","bad":"abc","empty":"{}","unknown":5,"nul":null}`)
	got := convertChangeData(cols, rec)
	want := map[string]any{
		"first_name": "Paul", "age": json.Number("33"), "ok": false, "price": json.Number("1.50"),
		"arr": []any{json.Number("1"), json.Number("2"), json.Number("3"), json.Number("4")},
		"txt": []any{"a", "b"}, "j": map[string]any{"x": json.Number("1")}, "ts": "2019-09-10T00:00:00",
		"tz": "2019-09-10 00:00:00+00", "bad": "abc", "empty": []any{}, "unknown": json.Number("5"), "nul": nil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}
	if got := convertChangeData(cols, nil); len(got) != 0 {
		t.Fatalf("nil record = %v", got)
	}
	if v := toNumber(" 12 "); v != json.Number("12") {
		t.Fatalf("toNumber = %#v", v)
	}
	if v := convertCell("_daterange", `{"[2021-01-01,2021-12-31)","(2021-01-01,2021-12-32]"}`); !reflect.DeepEqual(v, []any{"[2021-01-01,2021-12-31)", "(2021-01-01,2021-12-32]"}) {
		t.Fatalf("daterange array = %#v", v)
	}
}
