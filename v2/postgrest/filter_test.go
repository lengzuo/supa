package postgrest

import (
	"context"
	"net/url"
	"testing"
	"time"
)

// upstream: postgrest-js src/PostgrestFilterBuilder.ts (every filter); test/filters.test.ts
func TestFilters(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name  string
		build func(FilterBuilder) FilterBuilder
		want  url.Values
	}{
		{"eq", func(b FilterBuilder) FilterBuilder { return b.Eq("username", "supabot") }, url.Values{"username": {"eq.supabot"}}},
		{"eq_time", func(b FilterBuilder) FilterBuilder { return b.Eq("at", ts) }, url.Values{"at": {"eq.2024-01-02T03:04:05Z"}}},
		{"eq_nil_pointer", func(b FilterBuilder) FilterBuilder { var p *int; return b.Eq("x", p) }, url.Values{"x": {"eq.null"}}},
		{"neq", func(b FilterBuilder) FilterBuilder { return b.Neq("username", "supabot") }, url.Values{"username": {"neq.supabot"}}},
		{"gt", func(b FilterBuilder) FilterBuilder { return b.Gt("age", 18) }, url.Values{"age": {"gt.18"}}},
		{"gte", func(b FilterBuilder) FilterBuilder { return b.Gte("age", int64(18)) }, url.Values{"age": {"gte.18"}}},
		{"lt", func(b FilterBuilder) FilterBuilder { return b.Lt("score", 1.5) }, url.Values{"score": {"lt.1.5"}}},
		{"lte", func(b FilterBuilder) FilterBuilder { return b.Lte("score", uint(7)) }, url.Values{"score": {"lte.7"}}},
		{"like", func(b FilterBuilder) FilterBuilder { return b.Like("username", "%supa%") }, url.Values{"username": {"like.%supa%"}}},
		{"like_all", func(b FilterBuilder) FilterBuilder { return b.LikeAllOf("username", []string{"%supa%", "%bot%"}) }, url.Values{"username": {"like(all).{%supa%,%bot%}"}}},
		{"like_any", func(b FilterBuilder) FilterBuilder { return b.LikeAnyOf("username", []string{"%supa%", "%a,b%"}) }, url.Values{"username": {`like(any).{%supa%,"%a,b%"}`}}},
		{"ilike", func(b FilterBuilder) FilterBuilder { return b.ILike("username", "%SUPA%") }, url.Values{"username": {"ilike.%SUPA%"}}},
		{"ilike_all", func(b FilterBuilder) FilterBuilder { return b.ILikeAllOf("username", []string{"%SUPA%", "%BOT%"}) }, url.Values{"username": {"ilike(all).{%SUPA%,%BOT%}"}}},
		{"ilike_any", func(b FilterBuilder) FilterBuilder { return b.ILikeAnyOf("username", []string{"%SUPA%", "%KIWI%"}) }, url.Values{"username": {"ilike(any).{%SUPA%,%KIWI%}"}}},
		{"regex", func(b FilterBuilder) FilterBuilder { return b.RegexMatch("username", "^sup.*") }, url.Values{"username": {"match.^sup.*"}}},
		{"regex_icase", func(b FilterBuilder) FilterBuilder { return b.RegexIMatch("username", "^SUP.*") }, url.Values{"username": {"imatch.^SUP.*"}}},
		{"is_null", func(b FilterBuilder) FilterBuilder { return b.Is("data", nil) }, url.Values{"data": {"is.null"}}},
		{"is_true", func(b FilterBuilder) FilterBuilder { return b.Is("active", true) }, url.Values{"active": {"is.true"}}},
		{"is_distinct", func(b FilterBuilder) FilterBuilder { return b.IsDistinct("status", "ONLINE") }, url.Values{"status": {"isdistinct.ONLINE"}}},
		{"is_distinct_null", func(b FilterBuilder) FilterBuilder { return b.IsDistinct("status", nil) }, url.Values{"status": {"isdistinct.null"}}},
		{"in", func(b FilterBuilder) FilterBuilder { return b.In("status", []string{"ONLINE", "OFFLINE"}) }, url.Values{"status": {"in.(ONLINE,OFFLINE)"}}},
		{"in_dedupe_ints", func(b FilterBuilder) FilterBuilder { return b.In("id", []int{1, 2, 2, 3}) }, url.Values{"id": {"in.(1,2,3)"}}},
		{"in_reserved", func(b FilterBuilder) FilterBuilder {
			return b.In("name", []string{"a,b", "c(d)", "a,b", `q"x`, `back\slash`, "plain"})
		}, url.Values{"name": {`in.("a,b","c(d)","q\"x","back\\slash",plain)`}}},
		{"not_in", func(b FilterBuilder) FilterBuilder { return b.NotIn("status", []string{"ONLINE", "a)b"}) }, url.Values{"status": {`not.in.(ONLINE,"a)b")`}}},
		{"contains_string", func(b FilterBuilder) FilterBuilder { return b.Contains("age_range", "[1,2)") }, url.Values{"age_range": {"cs.[1,2)"}}},
		{"contains_array", func(b FilterBuilder) FilterBuilder { return b.Contains("tags", []string{"a", "b c"}) }, url.Values{"tags": {`cs.{a,"b c"}`}}},
		{"contains_json", func(b FilterBuilder) FilterBuilder { return b.Contains("data", map[string]any{"a": 1}) }, url.Values{"data": {`cs.{"a":1}`}}},
		{"contained_by_array", func(b FilterBuilder) FilterBuilder { return b.ContainedBy("tags", []int{1, 2}) }, url.Values{"tags": {"cd.{1,2}"}}},
		{"contained_by_json", func(b FilterBuilder) FilterBuilder { return b.ContainedBy("data", map[string]bool{"x": true}) }, url.Values{"data": {`cd.{"x":true}`}}},
		{"overlaps_array", func(b FilterBuilder) FilterBuilder { return b.Overlaps("tags", []string{"a", "b"}) }, url.Values{"tags": {"ov.{a,b}"}}},
		{"overlaps_range", func(b FilterBuilder) FilterBuilder { return b.Overlaps("during", "[2000-01-01,2000-01-02)") }, url.Values{"during": {"ov.[2000-01-01,2000-01-02)"}}},
		{"range_gt", func(b FilterBuilder) FilterBuilder { return b.RangeGt("r", "[1,2)") }, url.Values{"r": {"sr.[1,2)"}}},
		{"range_gte", func(b FilterBuilder) FilterBuilder { return b.RangeGte("r", "[1,2)") }, url.Values{"r": {"nxl.[1,2)"}}},
		{"range_lt", func(b FilterBuilder) FilterBuilder { return b.RangeLt("r", "[1,2)") }, url.Values{"r": {"sl.[1,2)"}}},
		{"range_lte", func(b FilterBuilder) FilterBuilder { return b.RangeLte("r", "[1,2)") }, url.Values{"r": {"nxr.[1,2)"}}},
		{"range_adjacent", func(b FilterBuilder) FilterBuilder { return b.RangeAdjacent("r", "[1,2)") }, url.Values{"r": {"adj.[1,2)"}}},
		{"text_search", func(b FilterBuilder) FilterBuilder { return b.TextSearch("c", "'fat' & 'cat'") }, url.Values{"c": {"fts.'fat' & 'cat'"}}},
		{"text_search_config", func(b FilterBuilder) FilterBuilder {
			return b.TextSearch("c", "'fat' & 'cat'", TextSearchOptions{Config: "english"})
		}, url.Values{"c": {"fts(english).'fat' & 'cat'"}}},
		{"text_search_plain", func(b FilterBuilder) FilterBuilder {
			return b.TextSearch("c", "fat cat", TextSearchOptions{Type: TextSearchPlain, Config: "english"})
		}, url.Values{"c": {"plfts(english).fat cat"}}},
		{"text_search_phrase", func(b FilterBuilder) FilterBuilder {
			return b.TextSearch("c", "cats", TextSearchOptions{Type: TextSearchPhrase})
		}, url.Values{"c": {"phfts.cats"}}},
		{"text_search_websearch", func(b FilterBuilder) FilterBuilder {
			return b.TextSearch("c", `"fat rat" or cat`, TextSearchOptions{Type: TextSearchWebsearch, Config: "english"})
		}, url.Values{"c": {`wfts(english)."fat rat" or cat`}}},
		{"match", func(b FilterBuilder) FilterBuilder {
			return b.Match(map[string]any{"username": "supabot", "status": "ONLINE"})
		}, url.Values{"username": {"eq.supabot"}, "status": {"eq.ONLINE"}}},
		{"not", func(b FilterBuilder) FilterBuilder { return b.Not("status", "eq", "OFFLINE") }, url.Values{"status": {"not.eq.OFFLINE"}}},
		{"not_is_null", func(b FilterBuilder) FilterBuilder { return b.Not("data", "is", nil) }, url.Values{"data": {"not.is.null"}}},
		{"or", func(b FilterBuilder) FilterBuilder { return b.Or("status.eq.OFFLINE,username.eq.supabot") }, url.Values{"or": {"(status.eq.OFFLINE,username.eq.supabot)"}}},
		{"or_referenced", func(b FilterBuilder) FilterBuilder {
			return b.Or("id.eq.1,id.eq.2", TableOptions{ReferencedTable: "messages"})
		}, url.Values{"messages.or": {"(id.eq.1,id.eq.2)"}}},
		{"raw_filter", func(b FilterBuilder) FilterBuilder { return b.Filter("username", "in", "(supabot,kiwicopple)") }, url.Values{"username": {"in.(supabot,kiwicopple)"}}},
		{"multiple_same_column", func(b FilterBuilder) FilterBuilder { return b.Gte("age", 18).Lt("age", 65) }, url.Values{"age": {"gte.18", "lt.65"}}},
	}
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.build(c.From("users").Select("*")).Execute(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := f.last(t).Query
			got.Del("select")
			if got.Encode() != tt.want.Encode() {
				t.Errorf("query = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterErrors(t *testing.T) {
	c, f, _ := newFake(t, jsonReply(200, `[]`))
	cases := map[string]FilterBuilder{
		"in_not_slice":       c.From("users").Select("*").In("id", 5),
		"not_in_not_slice":   c.From("users").Select("*").NotIn("id", "x"),
		"bad_json":           c.From("users").Select("*").Contains("data", map[string]any{"f": func() {}}),
		"bad_eq":             c.From("users").Select("*").Eq("data", map[string]any{"f": make(chan int)}),
		"bad_text_type":      c.From("users").Select("*").TextSearch("c", "q", TextSearchOptions{Type: "fuzzy"}),
		"empty_relation":     c.From("  ").Select("*"),
		"bad_insert":         c.From("users").Insert(func() {}),
		"bad_update":         c.From("users").Update(make(chan int)),
		"bad_rpc":            c.RPC("fn", func() {}),
		"empty_rpc":          c.RPC("", nil),
		"max_affected_get":   c.From("users").Select("*").MaxAffected(1),
		"strip_nulls_on_csv": c.From("users").Select("*").CSV().StripNulls(),
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := q.Execute(context.Background()); err == nil {
				t.Error("expected error")
			}
		})
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("%d requests sent for invalid builders", n)
	}
}
