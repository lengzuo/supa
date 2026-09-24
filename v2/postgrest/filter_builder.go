package postgrest

import (
	"fmt"
	"net/http"
	"sort"
)

// FilterBuilder is a query that can be filtered, shaped and executed. It
// is returned by QueryBuilder methods and Client.RPC.
//
// FilterBuilder is an immutable value: every method returns a new
// FilterBuilder and leaves the receiver unchanged, so a partially built
// query can be reused as a template and shared between goroutines:
//
//	active := db.From("users").Select("*").Eq("status", "active")
//	admins := active.Eq("role", "admin")   // active is unchanged
//	recent := active.Order("created_at", postgrest.OrderOptions{Descending: true})
//
// Invalid input (for example an un-encodable value) does not panic; the
// error is recorded and returned by Execute. The zero FilterBuilder is not
// usable: its Execute returns an error.
//
// Filter values of type any are rendered as text: nil and nil pointers
// are null; an encoding.TextMarshaler or driver.Valuer (such as
// sql.NullString) uses its text or database value; numbers, booleans and
// strings use their literal form, even when the type has a String method
// (so a stringer-style int enum is sent as its number); time.Time is RFC
// 3339; other fmt.Stringer values use String; slices are comma-joined;
// maps and structs are JSON.
type FilterBuilder struct {
	c      *Client
	method string
	path   string
	query  []param
	header http.Header
	body   []byte
	isRPC  bool

	maybeSingle bool
	stripNulls  bool
	retry       *bool
	err         error
}

// param is one query-string parameter. FilterBuilder.query keeps params in
// the order they were added, and Execute sends them in that order.
type param struct{ key, value string }

// appendParam returns a copy of ps with (key, value) appended, like
// URLSearchParams.append.
func appendParam(ps []param, key, value string) []param {
	out := make([]param, len(ps), len(ps)+1)
	copy(out, ps)
	return append(out, param{key, value})
}

// setParam returns a copy of ps where key has the single value value,
// placed at the position of its first occurrence, like
// URLSearchParams.set.
func setParam(ps []param, key, value string) []param {
	out := make([]param, 0, len(ps)+1)
	found := false
	for _, p := range ps {
		if p.key != key {
			out = append(out, p)
			continue
		}
		if !found {
			out = append(out, param{key, value})
			found = true
		}
	}
	if !found {
		out = append(out, param{key, value})
	}
	return out
}

func getParam(ps []param, key string) (string, bool) {
	for _, p := range ps {
		if p.key == key {
			return p.value, true
		}
	}
	return "", false
}

// setErr records the first builder error.
func (b *FilterBuilder) setErr(err error) {
	if b.err == nil {
		b.err = err
	}
}

// withHeader returns a copy of b whose header map is private to it.
func (b FilterBuilder) withHeader(fn func(h http.Header)) FilterBuilder {
	b.header = b.header.Clone()
	if b.header == nil {
		b.header = http.Header{}
	}
	fn(b.header)
	return b
}

func (b FilterBuilder) appendFilter(column, value string) FilterBuilder {
	b.query = appendParam(b.query, column, value)
	return b
}

func (b FilterBuilder) appendFormatted(column, op string, value any) FilterBuilder {
	s, err := formatValue(value)
	if err != nil {
		b.setErr(err)
		return b
	}
	return b.appendFilter(column, op+"."+s)
}

// Eq matches rows where column equals value. column may be a JSON path
// (data->>key) or a column of an embedded resource (orders.status).
func (b FilterBuilder) Eq(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "eq", value)
}

// Neq matches rows where column does not equal value.
func (b FilterBuilder) Neq(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "neq", value)
}

// Gt matches rows where column is greater than value.
func (b FilterBuilder) Gt(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "gt", value)
}

// Gte matches rows where column is greater than or equal to value.
func (b FilterBuilder) Gte(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "gte", value)
}

// Lt matches rows where column is less than value.
func (b FilterBuilder) Lt(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "lt", value)
}

// Lte matches rows where column is less than or equal to value.
func (b FilterBuilder) Lte(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "lte", value)
}

// Like matches rows where column matches the case-sensitive LIKE pattern.
func (b FilterBuilder) Like(column, pattern string) FilterBuilder {
	return b.appendFilter(column, "like."+pattern)
}

// LikeAllOf matches rows where column matches every LIKE pattern.
func (b FilterBuilder) LikeAllOf(column string, patterns []string) FilterBuilder {
	return b.appendPatterns(column, "like(all)", patterns)
}

// LikeAnyOf matches rows where column matches any LIKE pattern.
func (b FilterBuilder) LikeAnyOf(column string, patterns []string) FilterBuilder {
	return b.appendPatterns(column, "like(any)", patterns)
}

// ILike matches rows where column matches the case-insensitive ILIKE
// pattern.
func (b FilterBuilder) ILike(column, pattern string) FilterBuilder {
	return b.appendFilter(column, "ilike."+pattern)
}

// ILikeAllOf matches rows where column matches every ILIKE pattern.
func (b FilterBuilder) ILikeAllOf(column string, patterns []string) FilterBuilder {
	return b.appendPatterns(column, "ilike(all)", patterns)
}

// ILikeAnyOf matches rows where column matches any ILIKE pattern.
func (b FilterBuilder) ILikeAnyOf(column string, patterns []string) FilterBuilder {
	return b.appendPatterns(column, "ilike(any)", patterns)
}

func (b FilterBuilder) appendPatterns(column, op string, patterns []string) FilterBuilder {
	elems := make([]any, len(patterns))
	for i, p := range patterns {
		elems[i] = p
	}
	lit, err := formatArrayLiteral(elems)
	if err != nil {
		b.setErr(err)
		return b
	}
	return b.appendFilter(column, op+"."+lit)
}

// RegexMatch matches rows where column matches the POSIX regular
// expression pattern (case-sensitive, the ~ operator).
func (b FilterBuilder) RegexMatch(column, pattern string) FilterBuilder {
	return b.appendFilter(column, "match."+pattern)
}

// RegexIMatch matches rows where column matches the POSIX regular
// expression pattern case-insensitively (the ~* operator).
func (b FilterBuilder) RegexIMatch(column, pattern string) FilterBuilder {
	return b.appendFilter(column, "imatch."+pattern)
}

// Is matches rows where column IS value. value is nil (NULL), true or
// false.
func (b FilterBuilder) Is(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "is", value)
}

// IsDistinct matches rows where column IS DISTINCT FROM value: unlike Neq,
// NULL is treated as a comparable value.
func (b FilterBuilder) IsDistinct(column string, value any) FilterBuilder {
	return b.appendFormatted(column, "isdistinct", value)
}

// In matches rows where column is one of values, which must be a slice or
// array (for example []int or []string). Duplicates are removed, and any
// value whose text contains , ( ) " or \ is double-quoted and escaped,
// whatever its Go type.
//
// Inside In, NotIn and the array forms of Contains, ContainedBy and
// Overlaps, the string "null" is literal text; pass nil (or a nil pointer)
// for SQL NULL. Values are never un-quoted: the string `"a,b"` (with the
// quotes) matches that exact text, quotes included.
func (b FilterBuilder) In(column string, values any) FilterBuilder {
	list, err := formatInList(values)
	if err != nil {
		b.setErr(err)
		return b
	}
	return b.appendFilter(column, "in.("+list+")")
}

// NotIn matches rows where column is none of values. See In.
func (b FilterBuilder) NotIn(column string, values any) FilterBuilder {
	list, err := formatInList(values)
	if err != nil {
		b.setErr(err)
		return b
	}
	return b.appendFilter(column, "not.in.("+list+")")
}

func (b FilterBuilder) appendContainment(column, op string, value any) FilterBuilder {
	s, err := formatContainment(value)
	if err != nil {
		b.setErr(err)
		return b
	}
	return b.appendFilter(column, op+"."+s)
}

// Contains matches rows where the array, range or jsonb column contains
// value. value is a string in Postgres literal syntax, a slice (array
// columns) or a map/struct (jsonb columns).
func (b FilterBuilder) Contains(column string, value any) FilterBuilder {
	return b.appendContainment(column, "cs", value)
}

// ContainedBy matches rows where every element of the array, range or
// jsonb column is contained in value. See Contains for value.
func (b FilterBuilder) ContainedBy(column string, value any) FilterBuilder {
	return b.appendContainment(column, "cd", value)
}

// Overlaps matches rows where the array or range column shares an element
// with value (a slice, or a string in Postgres literal syntax).
func (b FilterBuilder) Overlaps(column string, value any) FilterBuilder {
	return b.appendContainment(column, "ov", value)
}

// RangeGt matches rows where the range column is strictly right of rng
// (the >> operator).
func (b FilterBuilder) RangeGt(column, rng string) FilterBuilder {
	return b.appendFilter(column, "sr."+rng)
}

// RangeGte matches rows where the range column does not extend to the
// left of rng (the &> operator).
func (b FilterBuilder) RangeGte(column, rng string) FilterBuilder {
	return b.appendFilter(column, "nxl."+rng)
}

// RangeLt matches rows where the range column is strictly left of rng
// (the << operator).
func (b FilterBuilder) RangeLt(column, rng string) FilterBuilder {
	return b.appendFilter(column, "sl."+rng)
}

// RangeLte matches rows where the range column does not extend to the
// right of rng (the &< operator).
func (b FilterBuilder) RangeLte(column, rng string) FilterBuilder {
	return b.appendFilter(column, "nxr."+rng)
}

// RangeAdjacent matches rows where the range column is adjacent to rng
// (the -|- operator).
func (b FilterBuilder) RangeAdjacent(column, rng string) FilterBuilder {
	return b.appendFilter(column, "adj."+rng)
}

// TextSearchType selects the tsquery parser used by TextSearch.
type TextSearchType string

const (
	// TextSearchDefault uses to_tsquery (fts).
	TextSearchDefault TextSearchType = ""
	// TextSearchPlain uses plainto_tsquery (plfts).
	TextSearchPlain TextSearchType = "plain"
	// TextSearchPhrase uses phraseto_tsquery (phfts).
	TextSearchPhrase TextSearchType = "phrase"
	// TextSearchWebsearch uses websearch_to_tsquery (wfts).
	TextSearchWebsearch TextSearchType = "websearch"
)

// TextSearchOptions configures TextSearch.
type TextSearchOptions struct {
	// Config is the text search configuration, e.g. "english".
	Config string
	// Type selects the query parser.
	Type TextSearchType
}

// TextSearch matches rows where the tsvector column matches the tsquery
// query. At most one TextSearchOptions is used (the last).
func (b FilterBuilder) TextSearch(column, query string, opts ...TextSearchOptions) FilterBuilder {
	o := lastOpt(opts)
	var typePart string
	switch o.Type {
	case TextSearchPlain:
		typePart = "pl"
	case TextSearchPhrase:
		typePart = "ph"
	case TextSearchWebsearch:
		typePart = "w"
	case TextSearchDefault:
	default:
		b.setErr(fmt.Errorf("postgrest: unknown text search type %q", o.Type))
		return b
	}
	configPart := ""
	if o.Config != "" {
		configPart = "(" + o.Config + ")"
	}
	return b.appendFilter(column, typePart+"fts"+configPart+"."+query)
}

// Match matches rows where every column in query equals its value. Keys
// are applied in sorted order so the URL is deterministic.
func (b FilterBuilder) Match(query map[string]any) FilterBuilder {
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b = b.Eq(k, query[k])
	}
	return b
}

// Not negates a filter: it matches rows where "column operator value" is
// false. operator is a raw PostgREST operator ("eq", "is", "in", ...) and
// value is sent verbatim in PostgREST syntax, e.g. Not("id", "in",
// "(1,2)").
func (b FilterBuilder) Not(column, operator string, value any) FilterBuilder {
	return b.appendFormatted(column, "not."+operator, value)
}

// TableOptions scopes Or, Order, Limit and Range to an embedded
// (referenced) resource instead of the top-level table.
type TableOptions struct {
	// ReferencedTable is the embedded resource's name or alias.
	ReferencedTable string
}

// Or matches rows satisfying at least one of filters, a raw PostgREST
// expression such as "id.eq.1,name.eq.bob" or
// "status.eq.active,and(age.gt.18,age.lt.65)". Values containing reserved
// characters must be double-quoted by the caller. At most one
// TableOptions is used (the last).
func (b FilterBuilder) Or(filters string, opts ...TableOptions) FilterBuilder {
	key := "or"
	if t := lastOpt(opts).ReferencedTable; t != "" {
		key = t + ".or"
	}
	return b.appendFilter(key, "("+filters+")")
}

// Filter adds a raw filter "column=operator.value". Use it for operators
// without a dedicated method; value is sent verbatim in PostgREST syntax
// (e.g. Filter("id", "in", "(1,2)")).
func (b FilterBuilder) Filter(column, operator string, value any) FilterBuilder {
	return b.appendFormatted(column, operator, value)
}
