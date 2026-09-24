package postgrest

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// Count selects the algorithm PostgREST uses to count rows. The count is
// returned in Response.Count.
type Count string

const (
	// CountExact runs COUNT(*): exact but slow on large tables.
	CountExact Count = "exact"
	// CountPlanned uses the Postgres planner's estimate: fast but approximate.
	CountPlanned Count = "planned"
	// CountEstimated uses an exact count for small tables and the planned
	// estimate for large ones.
	CountEstimated Count = "estimated"
)

// QueryBuilder starts a query on one table or view. Obtain it from
// Client.From. It is an immutable value: each method returns a new
// FilterBuilder and never modifies the receiver, so a QueryBuilder can be
// reused and shared between goroutines.
type QueryBuilder struct {
	c      *Client
	path   string
	header http.Header
	err    error
}

// SelectOptions configures QueryBuilder.Select.
type SelectOptions struct {
	// Head sends a HEAD request: no rows are returned, which is useful
	// together with Count.
	Head bool
	// Count asks PostgREST to count the matching rows.
	Count Count
}

// InsertOptions configures QueryBuilder.Insert.
type InsertOptions struct {
	// Count asks PostgREST to count the inserted rows.
	Count Count
	// MissingAsDefault fills columns that are missing from some rows of a
	// bulk insert with their column default instead of NULL (Prefer:
	// missing=default). It is the inverse of postgrest-js defaultToNull,
	// whose default (true) corresponds to MissingAsDefault=false.
	MissingAsDefault bool
}

// UpsertOptions configures QueryBuilder.Upsert.
type UpsertOptions struct {
	// OnConflict is a comma-separated list of columns with a UNIQUE
	// constraint used to detect duplicates. Defaults to the primary key.
	OnConflict string
	// IgnoreDuplicates skips duplicate rows instead of merging them.
	IgnoreDuplicates bool
	// Count asks PostgREST to count the upserted rows.
	Count Count
	// MissingAsDefault: see InsertOptions.MissingAsDefault.
	MissingAsDefault bool
}

// UpdateOptions configures QueryBuilder.Update.
type UpdateOptions struct {
	// Count asks PostgREST to count the updated rows.
	Count Count
}

// DeleteOptions configures QueryBuilder.Delete.
type DeleteOptions struct {
	// Count asks PostgREST to count the deleted rows.
	Count Count
}

func lastOpt[T any](opts []T) T {
	var zero T
	if len(opts) == 0 {
		return zero
	}
	return opts[len(opts)-1]
}

func (q QueryBuilder) builder(method string) FilterBuilder {
	return FilterBuilder{
		c:      q.c,
		method: method,
		path:   q.path,
		header: q.header.Clone(),
		err:    q.err,
	}
}

// Select reads rows. columns uses PostgREST select syntax, including
// resource embedding ("id, name, orders(id, total)"), renaming and casts;
// whitespace outside double quotes is removed and "" means "*". At most
// one SelectOptions is used (the last).
func (q QueryBuilder) Select(columns string, opts ...SelectOptions) FilterBuilder {
	o := lastOpt(opts)
	method := http.MethodGet
	if o.Head {
		method = http.MethodHead
	}
	b := q.builder(method)
	b.query = setParam(nil, "select", cleanColumns(columns))
	if o.Count != "" {
		b.header.Add(headerPrefer, "count="+string(o.Count))
	}
	return b
}

// Insert inserts one row (a struct or map) or many rows (a slice). The
// values are JSON-encoded immediately. By default no rows are returned;
// chain Select to return the inserted rows. At most one InsertOptions is
// used (the last).
func (q QueryBuilder) Insert(values any, opts ...InsertOptions) FilterBuilder {
	o := lastOpt(opts)
	b := q.builder(http.MethodPost)
	if o.Count != "" {
		b.header.Add(headerPrefer, "count="+string(o.Count))
	}
	if o.MissingAsDefault {
		b.header.Add(headerPrefer, "missing=default")
	}
	return b.withRowsBody(values)
}

// Upsert inserts rows, or merges them into existing rows that conflict on
// the primary key (or OnConflict columns). The values are JSON-encoded
// immediately. Chain Select to return the affected rows. At most one
// UpsertOptions is used (the last).
func (q QueryBuilder) Upsert(values any, opts ...UpsertOptions) FilterBuilder {
	o := lastOpt(opts)
	b := q.builder(http.MethodPost)
	resolution := "merge"
	if o.IgnoreDuplicates {
		resolution = "ignore"
	}
	b.header.Add(headerPrefer, "resolution="+resolution+"-duplicates")
	if o.OnConflict != "" {
		b.query = setParam(b.query, "on_conflict", o.OnConflict)
	}
	if o.Count != "" {
		b.header.Add(headerPrefer, "count="+string(o.Count))
	}
	if o.MissingAsDefault {
		b.header.Add(headerPrefer, "missing=default")
	}
	return b.withRowsBody(values)
}

// Update sets columns on the rows matched by the filters chained after it.
// values (a struct or map) is JSON-encoded immediately. Always add a
// filter: without one every row in the table is updated. At most one
// UpdateOptions is used (the last).
func (q QueryBuilder) Update(values any, opts ...UpdateOptions) FilterBuilder {
	o := lastOpt(opts)
	b := q.builder(http.MethodPatch)
	if o.Count != "" {
		b.header.Add(headerPrefer, "count="+string(o.Count))
	}
	body, err := json.Marshal(values)
	if err != nil {
		b.setErr(fmt.Errorf("postgrest: encode update values: %w", err))
		return b
	}
	b.body = body
	return b
}

// Delete deletes the rows matched by the filters chained after it. Always
// add a filter: without one every row in the table is deleted. At most one
// DeleteOptions is used (the last).
func (q QueryBuilder) Delete(opts ...DeleteOptions) FilterBuilder {
	o := lastOpt(opts)
	b := q.builder(http.MethodDelete)
	if o.Count != "" {
		b.header.Add(headerPrefer, "count="+string(o.Count))
	}
	return b
}

// withRowsBody encodes insert/upsert values and, for bulk inserts, sets
// the columns parameter listing every key present in any row.
func (b FilterBuilder) withRowsBody(values any) FilterBuilder {
	body, err := json.Marshal(values)
	if err != nil {
		b.setErr(fmt.Errorf("postgrest: encode rows: %w", err))
		return b
	}
	b.body = body
	if cols := insertColumns(body); cols != "" {
		b.query = setParam(b.query, "columns", cols)
	}
	return b
}

// RPCOptions configures Client.RPC.
type RPCOptions struct {
	// Head sends a HEAD request: the function's result is not returned.
	// Use it with Count. When an argument is an object (or an array of
	// objects) the call falls back to POST with Prefer: return=minimal,
	// because such values cannot be encoded as query parameters.
	Head bool
	// Get calls the function with GET and the arguments as query
	// parameters. Only valid for read-only (STABLE or IMMUTABLE) functions.
	Get bool
	// Count asks PostgREST to count the rows a set-returning function
	// returns.
	Count Count
}

// RPC calls the Postgres function fn with args (a struct or map encoded as
// a JSON object; nil means no arguments). The returned FilterBuilder
// supports filters and modifiers on set-returning functions. At most one
// RPCOptions is used (the last).
func (c *Client) RPC(fn string, args any, opts ...RPCOptions) FilterBuilder {
	o := lastOpt(opts)
	b := FilterBuilder{c: c, path: "/rpc/" + url.PathEscape(fn), header: c.headers.Clone(), isRPC: true}
	if fn == "" {
		b.setErr(errors.New("postgrest: function name is required"))
	}
	body := []byte("{}")
	if args != nil {
		enc, err := json.Marshal(args)
		if err != nil {
			b.setErr(fmt.Errorf("postgrest: encode rpc args: %w", err))
			return b
		}
		if string(enc) != "null" {
			body = enc
		}
	}
	members, isObject := objectMembers(body)

	hasObjectArg := false
	if o.Head && isObject {
		for _, m := range members {
			if isJSONObjectish(m.value) {
				hasObjectArg = true
				break
			}
		}
	}
	switch {
	case hasObjectArg:
		b.method = http.MethodPost
		b.body = body
	case o.Head || o.Get:
		b.method = http.MethodGet
		if o.Head {
			b.method = http.MethodHead
		}
		if !isObject {
			b.setErr(errors.New("postgrest: rpc args must encode to a JSON object for GET/HEAD calls"))
			return b
		}
		for _, m := range members {
			b.query = appendParam(b.query, m.key, rpcQueryValue(m.value))
		}
	default:
		b.method = http.MethodPost
		b.body = body
	}
	switch {
	case hasObjectArg && o.Count != "":
		b.header.Set(headerPrefer, "count="+string(o.Count)+",return=minimal")
	case hasObjectArg:
		b.header.Set(headerPrefer, "return=minimal")
	case o.Count != "":
		b.header.Set(headerPrefer, "count="+string(o.Count))
	}
	return b
}
