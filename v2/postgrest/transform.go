package postgrest

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// Accept media types understood by PostgREST.
const (
	mediaJSON       = "application/json"
	mediaObjectJSON = "application/vnd.pgrst.object+json"
	mediaArrayJSON  = "application/vnd.pgrst.array+json"
	mediaCSV        = "text/csv"
	mediaGeoJSON    = "application/geo+json"
	mediaPlanPrefix = "application/vnd.pgrst.plan+"
	mediaOpenAPI    = "application/openapi+json"
)

// Select sets the columns returned by the query. After Insert, Upsert,
// Update, Delete or RPC it also asks PostgREST to return the affected rows
// (Prefer: return=representation). "" means "*".
func (b FilterBuilder) Select(columns string) FilterBuilder {
	b.query = setParam(b.query, "select", cleanColumns(columns))
	return b.withHeader(func(h http.Header) { h.Add(headerPrefer, "return=representation") })
}

// NullsOrder places NULLs first or last in Order.
type NullsOrder int

const (
	// NullsDefault uses the Postgres default (NULLS LAST for ascending,
	// NULLS FIRST for descending).
	NullsDefault NullsOrder = iota
	// NullsFirst sorts NULLs before non-NULL values.
	NullsFirst
	// NullsLast sorts NULLs after non-NULL values.
	NullsLast
)

// OrderOptions configures Order. The zero value sorts ascending.
type OrderOptions struct {
	// Descending sorts from highest to lowest.
	Descending bool
	// Nulls controls where NULLs are placed.
	Nulls NullsOrder
	// ReferencedTable orders an embedded resource instead of the
	// top-level rows.
	ReferencedTable string
}

// Order sorts the result by column. Calling it again adds a secondary sort
// key. At most one OrderOptions is used (the last).
func (b FilterBuilder) Order(column string, opts ...OrderOptions) FilterBuilder {
	o := lastOpt(opts)
	key := "order"
	if o.ReferencedTable != "" {
		key = o.ReferencedTable + ".order"
	}
	v := column + ".asc"
	if o.Descending {
		v = column + ".desc"
	}
	switch o.Nulls {
	case NullsFirst:
		v += ".nullsfirst"
	case NullsLast:
		v += ".nullslast"
	}
	if existing, ok := getParam(b.query, key); ok && existing != "" {
		v = existing + "," + v
	}
	b.query = setParam(b.query, key, v)
	return b
}

// Limit caps the number of rows returned. At most one TableOptions is used
// (the last).
func (b FilterBuilder) Limit(count int, opts ...TableOptions) FilterBuilder {
	key := "limit"
	if t := lastOpt(opts).ReferencedTable; t != "" {
		key = t + ".limit"
	}
	b.query = setParam(b.query, key, strconv.Itoa(count))
	return b
}

// Range returns only rows from index from to index to, both inclusive and
// zero-based (it sets offset and limit). At most one TableOptions is used
// (the last).
func (b FilterBuilder) Range(from, to int, opts ...TableOptions) FilterBuilder {
	offsetKey, limitKey := "offset", "limit"
	if t := lastOpt(opts).ReferencedTable; t != "" {
		offsetKey, limitKey = t+".offset", t+".limit"
	}
	b.query = setParam(b.query, offsetKey, strconv.Itoa(from))
	b.query = setParam(b.query, limitKey, strconv.Itoa(to-from+1))
	return b
}

// Single returns the result as one object instead of an array. PostgREST
// responds with an error (406, code PGRST116) unless exactly one row
// matches.
func (b FilterBuilder) Single() FilterBuilder {
	return b.withHeader(func(h http.Header) { h.Set("Accept", mediaObjectJSON) })
}

// MaybeSingle returns at most one row as an object: Response.Data is the
// row, or nil when no rows match. More than one row yields an *Error with
// code PGRST116 and status 406, exactly like postgrest-js.
func (b FilterBuilder) MaybeSingle() FilterBuilder {
	b.maybeSingle = true
	return b
}

// CSV returns the result as CSV text in Response.Data.
func (b FilterBuilder) CSV() FilterBuilder {
	return b.withHeader(func(h http.Header) { h.Set("Accept", mediaCSV) })
}

// GeoJSON returns the result as a GeoJSON FeatureCollection. The table
// needs a geometry column (PostGIS).
func (b FilterBuilder) GeoJSON() FilterBuilder {
	return b.withHeader(func(h http.Header) { h.Set("Accept", mediaGeoJSON) })
}

// ExplainFormat is the output format of Explain.
type ExplainFormat string

const (
	// ExplainText returns the plan as text (the default).
	ExplainText ExplainFormat = "text"
	// ExplainJSON returns the plan as JSON.
	ExplainJSON ExplainFormat = "json"
)

// ExplainOptions configures Explain. Each flag maps to the EXPLAIN option
// of the same name.
type ExplainOptions struct {
	Analyze  bool
	Verbose  bool
	Settings bool
	Buffers  bool
	WAL      bool
	// Format defaults to ExplainText.
	Format ExplainFormat
}

// Explain returns the Postgres EXPLAIN plan of the query instead of its
// result. It must be enabled on the server (db-plan-enabled), and should
// not be used in production. Call it after Single, CSV or GeoJSON to
// explain those media types. At most one ExplainOptions is used (the last).
func (b FilterBuilder) Explain(opts ...ExplainOptions) FilterBuilder {
	o := lastOpt(opts)
	format := o.Format
	if format == "" {
		format = ExplainText
	}
	var flags []string
	for _, f := range []struct {
		on   bool
		name string
	}{{o.Analyze, "analyze"}, {o.Verbose, "verbose"}, {o.Settings, "settings"}, {o.Buffers, "buffers"}, {o.WAL, "wal"}} {
		if f.on {
			flags = append(flags, f.name)
		}
	}
	return b.withHeader(func(h http.Header) {
		forMedia := h.Get("Accept")
		if forMedia == "" {
			forMedia = mediaJSON
		}
		h.Set("Accept", mediaPlanPrefix+string(format)+`; for="`+forMedia+`"; options=`+strings.Join(flags, "|")+";")
	})
}

// Rollback runs the query in a transaction that is rolled back (Prefer:
// tx=rollback): a dry run of a mutation. The server must allow it
// (db-tx-end = commit-allow-override).
func (b FilterBuilder) Rollback() FilterBuilder {
	return b.withHeader(func(h http.Header) { h.Add(headerPrefer, "tx=rollback") })
}

// MaxAffected makes an Update, Delete or RPC call fail (and roll back)
// when it would affect more than rows rows (Prefer: handling=strict,
// max-affected=N). Requires PostgREST 13+. Using it on other queries
// returns an error from Execute.
func (b FilterBuilder) MaxAffected(rows int) FilterBuilder {
	if !b.isRPC && b.method != http.MethodPatch && b.method != http.MethodDelete {
		b.setErr(errors.New("postgrest: MaxAffected is only available on update, delete or rpc"))
		return b
	}
	return b.withHeader(func(h http.Header) {
		h.Add(headerPrefer, "handling=strict")
		h.Add(headerPrefer, "max-affected="+strconv.Itoa(rows))
	})
}

// StripNulls asks PostgREST to omit null-valued fields from the returned
// objects. It cannot be combined with CSV.
func (b FilterBuilder) StripNulls() FilterBuilder {
	if b.header.Get("Accept") == mediaCSV {
		b.setErr(errors.New("postgrest: StripNulls cannot be used with CSV"))
		return b
	}
	b.stripNulls = true
	return b
}

// Retry overrides the client's retry setting for this query. Retries only
// ever apply to GET and HEAD requests; see RetryPolicy.
func (b FilterBuilder) Retry(enabled bool) FilterBuilder {
	b.retry = &enabled
	return b
}

// SetHeader sets a request header for this query, replacing any value
// from the client or earlier builder calls. For example, to run a query
// with a specific user's permissions:
//
//	q.SetHeader("Authorization", "Bearer "+userJWT)
func (b FilterBuilder) SetHeader(name, value string) FilterBuilder {
	return b.withHeader(func(h http.Header) { h.Set(name, value) })
}
