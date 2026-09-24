package realtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
)

// PostgresChangesFilter selects database changes (upstream
// RealtimePostgresChangesFilter).
type PostgresChangesFilter struct {
	// Event is the change type. Empty means PostgresChangeAll ("*").
	Event PostgresChangeEvent
	// Schema is the database schema, e.g. "public" ("*" for all).
	Schema string
	// Table restricts changes to one table. Optional.
	Table string
	// Filter is a `column=operator.value` expression; several conditions
	// can be joined with commas (AND). Build it with NewPostgresFilter to
	// get PostgREST-style quoting. Optional.
	Filter string
	// Select restricts the payload to these columns. Optional.
	Select []string
}

// PostgresChangesPayload is delivered to OnPostgresChanges callbacks
// (upstream RealtimePostgresChangesPayload). Column values are converted
// from their Postgres text form like realtime-js does: bool -> bool,
// numeric types -> json.Number, json/jsonb -> decoded JSON, arrays ->
// []any, timestamp -> ISO 8601 string.
type PostgresChangesPayload struct {
	Schema          string              `json:"schema"`
	Table           string              `json:"table"`
	CommitTimestamp string              `json:"commit_timestamp"`
	EventType       PostgresChangeEvent `json:"eventType"`
	// New is the new row for INSERT and UPDATE; empty otherwise.
	New map[string]any `json:"new"`
	// Old is the old row (primary key only unless REPLICA IDENTITY FULL)
	// for UPDATE and DELETE; empty otherwise.
	Old    map[string]any `json:"old"`
	Errors []string       `json:"errors"`
	// Raw is the change data as sent by the server.
	Raw json.RawMessage `json:"-"`
}

// DecodeNew unmarshals the new record into v.
func (p PostgresChangesPayload) DecodeNew(v any) error { return remarshal(p.New, v) }

// DecodeOld unmarshals the old record into v.
func (p PostgresChangesPayload) DecodeOld(v any) error { return remarshal(p.Old, v) }

func remarshal(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

type pgColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// transformPostgresPayload mirrors RealtimeChannel._updateFilterTransform.
func transformPostgresPayload(data json.RawMessage) PostgresChangesPayload {
	var d struct {
		Schema          string          `json:"schema"`
		Table           string          `json:"table"`
		CommitTimestamp string          `json:"commit_timestamp"`
		Type            string          `json:"type"`
		Errors          json.RawMessage `json:"errors"`
		Columns         []pgColumn      `json:"columns"`
		Record          json.RawMessage `json:"record"`
		OldRecord       json.RawMessage `json:"old_record"`
	}
	_ = json.Unmarshal(data, &d)
	p := PostgresChangesPayload{
		Schema:          d.Schema,
		Table:           d.Table,
		CommitTimestamp: d.CommitTimestamp,
		EventType:       PostgresChangeEvent(d.Type),
		New:             map[string]any{},
		Old:             map[string]any{},
		Raw:             data,
	}
	var errs []string
	if json.Unmarshal(d.Errors, &errs) == nil {
		p.Errors = errs
	}
	if d.Type == "INSERT" || d.Type == "UPDATE" {
		p.New = convertChangeData(d.Columns, d.Record)
	}
	if d.Type == "UPDATE" || d.Type == "DELETE" {
		p.Old = convertChangeData(d.Columns, d.OldRecord)
	}
	return p
}

func decodeUseNumber(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

// convertChangeData mirrors lib/transformers.ts convertChangeData.
func convertChangeData(columns []pgColumn, record json.RawMessage) map[string]any {
	out := map[string]any{}
	var rec map[string]any
	if len(record) == 0 || decodeUseNumber(record, &rec) != nil || rec == nil {
		return out
	}
	types := make(map[string]string, len(columns))
	for _, c := range columns {
		if _, ok := types[c.Name]; !ok {
			types[c.Name] = c.Type
		}
	}
	for k, v := range rec {
		if t, ok := types[k]; ok && t != "" {
			out[k] = convertCell(t, v)
		} else {
			out[k] = v
		}
	}
	return out
}

// convertCell mirrors lib/transformers.ts convertCell.
func convertCell(typ string, value any) any {
	if strings.HasPrefix(typ, "_") {
		return toArray(value, typ[1:])
	}
	switch typ {
	case "bool":
		if s, ok := value.(string); ok {
			switch s {
			case "t":
				return true
			case "f":
				return false
			}
		}
		return value
	case "float4", "float8", "int2", "int4", "int8", "numeric", "oid":
		return toNumber(value)
	case "json", "jsonb":
		if s, ok := value.(string); ok {
			var v any
			if decodeUseNumber([]byte(s), &v) == nil {
				return v
			}
		}
		return value
	case "timestamp":
		if s, ok := value.(string); ok {
			return strings.Replace(s, " ", "T", 1)
		}
		return value
	default:
		return value
	}
}

func toNumber(value any) any {
	s, ok := value.(string)
	if !ok {
		return value
	}
	if isJSONNumber(s) {
		return json.Number(s)
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return value
	}
	return json.Number(strconv.FormatFloat(f, 'g', -1, 64))
}

func isJSONNumber(s string) bool {
	if s == "" {
		return false
	}
	var n json.Number
	return json.Unmarshal([]byte(s), &n) == nil && string(n) == s
}

// toArray mirrors lib/transformers.ts toArray for Postgres array literals.
func toArray(value any, typ string) any {
	s, ok := value.(string)
	if !ok || len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return value
	}
	inner := s[1 : len(s)-1]
	var arr []any
	if err := decodeUseNumber([]byte("["+inner+"]"), &arr); err != nil {
		arr = []any{}
		if inner != "" {
			for _, part := range strings.Split(inner, ",") {
				arr = append(arr, part)
			}
		}
	}
	for i, v := range arr {
		arr[i] = convertCell(typ, v)
	}
	return arr
}

// PostgresFilter builds postgres_changes filter strings (upstream
// RealtimePostgresFilterBuilder). Each method returns a new builder; the
// receiver is never modified, so builders can be shared and reused.
// Values containing reserved characters (, ( ) " \) or surrounding
// whitespace are double-quoted PostgREST-style.
type PostgresFilter struct {
	filters []string
	err     error
}

// NewPostgresFilter returns an empty filter builder (upstream
// postgresChangesFilter()).
func NewPostgresFilter() *PostgresFilter { return &PostgresFilter{} }

func (f *PostgresFilter) add(column, operator string, value any, negate bool) *PostgresFilter {
	out := &PostgresFilter{err: f.err}
	out.filters = append([]string(nil), f.filters...)
	if out.err != nil {
		return out
	}
	expr, err := serializeFilter(operator, value)
	if err != nil {
		out.err = err
		return out
	}
	prefix := ""
	if negate {
		prefix = "not."
	}
	out.filters = append(out.filters, column+"="+prefix+expr)
	return out
}

// Eq matches rows where column equals value (column=eq.value).
func (f *PostgresFilter) Eq(column string, value any) *PostgresFilter {
	return f.add(column, "eq", value, false)
}

// Neq matches rows where column does not equal value.
func (f *PostgresFilter) Neq(column string, value any) *PostgresFilter {
	return f.add(column, "neq", value, false)
}

// Gt matches rows where column is greater than value.
func (f *PostgresFilter) Gt(column string, value any) *PostgresFilter {
	return f.add(column, "gt", value, false)
}

// Gte matches rows where column is greater than or equal to value.
func (f *PostgresFilter) Gte(column string, value any) *PostgresFilter {
	return f.add(column, "gte", value, false)
}

// Lt matches rows where column is less than value.
func (f *PostgresFilter) Lt(column string, value any) *PostgresFilter {
	return f.add(column, "lt", value, false)
}

// Lte matches rows where column is less than or equal to value.
func (f *PostgresFilter) Lte(column string, value any) *PostgresFilter {
	return f.add(column, "lte", value, false)
}

// In matches rows where column is one of values (column=in.(a,b)).
// At least one value is required; duplicates are removed.
func (f *PostgresFilter) In(column string, values ...any) *PostgresFilter {
	if len(values) == 1 {
		// Allow In("id", []int{1, 2}) as well as In("id", 1, 2).
		return f.add(column, "in", toAnySlice(values[0]), false)
	}
	return f.add(column, "in", values, false)
}

// Like matches rows where column matches the case-sensitive pattern.
func (f *PostgresFilter) Like(column, pattern string) *PostgresFilter {
	return f.add(column, "like", pattern, false)
}

// ILike matches rows where column matches the case-insensitive pattern.
func (f *PostgresFilter) ILike(column, pattern string) *PostgresFilter {
	return f.add(column, "ilike", pattern, false)
}

// Match matches rows where column matches the POSIX regex pattern.
func (f *PostgresFilter) Match(column, pattern string) *PostgresFilter {
	return f.add(column, "match", pattern, false)
}

// IMatch matches rows where column matches the case-insensitive POSIX
// regex pattern.
func (f *PostgresFilter) IMatch(column, pattern string) *PostgresFilter {
	return f.add(column, "imatch", pattern, false)
}

// Is matches rows where column IS value: nil, a bool, or one of "null",
// "true", "false", "unknown".
func (f *PostgresFilter) Is(column string, value any) *PostgresFilter {
	return f.add(column, "is", value, false)
}

// IsDistinct matches rows where column IS DISTINCT FROM value.
func (f *PostgresFilter) IsDistinct(column string, value any) *PostgresFilter {
	return f.add(column, "isdistinct", value, false)
}

// Not negates operator (column=not.operator.value). For "in" pass a
// slice as value.
func (f *PostgresFilter) Not(column, operator string, value any) *PostgresFilter {
	if operator == "in" {
		value = toAnySlice(value)
	}
	return f.add(column, operator, value, true)
}

// Build returns the comma-separated (AND) filter string, or the first
// error recorded by a builder method.
func (f *PostgresFilter) Build() (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return strings.Join(f.filters, ","), nil
}

// String returns the filter string, or "" if the builder has an error.
func (f *PostgresFilter) String() string {
	s, _ := f.Build()
	return s
}

var validFilterOperators = map[string]bool{
	"eq": true, "neq": true, "lt": true, "lte": true, "gt": true, "gte": true, "in": true,
	"like": true, "ilike": true, "is": true, "match": true, "imatch": true, "isdistinct": true,
}

func serializeFilter(operator string, value any) (string, error) {
	if !validFilterOperators[operator] {
		return "", fmt.Errorf("realtime: unsupported postgres_changes filter operator %q", operator)
	}
	switch operator {
	case "in":
		values := toAnySlice(value)
		if len(values) == 0 {
			return "", errors.New("realtime: `in` filter requires at least one value")
		}
		seen := map[string]bool{}
		var items []string
		for _, v := range values {
			key := fmt.Sprintf("%T:%v", v, v)
			if seen[key] {
				continue
			}
			seen[key] = true
			items = append(items, serializeScalar(v))
		}
		return "in.(" + strings.Join(items, ",") + ")", nil
	case "is":
		if value == nil {
			return "is.null", nil
		}
		return "is." + scalarString(value), nil
	default:
		return operator + "." + serializeScalar(value), nil
	}
}

func toAnySlice(value any) []any {
	switch v := value.(type) {
	case nil:
		return nil
	case []any:
		return v
	case string, []byte:
		return []any{v}
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = rv.Index(i).Interface()
		}
		return out
	}
	return []any{value}
}

func serializeScalar(v any) string {
	s := scalarString(v)
	if strings.ContainsAny(s, `,()"\`) || s != strings.TrimSpace(s) {
		return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
	}
	return s
}

// scalarString mirrors JavaScript String(value) for filter values.
func scalarString(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return jsNumber(x)
	case float32:
		return jsNumber(float64(x))
	case json.Number:
		return x.String()
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(x)
	}
}

func jsNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[0]
		exp = strings.TrimLeft(exp[1:], "0")
		return mant + "e" + string(sign) + exp
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}
