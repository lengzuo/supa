package postgrest

import (
	"bytes"
	"database/sql/driver"
	"encoding"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// maxFormatDepth bounds the recursion of formatValue through pointers,
// interfaces and driver.Valuer results, so a pathological Valuer that
// returns itself cannot recurse forever.
const maxFormatDepth = 32

// formatValue renders a filter value the way postgrest-js stringifies it
// (`${value}`). See formatScalar for the rules.
func formatValue(v any) (string, error) {
	s, _, err := formatScalar(v, 0)
	return s, err
}

// formatScalar renders v as filter text. null reports that v is SQL NULL
// (a nil value, a nil pointer or a driver.Valuer returning nil), which is
// rendered as the bare word null.
//
// The rules, in order:
//
//  1. nil, nil pointers, nil interfaces, nil slices (including a nil
//     json.RawMessage) and nil maps are null.
//  2. json.RawMessage and []byte are used verbatim; time.Time and
//     *time.Time are RFC 3339; time.Duration is an interval literal in
//     microseconds (see formatInterval).
//  3. encoding.TextMarshaler, then driver.Valuer (e.g. sql.NullString,
//     uuid types), use the text or database value they produce.
//  4. Basic kinds use their literal form, even when the type has a
//     String method: a stringer-style int enum is sent as its number,
//     which is what the database column holds.
//  5. A pointer whose String method is on the pointer (*url.URL) uses
//     it, unless it points to a basic kind; other pointers are
//     dereferenced.
//  6. fmt.Stringer is used for the remaining (non-basic) kinds.
//  7. A non-pointer value whose TextMarshaler, Valuer or Stringer has a
//     pointer receiver (url.URL, big.Int) uses it via an addressable
//     copy; a type defined from time.Time is formatted as a time.
//  8. Slices and arrays are comma-joined.
//  9. Anything else (maps, structs) is JSON; JavaScript would print
//     "[object Object]", which is never useful.
func formatScalar(v any, depth int) (s string, null bool, err error) {
	if depth > maxFormatDepth {
		return "", false, fmt.Errorf("postgrest: cannot format filter value of type %T: nested too deeply", v)
	}
	if v == nil {
		return "null", true, nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
		// Nil slices and maps (including a nil json.RawMessage) are NULL
		// too, rather than "" or JSON "null" text.
		if rv.IsNil() {
			return "null", true, nil
		}
	}
	switch x := v.(type) {
	case json.RawMessage:
		return string(x), false, nil
	case []byte:
		return string(x), false, nil
	case time.Time:
		return x.Format(time.RFC3339Nano), false, nil
	case *time.Time:
		return x.Format(time.RFC3339Nano), false, nil
	case time.Duration:
		return formatInterval(x), false, nil
	case *time.Duration:
		return formatInterval(*x), false, nil
	case encoding.TextMarshaler:
		b, err := x.MarshalText()
		if err != nil {
			return "", false, fmt.Errorf("postgrest: cannot format filter value of type %T: %w", v, err)
		}
		return string(b), false, nil
	case driver.Valuer:
		dv, err := x.Value()
		if err != nil {
			return "", false, fmt.Errorf("postgrest: cannot format filter value of type %T: %w", v, err)
		}
		return formatScalar(dv, depth+1)
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10), false, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(rv.Uint(), 10), false, nil
	case reflect.Float32, reflect.Float64:
		return formatFloat(rv.Float(), rv.Type().Bits()), false, nil
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool()), false, nil
	case reflect.String:
		return rv.String(), false, nil
	case reflect.Pointer, reflect.Interface:
		// A pointer-receiver String method (*url.URL, *bytes.Buffer) is
		// lost by dereferencing, so use it here, unless the pointee is a
		// basic kind (a *Status enum is still sent as its number).
		if x, ok := v.(fmt.Stringer); ok && !isBasicKind(rv.Elem().Kind()) {
			return x.String(), false, nil
		}
		return formatScalar(rv.Elem().Interface(), depth+1)
	}
	// A non-pointer value whose TextMarshaler, Valuer or Stringer has a
	// pointer receiver (url.URL, big.Int) would otherwise become JSON:
	// format an addressable copy instead.
	p := reflect.New(rv.Type())
	p.Elem().Set(rv)
	switch p.Interface().(type) {
	case encoding.TextMarshaler, driver.Valuer, fmt.Stringer:
		return formatScalar(p.Interface(), depth+1)
	}
	// A type defined from time.Time (type myTime time.Time) has none of
	// its methods; format it as a time.Time.
	if rv.Kind() == reflect.Struct && rv.Type().ConvertibleTo(timeType) {
		t, _ := rv.Convert(timeType).Interface().(time.Time)
		return t.Format(time.RFC3339Nano), false, nil
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		parts := make([]string, rv.Len())
		for i := range parts {
			s, _, err := formatScalar(rv.Index(i).Interface(), depth+1)
			if err != nil {
				return "", false, err
			}
			parts[i] = s
		}
		return strings.Join(parts, ","), false, nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", false, fmt.Errorf("postgrest: cannot format filter value: %w", err)
		}
		return string(b), false, nil
	}
}

func isBasicKind(k reflect.Kind) bool {
	switch k {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// formatInterval renders d as a Postgres interval literal in microseconds
// (the interval type's resolution), e.g. "1500000 microseconds" for 1.5s.
// Sub-microsecond parts are kept as a fraction, which Postgres rounds.
func formatInterval(d time.Duration) string {
	neg := d < 0
	u := uint64(d)
	if neg {
		u = uint64(-(d + 1)) + 1 // safe for math.MinInt64
	}
	s := strconv.FormatUint(u/1000, 10)
	if frac := u % 1000; frac != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%03d", frac), "0")
	}
	if neg {
		s = "-" + s
	}
	return s + " microseconds"
}

var timeType = reflect.TypeOf(time.Time{})

// formatFloat renders f like JavaScript's Number to string conversion:
// the shortest representation that round-trips, in plain notation for
// magnitudes in [1e-6, 1e21) and exponent notation (1e+300, 1.5e-7)
// otherwise. Non-finite values use the spellings Postgres accepts
// (NaN, Infinity, -Infinity).
func formatFloat(f float64, bits int) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	if a := math.Abs(f); a == 0 || (a >= 1e-6 && a < 1e21) {
		return strconv.FormatFloat(f, 'f', -1, bits)
	}
	s := strconv.FormatFloat(f, 'e', -1, bits)
	// Go pads the exponent to two digits (1e-07); JavaScript does not.
	if i := strings.IndexByte(s, 'e'); i >= 0 {
		mant, exp := s[:i+2], strings.TrimLeft(s[i+2:], "0")
		if exp == "" {
			exp = "0"
		}
		s = mant + exp
	}
	return s
}

// listElements returns the elements of a slice or array value. ok is false
// when v is not a list (json.RawMessage and []byte are not lists).
func listElements(v any) (elems []any, ok bool) {
	switch v.(type) {
	case nil, json.RawMessage, []byte, string:
		return nil, false
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, false
	}
	elems = make([]any, rv.Len())
	for i := range elems {
		elems[i] = rv.Index(i).Interface()
	}
	return elems, true
}

// reservedListChars are the characters that force quoting inside a
// PostgREST list such as in.(...). postgrest-js quotes values containing
// , ( or ); this package also quotes values containing " or \ and escapes
// those two characters, so any value round-trips safely.
const reservedListChars = `,()"\`

// quoteListValue quotes s for use inside in.(...) when needed. The word
// null (any case) is quoted too, so that it is always literal text.
func quoteListValue(s string) string {
	if !strings.ContainsAny(s, reservedListChars) && !strings.EqualFold(s, "null") {
		return s
	}
	return `"` + escapeQuoted(s) + `"`
}

func escapeQuoted(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return r.Replace(s)
}

// formatInList renders values for in.(...) / not.in.(...): duplicates are
// removed (keeping the first occurrence) and every non-NULL value whose
// text contains reserved characters is quoted, whatever its Go type.
func formatInList(values any) (string, error) {
	elems, ok := listElements(values)
	if !ok {
		return "", fmt.Errorf("postgrest: in filter values must be a slice or array, got %T", values)
	}
	seen := make(map[string]bool, len(elems))
	parts := make([]string, 0, len(elems))
	for _, e := range elems {
		s, null, err := formatScalar(e, 0)
		if err != nil {
			return "", err
		}
		if !null {
			s = quoteListValue(s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		parts = append(parts, s)
	}
	return strings.Join(parts, ","), nil
}

// formatArrayLiteral renders elems as a Postgres array literal {a,b}.
// Elements whose text would change the literal's meaning (separators,
// braces, quotes, backslashes, whitespace, empty strings or the word
// NULL) are double-quoted, whatever their Go type; postgrest-js joins
// them verbatim. NULL elements and json.RawMessage elements are written
// as-is.
func formatArrayLiteral(elems []any) (string, error) {
	parts := make([]string, len(elems))
	for i, e := range elems {
		s, null, err := formatScalar(e, 0)
		if err != nil {
			return "", err
		}
		if _, raw := e.(json.RawMessage); !null && !raw && needsArrayQuote(s) {
			s = `"` + escapeQuoted(s) + `"`
		}
		parts[i] = s
	}
	return "{" + strings.Join(parts, ",") + "}", nil
}

func needsArrayQuote(s string) bool {
	if s == "" || strings.EqualFold(s, "null") {
		return true
	}
	for _, r := range s {
		if unicode.IsSpace(r) || strings.ContainsRune(`,{}"\`, r) {
			return true
		}
	}
	return false
}

// rawJSONBody returns a compacted copy of v when it is a []byte or
// json.RawMessage holding JSON text; ok is false for any other type.
// Without this, encoding/json would base64-encode a []byte.
func rawJSONBody(v any) (body []byte, ok bool, err error) {
	var raw []byte
	switch x := v.(type) {
	case json.RawMessage:
		raw = x
	case []byte:
		raw = x
	default:
		return nil, false, nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, true, fmt.Errorf("postgrest: raw JSON body is not valid JSON: %w", err)
	}
	return buf.Bytes(), true, nil
}

// encodeJSONBody JSON-encodes v, passing []byte and json.RawMessage
// through as raw JSON text.
func encodeJSONBody(v any) ([]byte, error) {
	if body, ok, err := rawJSONBody(v); ok {
		return body, err
	}
	return json.Marshal(v)
}

// formatContainment renders the value of cs/cd/ov filters: strings are
// used verbatim, slices become array literals and anything else (maps,
// structs, json.RawMessage) is JSON.
func formatContainment(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	if elems, ok := listElements(v); ok {
		return formatArrayLiteral(elems)
	}
	switch x := v.(type) {
	case json.RawMessage:
		return string(x), nil
	case []byte:
		return string(x), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("postgrest: cannot encode filter value: %w", err)
	}
	return string(b), nil
}

// cleanColumns removes whitespace outside double quotes, like postgrest-js.
func cleanColumns(columns string) string {
	if columns == "" {
		return "*"
	}
	var b strings.Builder
	quoted := false
	for _, r := range columns {
		if unicode.IsSpace(r) && !quoted {
			continue
		}
		if r == '"' {
			quoted = !quoted
		}
		b.WriteRune(r)
	}
	return b.String()
}

// jsonMember is one key of a JSON object in document order.
type jsonMember struct {
	key   string
	value json.RawMessage
}

// objectMembers decodes a JSON object preserving key order. ok is false
// when data is not an object.
func objectMembers(data []byte) (members []jsonMember, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		members = append(members, jsonMember{key: key, value: raw})
	}
	return members, true
}

// arrayItems splits a JSON array into its raw elements. ok is false when
// data is not an array.
func arrayItems(data []byte) (items []json.RawMessage, ok bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, false
	}
	return items, true
}

// insertColumns returns the quoted, de-duplicated column list for a bulk
// insert body, in first-seen order, or "" when body is not an array or
// has no keys. It mirrors postgrest-js's `columns` parameter.
func insertColumns(body []byte) string {
	items, ok := arrayItems(body)
	if !ok {
		return ""
	}
	seen := map[string]bool{}
	var cols []string
	for _, it := range items {
		members, ok := objectMembers(it)
		if !ok {
			continue
		}
		for _, m := range members {
			if !seen[m.key] {
				seen[m.key] = true
				cols = append(cols, `"`+m.key+`"`)
			}
		}
	}
	return strings.Join(cols, ",")
}

// rpcQueryValue renders an RPC argument for GET/HEAD calls: arrays become
// {a,b}, strings are verbatim, null is "null", and other values use their
// JSON text.
func rpcQueryValue(raw json.RawMessage) string {
	var items []json.RawMessage
	if len(raw) > 0 && raw[0] == '[' && json.Unmarshal(raw, &items) == nil {
		parts := make([]any, len(items))
		for i, it := range items {
			var s string
			if string(bytes.TrimSpace(it)) == "null" {
				parts[i] = nil
			} else if json.Unmarshal(it, &s) == nil {
				parts[i] = s
			} else {
				parts[i] = json.RawMessage(it)
			}
		}
		lit, _ := formatArrayLiteral(parts)
		return lit
	}
	if string(bytes.TrimSpace(raw)) == "null" {
		return "null"
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// isJSONObjectish reports whether a raw JSON value is an object, or an
// array containing an object (at any depth), mirroring postgrest-js's
// _isObject check for HEAD RPC calls.
func isJSONObjectish(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return false
	}
	switch t[0] {
	case '{':
		return true
	case '[':
		var items []json.RawMessage
		if json.Unmarshal(t, &items) != nil {
			return false
		}
		for _, it := range items {
			if isJSONObjectish(it) {
				return true
			}
		}
	}
	return false
}
