package postgrest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// formatValue renders a filter value the way postgrest-js stringifies it
// (`${value}`): nil is "null", strings are used verbatim, numbers and
// booleans use their literal form, slices are comma-joined. time.Time is
// formatted as RFC 3339, and maps/structs as JSON (JavaScript would print
// "[object Object]", which is never useful).
func formatValue(v any) (string, error) {
	switch x := v.(type) {
	case nil:
		return "null", nil
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case json.Number:
		return x.String(), nil
	case json.RawMessage:
		return string(x), nil
	case []byte:
		return string(x), nil
	case time.Time:
		return x.Format(time.RFC3339Nano), nil
	case float64:
		return formatFloat(x, 64), nil
	case float32:
		return formatFloat(float64(x), 32), nil
	case fmt.Stringer:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Pointer && rv.IsNil() {
			return "null", nil
		}
		return x.String(), nil
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return "null", nil
		}
		return formatValue(rv.Elem().Interface())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(rv.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(rv.Uint(), 10), nil
	case reflect.Float32, reflect.Float64:
		return formatFloat(rv.Float(), 64), nil
	case reflect.Bool:
		return strconv.FormatBool(rv.Bool()), nil
	case reflect.String:
		return rv.String(), nil
	case reflect.Slice, reflect.Array:
		parts := make([]string, rv.Len())
		for i := range parts {
			s, err := formatValue(rv.Index(i).Interface())
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return strings.Join(parts, ","), nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("postgrest: cannot format filter value: %w", err)
		}
		return string(b), nil
	}
}

func formatFloat(f float64, bits int) string {
	return strconv.FormatFloat(f, 'f', -1, bits)
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
// those two characters, so any string round-trips safely.
const reservedListChars = `,()"\`

// quoteListValue quotes s for use inside in.(...) when needed.
func quoteListValue(s string) string {
	if !strings.ContainsAny(s, reservedListChars) {
		return s
	}
	return `"` + escapeQuoted(s) + `"`
}

func escapeQuoted(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return r.Replace(s)
}

// formatInList renders values for in.(...) / not.in.(...): duplicates are
// removed (keeping the first occurrence) and strings containing reserved
// characters are quoted.
func formatInList(values any) (string, error) {
	elems, ok := listElements(values)
	if !ok {
		return "", fmt.Errorf("postgrest: in filter values must be a slice or array, got %T", values)
	}
	seen := make(map[string]bool, len(elems))
	parts := make([]string, 0, len(elems))
	for _, e := range elems {
		s, err := formatValue(e)
		if err != nil {
			return "", err
		}
		if isStringValue(e) {
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

func isStringValue(v any) bool {
	rv := reflect.ValueOf(v)
	for rv.IsValid() && (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface) {
		if rv.IsNil() {
			return false
		}
		rv = rv.Elem()
	}
	return rv.IsValid() && rv.Kind() == reflect.String
}

// formatArrayLiteral renders elems as a Postgres array literal {a,b}.
// Elements that would change the literal's meaning (separators, braces,
// quotes, backslashes, whitespace, empty strings or the word NULL) are
// double-quoted; postgrest-js joins them verbatim.
func formatArrayLiteral(elems []any) (string, error) {
	parts := make([]string, len(elems))
	for i, e := range elems {
		s, err := formatValue(e)
		if err != nil {
			return "", err
		}
		if isStringValue(e) && needsArrayQuote(s) {
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
