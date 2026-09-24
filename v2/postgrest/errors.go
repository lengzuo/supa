package postgrest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Error is returned for every failed PostgREST request: an error response
// from PostgREST or Postgres, a maybeSingle cardinality violation, a
// non-JSON success body, or a network failure (Status 0). Use errors.As to
// inspect it.
//
// Hint is often the most useful field: for permission errors (42501)
// Postgres puts the SQL that fixes the problem there.
type Error struct {
	// Code is the PostgREST (e.g. "PGRST116") or Postgres (e.g. "42501")
	// error code. Empty for network failures.
	Code string
	// Message is the human-readable summary.
	Message string
	// Details carries extra context, often the offending value or row.
	Details string
	// Hint is actionable guidance when available.
	Hint string
	// Status is the HTTP status code, or 0 when no response was received.
	Status int

	cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("postgrest: ")
	b.WriteString(e.Message)
	switch {
	case e.Code != "" && e.Status != 0:
		fmt.Fprintf(&b, " (code %s, status %d)", e.Code, e.Status)
	case e.Code != "":
		fmt.Fprintf(&b, " (code %s)", e.Code)
	case e.Status != 0:
		fmt.Fprintf(&b, " (status %d)", e.Status)
	}
	if e.Details != "" && e.cause == nil {
		b.WriteString(": ")
		b.WriteString(e.Details)
	}
	if e.Hint != "" {
		b.WriteString("; hint: ")
		b.WriteString(e.Hint)
	}
	return b.String()
}

// Unwrap returns the underlying transport error for network failures
// (for example context.Canceled or context.DeadlineExceeded), or nil.
func (e *Error) Unwrap() error { return e.cause }

// errorFromBody builds an Error from a PostgREST error body. ok is false
// when body is not a JSON object.
func errorFromBody(body []byte, status int) (*Error, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return nil, false
	}
	e := &Error{
		Code:    jsonString(raw["code"]),
		Message: jsonString(raw["message"]),
		Details: jsonString(raw["details"]),
		Hint:    jsonString(raw["hint"]),
		Status:  status,
	}
	if e.Message == "" {
		e.Message = string(body)
	}
	return e, true
}

// jsonString renders a JSON value as a string: strings are unquoted, null
// or absent is "", anything else is its JSON text.
func jsonString(v json.RawMessage) string {
	if len(v) == 0 || string(v) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		return s
	}
	return string(v)
}
