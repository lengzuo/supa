package supabase

import (
	"encoding/json"
	"errors"
)

type Exception interface {
	Error() string
	StatusCode() int
}

var ErrEmptyApiKey = errors.New("apiKey is mandatory")

type externalErr struct {
	body       []byte
	statusCode int
}

func External(body []byte, statusCode int) Exception {
	return &externalErr{
		body:       body,
		statusCode: statusCode,
	}
}

func (b externalErr) Error() string {
	return string(b.body)
}

func (b externalErr) StatusCode() int {
	return b.statusCode
}

type PostgresError struct {
	Code           string `json:"code"`
	Details        string `json:"details"`
	Hint           string `json:"hint"`
	HTTPStatusCode int    `json:"-"`
	Message        string `json:"message"`
}

func (rq *PostgresError) Error() string {
	return rq.Code + ": " + rq.Message
}

// errorCode extracts a machine-readable error code from an error response
// body for logging: "error_code" (GoTrue) or "code" (PostgREST, GoTrue,
// Storage). Free-text fields (message, details, hint, msg, error_description)
// are never used since they can echo row data and input values. Anything that
// doesn't look like a short identifier is dropped.
func errorCode(body []byte) string {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return ""
	}
	for _, key := range []string{"error_code", "code"} {
		raw, ok := fields[key]
		if !ok {
			continue
		}
		var code string
		var num json.Number
		if err := json.Unmarshal(raw, &code); err != nil {
			if err := json.Unmarshal(raw, &num); err != nil {
				continue
			}
			code = num.String()
		}
		if isErrorCode(code) {
			return code
		}
	}
	return ""
}

func isErrorCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}
