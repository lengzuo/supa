package functions

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxErrorBody bounds how much of an error response body is buffered.
const maxErrorBody = 1 << 20

// FetchError reports that the request never produced an HTTP response: a
// network failure, a cancelled or expired context (including
// InvokeOptions.Timeout), or a failure obtaining the access token. It
// corresponds to upstream FunctionsFetchError.
//
// Err is the underlying cause, so errors.Is(err, context.DeadlineExceeded)
// and errors.Is(err, context.Canceled) work through it.
type FetchError struct {
	Err error
}

func (e *FetchError) Error() string {
	return "functions: failed to send a request to the Edge Function: " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *FetchError) Unwrap() error { return e.Err }

// RelayError reports that the Supabase relay failed to invoke the function
// (the response carried "x-relay-error: true"). It corresponds to upstream
// FunctionsRelayError. The response body has already been read and closed.
type RelayError struct {
	// StatusCode is the HTTP status of the relay response.
	StatusCode int
	// Header holds the response headers.
	Header http.Header
	// Body holds up to 1 MiB of the response body.
	Body []byte
}

func (e *RelayError) Error() string {
	return fmt.Sprintf("functions: relay error invoking the Edge Function (status %d)", e.StatusCode)
}

// DecodeJSON unmarshals the error body into v.
func (e *RelayError) DecodeJSON(v any) error { return json.Unmarshal(e.Body, v) }

// HTTPError reports that the Edge Function returned a non-2xx status. It
// corresponds to upstream FunctionsHttpError. The response body has already
// been read and closed.
type HTTPError struct {
	// StatusCode is the HTTP status returned by the function.
	StatusCode int
	// Header holds the response headers.
	Header http.Header
	// Body holds up to 1 MiB of the response body.
	Body []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("functions: Edge Function returned a non-2xx status code (status %d)", e.StatusCode)
}

// DecodeJSON unmarshals the error body into v, e.g. a JSON error payload
// produced by the function.
func (e *HTTPError) DecodeJSON(v any) error { return json.Unmarshal(e.Body, v) }

// readErrorBody drains up to maxErrorBody bytes and closes body.
func readErrorBody(body io.ReadCloser) []byte {
	defer func() { _ = body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(body, maxErrorBody))
	return data
}
