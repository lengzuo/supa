package postgrest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Response is the successful result of a query.
type Response struct {
	// Data is the response body. It is JSON for normal queries, the single
	// row for Single/MaybeSingle, a GeoJSON document for GeoJSON, and raw
	// text (not JSON) for CSV and text Explain output. It is nil when there
	// is no content: HEAD requests, mutations without Select (Prefer:
	// return=minimal), a JSON null body, or MaybeSingle with no match.
	Data json.RawMessage
	// Count is the row count from the Content-Range header when a Count
	// option was requested, otherwise nil.
	Count *int64
	// Status is the HTTP status code (after the same normalizations
	// postgrest-js applies, e.g. an empty 404 becomes 204).
	Status int
	// StatusText is the HTTP reason phrase, e.g. "OK".
	StatusText string
	// Header holds the response headers.
	Header http.Header

	// text reports that Data is raw text rather than JSON.
	text bool
}

var countPreferRe = regexp.MustCompile(`count=(exact|planned|estimated)`)

// Execute runs the query. On success it returns the Response; on failure
// it returns nil and an error, which is an *Error for every failure that
// happens after the query was built (API errors, cardinality errors,
// network failures and context cancellation, which unwraps to ctx.Err()).
//
// Cancel a running query by cancelling ctx (the equivalent of
// postgrest-js abortSignal).
func (b FilterBuilder) Execute(ctx context.Context) (*Response, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.c == nil || b.c.t == nil {
		return nil, errNoClient
	}
	if ctx == nil {
		return nil, errors.New("postgrest: nil context")
	}
	h := b.finalHeader()
	// The query string is built here rather than passed as url.Values,
	// whose Encode sorts keys: parameters are sent in the order the
	// builder added them, like postgrest-js's URLSearchParams.
	path := b.path
	if rq := encodeParams(b.query); rq != "" {
		path += "?" + rq
	}
	req := &transport.Request{Method: b.method, Path: path, Header: h}
	if b.body != nil {
		req.Body = b.body
	}
	retry := !b.c.retry.Disabled
	if b.retry != nil {
		retry = *b.retry
	}
	resp, err := b.c.send(ctx, req, retry)
	if err != nil {
		return nil, b.c.networkError(err, b.c.hintURL(path))
	}
	defer func() { _ = resp.Body.Close() }()
	return b.process(resp, h, path)
}

// encodeParams renders ps as a query string in order. Keys and values are
// escaped with url.QueryEscape, as url.Values.Encode does.
func encodeParams(ps []param) string {
	var sb strings.Builder
	for i, p := range ps {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(url.QueryEscape(p.key))
		sb.WriteByte('=')
		sb.WriteString(url.QueryEscape(p.value))
	}
	return sb.String()
}

// finalHeader applies the request-time header rules of postgrest-js
// PostgrestBuilder.then to a private copy of the builder's headers.
func (b FilterBuilder) finalHeader() http.Header {
	h := b.header.Clone()
	if h == nil {
		h = http.Header{}
	}
	get := b.method == http.MethodGet || b.method == http.MethodHead
	if b.c.schema != "" {
		if get {
			h.Set(headerAcceptProfile, b.c.schema)
		} else {
			h.Set(headerContentProfile, b.c.schema)
		}
	}
	if !get {
		h.Set(transport.HeaderContentType, transport.ContentTypeJSON)
	}
	if b.stripNulls {
		switch accept := h.Get("Accept"); accept {
		case mediaObjectJSON:
			h.Set("Accept", mediaObjectJSON+";nulls=stripped")
		case "", mediaJSON:
			h.Set("Accept", mediaArrayJSON+";nulls=stripped")
		}
	}
	if vs := h.Values(headerPrefer); len(vs) > 1 {
		h.Set(headerPrefer, strings.Join(vs, ", "))
	}
	return h
}

func statusText(resp *http.Response) string {
	if s := strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)+" "); s != "" && s != resp.Status {
		return s
	}
	return http.StatusText(resp.StatusCode)
}

// process converts an HTTP response into a Response or *Error, mirroring
// postgrest-js PostgrestBuilder.processResponse.
func (b FilterBuilder) process(resp *http.Response, h http.Header, path string) (*Response, error) {
	out := &Response{Status: resp.StatusCode, StatusText: statusText(resp), Header: resp.Header}
	accept := h.Get("Accept")

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, b.c.readError(err, resp.StatusCode, path)
		}
		if e, ok := errorFromBody(body, resp.StatusCode); ok {
			return nil, e
		}
		if resp.StatusCode == http.StatusNotFound {
			// Workarounds for https://github.com/supabase/postgrest-js/issues/295.
			if _, isArray := arrayItems(body); isArray {
				out.Data, out.Status, out.StatusText = json.RawMessage("[]"), http.StatusOK, "OK"
				return out, nil
			}
			if len(body) == 0 {
				out.Status, out.StatusText = http.StatusNoContent, "No Content"
				return out, nil
			}
		}
		msg := string(body)
		if msg == "" {
			msg = out.StatusText
		}
		return nil, &Error{Message: msg, Status: resp.StatusCode}
	}

	if b.method != http.MethodHead {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, b.c.readError(err, resp.StatusCode, path)
		}
		switch {
		case len(body) == 0:
			// Prefer: return=minimal.
		case accept == mediaCSV, strings.Contains(accept, mediaPlanPrefix+"text"):
			out.Data, out.text = body, true
		case !json.Valid(body):
			return nil, &Error{Message: string(body), Status: resp.StatusCode}
		case string(bytes.TrimSpace(body)) != "null":
			out.Data = body
		}
	}

	if countPreferRe.MatchString(h.Get(headerPrefer)) {
		if _, total, ok := strings.Cut(resp.Header.Get("Content-Range"), "/"); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(total), 10, 64); err == nil {
				out.Count = &n
			}
		}
	}

	if b.maybeSingle {
		if items, ok := arrayItems(out.Data); ok {
			switch len(items) {
			case 0:
				out.Data = nil
			case 1:
				out.Data = items[0]
				if string(bytes.TrimSpace(out.Data)) == "null" {
					out.Data = nil
				}
			default:
				return nil, &Error{
					Code:    "PGRST116",
					Message: "JSON object requested, multiple (or no) rows returned",
					Details: fmt.Sprintf("Results contain %d rows, application/vnd.pgrst.object+json requires 1 row", len(items)),
					Status:  http.StatusNotAcceptable,
				}
			}
		}
	}
	return out, nil
}

// networkError wraps a transport failure like postgrest-js does for fetch
// rejections, including its hints for aborted requests and long URLs.
func (c *Client) networkError(err error, fullURL string) error {
	var pe *Error
	if errors.As(err, &pe) {
		return err
	}
	e := &Error{Message: err.Error(), cause: err}
	e.Hint = c.abortHint(err, fullURL)
	return e
}

// readError wraps a failure to read a response body. A Config.Timeout or
// context expiring mid-body gets the same hint as an aborted request.
func (c *Client) readError(err error, status int, path string) *Error {
	return &Error{
		Message: "read response: " + err.Error(),
		Status:  status,
		Hint:    c.abortHint(err, c.hintURL(path)),
		cause:   err,
	}
}

// abortHint returns postgrest-js's hint for aborted requests (with its
// URL-length note), or "" when err is not a cancellation or timeout.
func (c *Client) abortHint(err error, fullURL string) string {
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return ""
	}
	hint := "Request was aborted (timeout or manual cancellation)"
	if n := len(fullURL); n > c.urlLimit {
		hint += fmt.Sprintf(". Note: Your request URL is %d characters, which may exceed server limits. "+
			"If selecting many fields, consider using views. If filtering with large arrays "+
			"(e.g., In(\"id\", manyIDs)), consider using an RPC function to pass values server-side.", n)
	}
	return hint
}

// ExecuteInto runs the query and decodes Response.Data into dest, which
// must be a pointer. *[]byte and *json.RawMessage receive the raw data.
// For CSV and text Explain output, a *string receives the text; otherwise
// dest is decoded with encoding/json (so a *string receives a JSON string
// result, e.g. from an RPC returning text). When there is no data (see
// Response.Data), dest is left unchanged.
//
//	var todos []Todo
//	_, err := db.From("todos").Select("*").ExecuteInto(ctx, &todos)
func (b FilterBuilder) ExecuteInto(ctx context.Context, dest any) (*Response, error) {
	resp, err := b.Execute(ctx)
	if err != nil {
		return nil, err
	}
	if err := decodeInto(resp.Data, resp.text, dest); err != nil {
		return resp, err
	}
	return resp, nil
}

func decodeInto(data json.RawMessage, text bool, dest any) error {
	if dest == nil || data == nil {
		return nil
	}
	if d, ok := dest.(*string); ok && text {
		*d = string(data)
		return nil
	}
	switch d := dest.(type) {
	case *[]byte:
		*d = append([]byte(nil), data...)
	case *json.RawMessage:
		*d = append(json.RawMessage(nil), data...)
	default:
		if err := json.Unmarshal(data, dest); err != nil {
			return fmt.Errorf("postgrest: decode response: %w", err)
		}
	}
	return nil
}

// ExecuteTo runs q and decodes its data into a new T. It is the generic
// form of FilterBuilder.ExecuteInto:
//
//	todos, resp, err := postgrest.ExecuteTo[[]Todo](ctx, db.From("todos").Select("*"))
//
// When there is no data (e.g. MaybeSingle without a match) the zero T is
// returned with a nil error; use a pointer type such as *Todo to tell
// "no row" apart from an empty row.
func ExecuteTo[T any](ctx context.Context, q FilterBuilder) (T, *Response, error) {
	var out T
	resp, err := q.ExecuteInto(ctx, &out)
	return out, resp, err
}

// OpenAPISpec is the OpenAPI (Swagger 2.0) document PostgREST generates
// for the exposed schema.
type OpenAPISpec struct {
	Swagger     string                    `json:"swagger"`
	Info        map[string]any            `json:"info"`
	Host        string                    `json:"host,omitempty"`
	BasePath    string                    `json:"basePath,omitempty"`
	Paths       map[string]map[string]any `json:"paths"`
	Definitions map[string]map[string]any `json:"definitions,omitempty"`
	Parameters  map[string]map[string]any `json:"parameters,omitempty"`
	// Raw is the complete document, including fields not modeled above.
	Raw json.RawMessage `json:"-"`
}

// GetOpenAPISpec fetches the OpenAPI description of the client's schema
// (GET <URL>/ with Accept: application/openapi+json). The server must
// have the OpenAPI output enabled for the role in use. When a successful
// response is valid JSON that does not fit the typed fields, the spec is
// still returned with only Raw populated.
func (c *Client) GetOpenAPISpec(ctx context.Context) (*OpenAPISpec, error) {
	if c == nil || c.t == nil {
		return nil, errNoClient
	}
	if ctx == nil {
		return nil, errors.New("postgrest: nil context")
	}
	h := c.headers.Clone()
	h.Set("Accept", mediaOpenAPI)
	if c.schema != "" {
		h.Set(headerAcceptProfile, c.schema)
	}
	req := &transport.Request{Method: http.MethodGet, Path: "/", Header: h}
	resp, err := c.send(ctx, req, !c.retry.Disabled)
	if err != nil {
		return nil, c.networkError(err, c.hintURL("/"))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, c.readError(err, resp.StatusCode, "/")
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 && json.Valid(body) {
		var spec OpenAPISpec
		if json.Unmarshal(body, &spec) != nil {
			// Valid JSON that does not fit the typed fields (e.g. a
			// non-object "info"): return the document in Raw only.
			spec = OpenAPISpec{}
		}
		spec.Raw = body
		return &spec, nil
	}
	if e, ok := errorFromBody(body, resp.StatusCode); ok {
		return nil, e
	}
	msg := string(body)
	if msg == "" {
		msg = statusText(resp)
	}
	return nil, &Error{Message: msg, Status: resp.StatusCode}
}

// hintURL returns the request URL for error hints (e.g. the URL-length
// hint). A malformed query already failed before sending, so an error here
// only yields an empty string.
func (c *Client) hintURL(path string) string {
	u, err := c.t.URL(path, nil)
	if err != nil {
		return ""
	}
	return u
}
