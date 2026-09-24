// Package functions is a client for Supabase Edge Functions.
//
// A *Client is safe for concurrent use by multiple goroutines.
//
// Invoke returns the function's response as a stream; the caller must close
// it (Response.Close, or one of the helpers that read it fully). Non-2xx
// responses are returned as *HTTPError, relay failures as *RelayError and
// transport failures as *FetchError; match them with errors.As.
package functions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Header names and content types used by Invoke.
const (
	headerRegion     = "X-Region"
	headerRelayError = "X-Relay-Error"
	queryRegion      = "forceFunctionRegion"

	contentTypeText   = "text/plain"
	contentTypeBinary = "application/octet-stream"
	contentTypeForm   = "application/x-www-form-urlencoded"
)

// Config configures a Client. URL is required.
type Config struct {
	// URL is the Edge Functions root, e.g. https://<ref>.supabase.co/functions/v1.
	URL string
	// APIKey is the project's API key, sent in the apikey header. A legacy
	// JWT key is also used as the bearer token when there is no user token;
	// new-format keys (sb_publishable_…, sb_secret_…) never are.
	APIKey string
	// AccessToken returns the user's JWT per request. Optional. A token set
	// with Client.SetAuth takes precedence over it.
	AccessToken func(ctx context.Context) (string, error)
	// HTTPClient performs requests. Optional. The default client has no
	// overall timeout so streamed responses are not cut off; bound each
	// call with its context or InvokeOptions.Timeout instead.
	HTTPClient *http.Client
	// Headers are added to every request. Optional. Per-call headers
	// (InvokeOptions.Headers) take precedence over them.
	Headers http.Header
	// RequestEditors run on every outgoing request (e.g. tracing). Optional.
	RequestEditors []func(*http.Request) error
	// Logger receives redacted debug logs. Optional.
	Logger *slog.Logger
	// Region is the default region for every invocation. The zero value
	// means RegionAny.
	Region Region
}

// Client invokes Supabase Edge Functions.
type Client struct {
	t      *transport.Client
	region Region
	// clientRegionHeader reports whether Config.Headers sets X-Region.
	clientRegionHeader bool
	// auth holds the token set by SetAuth; nil or "" means unset.
	auth atomic.Pointer[string]
}

// New returns a Client for cfg.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("functions: URL is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		// No Client.Timeout: it would also bound reading streamed bodies.
		httpClient = &http.Client{}
	}
	editors := make([]transport.RequestEditor, 0, len(cfg.RequestEditors))
	for _, ed := range cfg.RequestEditors {
		editors = append(editors, ed)
	}
	t, err := transport.New(transport.Config{
		BaseURL:               cfg.URL,
		APIKey:                cfg.APIKey,
		HTTPClient:            httpClient,
		Headers:               canonicalHeader(cfg.Headers),
		Token:                 cfg.AccessToken,
		AllowKeyAsBearer:      true,
		KeyAsBearerLegacyOnly: true,
		Editors:               editors,
		Logger:                cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("functions: %w", err)
	}
	region := cfg.Region
	if region == "" {
		region = RegionAny
	}
	return &Client{t: t, region: region, clientRegionHeader: cfg.Headers != nil && canonicalHeader(cfg.Headers).Get(headerRegion) != ""}, nil
}

// SetAuth sets the bearer token sent in the Authorization header of every
// subsequent invocation, e.g. a user's access token. It is safe to call
// concurrently with Invoke. Passing "" clears the override.
//
// Authorization precedence, highest first: an Authorization entry in
// InvokeOptions.Headers; the SetAuth token; an Authorization entry in
// Config.Headers; the Config.AccessToken token; the API key (legacy JWT
// keys only).
func (c *Client) SetAuth(token string) {
	if token == "" {
		c.auth.Store(nil)
		return
	}
	c.auth.Store(&token)
}

// InvokeOptions configures one invocation. The zero value sends a POST with
// no body.
type InvokeOptions struct {
	// Headers are sent with this request and override client headers,
	// including Authorization and Content-Type.
	Headers http.Header
	// Method is the HTTP method. Defaults to POST.
	Method string
	// Region overrides Config.Region for this call. RegionAny disables
	// region pinning.
	Region Region
	// Body is the request payload. Unless Headers sets Content-Type, it is
	// sent as follows:
	//   - nil or "": no body
	//   - string: text/plain
	//   - []byte or io.Reader: application/octet-stream (readers are streamed)
	//   - url.Values: application/x-www-form-urlencoded
	//   - anything else: JSON-encoded, application/json
	// For multipart/form-data, pass the encoded body as an io.Reader and set
	// the Content-Type header (with boundary) from mime/multipart.Writer.
	Body any
	// Timeout aborts the invocation after this duration when > 0. It covers
	// reading the response body; the deadline is released when the
	// response is closed.
	Timeout time.Duration
}

// Response is a successful (2xx) function response. Body is streamed and
// must be closed by the caller, either directly or via Bytes, Text or
// DecodeJSON, which read it fully and close it.
type Response struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Header holds the response headers.
	Header http.Header
	// Body streams the response body, e.g. a text/event-stream.
	Body io.ReadCloser
}

// Close closes the response body.
func (r *Response) Close() error { return r.Body.Close() }

// MediaType returns the lower-cased response media type without
// parameters, defaulting to "text/plain" like upstream.
func (r *Response) MediaType() string {
	ct := r.Header.Get(transport.HeaderContentType)
	if ct == "" {
		return contentTypeText
	}
	mt, _, _ := strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(mt))
}

// Bytes reads the whole body and closes it.
func (r *Response) Bytes() ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return data, &FetchError{Err: err}
	}
	return data, nil
}

// Text reads the whole body as a string and closes it.
func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	return string(data), err
}

// DecodeJSON decodes the body as JSON into v and closes the body. An empty
// body leaves v unchanged.
func (r *Response) DecodeJSON(v any) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("functions: decode response: %w", err)
	}
	return nil
}

// Invoke calls the Edge Function name and returns its response stream.
//
// name may contain sub-paths ("fn/users/1") and a query string
// ("fn?page=2"); each path segment is escaped, and "." or ".." segments are
// rejected. opts may be nil.
//
// On success the caller must close the returned Response. On failure the
// Response is nil and the error is *HTTPError, *RelayError or *FetchError,
// or a plain error for invalid arguments.
func (c *Client) Invoke(ctx context.Context, name string, opts *InvokeOptions) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("functions: nil context")
	}
	if opts == nil {
		opts = &InvokeOptions{}
	}
	path, query, err := functionPath(name)
	if err != nil {
		return nil, err
	}

	header := canonicalHeader(opts.Headers)
	if header == nil {
		header = http.Header{}
	}
	if header.Get(transport.HeaderAuthorization) == "" {
		if tok := c.auth.Load(); tok != nil {
			header.Set(transport.HeaderAuthorization, "Bearer "+*tok)
		}
	}

	region := opts.Region
	if region == "" {
		region = c.region
	}
	if region != RegionAny {
		// Client-level X-Region headers win over the default, and per-call
		// headers win over both, matching upstream header priority.
		query.Set(queryRegion, string(region))
		if header.Get(headerRegion) == "" && !c.clientRegionHeader {
			header.Set(headerRegion, string(region))
		}
	}

	body, contentType, err := encodeBody(opts.Body)
	if err != nil {
		return nil, err
	}

	method := strings.ToUpper(strings.TrimSpace(opts.Method))
	if method == "" {
		method = http.MethodPost
	}

	cancel := context.CancelFunc(func() {})
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
	}

	resp, err := c.t.Do(ctx, &transport.Request{
		Method:      method,
		Path:        path,
		Query:       query,
		Header:      header,
		Body:        body,
		ContentType: contentType,
		NoRetry:     true,
	})
	if err != nil {
		cancel()
		return nil, &FetchError{Err: err}
	}

	if strings.EqualFold(resp.Header.Get(headerRelayError), "true") {
		data := readErrorBody(resp.Body)
		cancel()
		return nil, &RelayError{StatusCode: resp.StatusCode, Header: resp.Header, Body: data}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data := readErrorBody(resp.Body)
		cancel()
		return nil, &HTTPError{StatusCode: resp.StatusCode, Header: resp.Header, Body: data}
	}
	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       &cancelOnClose{ReadCloser: resp.Body, cancel: cancel},
	}, nil
}

// InvokeJSON invokes the function name and decodes a JSON response into a
// value of type T. An empty response body yields the zero value.
func InvokeJSON[T any](ctx context.Context, c *Client, name string, opts *InvokeOptions) (T, error) {
	var out T
	resp, err := c.Invoke(ctx, name, opts)
	if err != nil {
		return out, err
	}
	err = resp.DecodeJSON(&out)
	return out, err
}

// functionPath validates name and splits it into an escaped path and query.
func functionPath(name string) (string, url.Values, error) {
	p, rawQuery, _ := strings.Cut(name, "?")
	if strings.TrimSpace(p) == "" {
		return "", nil, errors.New("functions: function name is required")
	}
	if strings.HasPrefix(p, "/") {
		return "", nil, fmt.Errorf("functions: invalid function name %q: must not start with /", name)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", nil, fmt.Errorf("functions: invalid function name %q: dot segments are not allowed", name)
		}
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", nil, fmt.Errorf("functions: invalid query in function name: %w", err)
	}
	return "/" + transport.PathEscape(p), query, nil
}

// encodeBody maps an InvokeOptions.Body to a transport body and its default
// content type, following upstream functions-js rules.
func encodeBody(b any) (any, string, error) {
	switch v := b.(type) {
	case nil:
		return nil, "", nil
	case string:
		if v == "" {
			return nil, "", nil
		}
		return v, contentTypeText, nil
	case []byte:
		return v, contentTypeBinary, nil
	case io.Reader:
		return v, contentTypeBinary, nil
	case url.Values:
		return v.Encode(), contentTypeForm, nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, "", fmt.Errorf("functions: encode body: %w", err)
		}
		return data, transport.ContentTypeJSON, nil
	}
}

// canonicalHeader returns a copy of h with canonical keys so that lookups
// and overrides in the transport behave regardless of caller casing.
func canonicalHeader(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		out[ck] = append(out[ck], vs...)
	}
	return out
}

// cancelOnClose releases a per-call timeout when the body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
