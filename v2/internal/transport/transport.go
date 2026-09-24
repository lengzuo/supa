// Package transport is the HTTP core shared by every Supabase service client
// in this module. It owns header composition, authentication, JSON encoding,
// retries, timeouts and redacted debug logging so service packages only
// describe endpoints.
//
// A *Client is immutable after construction and safe for concurrent use.
// Per-request state (headers, query, body) always lives on a fresh
// *http.Request; nothing on the Client is mutated by a call.
package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Version is the SDK version reported in the X-Client-Info header.
const Version = "2.0.0"

// ClientInfo is the default X-Client-Info header value.
const ClientInfo = "supa-go/" + Version

// Header names used across services.
const (
	HeaderAPIKey        = "apikey"
	HeaderAuthorization = "Authorization"
	HeaderClientInfo    = "X-Client-Info"
	HeaderContentType   = "Content-Type"
	HeaderAccept        = "Accept"
	ContentTypeJSON     = "application/json"
)

// TokenFunc returns the bearer token to send for a request. Returning ""
// with a nil error means "no user session"; the client then falls back to
// the API key (unless AllowKeyAsBearer is false).
type TokenFunc func(ctx context.Context) (string, error)

// RequestEditor may modify an outgoing request before it is sent, e.g. to
// inject trace-propagation headers. Returning an error aborts the request.
type RequestEditor func(req *http.Request) error

// RetryPolicy controls automatic retries. Only requests whose body can be
// replayed are retried. A nil policy (or MaxAttempts <= 1) disables retries.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first.
	MaxAttempts int
	// Methods lists the HTTP methods eligible for retry. Empty means
	// GET, HEAD and OPTIONS.
	Methods []string
	// StatusCodes lists response statuses that trigger a retry. Empty means
	// 503 and 520.
	StatusCodes []int
	// RetryNetworkErrors retries when the transport returns an error
	// (excluding context cancellation).
	RetryNetworkErrors bool
	// BaseDelay is the initial backoff; it doubles each attempt with jitter,
	// capped at MaxDelay. Zero values default to 100ms and 5s.
	BaseDelay time.Duration
	MaxDelay  time.Duration
}

// Config configures a Client. Only BaseURL is required.
type Config struct {
	// BaseURL is the service root, e.g. https://<ref>.supabase.co/auth/v1.
	BaseURL string
	// APIKey is sent in the apikey header and, when there is no session
	// token and AllowKeyAsBearer is true, as the bearer token.
	APIKey string
	// HTTPClient performs requests. Defaults to a client with sane timeouts.
	HTTPClient *http.Client
	// Headers are sent on every request. They take precedence over the
	// defaults set by this package, but never over per-request headers.
	Headers http.Header
	// Token supplies the user's access token per request. Optional.
	Token TokenFunc
	// AllowKeyAsBearer allows the API key to be used as the Authorization
	// bearer when Token yields nothing. New-format keys (sb_publishable_,
	// sb_secret_) are never sent as a bearer regardless of this flag when
	// KeyAsBearerLegacyOnly is set.
	AllowKeyAsBearer bool
	// KeyAsBearerLegacyOnly suppresses the bearer fallback for new-format
	// API keys, matching supabase-js behavior for Edge Functions.
	KeyAsBearerLegacyOnly bool
	// Timeout bounds each attempt when > 0 (applied via context).
	Timeout time.Duration
	// Retry enables retries. Nil disables them.
	Retry *RetryPolicy
	// Editors run in order on every outgoing request.
	Editors []RequestEditor
	// Logger receives debug logs. Nil disables logging. Headers and bodies
	// are never logged.
	Logger *slog.Logger
}

// Client sends requests to one Supabase service.
type Client struct {
	base *url.URL
	cfg  Config
}

// DefaultHTTPClient returns the HTTP client used when none is configured.
// It sets no overall request timeout, because that would also bound
// streaming uploads and downloads. Callers bound requests with their
// context or Config.Timeout. Connection setup is bounded by the transport.
func DefaultHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{Transport: tr}
}

// New validates cfg and returns a Client. cfg is copied; later changes to
// the caller's Config or its Headers do not affect the Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("transport: base URL is required")
	}
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("transport: invalid base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("transport: base URL %q must be absolute", cfg.BaseURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("transport: base URL %q must not have a query or fragment", cfg.BaseURL)
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = DefaultHTTPClient()
	}
	cfg.Headers = canonicalHeader(cfg.Headers)
	cfg.Editors = append([]RequestEditor(nil), cfg.Editors...)
	cfg.Retry = cfg.Retry.clone()
	return &Client{base: u, cfg: cfg}, nil
}

// canonicalHeader returns a deep copy of h with canonical keys, so that
// "apikey" and "Apikey" can never both be sent.
func canonicalHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		out[ck] = append(out[ck], vs...)
	}
	return out
}

func (p *RetryPolicy) clone() *RetryPolicy {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Methods = append([]string(nil), p.Methods...)
	cp.StatusCodes = append([]int(nil), p.StatusCodes...)
	return &cp
}

// With returns a copy of c whose Config has been modified by fn. The
// receiver is not changed. Use it to derive clients with a different
// token, schema header or base path.
func (c *Client) With(fn func(cfg *Config)) (*Client, error) {
	cfg := c.Config()
	fn(&cfg)
	return New(cfg)
}

// Config returns a copy of the client's configuration.
func (c *Client) Config() Config {
	cfg := c.cfg
	cfg.Headers = canonicalHeader(cfg.Headers)
	cfg.Editors = append([]RequestEditor(nil), cfg.Editors...)
	cfg.Retry = cfg.Retry.clone()
	cfg.BaseURL = c.base.String()
	return cfg
}

// BaseURL returns a copy of the service root URL.
func (c *Client) BaseURL() *url.URL {
	u := *c.base
	return &u
}

// URL resolves path (which may contain a query) against the base URL.
// Path segments supplied by users must already be escaped by the caller
// (see PathEscape). A query string in path is kept verbatim (order and
// encoding preserved); query values are encoded and appended after it.
// It returns an error if the query in path is malformed, so that a filter
// can never be silently dropped.
func (c *Client) URL(path string, query url.Values) (string, error) {
	u := *c.base
	p, rawQuery, _ := strings.Cut(path, "?")
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	raw := c.base.EscapedPath() + p
	if unescaped, err := url.PathUnescape(raw); err == nil {
		u.Path, u.RawPath = unescaped, raw
	} else {
		u.Path, u.RawPath = raw, ""
	}
	if _, err := url.ParseQuery(rawQuery); err != nil {
		return "", fmt.Errorf("transport: malformed query in path: %w", err)
	}
	if extra := query.Encode(); extra != "" {
		if rawQuery != "" {
			rawQuery += "&"
		}
		rawQuery += extra
	}
	u.RawQuery = rawQuery
	return u.String(), nil
}

// PathEscape escapes each "/"-separated segment of p, keeping the slashes.
// Use it for object paths such as "folder/my file.png".
func PathEscape(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		switch s {
		case ".":
			parts[i] = "%2E"
		case "..":
			parts[i] = "%2E%2E"
		default:
			parts[i] = url.PathEscape(s)
		}
	}
	return strings.Join(parts, "/")
}

// Request describes one API call.
type Request struct {
	Method string
	// Path is relative to the base URL, e.g. "/token". It may include a
	// query string. User-supplied segments must be escaped.
	Path  string
	Query url.Values
	// Header overrides client and default headers for this request only.
	Header http.Header
	// Body is JSON-encoded unless it is nil, an io.Reader, []byte or string,
	// which are sent as-is. Readers are not replayable and disable retries.
	Body any
	// ContentType overrides the Content-Type header. JSON bodies default to
	// application/json.
	ContentType string
	// Token overrides the client's TokenFunc for this request when non-empty.
	Token string
	// NoRetry disables retries for this request.
	NoRetry bool
}

// HTTPError is returned by DoJSON (and DoRaw with CheckStatus) for non-2xx
// responses. Service packages convert it into their own error types.
type HTTPError struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (e *HTTPError) Error() string {
	body := e.Body
	if len(body) > 512 {
		body = body[:512]
		for len(body) > 0 && !utf8.Valid(body) {
			body = body[:len(body)-1]
		}
	}
	return fmt.Sprintf("supabase: HTTP %d: %s", e.StatusCode, strings.TrimSpace(string(body)))
}

// IsNewAPIKey reports whether key is a new-format, non-JWT API key.
func IsNewAPIKey(key string) bool {
	return strings.HasPrefix(key, "sb_publishable_") || strings.HasPrefix(key, "sb_secret_")
}

// Do sends req and returns the raw response. Non-2xx statuses are not
// errors here. The caller must close resp.Body.
func (c *Client) Do(ctx context.Context, req *Request) (*http.Response, error) {
	if ctx == nil {
		return nil, errors.New("transport: nil context")
	}
	if req == nil {
		return nil, errors.New("transport: nil request")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	body, contentType, replayable, err := encodeBody(req)
	if err != nil {
		return nil, err
	}
	fullURL, err := c.URL(req.Path, req.Query)
	if err != nil {
		return nil, err
	}

	policy := c.cfg.Retry
	attempts := 1
	if policy != nil && policy.MaxAttempts > 1 && replayable && !req.NoRetry && methodAllowed(policy, method) {
		attempts = policy.MaxAttempts
	}

	for attempt := 1; ; attempt++ {
		resp, err := c.once(ctx, method, fullURL, req, body, contentType)
		if attempt >= attempts || !shouldRetry(ctx, policy, resp, err) {
			return resp, err
		}
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
		}
		if err := sleep(ctx, backoff(policy, attempt, resp)); err != nil {
			return nil, err
		}
	}
}

func (c *Client) once(ctx context.Context, method, fullURL string, req *Request, body []byte, contentType string) (*http.Response, error) {
	if c.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		// The cancel func is tied to the body so streaming reads keep working.
		defer func() {
			if cancel != nil {
				cancel()
			}
		}()
		resp, err := c.send(ctx, method, fullURL, req, body, contentType)
		if err != nil {
			return nil, err
		}
		resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
		cancel = nil
		return resp, nil
	}
	return c.send(ctx, method, fullURL, req, body, contentType)
}

func (c *Client) send(ctx context.Context, method, fullURL string, req *Request, body []byte, contentType string) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	} else if r, ok := req.Body.(io.Reader); ok {
		rdr = r
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, fmt.Errorf("transport: build request: %w", err)
	}
	h := httpReq.Header
	h.Set(HeaderClientInfo, ClientInfo)
	if c.cfg.APIKey != "" {
		h.Set(HeaderAPIKey, c.cfg.APIKey)
	}
	if contentType != "" {
		h.Set(HeaderContentType, contentType)
	}
	for k, vs := range c.cfg.Headers {
		h[k] = append([]string(nil), vs...)
	}
	for k, vs := range req.Header {
		h[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	// Precedence for Authorization: an explicit per-request Token wins
	// (like auth-js's jwt option), then any Authorization header set on
	// the client or request, then the TokenFunc, then the API key.
	if req.Token != "" {
		h.Set(HeaderAuthorization, "Bearer "+req.Token)
	} else if h.Get(HeaderAuthorization) == "" {
		var token string
		if c.cfg.Token != nil {
			token, err = c.cfg.Token(ctx)
			if err != nil {
				return nil, fmt.Errorf("transport: access token: %w", err)
			}
		}
		if token == "" && c.cfg.AllowKeyAsBearer && c.cfg.APIKey != "" &&
			(!c.cfg.KeyAsBearerLegacyOnly || !IsNewAPIKey(c.cfg.APIKey)) {
			token = c.cfg.APIKey
		}
		if token != "" {
			h.Set(HeaderAuthorization, "Bearer "+token)
		}
	}
	for _, ed := range c.cfg.Editors {
		if err := ed(httpReq); err != nil {
			return nil, err
		}
	}

	start := time.Now()
	resp, err := c.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			ue.URL = redactURL(httpReq.URL)
		}
	}
	if c.cfg.Logger != nil && c.cfg.Logger.Enabled(ctx, slog.LevelDebug) {
		logURL := redactURL(httpReq.URL)
		if err != nil {
			c.cfg.Logger.LogAttrs(ctx, slog.LevelDebug, "supabase request failed",
				slog.String("method", method), slog.String("url", logURL),
				slog.Duration("elapsed", time.Since(start)), slog.String("error", err.Error()))
		} else {
			c.cfg.Logger.LogAttrs(ctx, slog.LevelDebug, "supabase request",
				slog.String("method", method), slog.String("url", logURL),
				slog.Int("status", resp.StatusCode), slog.Duration("elapsed", time.Since(start)))
		}
	}
	return resp, err
}

// DoJSON sends req, returns *HTTPError for non-2xx statuses, and decodes a
// JSON response into out when out is non-nil and the body is non-empty.
// The response headers are returned for callers that need them (e.g.
// Content-Range).
func (c *Client) DoJSON(ctx context.Context, req *Request, out any) (http.Header, error) {
	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.Header, fmt.Errorf("transport: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.Header, &HTTPError{StatusCode: resp.StatusCode, Header: resp.Header, Body: data}
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return resp.Header, nil
	}
	if b, ok := out.(*[]byte); ok {
		*b = data
		return resp.Header, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return resp.Header, fmt.Errorf("transport: decode response: %w", err)
	}
	return resp.Header, nil
}

// CheckResponse returns *HTTPError (consuming and closing the body) when
// resp has a non-2xx status, otherwise nil with the body untouched.
func CheckResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return &HTTPError{StatusCode: resp.StatusCode, Header: resp.Header, Body: data}
}

func encodeBody(req *Request) (body []byte, contentType string, replayable bool, err error) {
	contentType = req.ContentType
	switch b := req.Body.(type) {
	case nil:
		return nil, contentType, true, nil
	case []byte:
		return b, contentType, true, nil
	case string:
		return []byte(b), contentType, true, nil
	case io.Reader:
		return nil, contentType, false, nil
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return nil, "", false, fmt.Errorf("transport: encode request: %w", err)
		}
		if contentType == "" {
			contentType = ContentTypeJSON
		}
		return data, contentType, true, nil
	}
}

func methodAllowed(p *RetryPolicy, method string) bool {
	methods := p.Methods
	if len(methods) == 0 {
		methods = []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	}
	for _, m := range methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

// shouldRetry reports whether another attempt should be made. ctx is the
// caller's context: once it is done nothing is retried, but a per-attempt
// Config.Timeout expiring counts as a retryable network error.
func shouldRetry(ctx context.Context, p *RetryPolicy, resp *http.Response, err error) bool {
	if p == nil || ctx.Err() != nil {
		return false
	}
	if err != nil {
		return p.RetryNetworkErrors && !errors.Is(err, context.Canceled)
	}
	codes := p.StatusCodes
	if len(codes) == 0 {
		codes = []int{http.StatusServiceUnavailable, 520}
	}
	for _, code := range codes {
		if resp.StatusCode == code {
			return true
		}
	}
	return false
}

func backoff(p *RetryPolicy, attempt int, resp *http.Response) time.Duration {
	base, maxDelay := p.BaseDelay, p.MaxDelay
	if base <= 0 {
		base = 100 * time.Millisecond
	}
	if maxDelay <= 0 {
		maxDelay = 5 * time.Second
	}
	if resp != nil {
		if s := resp.Header.Get("Retry-After"); s != "" {
			var d time.Duration
			if secs, err := strconv.Atoi(s); err == nil && secs >= 0 {
				d = time.Duration(secs) * time.Second
			} else if t, err := http.ParseTime(s); err == nil {
				d = time.Until(t)
			}
			if d > 0 {
				return min(d, maxDelay)
			}
		}
	}
	d := base << (attempt - 1)
	if d <= 0 || d > maxDelay {
		d = maxDelay
	}
	// Full jitter in [d/2, d].
	return d/2 + time.Duration(rand.Int64N(int64(d/2)+1))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// sensitiveQueryKeys are redacted from logged URLs.
var sensitiveQueryKeys = map[string]bool{
	"apikey": true, "token": true, "access_token": true, "refresh_token": true,
	"code": true, "code_verifier": true, "token_hash": true, "password": true,
	"jwt": true, "signature": true,
}

func redactURL(u *url.URL) string {
	cp := *u
	q := cp.Query()
	changed := false
	for k := range q {
		if sensitiveQueryKeys[strings.ToLower(k)] {
			q[k] = []string{"REDACTED"}
			changed = true
		}
	}
	if changed {
		cp.RawQuery = q.Encode()
	} else if _, err := url.ParseQuery(cp.RawQuery); err != nil {
		cp.RawQuery = "REDACTED"
	}
	cp.User = nil
	return cp.String()
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}
