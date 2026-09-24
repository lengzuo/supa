package postgrest

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// DefaultSchema is the schema used when Config.Schema is empty, matching
// supabase-js (db.schema defaults to "public").
const DefaultSchema = "public"

// DefaultURLLengthLimit is the URL length above which aborted requests get
// an extra hint about long URLs, matching postgrest-js.
const DefaultURLLengthLimit = 8000

// Header names specific to PostgREST.
const (
	headerPrefer         = "Prefer"
	headerAcceptProfile  = "Accept-Profile"
	headerContentProfile = "Content-Profile"
	headerRetryCount     = "X-Retry-Count"
)

// Config configures a Client. URL and APIKey are required.
type Config struct {
	// URL is the PostgREST root, e.g. https://<ref>.supabase.co/rest/v1.
	URL string
	// APIKey is the project's API key. It is sent in the apikey header and,
	// when AccessToken yields no token, as the bearer token.
	APIKey string
	// AccessToken returns the user's JWT per request. Optional. When it is
	// nil or returns "", the API key is used as the bearer.
	AccessToken func(ctx context.Context) (string, error)
	// HTTPClient performs requests. Optional.
	HTTPClient *http.Client
	// Headers are added to every request. A Prefer value here is combined
	// with the Prefer directives each query adds. Optional.
	Headers http.Header
	// RequestEditors run on every outgoing request (e.g. tracing). Optional.
	RequestEditors []func(*http.Request) error
	// Logger receives redacted debug logs. Optional.
	Logger *slog.Logger
	// Schema is the Postgres schema queries run against. Defaults to
	// DefaultSchema ("public"). It is sent as Accept-Profile (GET/HEAD) or
	// Content-Profile (other methods).
	Schema string
	// Timeout bounds each request attempt when > 0, like the postgrest-js
	// timeout option. Zero or negative disables it; the caller's context
	// deadline always applies.
	Timeout time.Duration
	// Retry configures automatic retries. Nil means the upstream default:
	// up to 3 retries of GET/HEAD/OPTIONS requests on network errors and
	// HTTP 503/520, with exponential backoff (1s, 2s, 4s, capped at 30s)
	// honoring Retry-After. See RetryPolicy.
	Retry *RetryPolicy
	// URLLengthLimit is the URL length above which an aborted request's
	// error hint mentions the URL length. Defaults to DefaultURLLengthLimit.
	URLLengthLimit int
}

// RetryPolicy configures automatic retries of idempotent requests. The zero
// value is the upstream default policy.
//
// Only GET, HEAD and OPTIONS requests are ever retried (so inserts,
// updates, deletes and POST RPC calls never are), and only on a network
// error or an HTTP 503 or 520 response. Context cancellation and
// Config.Timeout expiry are never retried. Retried attempts carry an
// X-Retry-Count header.
type RetryPolicy struct {
	// Disabled turns retries off for every request unless a query opts in
	// with FilterBuilder.Retry(true).
	Disabled bool
	// MaxRetries is the number of retries after the first attempt.
	// Values <= 0 mean 3.
	MaxRetries int
	// BaseDelay is the delay before the first retry; it doubles on each
	// following retry. Values <= 0 mean 1s. A Retry-After header (in
	// seconds) takes precedence.
	BaseDelay time.Duration
	// MaxDelay caps the exponential delay. Values <= 0 mean 30s.
	MaxDelay time.Duration
}

func (p RetryPolicy) maxRetries() int {
	if p.MaxRetries <= 0 {
		return 3
	}
	return p.MaxRetries
}

// delay returns the backoff before retry number attempt+1 (attempt is
// zero-based), matching postgrest-js getRetryDelay.
func (p RetryPolicy) delay(attempt int) time.Duration {
	base, maxDelay := p.BaseDelay, p.MaxDelay
	if base <= 0 {
		base = time.Second
	}
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	// base << attempt would overflow for large attempts; compare against
	// maxDelay >> attempt instead (0 once attempt >= 63).
	if attempt < 0 || attempt >= 63 || base > maxDelay>>attempt {
		return maxDelay
	}
	return base << attempt
}

// parseRetryAfter returns the Retry-After delay the way postgrest-js
// computes it: Math.max(0, parseInt(value, 10) || 0) seconds. Only the
// leading integer is used ("1.5" is 1s); anything unparsable is 0, and
// absurdly large values are capped rather than overflowing.
func parseRetryAfter(v string) time.Duration {
	s := strings.TrimLeft(v, " \t\n\r\v\f")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	const maxSecs = int64(math.MaxInt64 / int64(time.Second))
	var secs int64
	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		if secs <= maxSecs {
			secs = secs*10 + int64(s[i]-'0')
		}
	}
	if neg || secs <= 0 {
		return 0
	}
	if secs > maxSecs {
		secs = maxSecs
	}
	return time.Duration(secs) * time.Second
}

// Client queries a PostgREST API. It is immutable and safe for concurrent
// use; Schema returns a derived Client instead of modifying the receiver.
type Client struct {
	t         *transport.Client
	headers   http.Header
	schema    string
	retry     RetryPolicy
	urlLimit  int
	sleepFunc func(ctx context.Context, d time.Duration) error
}

// New returns a Client for cfg.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("postgrest: API key is required")
	}
	editors := make([]transport.RequestEditor, 0, len(cfg.RequestEditors))
	for _, ed := range cfg.RequestEditors {
		editors = append(editors, ed)
	}
	t, err := transport.New(transport.Config{
		BaseURL:          cfg.URL,
		APIKey:           cfg.APIKey,
		HTTPClient:       cfg.HTTPClient,
		Token:            cfg.AccessToken,
		AllowKeyAsBearer: true,
		Editors:          editors,
		Logger:           cfg.Logger,
		Timeout:          cfg.Timeout,
		// Retries are implemented in this package to match postgrest-js
		// exactly (X-Retry-Count, per-query override).
		Retry: nil,
	})
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	for k, vs := range cfg.Headers {
		for _, v := range vs {
			headers.Add(k, v) // canonicalizes the key
		}
	}
	c := &Client{
		t:         t,
		headers:   headers,
		schema:    cfg.Schema,
		urlLimit:  cfg.URLLengthLimit,
		sleepFunc: sleepCtx,
	}
	if c.schema == "" {
		c.schema = DefaultSchema
	}
	if c.urlLimit <= 0 {
		c.urlLimit = DefaultURLLengthLimit
	}
	if cfg.Retry != nil {
		c.retry = *cfg.Retry
	}
	return c, nil
}

// Schema returns a Client that runs queries against schema. The schema
// must be exposed in the project's API settings. The receiver is not
// modified.
func (c *Client) Schema(schema string) *Client {
	cp := *c
	cp.schema = schema
	return &cp
}

// SchemaName returns the schema this client queries.
func (c *Client) SchemaName() string { return c.schema }

// From starts a query on a table or view.
func (c *Client) From(relation string) QueryBuilder {
	if c == nil {
		return QueryBuilder{err: errNoClient}
	}
	q := QueryBuilder{c: c, header: c.headers}
	if strings.TrimSpace(relation) == "" {
		q.err = errors.New("postgrest: invalid relation name: relation must be a non-empty string")
		return q
	}
	q.path = "/" + url.PathEscape(relation)
	return q
}

// send performs req with the client's retry policy. retryEnabled is the
// effective per-request setting.
func (c *Client) send(ctx context.Context, req *transport.Request, retryEnabled bool) (*http.Response, error) {
	maxRetries := 0
	if retryEnabled && isIdempotent(req.Method) {
		maxRetries = c.retry.maxRetries()
	}
	req.NoRetry = true
	for attempt := 0; ; attempt++ {
		r := *req
		if attempt > 0 {
			r.Header = req.Header.Clone()
			r.Header.Set(headerRetryCount, strconv.Itoa(attempt))
		}
		resp, err := c.t.Do(ctx, &r)
		var wait time.Duration
		if err != nil {
			if attempt >= maxRetries || ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || transport.IsPreSend(err) {
				return nil, err
			}
			wait = c.retry.delay(attempt)
		} else {
			if attempt >= maxRetries || !isRetryableStatus(resp.StatusCode) {
				return resp, nil
			}
			if ra, ok := resp.Header["Retry-After"]; ok && len(ra) > 0 {
				wait = parseRetryAfter(ra[0])
			} else {
				wait = c.retry.delay(attempt)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
		}
		if err := c.sleepFunc(ctx, wait); err != nil {
			return nil, err
		}
	}
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func isRetryableStatus(code int) bool {
	return code == 520 || code == http.StatusServiceUnavailable
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
