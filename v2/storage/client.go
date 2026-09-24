// Package storage is a client for Supabase Storage: file buckets and
// objects, analytics (Apache Iceberg) buckets, and vector buckets.
//
// A *Client is safe for concurrent use.
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Config configures a Client. URL and APIKey are required.
type Config struct {
	// URL is the Storage service root, e.g. https://<ref>.supabase.co/storage/v1.
	URL string
	// APIKey is the project's API key.
	APIKey string
	// AccessToken returns the user's JWT per request. When it is nil or
	// returns "", the API key is used as the bearer (legacy JWT keys only).
	AccessToken func(ctx context.Context) (string, error)
	// HTTPClient performs requests. Optional.
	HTTPClient *http.Client
	// Headers are added to every request. Optional.
	Headers http.Header
	// RequestEditors run on every outgoing request (e.g. tracing). Optional.
	RequestEditors []func(*http.Request) error
	// Logger receives redacted debug logs. Optional.
	Logger *slog.Logger
	// Timeout bounds each request attempt when > 0.
	Timeout time.Duration
	// Retry enables automatic retries of replayable requests. Nil (the
	// default) disables retries. Streamed uploads are never retried.
	Retry *RetryPolicy
	// UseNewHostname rewrites a hosted project URL such as
	// https://<ref>.supabase.co/storage/v1 to the dedicated storage host
	// https://<ref>.storage.supabase.co/storage/v1, which does not buffer
	// requests and so allows uploads larger than 50GB. Other hosts
	// (self-hosted, local) are left unchanged.
	UseNewHostname bool
}

// RetryPolicy controls automatic retries. Only requests whose body can be
// replayed are retried, so streamed uploads are always sent once.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first.
	// Values <= 1 disable retries.
	MaxAttempts int
	// Methods lists the HTTP methods eligible for retry. Empty means GET,
	// HEAD and OPTIONS.
	Methods []string
	// StatusCodes lists response statuses that trigger a retry. Empty
	// means 503 and 520.
	StatusCodes []int
	// RetryNetworkErrors also retries when the request fails without a
	// response. Context cancellation is never retried.
	RetryNetworkErrors bool
	// BaseDelay is the initial backoff; it doubles every attempt (with
	// jitter) up to MaxDelay. Zero defaults to 100ms.
	BaseDelay time.Duration
	// MaxDelay caps the backoff between attempts. Zero defaults to 5s.
	MaxDelay time.Duration
}

func (p *RetryPolicy) toTransport() *transport.RetryPolicy {
	if p == nil {
		return nil
	}
	return &transport.RetryPolicy{
		MaxAttempts:        p.MaxAttempts,
		Methods:            append([]string(nil), p.Methods...),
		StatusCodes:        append([]int(nil), p.StatusCodes...),
		RetryNetworkErrors: p.RetryNetworkErrors,
		BaseDelay:          p.BaseDelay,
		MaxDelay:           p.MaxDelay,
	}
}

// supabaseHost matches hosted Supabase domains that have a dedicated
// storage hostname.
var supabaseHost = regexp.MustCompile(`supabase\.(co|in|red)$`)

// storageURL applies Config.UseNewHostname to rawURL, mirroring the
// storage-js StorageBucketApi constructor.
func storageURL(rawURL string, useNewHostname bool) (string, error) {
	if !useNewHostname {
		return rawURL, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("storage: invalid URL: %w", err)
	}
	host := u.Hostname()
	if supabaseHost.MatchString(host) && !strings.Contains(host, "storage.supabase.") {
		newHost := strings.Replace(host, "supabase.", "storage.supabase.", 1)
		if port := u.Port(); port != "" {
			newHost = net.JoinHostPort(newHost, port)
		}
		u.Host = newHost
	}
	return u.String(), nil
}

// Client talks to Supabase Storage.
type Client struct {
	t   *transport.Client
	cfg Config
}

// New returns a Client for cfg.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("storage: API key is required")
	}
	editors := make([]transport.RequestEditor, 0, len(cfg.RequestEditors))
	for _, ed := range cfg.RequestEditors {
		editors = append(editors, ed)
	}
	baseURL, err := storageURL(cfg.URL, cfg.UseNewHostname)
	if err != nil {
		return nil, err
	}
	t, err := transport.New(transport.Config{
		BaseURL:          baseURL,
		APIKey:           cfg.APIKey,
		HTTPClient:       cfg.HTTPClient,
		Headers:          cfg.Headers,
		Token:            cfg.AccessToken,
		AllowKeyAsBearer: true,
		Editors:          editors,
		Logger:           cfg.Logger,
		Timeout:          cfg.Timeout,
		Retry:            cfg.Retry.toTransport(),
	})
	if err != nil {
		return nil, err
	}
	return &Client{t: t, cfg: cfg}, nil
}

// sub returns a transport rooted at <URL><suffix>, e.g. "/vector".
func (c *Client) sub(suffix string) (*transport.Client, error) {
	base := c.t.BaseURL().String() + suffix
	return c.t.With(func(cfg *transport.Config) { cfg.BaseURL = base })
}

// Error is returned for every failed Storage API call. Use errors.As to
// inspect it.
//
// The field names mirror storage-js StorageApiError: Status is the numeric
// HTTP status of the response, while StatusCode is the string "statusCode"
// reported by the Storage server, which is not always an HTTP status (it
// can be a code such as "NoSuchKey"). Compare Status for HTTP semantics
// and Code (or IsErrorCode) for the Storage error kind.
type Error struct {
	// Message is the human-readable error message.
	Message string
	// Status is the HTTP status code of the response, e.g. 404.
	Status int
	// StatusCode is the string status reported by Storage. Like
	// storage-js it is the body's "statusCode" when non-empty, else its
	// "code", else the HTTP status formatted as a string ("404").
	StatusCode string
	// Code is the service-specific code, e.g. "NoSuchKey",
	// "ResourceAlreadyExists", "AccessDenied". A numeric "code" in the
	// body is formatted as a decimal string.
	Code string
	// Namespace is "storage" or "vectors".
	Namespace string
}

func (e *Error) Error() string {
	ns := e.Namespace
	if ns == "" {
		ns = "storage"
	}
	if e.Code != "" {
		return fmt.Sprintf("%s: %s (status %d, code %s)", ns, e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("%s: %s (status %d)", ns, e.Message, e.Status)
}

// jsTruthyString returns v as a string when it is a JSON value that
// JavaScript treats as truthy and that storage-js would use as a status
// or code (a non-empty string or a non-zero number).
func jsTruthyString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, x != ""
	case float64:
		if x == 0 || math.IsNaN(x) {
			return "", false
		}
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}

// toError converts a transport error into *Error for namespace, mirroring
// storage-js handleError and _getErrorMessage.
func toError(err error, namespace string) error {
	if err == nil {
		return nil
	}
	var he *transport.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	out := &Error{Status: he.StatusCode, StatusCode: strconv.Itoa(he.StatusCode), Namespace: namespace}
	var parsed any
	if json.Unmarshal(he.Body, &parsed) != nil {
		out.Message = http.StatusText(he.StatusCode)
		if out.Message == "" {
			out.Message = fmt.Sprintf("HTTP %d error", he.StatusCode)
		}
		return out
	}
	body, _ := parsed.(map[string]any)
	str := func(k string) string { s, _ := body[k].(string); return s }
	switch {
	case str("msg") != "":
		out.Message = str("msg")
	case str("message") != "":
		out.Message = str("message")
	case str("error_description") != "":
		out.Message = str("error_description")
	case str("error") != "":
		out.Message = str("error")
	default:
		if nested, ok := body["error"].(map[string]any); ok {
			out.Message, _ = nested["message"].(string)
		}
		if out.Message == "" {
			// JSON.stringify(err): arrays, strings, numbers, null and
			// objects without a message are reported as compact JSON.
			var buf bytes.Buffer
			if json.Compact(&buf, he.Body) == nil {
				out.Message = buf.String()
			} else {
				out.Message = string(he.Body)
			}
		}
	}
	code, hasCode := jsTruthyString(body["code"])
	if hasCode {
		out.Code = code
	}
	// storage-js: err.statusCode || err.code || String(status).
	if sc, ok := jsTruthyString(body["statusCode"]); ok {
		out.StatusCode = sc
	} else if hasCode {
		out.StatusCode = code
	}
	return out
}

// request sends req against t and decodes JSON into out.
func request(ctx context.Context, t *transport.Client, req *transport.Request, out any, namespace string) (http.Header, error) {
	h, err := t.DoJSON(ctx, req, out)
	return h, toError(err, namespace)
}
