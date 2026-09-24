// Package storage is a client for Supabase Storage: file buckets and
// objects, analytics (Apache Iceberg) buckets, and vector buckets.
//
// A *Client is safe for concurrent use.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	t, err := transport.New(transport.Config{
		BaseURL:          cfg.URL,
		APIKey:           cfg.APIKey,
		HTTPClient:       cfg.HTTPClient,
		Headers:          cfg.Headers,
		Token:            cfg.AccessToken,
		AllowKeyAsBearer: true,
		Editors:          editors,
		Logger:           cfg.Logger,
		Timeout:          cfg.Timeout,
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
type Error struct {
	// Message is the human-readable error message.
	Message string
	// Status is the HTTP status code.
	Status int
	// StatusCode is the Storage "statusCode" field (a string such as
	// "404"), or the HTTP status when absent.
	StatusCode string
	// Code is the service-specific code, e.g. "NoSuchKey",
	// "ResourceAlreadyExists", "AccessDenied".
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

// toError converts a transport error into *Error for namespace.
func toError(err error, namespace string) error {
	if err == nil {
		return nil
	}
	var he *transport.HTTPError
	if !errors.As(err, &he) {
		return err
	}
	out := &Error{Status: he.StatusCode, StatusCode: strconv.Itoa(he.StatusCode), Namespace: namespace}
	var body map[string]any
	if json.Unmarshal(he.Body, &body) != nil || body == nil {
		out.Message = http.StatusText(he.StatusCode)
		if out.Message == "" {
			out.Message = fmt.Sprintf("HTTP %d error", he.StatusCode)
		}
		return out
	}
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
			out.Message = string(he.Body)
		}
	}
	out.Code = str("code")
	switch v := body["statusCode"].(type) {
	case string:
		out.StatusCode = v
	case float64:
		out.StatusCode = strconv.Itoa(int(v))
	default:
		if out.Code != "" {
			out.StatusCode = out.Code
		}
	}
	return out
}

// request sends req against t and decodes JSON into out.
func request(ctx context.Context, t *transport.Client, req *transport.Request, out any, namespace string) (http.Header, error) {
	h, err := t.DoJSON(ctx, req, out)
	return h, toError(err, namespace)
}
