// Package auth is a client for Supabase Auth (GoTrue).
//
// It covers the user-facing API (sign-up, sign-in, sessions, user
// management, identities, MFA, passkeys, OAuth server), and the admin API
// (via Client.Admin, which requires a service-role or secret key).
//
// A *Client is safe for concurrent use. It optionally keeps a current
// session in a SessionStorage (in-memory by default) so it can be used the
// same way as supabase-js; server applications that handle many users
// usually call the token-taking methods (GetUser, UpdateUser, ...) with the
// caller's JWT instead and never store a session.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// APIVersionHeader is the header GoTrue uses to negotiate its API version.
const APIVersionHeader = "X-Supabase-Api-Version"

// APIVersion is the GoTrue API version this client speaks.
const APIVersion = "2024-01-01"

// FlowType selects the OAuth/magic-link flow.
type FlowType string

const (
	// FlowImplicit returns tokens directly in the redirect URL fragment.
	FlowImplicit FlowType = "implicit"
	// FlowPKCE returns an auth code that must be exchanged with
	// ExchangeCodeForSession, using a verifier kept in SessionStorage.
	FlowPKCE FlowType = "pkce"
)

// Config configures a Client. URL and APIKey are required.
type Config struct {
	// URL is the Auth service root, e.g. https://<ref>.supabase.co/auth/v1.
	URL string
	// APIKey is the project's anon/publishable key, or a service-role/secret
	// key for admin use.
	APIKey string
	// HTTPClient performs requests. Optional.
	HTTPClient *http.Client
	// Headers are added to every request. Optional.
	Headers http.Header
	// RequestEditors run on every outgoing request (e.g. tracing). Optional.
	RequestEditors []func(*http.Request) error
	// Logger receives redacted debug logs. Optional.
	Logger *slog.Logger

	// Storage persists the current session and PKCE verifiers. Defaults to
	// an in-memory store.
	Storage SessionStorage
	// StorageKey is the key under which the session is stored. Defaults to
	// "sb-<project-ref>-auth-token".
	StorageKey string
	// FlowType defaults to FlowImplicit.
	FlowType FlowType
	// AutoRefreshToken, when true, lets StartAutoRefresh keep the stored
	// session fresh in the background.
	AutoRefreshToken bool
}

// Client talks to Supabase Auth.
type Client struct {
	t          *transport.Client
	cfg        Config
	storage    SessionStorage
	storageKey string

	// sessionMu serializes session read-modify-write cycles (refresh,
	// sign-in, sign-out) so concurrent callers do not race.
	sessionMu sync.Mutex

	listenersMu sync.RWMutex
	listeners   map[uint64]func(AuthChangeEvent, *Session)
	nextID      uint64

	// now is replaceable in tests.
	now func() time.Time
}

// New returns a Client for cfg.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("auth: API key is required")
	}
	editors := make([]transport.RequestEditor, 0, len(cfg.RequestEditors))
	for _, ed := range cfg.RequestEditors {
		editors = append(editors, ed)
	}
	headers := cfg.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	if headers.Get(APIVersionHeader) == "" {
		headers.Set(APIVersionHeader, APIVersion)
	}
	t, err := transport.New(transport.Config{
		BaseURL:          cfg.URL,
		APIKey:           cfg.APIKey,
		HTTPClient:       cfg.HTTPClient,
		Headers:          headers,
		AllowKeyAsBearer: true,
		Editors:          editors,
		Logger:           cfg.Logger,
	})
	if err != nil {
		return nil, err
	}
	if cfg.FlowType == "" {
		cfg.FlowType = FlowImplicit
	}
	c := &Client{
		t:          t,
		cfg:        cfg,
		storage:    cfg.Storage,
		storageKey: cfg.StorageKey,
		listeners:  map[uint64]func(AuthChangeEvent, *Session){},
		now:        time.Now,
	}
	if c.storage == nil {
		c.storage = NewMemoryStorage()
	}
	if c.storageKey == "" {
		c.storageKey = defaultStorageKey(t.BaseURL())
	}
	return c, nil
}

func defaultStorageKey(u *url.URL) string {
	ref := strings.Split(u.Hostname(), ".")[0]
	return "sb-" + ref + "-auth-token"
}

// request sends req and decodes the JSON response into out, converting
// HTTP failures into *Error.
func (c *Client) request(ctx context.Context, req *transport.Request, out any) error {
	_, err := c.t.DoJSON(ctx, req, out)
	return toError(err)
}
