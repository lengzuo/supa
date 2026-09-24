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
//
// # Token-taking methods
//
// Every method that acts on behalf of a signed-in user takes an
// accessToken argument right after ctx (GetUser, UpdateUser,
// Reauthenticate, SignOut, GetUserIdentities, LinkIdentity,
// LinkIdentityWithIDToken, UnlinkIdentity and the PasskeyAPI calls that
// need a user):
//
//   - accessToken != "": the call is made with that JWT. The stored session
//     is neither read nor modified and no events are emitted. This is the
//     form for servers that handle many users without storing sessions.
//   - accessToken == "": the stored session is used (refreshed first when
//     it is within ExpiryMargin of expiring, see GetSession); results are
//     written back to it and listeners are notified, like supabase-js.
//     ErrSessionMissing is returned when there is no stored session.
//
// GetClaims (jwt) and RefreshSession (refreshToken) follow the same rule,
// and so do ExchangeCodeForSession and GetSessionFromURL through their
// NoStore option.
//
// The MFA and OAuth server APIs, whose methods take parameter structs, use
// a builder instead of an argument: Client.MFA().WithAccessToken(jwt) and
// Client.OAuth().WithAccessToken(jwt) act for that JWT (stateless); without
// it they use the stored session. Admin calls (Client.Admin) always use the
// API key.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	// FlowType defaults to FlowImplicit. With FlowPKCE, flows that end in a
	// redirect (SignUp and SignInWithOTP by email, SignInWithOAuth,
	// SignInWithSSO, ResetPasswordForEmail, Resend, LinkIdentity and email
	// changes via UpdateUser) store a code verifier in Storage and the
	// redirect carries a code for ExchangeCodeForSession.
	FlowType FlowType
	// AutoRefreshToken, when true, makes New start the background refresher
	// (see StartAutoRefresh) for the lifetime of the Client. Call
	// StopAutoRefresh when the Client is no longer needed so the goroutine
	// exits. Servers that create a Client per request should leave this off.
	AutoRefreshToken bool
	// AppendPKCEFlowIDToRedirects, when true, appends the reserved
	// "sb_flow_id" query parameter to redirect URLs of PKCE flows so that
	// ExchangeCodeForSession / GetSessionFromURL can pick the verifier of
	// that exact flow when several flows are pending at once. Mirrors the
	// auth-js experimental.appendPkceFlowIdToRedirects flag.
	AppendPKCEFlowIDToRedirects bool
}

// Client talks to Supabase Auth.
type Client struct {
	t          *transport.Client
	cfg        Config
	storage    SessionStorage
	storageKey string

	// rotateMu is held across every stored-session round trip after which
	// the server rotates the session's refresh token (token refresh, MFA
	// verification), from reading the stored token to committing the
	// result, so two such round trips never use the same refresh token.
	// Lock order: rotateMu -> sessionMu -> evMu. Events are never delivered
	// while rotateMu is held, and nothing that may itself need rotateMu
	// (e.g. GetSession, which can refresh) is called while holding it.
	rotateMu sync.Mutex

	// sessionMu serializes session read-modify-write cycles (refresh,
	// sign-in, sign-out) so concurrent callers do not race.
	sessionMu sync.Mutex

	listenersMu sync.RWMutex
	listeners   map[uint64]func(AuthChangeEvent, *Session)
	nextID      uint64

	// evMu guards evQueue and delivering: session events are queued in
	// commit order (while sessionMu is held) and delivered in that order.
	evMu       sync.Mutex
	evQueue    []queuedEvent
	delivering bool

	// removalEpoch is bumped by removeSession so an in-flight refresh can
	// detect a concurrent sign-out that happened while it saved.
	removalEpoch atomic.Uint64

	// refreshMu guards refreshing and lastRefreshFailure.
	refreshMu          sync.Mutex
	refreshing         map[string]*refreshCall
	lastRefreshFailure *refreshFailure
	// refreshRetryBudget and refreshRetryBase bound the retries of a
	// refresh that failed with a retryable error (replaceable in tests).
	refreshRetryBudget time.Duration
	refreshRetryBase   time.Duration

	// pkceMu serializes read-modify-write cycles of the PKCE flow index.
	pkceMu sync.Mutex

	// autoMu guards the background refresher.
	autoMu     sync.Mutex
	autoCancel context.CancelFunc
	autoDone   chan struct{}
	// tickDuration is the auto-refresh tick (replaceable in tests).
	tickDuration time.Duration

	// customAuth records whether Config.Headers sets Authorization.
	customAuth bool

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
	// Keep a canonicalized copy (not the caller's map) so lookups such as
	// Get("Authorization") also see keys set as e.g. "authorization".
	headers := http.Header{}
	for k, vs := range cfg.Headers {
		for _, v := range vs {
			headers.Add(k, v)
		}
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
	cfg.Headers = headers.Clone()
	c := &Client{
		t:          t,
		cfg:        cfg,
		storage:    cfg.Storage,
		storageKey: cfg.StorageKey,
		listeners:  map[uint64]func(AuthChangeEvent, *Session){},
		now:        time.Now,

		refreshing:         map[string]*refreshCall{},
		refreshRetryBudget: autoRefreshTickDuration,
		refreshRetryBase:   200 * time.Millisecond,
		tickDuration:       autoRefreshTickDuration,
		customAuth:         headers.Get("Authorization") != "",
	}
	if c.storage == nil {
		c.storage = NewMemoryStorage()
	}
	if c.storageKey == "" {
		c.storageKey = defaultStorageKey(t.BaseURL())
	}
	if cfg.AutoRefreshToken {
		c.StartAutoRefresh(context.Background())
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
