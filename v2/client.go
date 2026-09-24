// Package supabase is a Go client for Supabase: Auth, Database (PostgREST),
// Storage, Edge Functions and Realtime, with feature parity with the
// official supabase-js client.
//
//	client, err := supabase.New("https://<ref>.supabase.co", "<publishable-or-anon-key>", nil)
//	if err != nil { ... }
//	var rows []Todo
//	_, err = client.From("todos").Select("*").Eq("done", false).ExecuteInto(ctx, &rows)
//
// Each service is also usable on its own through its package (auth,
// postgrest, storage, functions, realtime).
//
// A *Client is safe for concurrent use. By default the Auth client keeps
// one current session (in memory), like supabase-js in a browser, and the
// other services send that session's access token. Servers that act for
// many users should instead pass each user's JWT explicitly (for example
// auth.Client.GetUser(ctx, jwt) or a postgrest SetHeader("Authorization",
// ...)), or create a client per request with Options.AccessToken.
package supabase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lengzuo/supa/v2/auth"
	"github.com/lengzuo/supa/v2/functions"
	"github.com/lengzuo/supa/v2/internal/transport"
	"github.com/lengzuo/supa/v2/postgrest"
	"github.com/lengzuo/supa/v2/realtime"
	"github.com/lengzuo/supa/v2/storage"
)

// Version is the SDK version.
const Version = transport.Version

// ErrAuthDisabled is returned by Client.AuthClient when Options.AccessToken
// is set (third-party auth); supabase-js throws in the same situation.
var ErrAuthDisabled = errors.New("supabase: Auth is disabled because Options.AccessToken is set")

// Options configures New. The zero value (or nil) is valid.
//
// The per-service configs (Auth, DB, Storage, Functions, Realtime) are
// passed through to the service constructors. New always sets their URL,
// APIKey and (except Auth) AccessToken fields, and fills HTTPClient,
// Headers, RequestEditors and Logger from the global options when they are
// unset; every other field is used as given.
type Options struct {
	// HTTPClient is used by every service (custom_http_client). Use it to
	// add proxies, mTLS or an instrumented transport such as otelhttp.
	HTTPClient *http.Client
	// Headers are sent with every request to every service
	// (global_headers). An Authorization header here overrides the session
	// token for all services, like supabase-js.
	Headers http.Header
	// RequestEditors run on every outgoing HTTP request to Supabase. They
	// are the hook for trace propagation: see PropagateTrace.
	RequestEditors []func(*http.Request) error
	// Logger receives redacted debug logs from every service.
	Logger *slog.Logger

	// AccessToken supplies the access token for every request (third-party
	// auth, e.g. Clerk, Auth0, Firebase, Cognito). When set, the Auth client
	// is disabled (Client.Auth is nil) and the token is also used for
	// Realtime.
	AccessToken func(ctx context.Context) (string, error)

	Auth      auth.Config
	DB        postgrest.Config
	Storage   storage.Config
	Functions functions.Config
	Realtime  realtime.Config
}

// Client is a Supabase project client.
type Client struct {
	// Auth is the Auth client. It is nil when Options.AccessToken is set
	// (third-party auth); use AuthClient to get an error instead of a nil
	// pointer in code that supports both modes.
	Auth *auth.Client
	// Storage is the Storage client.
	Storage *storage.Client
	// Functions is the Edge Functions client.
	Functions *functions.Client
	// Realtime is the Realtime client. It connects lazily on the first
	// channel subscription.
	Realtime *realtime.Client

	rest        *postgrest.Client
	apiKey      string
	accessToken func(ctx context.Context) (string, error)
	unsubscribe func()

	tokenMu   sync.Mutex
	lastToken string
	// syncMu serializes pushes to Realtime so the latest token always wins.
	syncMu      sync.Mutex
	syncWG      sync.WaitGroup
	syncTimeout time.Duration
	closeOnce   sync.Once
	closed      chan struct{}
}

// New returns a client for the project at supabaseURL (for example
// "https://<ref>.supabase.co", or a self-hosted/local URL) using
// supabaseKey (a publishable/anon key, or a secret/service-role key on
// trusted servers only).
func New(supabaseURL, supabaseKey string, opts *Options) (*Client, error) {
	base, err := validateURL(supabaseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(supabaseKey) == "" {
		return nil, errors.New("supabase: supabaseKey is required")
	}
	var o Options
	if opts != nil {
		o = *opts
	}
	endpoint := func(p string) string { return base + "/" + p }

	c := &Client{apiKey: supabaseKey, accessToken: o.AccessToken, closed: make(chan struct{}), syncTimeout: 30 * time.Second}
	if o.Realtime.Timeout > 0 {
		c.syncTimeout = o.Realtime.Timeout
	}

	if o.AccessToken == nil {
		ac := o.Auth
		ac.URL, ac.APIKey = endpoint("auth/v1"), supabaseKey
		ac.HTTPClient = firstClient(ac.HTTPClient, o.HTTPClient)
		ac.Headers = mergeHeaders(o.Headers, ac.Headers)
		ac.RequestEditors = appendEditors(o.RequestEditors, ac.RequestEditors)
		ac.Logger = firstLogger(ac.Logger, o.Logger)
		if c.Auth, err = auth.New(ac); err != nil {
			return nil, fmt.Errorf("supabase: auth: %w", err)
		}
	}

	db := o.DB
	db.URL, db.APIKey, db.AccessToken = endpoint("rest/v1"), supabaseKey, c.sessionToken
	db.HTTPClient = firstClient(db.HTTPClient, o.HTTPClient)
	db.Headers = mergeHeaders(o.Headers, db.Headers)
	db.RequestEditors = appendEditors(o.RequestEditors, db.RequestEditors)
	db.Logger = firstLogger(db.Logger, o.Logger)
	if c.rest, err = postgrest.New(db); err != nil {
		return nil, fmt.Errorf("supabase: database: %w", err)
	}

	sc := o.Storage
	sc.URL, sc.APIKey, sc.AccessToken = endpoint("storage/v1"), supabaseKey, c.sessionToken
	sc.HTTPClient = firstClient(sc.HTTPClient, o.HTTPClient)
	sc.Headers = mergeHeaders(o.Headers, sc.Headers)
	sc.RequestEditors = appendEditors(o.RequestEditors, sc.RequestEditors)
	sc.Logger = firstLogger(sc.Logger, o.Logger)
	if c.Storage, err = storage.New(sc); err != nil {
		return nil, fmt.Errorf("supabase: storage: %w", err)
	}

	fc := o.Functions
	fc.URL, fc.APIKey, fc.AccessToken = endpoint("functions/v1"), supabaseKey, c.sessionToken
	fc.HTTPClient = firstClient(fc.HTTPClient, o.HTTPClient)
	fc.Headers = mergeHeaders(o.Headers, fc.Headers)
	fc.RequestEditors = appendEditors(o.RequestEditors, fc.RequestEditors)
	fc.Logger = firstLogger(fc.Logger, o.Logger)
	if c.Functions, err = functions.New(fc); err != nil {
		return nil, fmt.Errorf("supabase: functions: %w", err)
	}

	rc := o.Realtime
	rc.URL, rc.APIKey, rc.AccessToken = endpoint("realtime/v1"), supabaseKey, c.realtimeToken
	rc.HTTPClient = firstClient(rc.HTTPClient, o.HTTPClient)
	rc.Headers = mergeHeaders(o.Headers, rc.Headers)
	rc.RequestEditors = appendEditors(o.RequestEditors, rc.RequestEditors)
	rc.Logger = firstLogger(rc.Logger, o.Logger)
	if c.Realtime, err = realtime.New(rc); err != nil {
		return nil, fmt.Errorf("supabase: realtime: %w", err)
	}

	if c.Auth != nil {
		// cross_client_token_sync: keep Realtime's token in step with the
		// Auth session, like supabase-js _handleTokenChanged.
		c.unsubscribe = c.Auth.OnAuthStateChange(c.handleAuthChange)
	}
	return c, nil
}

// AuthClient returns the Auth client, or ErrAuthDisabled when the Client
// was created with Options.AccessToken.
func (c *Client) AuthClient() (*auth.Client, error) {
	if c.Auth == nil {
		return nil, ErrAuthDisabled
	}
	return c.Auth, nil
}

// ProjectURL returns the hosted API URL for a project reference.
func ProjectURL(projectRef string) string {
	return "https://" + projectRef + ".supabase.co"
}

// From starts a query on a table or view in the default schema.
func (c *Client) From(relation string) postgrest.QueryBuilder { return c.rest.From(relation) }

// Schema returns a Database client for another exposed schema.
func (c *Client) Schema(schema string) *postgrest.Client { return c.rest.Schema(schema) }

// RPC calls a Postgres function.
func (c *Client) RPC(fn string, args any, opts ...postgrest.RPCOptions) postgrest.FilterBuilder {
	return c.rest.RPC(fn, args, opts...)
}

// DB returns the Database (PostgREST) client.
func (c *Client) DB() *postgrest.Client { return c.rest }

// Channel returns a Realtime channel for topic (created on first use).
func (c *Client) Channel(topic string, opts realtime.ChannelOptions) (*realtime.Channel, error) {
	return c.Realtime.Channel(topic, opts)
}

// GetChannels returns every Realtime channel.
func (c *Client) GetChannels() []*realtime.Channel { return c.Realtime.GetChannels() }

// RemoveChannel unsubscribes and removes a Realtime channel.
func (c *Client) RemoveChannel(ctx context.Context, ch *realtime.Channel) error {
	return c.Realtime.RemoveChannel(ctx, ch)
}

// RemoveAllChannels unsubscribes and removes every Realtime channel.
func (c *Client) RemoveAllChannels(ctx context.Context) error {
	return c.Realtime.RemoveAllChannels(ctx)
}

// Close stops background work: the auth listener and auto-refresh, and the
// Realtime connection. The Client must not be used afterwards.
func (c *Client) Close(ctx context.Context) error {
	c.closeOnce.Do(func() { close(c.closed) })
	if c.unsubscribe != nil {
		c.unsubscribe()
	}
	if c.Auth != nil {
		c.Auth.StopAutoRefresh()
	}
	done := make(chan struct{})
	go func() { c.syncWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return c.Realtime.Disconnect(ctx)
}

// sessionToken returns the user access token for HTTP services: the
// third-party token, else the current Auth session's token, else "" (the
// services then fall back to the API key where upstream does).
func (c *Client) sessionToken(ctx context.Context) (string, error) {
	if c.accessToken != nil {
		return c.accessToken(ctx)
	}
	s, err := c.Auth.GetSession(ctx)
	if err != nil {
		// Fail closed: a session that exists but cannot be loaded or
		// refreshed must never downgrade (or, with a secret key, upgrade)
		// the request to the API key. supabase-js falls back to the key on
		// refresh failures; we return the error instead. Once Auth drops an
		// unrecoverable session, GetSession returns (nil, nil) and requests
		// use the key again.
		return "", fmt.Errorf("supabase: current session: %w", err)
	}
	if s == nil {
		return "", nil
	}
	return s.AccessToken, nil
}

// realtimeToken is Realtime's AccessToken callback: the session token, or
// the API key when there is none (supabase-js _getAccessToken).
func (c *Client) realtimeToken(ctx context.Context) (string, error) {
	t, err := c.sessionToken(ctx)
	if err != nil || t != "" {
		return t, err
	}
	return c.apiKey, nil
}

// handleAuthChange mirrors supabase-js _handleTokenChanged: token-bearing
// events push the new token to Realtime when it changed, and SIGNED_OUT
// always resets Realtime to the API key. MFA_CHALLENGE_VERIFIED (a new aal2
// token) is also synced, which supabase-js does not do.
func (c *Client) handleAuthChange(event auth.AuthChangeEvent, s *auth.Session) {
	var token string
	always := false
	switch event {
	case auth.EventSignedIn, auth.EventTokenRefreshed, auth.EventInitialSession, auth.EventMFAChallengeVerified:
		if s == nil {
			return
		}
		token = s.AccessToken
	case auth.EventSignedOut:
		token, always = "", true
	default:
		return
	}
	c.tokenMu.Lock()
	changed := token != c.lastToken
	c.lastToken = token
	c.tokenMu.Unlock()
	if !changed && !always {
		return
	}
	select {
	case <-c.closed:
		return
	default:
	}
	// Auth callbacks must not block, so propagate asynchronously. Each
	// push sends the latest token under syncMu, so a slow earlier push can
	// never overwrite a newer token. SetAuth("") re-reads the token via the
	// AccessToken callback (the API key after sign-out).
	c.syncWG.Add(1)
	go c.syncRealtimeToken()
}

func (c *Client) syncRealtimeToken() {
	defer c.syncWG.Done()
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	select {
	case <-c.closed:
		return
	default:
	}
	c.tokenMu.Lock()
	token := c.lastToken
	c.tokenMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), c.syncTimeout)
	defer cancel()
	_ = c.Realtime.SetAuth(ctx, token)
}

// PropagateTrace returns a request editor that copies trace context into
// outgoing Supabase requests (trace_propagation). inject is typically
//
//	func(r *http.Request) {
//		otel.GetTextMapPropagator().Inject(r.Context(), propagation.HeaderCarrier(r.Header))
//	}
//
// Like supabase-js, each of traceparent, tracestate and baggage is only
// added when the request does not already carry it, nothing is added
// without a traceparent, and for unsampled traces (trace-flags 00) only
// traceparent is sent. Only Supabase requests are affected.
func PropagateTrace(inject func(r *http.Request)) func(*http.Request) error {
	return func(r *http.Request) error {
		scratch := r.Clone(r.Context())
		scratch.Header = http.Header{}
		inject(scratch)
		tp := scratch.Header.Get("traceparent")
		if tp == "" {
			return nil
		}
		keys := []string{"traceparent", "tracestate", "baggage"}
		if !traceSampled(tp) {
			keys = keys[:1]
		}
		for _, k := range keys {
			if v := scratch.Header.Get(k); v != "" && r.Header.Get(k) == "" {
				r.Header.Set(k, v)
			}
		}
		return nil
	}
}

// traceSampled reports whether a W3C traceparent has the sampled flag set.
// Unparseable values are treated as sampled (propagated as-is).
func traceSampled(tp string) bool {
	parts := strings.Split(tp, "-")
	if len(parts) < 4 || len(parts[3]) != 2 {
		return true
	}
	var flags byte
	if _, err := fmt.Sscanf(parts[3], "%02x", &flags); err != nil {
		return true
	}
	return flags&0x01 == 1
}

func validateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("supabase: supabaseURL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("supabase: invalid supabaseURL %q: must be an absolute http(s) URL", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("supabase: invalid supabaseURL %q: must not have a query or fragment", raw)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

func firstClient(a, b *http.Client) *http.Client {
	if a != nil {
		return a
	}
	return b
}

func firstLogger(a, b *slog.Logger) *slog.Logger {
	if a != nil {
		return a
	}
	return b
}

// mergeHeaders returns global headers overridden by service headers.
func mergeHeaders(global, service http.Header) http.Header {
	if len(global) == 0 {
		return service.Clone()
	}
	out := make(http.Header, len(global)+len(service))
	for k, vs := range global {
		out[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	for k, vs := range service {
		out[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}
	return out
}

func appendEditors(global, service []func(*http.Request) error) []func(*http.Request) error {
	if len(global) == 0 {
		return service
	}
	out := make([]func(*http.Request) error, 0, len(global)+len(service))
	return append(append(out, global...), service...)
}
