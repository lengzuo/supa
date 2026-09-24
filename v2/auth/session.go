package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// GetSession returns the stored session, or (nil, nil) when there is none.
//
// A session whose access token expires within ExpiryMargin is refreshed
// first (emitting TOKEN_REFRESHED). Concurrent callers share one in-flight
// refresh. If the refresh fails but the stored access token is still valid,
// that session is returned. A refresh that fails with a retryable error
// (network, 5xx) never removes the stored session; a definitive failure
// (e.g. revoked refresh token) removes it once its access token has
// actually expired, emitting SIGNED_OUT.
//
// The session comes from storage and is not verified; on a server use
// GetUser or GetClaims to authenticate a request.
func (c *Client) GetSession(ctx context.Context) (*Session, error) {
	// Read the removal epoch before the session: a sign-out that lands
	// after this point discards the refresh result instead of letting it
	// resurrect the session.
	epoch := c.removalEpoch.Load()
	s, err := c.loadSession(ctx)
	if err != nil || s == nil {
		return nil, err
	}
	if !c.expiresWithinMargin(s) {
		return s, nil
	}
	refreshed, rerr := c.callRefreshToken(ctx, s.RefreshToken, epoch, true)
	if rerr == nil {
		return refreshed, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Storage is the source of truth after a failed refresh: a proactive
	// refresh may have failed while the access token is still valid, or a
	// concurrent writer may have committed its own session.
	stored, err := c.loadSession(ctx)
	if err == nil && stored != nil && c.accessTokenValid(stored) {
		return stored, nil
	}
	if err == nil && stored == nil && errors.Is(rerr, ErrRefreshDiscarded) {
		// Signed out while the refresh was in flight: there is no session.
		return nil, nil
	}
	return nil, rerr
}

// expiresWithinMargin reports whether s must be refreshed before use. A
// session without expires_at is treated as not expiring, like auth-js.
func (c *Client) expiresWithinMargin(s *Session) bool {
	if s.ExpiresAt == 0 {
		return false
	}
	return time.Unix(s.ExpiresAt, 0).Sub(c.now()) < ExpiryMargin
}

func (c *Client) accessTokenValid(s *Session) bool {
	return s.ExpiresAt != 0 && time.Unix(s.ExpiresAt, 0).After(c.now())
}

// refreshCall is one in-flight refresh shared by concurrent callers.
type refreshCall struct {
	done    chan struct{}
	session *Session
	err     error
	// next is set when the caller's refresh token was stale (storage
	// already holds a rotated one that must itself be refreshed).
	next string
}

// refreshFailure caches a failed refresh for refreshFailureCooldown.
type refreshFailure struct {
	token string
	err   error
	until time.Time
}

// refreshTimeout bounds a detached refresh (including its retries).
const refreshTimeout = 2 * autoRefreshTickDuration

// maxRefreshHops bounds how often a stale refresh token is swapped for the
// one currently stored before giving up with ErrRefreshDiscarded.
const maxRefreshHops = 3

// callRefreshToken refreshes the session identified by refreshToken and
// commits the result to storage (emitting TOKEN_REFRESHED). Concurrent
// calls for the same token share one request. The request runs detached
// from ctx (bounded by refreshTimeout) so that rotated tokens the server
// already issued are never lost; ctx only bounds how long this caller
// waits. epoch is c.removalEpoch as read by the caller before it read
// refreshToken: if a sign-out happened since, the result is discarded.
//
// fromStorage marks refreshToken as read from storage without a lock, so it
// may be stale: before anything is sent, storage is re-read and, if it now
// holds a different refresh token (someone else already rotated it), the
// stale token is never sent. The stored session is returned as is when it
// is outside the expiry margin, otherwise the stored token is refreshed
// instead. Explicit tokens (fromStorage false) are sent as given.
func (c *Client) callRefreshToken(ctx context.Context, refreshToken string, epoch uint64, fromStorage bool) (*Session, error) {
	for hop := 0; ; hop++ {
		s, next, err := c.callRefreshOnce(ctx, refreshToken, epoch, fromStorage)
		if next == "" {
			return s, err
		}
		if hop >= maxRefreshHops {
			return nil, ErrRefreshDiscarded
		}
		refreshToken = next
	}
}

func (c *Client) callRefreshOnce(ctx context.Context, refreshToken string, epoch uint64, fromStorage bool) (*Session, string, error) {
	if refreshToken == "" {
		return nil, "", ErrSessionMissing
	}
	c.refreshMu.Lock()
	call, inFlight := c.refreshing[refreshToken]
	if !inFlight {
		if f := c.lastRefreshFailure; f != nil && f.token == refreshToken && c.now().Before(f.until) {
			c.refreshMu.Unlock()
			return nil, "", f.err
		}
		call = &refreshCall{done: make(chan struct{})}
		c.refreshing[refreshToken] = call
	}
	c.refreshMu.Unlock()

	if !inFlight {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		go func() {
			defer cancel()
			c.runRefresh(rctx, refreshToken, epoch, fromStorage, call)
		}()
	}
	select {
	case <-call.done:
		return call.session, call.next, call.err
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

// runRefresh performs one shared refresh. The snapshot, the request and
// the commit run under rotateMu, so an MFA verification (which also rotates
// the refresh token server-side) can never interleave with it. When it
// ends, rotateMu is released, the in-flight entry is removed (so a
// listener that refreshes starts a new call instead of joining this one),
// the queued events are delivered (by this goroutine, or by one that is
// already delivering, in commit order; see OnAuthStateChange), and only
// then are the waiting callers released.
func (c *Client) runRefresh(ctx context.Context, refreshToken string, epoch uint64, fromStorage bool, call *refreshCall) {
	defer func() {
		c.refreshMu.Lock()
		delete(c.refreshing, refreshToken)
		c.refreshMu.Unlock()
		c.deliverEvents()
		close(call.done)
	}()
	c.rotateMu.Lock()
	defer c.rotateMu.Unlock() // runs before the delivery above

	// Snapshot storage before the request: the commit guard discards the
	// result if a non-empty snapshot changed under us (a concurrent
	// sign-in or another refresh), or if any sign-out happened since the
	// caller read the session (removal epoch).
	c.sessionMu.Lock()
	snapshot, err := c.loadSession(ctx)
	c.sessionMu.Unlock()
	if err != nil {
		call.err = err
		return
	}
	if fromStorage {
		switch {
		case snapshot == nil:
			// Signed out since the caller read the token.
			call.err = ErrRefreshDiscarded
			return
		case snapshot.RefreshToken != refreshToken:
			// The caller's token is stale: it was already rotated. Never
			// send it (the server would treat it as reuse).
			if !c.expiresWithinMargin(snapshot) {
				call.session = snapshot
				return
			}
			call.next = snapshot.RefreshToken
			return
		}
	}
	resp, err := c.refreshAccessToken(ctx, refreshToken)
	if err != nil {
		c.handleRefreshFailure(ctx, refreshToken, err)
		call.err = err
		return
	}

	// Every session removal holds sessionMu, so checking the epoch and
	// saving under sessionMu is atomic with respect to sign-out.
	c.sessionMu.Lock()
	after, err := c.loadSession(ctx)
	if err != nil {
		c.sessionMu.Unlock()
		call.err = err
		return
	}
	if c.removalEpoch.Load() != epoch ||
		(snapshot != nil && (after == nil || after.RefreshToken != snapshot.RefreshToken)) {
		c.sessionMu.Unlock()
		c.debug(ctx, "refresh discarded: stored session changed while in flight")
		call.err = ErrRefreshDiscarded
		return
	}
	if err := c.saveSession(ctx, resp); err != nil {
		c.sessionMu.Unlock()
		call.err = err
		return
	}
	c.enqueueEvent(EventTokenRefreshed, resp)
	c.sessionMu.Unlock()

	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
	call.session = resp
}

// handleRefreshFailure applies auth-js semantics: retryable failures keep
// the session; a definitive auth failure removes the stored session only if
// it still holds refreshToken and its access token has actually expired
// (checked and removed atomically under sessionMu, so a session committed
// meanwhile survives). The SIGNED_OUT event is queued and delivered by
// runRefresh. Auth failures (*Error) and pre-send failures are cached so
// serial callers within the cooldown do not retry at once; other local
// failures (storage, decoding, timeouts) are not cached.
func (c *Client) handleRefreshFailure(ctx context.Context, refreshToken string, err error) {
	var ae *Error
	isAuth := errors.As(err, &ae)
	if isAuth && !ae.Retryable {
		_, _ = c.removeSessionIf(ctx, func(stored *Session) bool {
			return stored.RefreshToken == refreshToken && !c.accessTokenValid(stored)
		})
	}
	if !isAuth && !transport.IsPreSend(err) {
		return
	}
	c.refreshMu.Lock()
	c.lastRefreshFailure = &refreshFailure{token: refreshToken, err: err, until: c.now().Add(refreshFailureCooldown)}
	c.refreshMu.Unlock()
}

// refreshAccessToken calls POST /token?grant_type=refresh_token, retrying
// retryable failures with exponential backoff (200ms, 400ms, ...) while the
// next attempt still fits in the retry budget (one auto-refresh tick).
func (c *Client) refreshAccessToken(ctx context.Context, refreshToken string) (*Session, error) {
	start := time.Now()
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			t := time.NewTimer(c.refreshRetryBase << (attempt - 1))
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
		}
		var raw json.RawMessage
		err := c.call(ctx, http.MethodPost, "/token", url.Values{"grant_type": {"refresh_token"}}, "",
			map[string]string{"refresh_token": refreshToken}, &raw)
		if err == nil {
			resp, derr := c.decodeSessionResponse(raw)
			if derr != nil {
				return nil, derr
			}
			if resp.Session == nil {
				return nil, ErrSessionMissing
			}
			return resp.Session, nil
		}
		next := c.refreshRetryBase << attempt
		if !isRetryable(err) || ctx.Err() != nil || time.Since(start)+next >= c.refreshRetryBudget {
			return nil, err
		}
		c.debug(ctx, "refresh failed with a retryable error, retrying", "attempt", attempt+1)
	}
}

// RefreshSession exchanges a refresh token for a new session.
//
// With refreshToken == "" the stored session is refreshed (even if it is
// not close to expiry), stored, and TOKEN_REFRESHED is emitted;
// ErrSessionMissing is returned if there is none. With an explicit
// refreshToken the new session is only returned: storage is untouched and
// no event is emitted (use SetSession to adopt it). Refresh tokens are
// single-use: keep the returned RefreshToken.
func (c *Client) RefreshSession(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	if refreshToken != "" {
		s, err := c.refreshAccessToken(ctx, refreshToken)
		if err != nil {
			return nil, err
		}
		return &AuthResponse{User: s.User, Session: s}, nil
	}
	epoch := c.removalEpoch.Load()
	stored, err := c.loadSession(ctx)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrSessionMissing
	}
	s, err := c.callRefreshToken(ctx, stored.RefreshToken, epoch, true)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{User: s.User, Session: s}, nil
}

// SetSession adopts a session from an access and refresh token pair (for
// example tokens handed over from a browser), stores it and emits
// SIGNED_IN. If the access token has expired it is refreshed instead
// (emitting TOKEN_REFRESHED); otherwise it is validated with GetUser.
func (c *Client) SetSession(ctx context.Context, accessToken, refreshToken string) (*AuthResponse, error) {
	if accessToken == "" || refreshToken == "" {
		return nil, ErrSessionMissing
	}
	epoch := c.removalEpoch.Load()
	jwt, err := decodeJWT(accessToken)
	if err != nil {
		return nil, err
	}
	now := c.now().Unix()
	expiresAt, expired := now, true
	if exp := jwt.Claims.ExpiresAt; exp != 0 {
		expiresAt, expired = exp, exp <= now
	}
	if expired {
		s, err := c.callRefreshToken(ctx, refreshToken, epoch, false)
		if err != nil {
			return nil, err
		}
		return &AuthResponse{User: s.User, Session: s}, nil
	}
	user, err := c.fetchUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	s := &Session{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
		ExpiresIn:    expiresAt - now,
		ExpiresAt:    expiresAt,
		User:         user,
	}
	if err := c.commitSession(ctx, s, EventSignedIn); err != nil {
		return nil, err
	}
	return &AuthResponse{User: user, Session: s}, nil
}

// SignOutScope selects which sessions SignOut ends.
type SignOutScope string

const (
	// SignOutGlobal ends every session of the user, on every device. It is
	// the default, as in supabase-js.
	SignOutGlobal SignOutScope = "global"
	// SignOutLocal ends only the current session.
	SignOutLocal SignOutScope = "local"
	// SignOutOthers ends every session except the current one; the stored
	// session is kept and no SIGNED_OUT event is emitted.
	SignOutOthers SignOutScope = "others"
)

// SignOut revokes refresh tokens server-side (POST /logout) for scope
// ("" means SignOutGlobal). Access tokens stay valid until they expire.
//
// With accessToken == "" the stored session is used; unless scope is
// SignOutOthers the stored session and all pending PKCE verifiers are then
// removed and SIGNED_OUT is emitted, even if the server call failed (the
// error is still returned). 401, 403 and 404 responses, which mean the
// session is already gone, are not errors. With an explicit accessToken
// only the server call is made and its error returned as is.
func (c *Client) SignOut(ctx context.Context, accessToken string, scope SignOutScope) error {
	if scope == "" {
		scope = SignOutGlobal
	}
	switch scope {
	case SignOutGlobal, SignOutLocal, SignOutOthers:
	default:
		return fmt.Errorf("%w: sign-out scope must be one of global, local, others", ErrInvalidArgument)
	}
	logout := func(token string) error {
		return c.call(ctx, http.MethodPost, "/logout", url.Values{"scope": {string(scope)}}, token, nil, nil)
	}
	if accessToken != "" {
		return logout(accessToken)
	}

	s, err := c.GetSession(ctx)
	if err != nil && !isSessionMissing(err) {
		return err
	}
	// Clear only the session that was signed out: one committed meanwhile
	// (e.g. a concurrent sign-in) survives. With no stored session the
	// clear is unconditional (it still removes PKCE verifiers and emits
	// SIGNED_OUT, like auth-js).
	clear := func() error {
		if s == nil {
			return c.clearSession(ctx)
		}
		_, err := c.clearSessionIf(ctx, basisOf(s).matches)
		return err
	}
	if s != nil {
		if err := logout(s.AccessToken); err != nil && !ignorableSignOutError(err) {
			if scope != SignOutOthers {
				_ = clear()
			}
			return err
		}
	}
	if scope != SignOutOthers {
		return clear()
	}
	return nil
}

func ignorableSignOutError(err error) bool {
	if isSessionMissing(err) {
		return true
	}
	var e *Error
	if errors.As(err, &e) {
		switch e.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return true
		}
	}
	return false
}

// GetUser fetches the user for accessToken from the server (GET /user),
// which validates the token. Use it (or GetClaims) to authenticate requests
// on a server; never trust GetSession's user for that.
//
// With accessToken == "" the stored session's access token is used (see
// "Token-taking methods" in the package documentation); if the server
// reports that the session no longer exists, the stored session is removed
// and SIGNED_OUT emitted.
func (c *Client) GetUser(ctx context.Context, accessToken string) (*User, error) {
	if accessToken != "" {
		return c.fetchUser(ctx, accessToken)
	}
	s, err := c.GetSession(ctx)
	if err != nil {
		return nil, err
	}
	token := ""
	if s != nil {
		token = s.AccessToken
	} else if !c.hasCustomAuthorization() {
		return nil, ErrSessionMissing
	}
	user, err := c.fetchUser(ctx, token)
	if err != nil && isSessionMissing(err) && token != "" {
		// Remove only the session this token belongs to; one committed
		// meanwhile (e.g. a fresh sign-in) is kept.
		_, _ = c.clearSessionIf(ctx, func(stored *Session) bool { return stored.AccessToken == token })
	}
	return user, err
}

// fetchUser calls GET /user with token.
func (c *Client) fetchUser(ctx context.Context, token string) (*User, error) {
	var raw json.RawMessage
	if err := c.call(ctx, http.MethodGet, "/user", nil, token, nil, &raw); err != nil {
		return nil, err
	}
	return decodeUser(raw)
}

// UpdateUserParams are the attributes UpdateUser changes. Empty fields are
// left unchanged.
type UpdateUserParams struct {
	// Email sets a new email; a confirmation is sent per project settings.
	Email string `json:"email,omitempty"`
	// Phone sets a new phone number.
	Phone string `json:"phone,omitempty"`
	// Password sets a new password.
	Password string `json:"password,omitempty"`
	// CurrentPassword is required by projects that enforce it when
	// changing the password.
	CurrentPassword string `json:"current_password,omitempty"`
	// Nonce is the reauthentication nonce (see Reauthenticate), required
	// for password changes when secure password change is enabled.
	Nonce string `json:"nonce,omitempty"`
	// Data replaces keys of the user's user_metadata.
	Data map[string]any `json:"data,omitempty"`
	// EmailRedirectTo is where the email-change link redirects.
	EmailRedirectTo string `json:"-"`
}

// UpdateUser updates the user identified by accessToken (PUT /user). With
// accessToken == "" the stored session's user is updated, the stored
// session gets the new user and USER_UPDATED is emitted. If the stored
// session was signed out while the request was in flight it is not
// resurrected (no event); if it was refreshed meanwhile, its new tokens are
// kept and only the user is swapped in. With FlowPKCE and an Email change a
// code verifier is stored for the confirmation redirect.
func (c *Client) UpdateUser(ctx context.Context, accessToken string, params UpdateUserParams) (*User, error) {
	token, session, err := c.sessionToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	var flow *pkceFlow
	if params.Email != "" {
		if flow, err = c.maybeStartPKCE(ctx, false); err != nil {
			return nil, err
		}
	}
	challenge, method := flowChallenge(flow)
	body := struct {
		UpdateUserParams
		CodeChallenge       *string `json:"code_challenge"`
		CodeChallengeMethod *string `json:"code_challenge_method"`
	}{params, challenge, method}
	var raw json.RawMessage
	err = c.call(ctx, http.MethodPut, "/user", redirectQuery(c.redirectWithFlowID(params.EmailRedirectTo, flow)), token, body, &raw)
	if err != nil {
		c.removePKCEVerifier(ctx, flowIDOf(flow))
		return nil, err
	}
	user, err := decodeUser(raw)
	if err != nil {
		c.removePKCEVerifier(ctx, flowIDOf(flow))
		return nil, err
	}
	if session != nil {
		// Guarded write-back: the stored session may have been refreshed or
		// signed out while the request was in flight.
		if _, err := c.updateStoredUser(ctx, basisOf(session), user); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// Reauthenticate sends a reauthentication nonce (OTP) to the user's email
// or phone (GET /reauthenticate). Pass the nonce to UpdateUser to change
// the password when secure password change is enabled.
func (c *Client) Reauthenticate(ctx context.Context, accessToken string) error {
	token, _, err := c.sessionToken(ctx, accessToken)
	if err != nil {
		return err
	}
	return c.call(ctx, http.MethodGet, "/reauthenticate", nil, token, nil, nil)
}
