package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
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
	refreshed, rerr := c.callRefreshToken(ctx, s.RefreshToken, epoch)
	if rerr == nil {
		return refreshed, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Storage is the source of truth after a failed refresh: a proactive
	// refresh may have failed while the access token is still valid, or a
	// concurrent writer may have committed its own rotated session.
	stored, err := c.loadSession(ctx)
	if err == nil && stored != nil && c.accessTokenValid(stored) {
		return stored, nil
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
}

// refreshFailure caches a failed refresh for refreshFailureCooldown.
type refreshFailure struct {
	token string
	err   error
	until time.Time
}

// refreshTimeout bounds a detached refresh (including its retries).
const refreshTimeout = 2 * autoRefreshTickDuration

// callRefreshToken refreshes the session identified by refreshToken and
// commits the result to storage (emitting TOKEN_REFRESHED). Concurrent
// calls for the same token share one request. The request runs detached
// from ctx (bounded by refreshTimeout) so that rotated tokens the server
// already issued are never lost; ctx only bounds how long this caller
// waits. epoch is c.removalEpoch as read by the caller before it loaded
// the session: if a sign-out happened since, the result is discarded.
func (c *Client) callRefreshToken(ctx context.Context, refreshToken string, epoch uint64) (*Session, error) {
	if refreshToken == "" {
		return nil, ErrSessionMissing
	}
	c.refreshMu.Lock()
	call, inFlight := c.refreshing[refreshToken]
	if !inFlight {
		if f := c.lastRefreshFailure; f != nil && f.token == refreshToken && c.now().Before(f.until) {
			c.refreshMu.Unlock()
			return nil, f.err
		}
		call = &refreshCall{done: make(chan struct{})}
		c.refreshing[refreshToken] = call
	}
	c.refreshMu.Unlock()

	if !inFlight {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
		go func() {
			defer cancel()
			c.runRefresh(rctx, refreshToken, epoch, call)
		}()
	}
	select {
	case <-call.done:
		return call.session, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// runRefresh performs one shared refresh. call.done is closed before
// listeners are notified, so a listener that itself calls GetSession (or
// anything that refreshes) does not wait on this call.
func (c *Client) runRefresh(ctx context.Context, refreshToken string, epoch uint64, call *refreshCall) {
	var committed *Session
	defer func() {
		if committed != nil {
			c.notify(EventTokenRefreshed, committed)
		}
	}()
	defer func() {
		c.refreshMu.Lock()
		delete(c.refreshing, refreshToken)
		c.refreshMu.Unlock()
		close(call.done)
	}()

	// Snapshot storage before the request: the commit guard discards the
	// result if a non-empty snapshot changed under us (a concurrent
	// sign-in or another refresh), or if any sign-out happened since the
	// caller read the session (removal epoch).
	snapshot, err := c.loadSession(ctx)
	if err != nil {
		call.err = err
		return
	}
	resp, err := c.refreshAccessToken(ctx, refreshToken)
	if err != nil {
		c.handleRefreshFailure(ctx, refreshToken, err)
		call.err = err
		return
	}

	// Every session removal goes through clearSession, which holds
	// sessionMu, so checking the epoch and saving under sessionMu is atomic
	// with respect to sign-out.
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
	err = c.saveSession(ctx, resp)
	c.sessionMu.Unlock()
	if err != nil {
		call.err = err
		return
	}

	c.refreshMu.Lock()
	c.lastRefreshFailure = nil
	c.refreshMu.Unlock()
	call.session = resp
	committed = resp
}

// handleRefreshFailure applies auth-js semantics: retryable failures keep
// the session; definitive failures remove it unless the stored access
// token is still valid (a proactive refresh). Auth failures (*Error) are
// cached so serial callers within the cooldown do not hammer /token;
// local failures (storage, decoding, timeouts) are not cached.
func (c *Client) handleRefreshFailure(ctx context.Context, refreshToken string, err error) {
	var ae *Error
	if !errors.As(err, &ae) {
		return
	}
	if !ae.Retryable {
		stored, lerr := c.loadSession(ctx)
		if lerr == nil && (stored == nil || !c.accessTokenValid(stored)) {
			_ = c.clearSession(ctx)
		}
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
	s, err := c.callRefreshToken(ctx, stored.RefreshToken, epoch)
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
		s, err := c.callRefreshToken(ctx, refreshToken, epoch)
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
	if s != nil {
		if err := logout(s.AccessToken); err != nil && !ignorableSignOutError(err) {
			if scope != SignOutOthers {
				_ = c.clearSession(ctx)
			}
			return err
		}
	}
	if scope != SignOutOthers {
		return c.clearSession(ctx)
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

// GetUser fetches the user for jwt from the server (GET /user), which
// validates the token. Use it (or GetClaims) to authenticate requests on a
// server; never trust GetSession's user for that.
//
// With jwt == "" the stored session's access token is used (see
// "Token-taking methods" in the package documentation); if the server
// reports that the session no longer exists, the stored session is removed
// and SIGNED_OUT emitted.
func (c *Client) GetUser(ctx context.Context, jwt string) (*User, error) {
	if jwt != "" {
		return c.fetchUser(ctx, jwt)
	}
	s, err := c.GetSession(ctx)
	if err != nil {
		if isSessionMissing(err) {
			_ = c.clearSession(ctx)
		}
		return nil, err
	}
	token := ""
	if s != nil {
		token = s.AccessToken
	} else if !c.hasCustomAuthorization() {
		return nil, ErrSessionMissing
	}
	user, err := c.fetchUser(ctx, token)
	if err != nil && isSessionMissing(err) {
		_ = c.clearSession(ctx)
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
