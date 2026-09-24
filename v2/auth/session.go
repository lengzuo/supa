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
// A session that is not within ExpiryMargin of expiring is returned
// straight from storage without taking the session lock. Otherwise the
// session lock is taken, the stored session re-read, and (if still near
// expiry) refreshed, emitting TOKEN_REFRESHED; concurrent callers queue on
// the lock and find the refreshed session. If the refresh fails but the
// stored access token is still valid, that session is returned. A refresh
// that fails with a retryable error (network, 5xx) never removes the
// stored session; a definitive failure (e.g. revoked refresh token)
// removes it once its access token has actually expired, emitting
// SIGNED_OUT.
//
// The session comes from storage and is not verified; on a server use
// GetUser or GetClaims to authenticate a request.
func (c *Client) GetSession(ctx context.Context) (*Session, error) {
	s, err := c.loadSession(ctx)
	if err != nil || s == nil || !c.expiresWithinMargin(s) {
		return s, err
	}
	var out *Session
	err = c.withSessionLockDetached(ctx, func(ctx context.Context) error {
		s, err := c.loadSession(ctx)
		if err != nil || s == nil || !c.expiresWithinMargin(s) {
			out = s
			return err
		}
		refreshed, err := c.refreshLocked(ctx, s.RefreshToken)
		if err == nil {
			out = refreshed
			return nil
		}
		// A proactive refresh failed while the access token still works.
		if c.accessTokenValid(s) {
			if stored, lerr := c.loadSession(ctx); lerr == nil && stored != nil && stored.RefreshToken == s.RefreshToken {
				out = stored
				return nil
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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

// refreshFailure caches a failed refresh for refreshFailureCooldown.
type refreshFailure struct {
	token string
	err   error
	until time.Time
}

// refreshTimeout bounds a detached, token-rotating request (including a
// refresh's retries).
const refreshTimeout = 2 * autoRefreshTickDuration

// refreshLocked refreshes refreshToken and commits the new session
// (queuing TOKEN_REFRESHED). The session lock must be held, and ctx should
// be detached from the caller (see withSessionLockDetached).
//
// Because the lock is held from reading the token to committing the
// result, the token sent is always the current one: no other operation can
// rotate it in between. A failed refresh for the same token within
// refreshFailureCooldown returns the cached failure without a request. A
// definitive (non-retryable) auth failure removes the stored session,
// queuing SIGNED_OUT, if it still holds refreshToken and its access token
// has expired; retryable and local failures keep it.
func (c *Client) refreshLocked(ctx context.Context, refreshToken string) (*Session, error) {
	if refreshToken == "" {
		return nil, ErrSessionMissing
	}
	c.refreshMu.Lock()
	f := c.lastRefreshFailure
	c.refreshMu.Unlock()
	if f != nil && f.token == refreshToken && c.now().Before(f.until) {
		return nil, f.err
	}
	s, err := c.refreshAccessToken(ctx, refreshToken)
	if err != nil {
		var ae *Error
		isAuth := errors.As(err, &ae)
		if isAuth && !ae.Retryable {
			stored, lerr := c.loadSession(ctx)
			if lerr == nil && stored != nil && stored.RefreshToken == refreshToken && !c.accessTokenValid(stored) {
				_ = c.signOutLocked(ctx)
			}
		}
		if isAuth || transport.IsPreSend(err) {
			c.refreshMu.Lock()
			c.lastRefreshFailure = &refreshFailure{token: refreshToken, err: err, until: c.now().Add(refreshFailureCooldown)}
			c.refreshMu.Unlock()
		}
		return nil, err
	}
	if err := c.commitLocked(ctx, s, EventTokenRefreshed); err != nil {
		return nil, err
	}
	return s, nil
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
// not close to expiry) under the session lock, stored, and TOKEN_REFRESHED
// is emitted; ErrSessionMissing is returned if there is none. With an
// explicit refreshToken the new session is only returned: storage is
// untouched and no event is emitted (use SetSession to adopt it). Refresh
// tokens are single-use: keep the returned RefreshToken.
func (c *Client) RefreshSession(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	if refreshToken != "" {
		s, err := c.refreshAccessToken(ctx, refreshToken)
		if err != nil {
			return nil, err
		}
		return &AuthResponse{User: s.User, Session: s}, nil
	}
	var out *Session
	err := c.withSessionLockDetached(ctx, func(ctx context.Context) error {
		stored, err := c.loadSession(ctx)
		if err != nil {
			return err
		}
		if stored == nil {
			return ErrSessionMissing
		}
		out, err = c.refreshLocked(ctx, stored.RefreshToken)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &AuthResponse{User: out.User, Session: out}, nil
}

// SetSession adopts a session from an access and refresh token pair (for
// example tokens handed over from a browser), stores it and emits
// SIGNED_IN. If the access token has expired it is refreshed instead
// (emitting TOKEN_REFRESHED); otherwise it is validated with GetUser. It
// runs under the session lock, detached from ctx once started (a refresh
// the server performed is never lost).
func (c *Client) SetSession(ctx context.Context, accessToken, refreshToken string) (*AuthResponse, error) {
	if accessToken == "" || refreshToken == "" {
		return nil, ErrSessionMissing
	}
	jwt, err := decodeJWT(accessToken)
	if err != nil {
		return nil, err
	}
	var out *AuthResponse
	err = c.withSessionLockDetached(ctx, func(ctx context.Context) error {
		now := c.now().Unix()
		expiresAt, expired := now, true
		if exp := jwt.Claims.ExpiresAt; exp != 0 {
			expiresAt, expired = exp, exp <= now
		}
		if expired {
			s, err := c.refreshLocked(ctx, refreshToken)
			if err != nil {
				return err
			}
			out = &AuthResponse{User: s.User, Session: s}
			return nil
		}
		user, err := c.fetchUser(ctx, accessToken)
		if err != nil {
			return err
		}
		s := &Session{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			TokenType:    "bearer",
			ExpiresIn:    expiresAt - now,
			ExpiresAt:    expiresAt,
			User:         user,
		}
		if err := c.commitLocked(ctx, s, EventSignedIn); err != nil {
			return err
		}
		out = &AuthResponse{User: user, Session: s}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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
// With accessToken == "" the stored session is refreshed if needed, then,
// under the session lock, re-read and signed out with its access token;
// unless scope is SignOutOthers the stored session and all pending PKCE
// verifiers are then removed and SIGNED_OUT is emitted, even if the server
// call failed (the error is still returned), like auth-js _signOut. 401,
// 403 and 404 responses, which mean the session is already gone, are not
// errors. With an explicit accessToken only the server call is made and its
// error returned as is.
func (c *Client) SignOut(ctx context.Context, accessToken string, scope SignOutScope) error {
	if scope == "" {
		scope = SignOutGlobal
	}
	switch scope {
	case SignOutGlobal, SignOutLocal, SignOutOthers:
	default:
		return fmt.Errorf("%w: sign-out scope must be one of global, local, others", ErrInvalidArgument)
	}
	logout := func(ctx context.Context, token string) error {
		return c.call(ctx, http.MethodPost, "/logout", url.Values{"scope": {string(scope)}}, token, nil, nil)
	}
	if accessToken != "" {
		return logout(ctx, accessToken)
	}

	// Refresh first if needed so that the logout uses a live access token.
	if _, err := c.GetSession(ctx); err != nil && !isSessionMissing(err) {
		return err
	}
	return c.withSessionLock(ctx, func() error {
		s, err := c.loadSession(ctx)
		if err != nil {
			return err
		}
		if s != nil {
			if err := logout(ctx, s.AccessToken); err != nil && !ignorableSignOutError(err) {
				if scope != SignOutOthers {
					_ = c.signOutLocked(ctx)
				}
				return err
			}
		}
		if scope != SignOutOthers {
			return c.signOutLocked(ctx)
		}
		return nil
	})
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
// (under the session lock, only if it still holds that token) and
// SIGNED_OUT emitted.
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

// lockedSessionOp runs fn for the stored session under the session lock:
// the session is refreshed first if needed (outside the lock), then
// re-read under it; fn gets the session current at that moment.
// ErrSessionMissing is returned when there is none.
func (c *Client) lockedSessionOp(ctx context.Context, detached bool, fn func(ctx context.Context, s *Session) error) error {
	s, err := c.GetSession(ctx)
	if err != nil {
		return err
	}
	if s == nil {
		return ErrSessionMissing
	}
	op := func(ctx context.Context) error {
		s, err := c.loadSession(ctx)
		if err != nil {
			return err
		}
		if s == nil {
			return ErrSessionMissing
		}
		return fn(ctx, s)
	}
	if detached {
		return c.withSessionLockDetached(ctx, op)
	}
	return c.withSessionLock(ctx, func() error { return op(ctx) })
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
// accessToken == "" the request is made, under the session lock, with the
// stored session's access token; the stored session then gets the new user
// and USER_UPDATED is emitted. With FlowPKCE and an Email change a code
// verifier is stored for the confirmation redirect.
func (c *Client) UpdateUser(ctx context.Context, accessToken string, params UpdateUserParams) (*User, error) {
	update := func(ctx context.Context, token string) (*User, error) {
		var flow *pkceFlow
		if params.Email != "" {
			var err error
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
		err := c.call(ctx, http.MethodPut, "/user", redirectQuery(c.redirectWithFlowID(params.EmailRedirectTo, flow)), token, body, &raw)
		if err != nil {
			c.removePKCEVerifier(ctx, flowIDOf(flow))
			return nil, err
		}
		user, err := decodeUser(raw)
		if err != nil {
			c.removePKCEVerifier(ctx, flowIDOf(flow))
			return nil, err
		}
		return user, nil
	}
	if accessToken != "" {
		return update(ctx, accessToken)
	}
	var out *User
	err := c.lockedSessionOp(ctx, false, func(ctx context.Context, s *Session) error {
		user, err := update(ctx, s.AccessToken)
		if err != nil {
			return err
		}
		updated := *s
		updated.User = user
		if err := c.commitLocked(ctx, &updated, EventUserUpdated); err != nil {
			return err
		}
		out = user
		return nil
	})
	return out, err
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
