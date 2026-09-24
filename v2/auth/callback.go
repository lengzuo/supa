package auth

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// GetSessionFromURL completes a sign-in from the URL the Auth server
// redirected the user to (the server-side counterpart of auth-js
// detectSessionInUrl). Parameters are read from both the fragment and the
// query string; query parameters win.
//
//   - error / error_description / error_code parameters are returned as an
//     *Error whose Code is the error_code (e.g. "otp_expired") and which
//     also matches ErrImplicitGrantRedirect under errors.Is.
//   - A "code" parameter (FlowPKCE) is exchanged with
//     ExchangeCodeForSession, using the sb_flow_id parameter if present (a
//     malformed sb_flow_id fails with ErrPKCEVerifierMissing rather than
//     falling back to another flow's verifier).
//   - access_token, refresh_token, expires_in and token_type (FlowImplicit)
//     are validated with GetUser and adopted as the session.
//
// The session is stored and SIGNED_IN (PASSWORD_RECOVERY for recovery
// links) emitted. A callback type that does not match Config.FlowType is
// rejected. Note that implicit-flow fragments never reach a server; a
// server receives them only if the page forwards them.
func (c *Client) GetSessionFromURL(ctx context.Context, rawURL string) (*AuthResponse, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid callback URL", ErrInvalidArgument)
	}
	params := map[string]string{}
	if u.Fragment != "" {
		if frag, err := url.ParseQuery(u.Fragment); err == nil {
			for k, v := range frag {
				params[k] = v[0]
			}
		}
	}
	for k, v := range u.Query() {
		params[k] = v[0]
	}

	if params["error"] != "" || params["error_description"] != "" || params["error_code"] != "" {
		// Like auth-js AuthImplicitGrantRedirectError: the error matches
		// ErrImplicitGrantRedirect and carries the URL's error_code.
		msg := params["error_description"]
		if msg == "" {
			msg = "Error in URL with unspecified error_description"
		}
		code := params["error_code"]
		if code == "" {
			code = "unspecified_code"
		}
		redirectErr := params["error"]
		if redirectErr == "" {
			redirectErr = "unspecified_error"
		}
		return nil, &Error{Message: msg, Code: code, RedirectError: redirectErr, kind: ErrImplicitGrantRedirect.Code}
	}

	switch {
	case params["access_token"] != "":
		if c.cfg.FlowType == FlowPKCE {
			return nil, newError(ErrPKCEGrantCodeExchange.Code, "not a valid PKCE flow url")
		}
		return c.sessionFromImplicitGrant(ctx, params)
	case params["code"] != "":
		if c.cfg.FlowType != FlowPKCE {
			return nil, newError(ErrImplicitGrantRedirect.Code, "not a valid implicit grant flow url")
		}
		if flowID, ok := params[PKCEFlowIDParam]; ok && validPKCEFlowID(flowID) == "" {
			// Present but invalid (including empty): fail fast instead of
			// borrowing another flow's verifier, like auth-js.
			return nil, ErrPKCEVerifierMissing
		}
		return c.ExchangeCodeForSession(ctx, params["code"], &ExchangeCodeOptions{FlowID: params[PKCEFlowIDParam]})
	default:
		return nil, newError(ErrImplicitGrantRedirect.Code, "no session defined in URL")
	}
}

func (c *Client) sessionFromImplicitGrant(ctx context.Context, params map[string]string) (*AuthResponse, error) {
	accessToken, refreshToken := params["access_token"], params["refresh_token"]
	if accessToken == "" || params["expires_in"] == "" || refreshToken == "" || params["token_type"] == "" {
		return nil, newError(ErrImplicitGrantRedirect.Code, "no session defined in URL")
	}
	expiresIn, err := strconv.ParseInt(params["expires_in"], 10, 64)
	if err != nil {
		return nil, newError(ErrImplicitGrantRedirect.Code, "invalid expires_in in URL")
	}
	now := c.now().Unix()
	expiresAt := now + expiresIn
	if v := params["expires_at"]; v != "" {
		if expiresAt, err = strconv.ParseInt(v, 10, 64); err != nil {
			return nil, newError(ErrImplicitGrantRedirect.Code, "invalid expires_at in URL")
		}
	}
	if issuedAt := expiresAt - expiresIn; now-issuedAt >= 120 {
		c.debug(ctx, "session in URL was issued over 120s ago, URL could be stale")
	}
	user, err := c.fetchUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	s := &Session{
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		TokenType:            params["token_type"],
		ExpiresIn:            expiresIn,
		ExpiresAt:            expiresAt,
		ProviderToken:        params["provider_token"],
		ProviderRefreshToken: params["provider_refresh_token"],
		User:                 user,
	}
	event := EventSignedIn
	if params["type"] == OTPTypeRecovery {
		event = EventPasswordRecovery
	}
	if err := c.commitSession(ctx, s, event); err != nil {
		return nil, err
	}
	return &AuthResponse{User: user, Session: s, RedirectType: params["type"]}, nil
}
