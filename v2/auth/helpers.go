package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// Timing constants mirrored from auth-js lib/constants.ts.
const (
	// autoRefreshTickDuration is how often the background refresher checks
	// the stored session (AUTO_REFRESH_TICK_DURATION_MS).
	autoRefreshTickDuration = 30 * time.Second
	// autoRefreshTickThreshold is how many ticks before expiry a refresh is
	// attempted (AUTO_REFRESH_TICK_THRESHOLD).
	autoRefreshTickThreshold = 3
	// ExpiryMargin is how long before its access token expires a session is
	// treated as expired and refreshed by GetSession (auth-js
	// EXPIRY_MARGIN_MS).
	ExpiryMargin = autoRefreshTickThreshold * autoRefreshTickDuration
	// refreshFailureCooldown is how long a failed refresh result is reused
	// for the same refresh token (REFRESH_FAILURE_COOLDOWN_MS).
	refreshFailureCooldown = 2 * autoRefreshTickDuration
)

// gotrueMetaSecurity carries the captcha token in request bodies.
type gotrueMetaSecurity struct {
	CaptchaToken string `json:"captcha_token,omitempty"`
}

func metaSecurity(captchaToken string) gotrueMetaSecurity {
	return gotrueMetaSecurity{CaptchaToken: captchaToken}
}

// optionalMeta returns nil (field omitted) unless a captcha token is set;
// some auth-js calls only send gotrue_meta_security in that case.
func optionalMeta(captchaToken string) *gotrueMetaSecurity {
	if captchaToken == "" {
		return nil
	}
	return &gotrueMetaSecurity{CaptchaToken: captchaToken}
}

// redirectQuery returns the redirect_to query, or nil when redirectTo is "".
func redirectQuery(redirectTo string) url.Values {
	if redirectTo == "" {
		return nil
	}
	return url.Values{"redirect_to": {redirectTo}}
}

// orEmptyMap returns m, or an empty map so the field encodes as {} like
// auth-js' `data ?? {}`.
func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// call sends a request on behalf of token (empty = API key only).
func (c *Client) call(ctx context.Context, method, path string, query url.Values, token string, body, out any) error {
	return c.request(ctx, &transport.Request{
		Method: method,
		Path:   path,
		Query:  query,
		Token:  token,
		Body:   body,
	}, out)
}

// decodeSessionResponse mirrors auth-js _sessionResponse: the body holds a
// session when it has access_token, refresh_token and expires_in; the user
// is either data.user or the body itself when it looks like a user.
func (c *Client) decodeSessionResponse(raw []byte) (*AuthResponse, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return &AuthResponse{}, nil
	}
	var probe struct {
		AccessToken  string          `json:"access_token"`
		RefreshToken string          `json:"refresh_token"`
		ExpiresIn    int64           `json:"expires_in"`
		ID           json.RawMessage `json:"id"`
		User         json.RawMessage `json:"user"`
		WeakPassword *WeakPassword   `json:"weak_password"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("auth: decode response: %w", err)
	}
	out := &AuthResponse{}
	switch {
	case len(probe.User) > 0 && string(probe.User) != "null":
		var u User
		if err := json.Unmarshal(probe.User, &u); err != nil {
			return nil, fmt.Errorf("auth: decode user: %w", err)
		}
		out.User = &u
	case len(probe.ID) > 0 && probe.ID[0] == '"':
		var u User
		if err := json.Unmarshal(raw, &u); err != nil {
			return nil, fmt.Errorf("auth: decode user: %w", err)
		}
		out.User = &u
	}
	if probe.AccessToken != "" && probe.RefreshToken != "" && probe.ExpiresIn != 0 {
		var s Session
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("auth: decode session: %w", err)
		}
		if s.ExpiresAt == 0 {
			s.ExpiresAt = c.now().Unix() + s.ExpiresIn
		}
		s.User = out.User
		out.Session = &s
	}
	if w := probe.WeakPassword; w != nil && len(w.Reasons) > 0 && w.Message != "" {
		out.WeakPassword = w
	}
	return out, nil
}

// decodeUser mirrors auth-js _userResponse: {user: {...}} or the user
// object itself.
func decodeUser(raw []byte) (*User, error) {
	if isEmptyJSON(raw) {
		return nil, errors.New("auth: decode user: empty response body")
	}
	var wrapped struct {
		User json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("auth: decode user: %w", err)
	}
	src := raw
	if len(wrapped.User) > 0 && string(wrapped.User) != "null" {
		src = wrapped.User
	}
	var u User
	if err := json.Unmarshal(src, &u); err != nil {
		return nil, fmt.Errorf("auth: decode user: %w", err)
	}
	return &u, nil
}

// pathSegment escapes one user-supplied path segment: "/" and other
// reserved characters are percent-encoded, and the dot segments "." and
// ".." (which URL resolution would collapse, changing the endpoint) are
// encoded as %2E.
func pathSegment(s string) string {
	switch s {
	case ".":
		return "%2E"
	case "..":
		return "%2E%2E"
	}
	return url.PathEscape(s)
}

// isEmptyJSON reports whether raw is an empty body or JSON null.
func isEmptyJSON(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// encodeURIComponent escapes s like JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	// QueryEscape escapes these; encodeURIComponent does not.
	for _, r := range []struct{ from, to string }{
		{"%21", "!"}, {"%27", "'"}, {"%28", "("}, {"%29", ")"}, {"%2A", "*"},
	} {
		e = strings.ReplaceAll(e, r.from, r.to)
	}
	return e
}

// hasCustomAuthorization reports whether Config.Headers sets an
// Authorization header (auth-js hasCustomAuthorizationHeader).
func (c *Client) hasCustomAuthorization() bool { return c.customAuth }

// sessionToken returns accessToken when set, otherwise the access token of
// the stored session (refreshed if needed), or ErrSessionMissing. The
// returned session is nil when accessToken was supplied.
func (c *Client) sessionToken(ctx context.Context, accessToken string) (string, *Session, error) {
	if accessToken != "" {
		return accessToken, nil, nil
	}
	s, err := c.GetSession(ctx)
	if err != nil {
		return "", nil, err
	}
	if s == nil {
		return "", nil, ErrSessionMissing
	}
	return s.AccessToken, s, nil
}

// debug logs msg at debug level when a Logger is configured. Never pass
// secrets.
func (c *Client) debug(ctx context.Context, msg string, args ...any) {
	if c.cfg.Logger != nil {
		c.cfg.Logger.DebugContext(ctx, "auth: "+msg, args...)
	}
}
