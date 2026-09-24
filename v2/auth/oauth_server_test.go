package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

const oauthTestDetailsJSON = `{"authorization_id":"auth_1","redirect_uri":"https://acme.example/cb","client":{"id":"cl_123","name":"Acme","uri":"https://acme.example","logo_uri":"https://acme.example/logo.png"},"user":{"id":"8a4c1b2e-1f2d-4c5b-9e7a-0d1c2b3a4f5e","email":"jane@example.com"},"scope":"openid email"}`

// oauthStoreSession stores a session with the given access token in c.
func oauthStoreSession(t *testing.T, c *Client, token string) {
	t.Helper()
	if err := c.saveSession(context.Background(), &Session{AccessToken: token, RefreshToken: "r", ExpiresIn: 3600, TokenType: "bearer"}); err != nil {
		t.Fatal(err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _getAuthorizationDetails
func TestOAuthGetAuthorizationDetails(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, oauthTestDetailsJSON, nil)
	d, err := c.OAuth().WithToken("user-jwt").GetAuthorizationDetails(context.Background(), "auth_1")
	if err != nil {
		t.Fatal(err)
	}
	if !d.NeedsConsent() || d.AuthorizationID != "auth_1" || d.Client.Name != "Acme" || d.User.Email != "jane@example.com" || d.Scope != "openid email" {
		t.Errorf("details = %+v", d)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/oauth/authorizations/auth_1", "", "user-jwt")

	// Already consented: only a redirect URL comes back.
	c, got = adminTestServer(t, http.StatusOK, `{"redirect_url":"https://acme.example/cb?code=xyz"}`, nil)
	oauthStoreSession(t, c, "session-jwt")
	d, err = c.OAuth().GetAuthorizationDetails(context.Background(), "auth/1")
	if err != nil {
		t.Fatal(err)
	}
	if d.NeedsConsent() || d.RedirectURL != "https://acme.example/cb?code=xyz" {
		t.Errorf("details = %+v", d)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/oauth/authorizations/auth%2F1", "", "session-jwt")

	if _, err := c.OAuth().GetAuthorizationDetails(context.Background(), ""); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}

	body, h := adminAPIErrorBody("oauth_authorization_not_found", "not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.OAuth().WithToken("t").GetAuthorizationDetails(context.Background(), "auth_1")
	adminWantAPIError(t, err, 404, "oauth_authorization_not_found")
}

// upstream: auth-js src/GoTrueClient.ts _getAuthorizationDetails (AuthSessionMissingError)
func TestOAuthSessionMissing(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, `{}`, nil)
	ctx := context.Background()
	o := c.OAuth()
	if _, err := o.GetAuthorizationDetails(ctx, "a"); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("GetAuthorizationDetails err = %v", err)
	}
	if _, err := o.ApproveAuthorization(ctx, "a"); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("ApproveAuthorization err = %v", err)
	}
	if _, err := o.DenyAuthorization(ctx, "a"); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("DenyAuthorization err = %v", err)
	}
	if _, err := o.ListGrants(ctx); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("ListGrants err = %v", err)
	}
	if err := o.RevokeGrant(ctx, "cl"); !errors.Is(err, ErrSessionMissing) {
		t.Errorf("RevokeGrant err = %v", err)
	}
	if len(got()) != 0 {
		t.Error("request sent without a session")
	}
}

// upstream: auth-js src/GoTrueClient.ts _approveAuthorization
func TestOAuthApproveAuthorization(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, `{"redirect_url":"https://acme.example/cb?code=abc&state=s"}`, nil)
	// A custom Authorization header must not override the user's token.
	c2, err := New(Config{URL: c.t.BaseURL().String(), APIKey: adminTestKey, Headers: http.Header{"Authorization": {"Bearer custom"}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := c2.OAuth().WithToken("user-jwt").ApproveAuthorization(context.Background(), "auth_1")
	if err != nil {
		t.Fatal(err)
	}
	if r.RedirectURL != "https://acme.example/cb?code=abc&state=s" {
		t.Errorf("redirect = %+v", r)
	}
	rec := adminOne(t, got)
	adminCheck(t, rec, http.MethodPost, "/auth/v1/oauth/authorizations/auth_1/consent", "", "user-jwt")
	adminJSONBody(t, rec, `{"action":"approve"}`)

	body, h := adminAPIErrorBody("validation_failed", "expired")
	c, _ = adminTestServer(t, http.StatusBadRequest, body, h)
	_, err = c.OAuth().WithToken("t").ApproveAuthorization(context.Background(), "auth_1")
	adminWantAPIError(t, err, 400, "validation_failed")
}

// upstream: auth-js src/GoTrueClient.ts _denyAuthorization
func TestOAuthDenyAuthorization(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, `{"redirect_url":"https://acme.example/cb?error=access_denied"}`, nil)
	oauthStoreSession(t, c, "session-jwt")
	r, err := c.OAuth().DenyAuthorization(context.Background(), "auth_1")
	if err != nil {
		t.Fatal(err)
	}
	if r.RedirectURL != "https://acme.example/cb?error=access_denied" {
		t.Errorf("redirect = %+v", r)
	}
	rec := adminOne(t, got)
	adminCheck(t, rec, http.MethodPost, "/auth/v1/oauth/authorizations/auth_1/consent", "", "session-jwt")
	adminJSONBody(t, rec, `{"action":"deny"}`)

	body, h := adminAPIErrorBody(ErrorCodeBadJWT, "bad jwt")
	c, _ = adminTestServer(t, http.StatusUnauthorized, body, h)
	_, err = c.OAuth().WithToken("t").DenyAuthorization(context.Background(), "auth_1")
	adminWantAPIError(t, err, 401, ErrorCodeBadJWT)
}

// upstream: auth-js src/GoTrueClient.ts _listOAuthGrants
func TestOAuthListGrants(t *testing.T) {
	resp := `[{"client":{"id":"cl_123","name":"Acme","uri":"https://acme.example","logo_uri":""},"scopes":["openid","email"],"granted_at":"2025-03-01T12:00:00Z"}]`
	c, got := adminTestServer(t, http.StatusOK, resp, nil)
	gs, err := c.OAuth().WithToken("user-jwt").ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 || gs[0].Client.ID != "cl_123" || len(gs[0].Scopes) != 2 || gs[0].GrantedAt.IsZero() {
		t.Errorf("grants = %+v", gs)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/user/oauth/grants", "", "user-jwt")

	body, h := adminAPIErrorBody(ErrorCodeBadJWT, "bad jwt")
	c, _ = adminTestServer(t, http.StatusUnauthorized, body, h)
	_, err = c.OAuth().WithToken("t").ListGrants(context.Background())
	adminWantAPIError(t, err, 401, ErrorCodeBadJWT)
}

// upstream: auth-js src/GoTrueClient.ts _revokeOAuthGrant
func TestOAuthRevokeGrant(t *testing.T) {
	c, got := adminTestServer(t, http.StatusNoContent, "", nil)
	if err := c.OAuth().WithToken("user-jwt").RevokeGrant(context.Background(), "cl_123"); err != nil {
		t.Fatal(err)
	}
	adminCheck(t, adminOne(t, got), http.MethodDelete, "/auth/v1/user/oauth/grants", "client_id=cl_123", "user-jwt")
	if err := c.OAuth().WithToken("t").RevokeGrant(context.Background(), ""); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}

	body, h := adminAPIErrorBody("oauth_grant_not_found", "nf")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	adminWantAPIError(t, c.OAuth().WithToken("t").RevokeGrant(context.Background(), "cl_123"), 404, "oauth_grant_not_found")
}

func TestOAuthContextCanceled(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, `[]`, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.OAuth().WithToken("t").ListGrants(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if len(got()) != 0 {
		t.Error("request reached server")
	}
}

func TestOAuthWithTokenDoesNotMutate(t *testing.T) {
	c, _ := adminTestServer(t, http.StatusOK, `[]`, nil)
	base := c.OAuth()
	_ = base.WithToken("a")
	if base.token != "" {
		t.Error("WithToken mutated the receiver")
	}
}
