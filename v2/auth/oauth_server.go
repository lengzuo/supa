package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// OAuthServerAPI is the user-facing side of the project's OAuth 2.1
// server, used to build a consent page (auth-js auth.oauth). Only relevant
// when the OAuth 2.1 server is enabled in Supabase Auth.
//
// Calls are made on behalf of a signed-in user. By default the access
// token of the Client's stored session (GetSession) is used; server
// applications should call WithAccessToken with the caller's access token
// instead. An *OAuthServerAPI is immutable and safe for concurrent use.
type OAuthServerAPI struct {
	c     *Client
	token string
}

// OAuth returns the OAuth 2.1 server consent API.
func (c *Client) OAuth() *OAuthServerAPI { return &OAuthServerAPI{c: c} }

// WithAccessToken returns a copy of o that authorizes every call with
// accessToken (a user JWT) instead of the stored session.
func (o *OAuthServerAPI) WithAccessToken(accessToken string) *OAuthServerAPI {
	return &OAuthServerAPI{c: o.c, token: strings.TrimSpace(accessToken)}
}

// oauthToken resolves the user access token for a call.
func (o *OAuthServerAPI) oauthToken(ctx context.Context) (string, error) {
	if o.token != "" {
		return o.token, nil
	}
	s, err := o.c.GetSession(ctx)
	if err != nil {
		return "", err
	}
	if s == nil || s.AccessToken == "" {
		return "", ErrSessionMissing
	}
	return s.AccessToken, nil
}

// oauthDo sends req authorized with the user's access token.
func (o *OAuthServerAPI) oauthDo(ctx context.Context, req *transport.Request, out any) error {
	token, err := o.oauthToken(ctx)
	if err != nil {
		return err
	}
	// Set the header explicitly so the user's token takes precedence over
	// any Authorization header in Config.Headers, as in auth-js.
	req.Header = http.Header{transport.HeaderAuthorization: {"Bearer " + token}}
	return o.c.request(ctx, req, out)
}

// OAuthAuthorizationClient describes the OAuth client requesting access.
type OAuthAuthorizationClient struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URI     string `json:"uri"`
	LogoURI string `json:"logo_uri"`
}

// OAuthAuthorizationUser is the user an authorization request is for.
type OAuthAuthorizationUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// OAuthAuthorizationDetails is returned by GetAuthorizationDetails. The
// server answers in one of two shapes:
//
//   - consent is required: AuthorizationID, RedirectURI, Client, User and
//     Scope are set, and the consent page should be shown;
//   - the user already consented: only RedirectURL is set, and the user
//     should be redirected there immediately.
//
// Use NeedsConsent to tell them apart.
type OAuthAuthorizationDetails struct {
	AuthorizationID string                   `json:"authorization_id,omitempty"`
	RedirectURI     string                   `json:"redirect_uri,omitempty"`
	Client          OAuthAuthorizationClient `json:"client"`
	User            OAuthAuthorizationUser   `json:"user"`
	// Scope is a space-separated list of requested scopes.
	Scope string `json:"scope,omitempty"`
	// RedirectURL is set instead of the fields above when consent was
	// already given.
	RedirectURL string `json:"redirect_url,omitempty"`
}

// NeedsConsent reports whether the user must be shown a consent page
// (true) or can be redirected to RedirectURL right away (false).
func (d *OAuthAuthorizationDetails) NeedsConsent() bool {
	return d.AuthorizationID != ""
}

// OAuthRedirect holds the URL to send the user back to the OAuth client,
// carrying either an authorization code or an access_denied error.
type OAuthRedirect struct {
	RedirectURL string `json:"redirect_url"`
}

// OAuthGrant is an OAuth client the user has authorized.
type OAuthGrant struct {
	Client    OAuthAuthorizationClient `json:"client"`
	Scopes    []string                 `json:"scopes"`
	GrantedAt time.Time                `json:"granted_at"`
}

func oauthAuthorizationPath(authorizationID string) (string, error) {
	if strings.TrimSpace(authorizationID) == "" {
		return "", fmt.Errorf("%w: authorization ID is required", ErrInvalidArgument)
	}
	return "/oauth/authorizations/" + pathSegment(authorizationID), nil
}

// GetAuthorizationDetails returns the details of an authorization request,
// to be shown on the consent page.
func (o *OAuthServerAPI) GetAuthorizationDetails(ctx context.Context, authorizationID string) (*OAuthAuthorizationDetails, error) {
	p, err := oauthAuthorizationPath(authorizationID)
	if err != nil {
		return nil, err
	}
	var out OAuthAuthorizationDetails
	if err := o.oauthDo(ctx, &transport.Request{Method: http.MethodGet, Path: p}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (o *OAuthServerAPI) oauthConsent(ctx context.Context, authorizationID, action string) (*OAuthRedirect, error) {
	p, err := oauthAuthorizationPath(authorizationID)
	if err != nil {
		return nil, err
	}
	body := struct {
		Action string `json:"action"`
	}{action}
	var out OAuthRedirect
	if err := o.oauthDo(ctx, &transport.Request{Method: http.MethodPost, Path: p + "/consent", Body: body}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ApproveAuthorization records the user's consent and returns the URL to
// redirect the user to, which carries the authorization code. Unlike
// auth-js in a browser, it never redirects by itself.
func (o *OAuthServerAPI) ApproveAuthorization(ctx context.Context, authorizationID string) (*OAuthRedirect, error) {
	return o.oauthConsent(ctx, authorizationID, "approve")
}

// DenyAuthorization rejects the authorization request and returns the URL
// to redirect the user to, which carries an access_denied error. Unlike
// auth-js in a browser, it never redirects by itself.
func (o *OAuthServerAPI) DenyAuthorization(ctx context.Context, authorizationID string) (*OAuthRedirect, error) {
	return o.oauthConsent(ctx, authorizationID, "deny")
}

// ListGrants returns the OAuth clients the user has authorized.
func (o *OAuthServerAPI) ListGrants(ctx context.Context) ([]OAuthGrant, error) {
	var out []OAuthGrant
	if err := o.oauthDo(ctx, &transport.Request{Method: http.MethodGet, Path: "/user/oauth/grants"}, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []OAuthGrant{}
	}
	return out, nil
}

// RevokeGrant revokes the user's consent for the OAuth client clientID,
// ending that client's sessions and invalidating its refresh tokens.
func (o *OAuthServerAPI) RevokeGrant(ctx context.Context, clientID string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("%w: client ID is required", ErrInvalidArgument)
	}
	req := &transport.Request{
		Method: http.MethodDelete,
		Path:   "/user/oauth/grants",
		Query:  url.Values{"client_id": {clientID}},
	}
	return o.oauthDo(ctx, req, nil)
}
