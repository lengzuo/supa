package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetUserIdentities returns the identities linked to the user (from
// GetUser). See "Token-taking methods" in the package documentation for
// accessToken.
func (c *Client) GetUserIdentities(ctx context.Context, accessToken string) ([]Identity, error) {
	user, err := c.GetUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	if user.Identities == nil {
		return []Identity{}, nil
	}
	return user.Identities, nil
}

// LinkIdentity returns the provider URL that links an OAuth identity to
// the user (GET /user/identities/authorize). Manual linking must be enabled
// for the project. With FlowPKCE a code verifier is stored; finish with
// ExchangeCodeForSession after the redirect.
func (c *Client) LinkIdentity(ctx context.Context, accessToken string, params SignInWithOAuthParams) (*OAuthResponse, error) {
	if params.Provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidArgument)
	}
	token, _, err := c.sessionToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	full, flow, err := c.providerURL(ctx, "/user/identities/authorize", params, true)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(full)
	if err != nil {
		return nil, err
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := c.call(ctx, http.MethodGet, "/user/identities/authorize?"+u.RawQuery, nil, token, nil, &out); err != nil {
		c.removePKCEVerifier(ctx, flowIDOf(flow))
		return nil, err
	}
	return &OAuthResponse{Provider: params.Provider, URL: out.URL, FlowID: flowIDOf(flow)}, nil
}

// LinkIdentityWithIDToken links an OIDC identity to the user with an ID
// token (POST /token?grant_type=id_token with link_identity). With
// accessToken == "" the request is made under the session lock with the
// stored session's access token, the returned session replaces the stored
// one and USER_UPDATED is emitted.
func (c *Client) LinkIdentityWithIDToken(ctx context.Context, accessToken string, params SignInWithIDTokenParams) (*AuthResponse, error) {
	if params.Provider == "" || params.Token == "" {
		return nil, fmt.Errorf("%w: provider and token are required", ErrInvalidArgument)
	}
	body := struct {
		SignInWithIDTokenParams
		LinkIdentity bool               `json:"link_identity"`
		Meta         gotrueMetaSecurity `json:"gotrue_meta_security"`
	}{params, true, metaSecurity(params.CaptchaToken)}
	link := func(ctx context.Context, token string) (*AuthResponse, error) {
		resp, err := c.postSession(ctx, "/token", url.Values{"grant_type": {"id_token"}}, token, body)
		if err != nil {
			return nil, err
		}
		if resp.Session == nil || resp.User == nil {
			return nil, ErrInvalidTokenResponse
		}
		return resp, nil
	}
	if accessToken != "" {
		return link(ctx, accessToken)
	}
	var out *AuthResponse
	err := c.lockedSessionOp(ctx, false, func(ctx context.Context, s *Session) error {
		resp, err := link(ctx, s.AccessToken)
		if err != nil {
			return err
		}
		if err := c.commitLocked(ctx, resp.Session, EventUserUpdated); err != nil {
			return err
		}
		out = resp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnlinkIdentity removes an identity from the user
// (DELETE /user/identities/{identity_id}). Pass Identity.IdentityID. A user
// must keep at least one identity.
func (c *Client) UnlinkIdentity(ctx context.Context, accessToken, identityID string) error {
	if identityID == "" {
		return fmt.Errorf("%w: identity id is required", ErrInvalidArgument)
	}
	token, _, err := c.sessionToken(ctx, accessToken)
	if err != nil {
		return err
	}
	return c.call(ctx, http.MethodDelete, "/user/identities/"+pathSegment(identityID), nil, token, nil, nil)
}
