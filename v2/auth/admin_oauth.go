package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// AdminOAuthAPI manages the OAuth 2.1 clients of the project's OAuth
// server. Obtain it with AdminAPI.OAuth. Only relevant when the OAuth 2.1
// server is enabled in Supabase Auth.
type AdminOAuthAPI struct {
	c *Client
}

// OAuthClientType is an OAuth client's type.
type OAuthClientType string

const (
	// OAuthClientTypePublic is a client that cannot keep a secret.
	OAuthClientTypePublic OAuthClientType = "public"
	// OAuthClientTypeConfidential is a client that holds a client secret.
	OAuthClientTypeConfidential OAuthClientType = "confidential"
)

// OAuthClientRegistrationType records how an OAuth client was registered.
type OAuthClientRegistrationType string

const (
	// OAuthClientRegistrationDynamic is a dynamically registered client.
	OAuthClientRegistrationDynamic OAuthClientRegistrationType = "dynamic"
	// OAuthClientRegistrationManual is a client created by an admin.
	OAuthClientRegistrationManual OAuthClientRegistrationType = "manual"
)

// OAuthTokenEndpointAuthMethod is how an OAuth client authenticates at the
// token endpoint.
type OAuthTokenEndpointAuthMethod string

const (
	// OAuthTokenEndpointAuthNone is used by public clients.
	OAuthTokenEndpointAuthNone OAuthTokenEndpointAuthMethod = "none"
	// OAuthTokenEndpointAuthClientSecretBasic sends the secret with HTTP
	// Basic authentication.
	OAuthTokenEndpointAuthClientSecretBasic OAuthTokenEndpointAuthMethod = "client_secret_basic"
	// OAuthTokenEndpointAuthClientSecretPost sends the secret in the form
	// body.
	OAuthTokenEndpointAuthClientSecretPost OAuthTokenEndpointAuthMethod = "client_secret_post"
)

// OAuthClient is an OAuth client registered with the project's OAuth
// server.
type OAuthClient struct {
	ClientID                string                       `json:"client_id"`
	ClientName              string                       `json:"client_name"`
	ClientSecret            string                       `json:"client_secret,omitempty"`
	ClientType              OAuthClientType              `json:"client_type"`
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
	RegistrationType        OAuthClientRegistrationType  `json:"registration_type"`
	ClientURI               string                       `json:"client_uri,omitempty"`
	LogoURI                 string                       `json:"logo_uri,omitempty"`
	RedirectURIs            []string                     `json:"redirect_uris"`
	// GrantTypes are e.g. "authorization_code" and "refresh_token".
	GrantTypes []string `json:"grant_types"`
	// ResponseTypes is currently always ["code"].
	ResponseTypes []string  `json:"response_types"`
	Scope         string    `json:"scope,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// AdminCreateOAuthClientParams are the inputs to AdminOAuthAPI.CreateClient.
type AdminCreateOAuthClientParams struct {
	// ClientName is the human-readable name. Required.
	ClientName string `json:"client_name"`
	// ClientURI is the client's home page.
	ClientURI string `json:"client_uri,omitempty"`
	// RedirectURIs are the allowed redirect URIs. Required.
	RedirectURIs []string `json:"redirect_uris"`
	// GrantTypes defaults to authorization_code and refresh_token.
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes defaults to ["code"].
	ResponseTypes []string `json:"response_types,omitempty"`
	// Scope is a space-separated scope list.
	Scope string `json:"scope,omitempty"`
	// TokenEndpointAuthMethod selects how the client authenticates.
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod `json:"token_endpoint_auth_method,omitempty"`
}

// AdminUpdateOAuthClientParams are the inputs to AdminOAuthAPI.UpdateClient.
// Only non-zero fields are sent.
type AdminUpdateOAuthClientParams struct {
	ClientName              string                       `json:"client_name,omitempty"`
	ClientURI               string                       `json:"client_uri,omitempty"`
	LogoURI                 string                       `json:"logo_uri,omitempty"`
	RedirectURIs            []string                     `json:"redirect_uris,omitempty"`
	GrantTypes              []string                     `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod OAuthTokenEndpointAuthMethod `json:"token_endpoint_auth_method,omitempty"`
}

// AdminOAuthClientList is one page of OAuth clients.
type AdminOAuthClientList struct {
	Clients []OAuthClient `json:"clients"`
	Aud     string        `json:"aud"`
	AdminPagination
}

func adminClientPath(clientID string) (string, error) {
	if clientID == "" {
		return "", fmt.Errorf("%w: client ID is required", ErrInvalidArgument)
	}
	return "/admin/oauth/clients/" + url.PathEscape(clientID), nil
}

// ListClients returns a page of OAuth clients. params may be nil.
func (o *AdminOAuthAPI) ListClients(ctx context.Context, params *AdminPageParams) (*AdminOAuthClientList, error) {
	var out AdminOAuthClientList
	h, err := o.c.adminRequest(ctx, &transport.Request{Method: http.MethodGet, Path: "/admin/oauth/clients", Query: params.query()}, &out)
	if err != nil {
		return nil, err
	}
	out.AdminPagination = adminParsePagination(h)
	if out.Clients == nil {
		out.Clients = []OAuthClient{}
	}
	return &out, nil
}

// CreateClient registers a new OAuth client. For confidential clients the
// returned ClientSecret is only available in this response.
func (o *AdminOAuthAPI) CreateClient(ctx context.Context, params AdminCreateOAuthClientParams) (*OAuthClient, error) {
	var out OAuthClient
	if _, err := o.c.adminRequest(ctx, &transport.Request{Method: http.MethodPost, Path: "/admin/oauth/clients", Body: params}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetClient returns the OAuth client with the given client ID.
func (o *AdminOAuthAPI) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	p, err := adminClientPath(clientID)
	if err != nil {
		return nil, err
	}
	var out OAuthClient
	if _, err := o.c.adminRequest(ctx, &transport.Request{Method: http.MethodGet, Path: p}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateClient updates the OAuth client with the given client ID.
func (o *AdminOAuthAPI) UpdateClient(ctx context.Context, clientID string, params AdminUpdateOAuthClientParams) (*OAuthClient, error) {
	p, err := adminClientPath(clientID)
	if err != nil {
		return nil, err
	}
	var out OAuthClient
	if _, err := o.c.adminRequest(ctx, &transport.Request{Method: http.MethodPut, Path: p, Body: params}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteClient deletes the OAuth client with the given client ID.
func (o *AdminOAuthAPI) DeleteClient(ctx context.Context, clientID string) error {
	p, err := adminClientPath(clientID)
	if err != nil {
		return err
	}
	_, err = o.c.adminRequest(ctx, &transport.Request{Method: http.MethodDelete, Path: p}, nil)
	return err
}

// RegenerateClientSecret issues a new secret for a confidential OAuth
// client, invalidating the old one. The new secret is in the returned
// client's ClientSecret.
func (o *AdminOAuthAPI) RegenerateClientSecret(ctx context.Context, clientID string) (*OAuthClient, error) {
	p, err := adminClientPath(clientID)
	if err != nil {
		return nil, err
	}
	var out OAuthClient
	if _, err := o.c.adminRequest(ctx, &transport.Request{Method: http.MethodPost, Path: p + "/regenerate_secret"}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
