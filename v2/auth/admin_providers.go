package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// AdminCustomProviderAPI manages custom OAuth2/OIDC sign-in providers.
// Obtain it with AdminAPI.CustomProviders.
type AdminCustomProviderAPI struct {
	c *Client
}

// AdminCustomProviderType is a custom provider's protocol.
type AdminCustomProviderType string

const (
	// AdminCustomProviderOAuth2 is a plain OAuth 2.0 provider.
	AdminCustomProviderOAuth2 AdminCustomProviderType = "oauth2"
	// AdminCustomProviderOIDC is an OpenID Connect provider.
	AdminCustomProviderOIDC AdminCustomProviderType = "oidc"
)

// AdminOIDCDiscoveryDocument is the cached OIDC discovery document of a
// custom OIDC provider.
type AdminOIDCDiscoveryDocument struct {
	Issuer                      string   `json:"issuer"`
	AuthorizationEndpoint       string   `json:"authorization_endpoint"`
	TokenEndpoint               string   `json:"token_endpoint"`
	JWKSURI                     string   `json:"jwks_uri"`
	UserinfoEndpoint            string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint          string   `json:"revocation_endpoint,omitempty"`
	SupportedScopes             []string `json:"supported_scopes,omitempty"`
	SupportedResponseTypes      []string `json:"supported_response_types,omitempty"`
	SupportedSubjectTypes       []string `json:"supported_subject_types,omitempty"`
	SupportedIDTokenSigningAlgs []string `json:"supported_id_token_signing_algs,omitempty"`
}

// AdminCustomProvider is a custom OAuth2/OIDC provider.
type AdminCustomProvider struct {
	ID                    string                      `json:"id"`
	ProviderType          AdminCustomProviderType     `json:"provider_type"`
	Identifier            string                      `json:"identifier"`
	Name                  string                      `json:"name"`
	ClientID              string                      `json:"client_id"`
	AcceptableClientIDs   []string                    `json:"acceptable_client_ids,omitempty"`
	Scopes                []string                    `json:"scopes,omitempty"`
	CustomClaimsAllowlist []string                    `json:"custom_claims_allowlist,omitempty"`
	PKCEEnabled           bool                        `json:"pkce_enabled,omitempty"`
	AttributeMapping      map[string]any              `json:"attribute_mapping,omitempty"`
	AuthorizationParams   map[string]string           `json:"authorization_params,omitempty"`
	Enabled               bool                        `json:"enabled,omitempty"`
	EmailOptional         bool                        `json:"email_optional,omitempty"`
	Issuer                string                      `json:"issuer,omitempty"`
	DiscoveryURL          string                      `json:"discovery_url,omitempty"`
	SkipNonceCheck        bool                        `json:"skip_nonce_check,omitempty"`
	AuthorizationURL      string                      `json:"authorization_url,omitempty"`
	TokenURL              string                      `json:"token_url,omitempty"`
	UserinfoURL           string                      `json:"userinfo_url,omitempty"`
	JWKSURI               string                      `json:"jwks_uri,omitempty"`
	DiscoveryDocument     *AdminOIDCDiscoveryDocument `json:"discovery_document,omitempty"`
	CreatedAt             time.Time                   `json:"created_at"`
	UpdatedAt             time.Time                   `json:"updated_at"`
}

// AdminCreateCustomProviderParams are the inputs to
// AdminCustomProviderAPI.CreateProvider.
type AdminCreateCustomProviderParams struct {
	// ProviderType is oauth2 or oidc. Required.
	ProviderType AdminCustomProviderType `json:"provider_type"`
	// Identifier is the unique provider identifier, e.g. "custom:acme".
	// Required.
	Identifier string `json:"identifier"`
	// Name is the display name. Required.
	Name string `json:"name"`
	// ClientID is the OAuth client ID issued by the provider. Required.
	ClientID string `json:"client_id"`
	// ClientSecret is the OAuth client secret issued by the provider.
	// Required.
	ClientSecret          string            `json:"client_secret"`
	AcceptableClientIDs   []string          `json:"acceptable_client_ids,omitempty"`
	Scopes                []string          `json:"scopes,omitempty"`
	CustomClaimsAllowlist []string          `json:"custom_claims_allowlist,omitempty"`
	PKCEEnabled           *bool             `json:"pkce_enabled,omitempty"`
	AttributeMapping      map[string]any    `json:"attribute_mapping,omitempty"`
	AuthorizationParams   map[string]string `json:"authorization_params,omitempty"`
	Enabled               *bool             `json:"enabled,omitempty"`
	EmailOptional         *bool             `json:"email_optional,omitempty"`
	Issuer                string            `json:"issuer,omitempty"`
	DiscoveryURL          string            `json:"discovery_url,omitempty"`
	SkipNonceCheck        *bool             `json:"skip_nonce_check,omitempty"`
	AuthorizationURL      string            `json:"authorization_url,omitempty"`
	TokenURL              string            `json:"token_url,omitempty"`
	UserinfoURL           string            `json:"userinfo_url,omitempty"`
	JWKSURI               string            `json:"jwks_uri,omitempty"`
}

// AdminUpdateCustomProviderParams are the inputs to
// AdminCustomProviderAPI.UpdateProvider. Only non-zero fields are sent;
// the provider type and identifier cannot be changed.
type AdminUpdateCustomProviderParams struct {
	Name                  string            `json:"name,omitempty"`
	ClientID              string            `json:"client_id,omitempty"`
	ClientSecret          string            `json:"client_secret,omitempty"`
	AcceptableClientIDs   []string          `json:"acceptable_client_ids,omitempty"`
	Scopes                []string          `json:"scopes,omitempty"`
	CustomClaimsAllowlist []string          `json:"custom_claims_allowlist,omitempty"`
	PKCEEnabled           *bool             `json:"pkce_enabled,omitempty"`
	AttributeMapping      map[string]any    `json:"attribute_mapping,omitempty"`
	AuthorizationParams   map[string]string `json:"authorization_params,omitempty"`
	Enabled               *bool             `json:"enabled,omitempty"`
	EmailOptional         *bool             `json:"email_optional,omitempty"`
	Issuer                string            `json:"issuer,omitempty"`
	DiscoveryURL          string            `json:"discovery_url,omitempty"`
	SkipNonceCheck        *bool             `json:"skip_nonce_check,omitempty"`
	AuthorizationURL      string            `json:"authorization_url,omitempty"`
	TokenURL              string            `json:"token_url,omitempty"`
	UserinfoURL           string            `json:"userinfo_url,omitempty"`
	JWKSURI               string            `json:"jwks_uri,omitempty"`
}

// AdminListCustomProvidersParams filter AdminCustomProviderAPI.ListProviders.
type AdminListCustomProvidersParams struct {
	// Type limits the result to one provider type. Empty lists all.
	Type AdminCustomProviderType
}

func adminProviderPath(identifier string) (string, error) {
	if identifier == "" {
		return "", fmt.Errorf("%w: provider identifier is required", ErrInvalidArgument)
	}
	return "/admin/custom-providers/" + url.PathEscape(identifier), nil
}

// ListProviders returns the custom providers. params may be nil.
func (p *AdminCustomProviderAPI) ListProviders(ctx context.Context, params *AdminListCustomProvidersParams) ([]AdminCustomProvider, error) {
	q := url.Values{}
	if params != nil && params.Type != "" {
		q.Set("type", string(params.Type))
	}
	var out struct {
		Providers []AdminCustomProvider `json:"providers"`
	}
	if _, err := p.c.adminRequest(ctx, &transport.Request{Method: http.MethodGet, Path: "/admin/custom-providers", Query: q}, &out); err != nil {
		return nil, err
	}
	if out.Providers == nil {
		out.Providers = []AdminCustomProvider{}
	}
	return out.Providers, nil
}

// CreateProvider creates a custom provider.
func (p *AdminCustomProviderAPI) CreateProvider(ctx context.Context, params AdminCreateCustomProviderParams) (*AdminCustomProvider, error) {
	var out AdminCustomProvider
	if _, err := p.c.adminRequest(ctx, &transport.Request{Method: http.MethodPost, Path: "/admin/custom-providers", Body: params}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetProvider returns the custom provider with the given identifier.
func (p *AdminCustomProviderAPI) GetProvider(ctx context.Context, identifier string) (*AdminCustomProvider, error) {
	path, err := adminProviderPath(identifier)
	if err != nil {
		return nil, err
	}
	var out AdminCustomProvider
	if _, err := p.c.adminRequest(ctx, &transport.Request{Method: http.MethodGet, Path: path}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateProvider updates the custom provider with the given identifier.
func (p *AdminCustomProviderAPI) UpdateProvider(ctx context.Context, identifier string, params AdminUpdateCustomProviderParams) (*AdminCustomProvider, error) {
	path, err := adminProviderPath(identifier)
	if err != nil {
		return nil, err
	}
	var out AdminCustomProvider
	if _, err := p.c.adminRequest(ctx, &transport.Request{Method: http.MethodPut, Path: path, Body: params}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteProvider deletes the custom provider with the given identifier.
func (p *AdminCustomProviderAPI) DeleteProvider(ctx context.Context, identifier string) error {
	path, err := adminProviderPath(identifier)
	if err != nil {
		return err
	}
	_, err = p.c.adminRequest(ctx, &transport.Request{Method: http.MethodDelete, Path: path}, nil)
	return err
}
