package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

const (
	adminTestPasskeyID  = "2b3c4d5e-6f70-4812-9a3b-4c5d6e7f8091"
	adminTestClientJSON = `{"client_id":"cl_123","client_name":"Acme","client_secret":"sec_abc","client_type":"confidential","token_endpoint_auth_method":"client_secret_basic","registration_type":"manual","client_uri":"https://acme.example","redirect_uris":["https://acme.example/cb"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"openid email","created_at":"2025-01-01T00:00:00Z","updated_at":"2025-01-02T00:00:00Z"}`
	adminTestProvJSON   = `{"id":"p1","provider_type":"oidc","identifier":"custom:acme","name":"Acme","client_id":"cid","scopes":["openid"],"pkce_enabled":true,"enabled":true,"issuer":"https://id.acme.example","discovery_document":{"issuer":"https://id.acme.example","authorization_endpoint":"https://id.acme.example/auth","token_endpoint":"https://id.acme.example/token","jwks_uri":"https://id.acme.example/jwks"},"attribute_mapping":{"email":"mail"},"created_at":"2025-01-01T00:00:00Z","updated_at":"2025-01-01T00:00:00Z"}`
)

func adminCheckClient(t *testing.T, cl *OAuthClient) {
	t.Helper()
	if cl.ClientID != "cl_123" || cl.ClientSecret != "sec_abc" || cl.ClientType != OAuthClientTypeConfidential ||
		cl.TokenEndpointAuthMethod != OAuthTokenEndpointAuthClientSecretBasic || cl.RegistrationType != OAuthClientRegistrationManual ||
		len(cl.RedirectURIs) != 1 || len(cl.GrantTypes) != 2 || cl.CreatedAt.IsZero() {
		t.Errorf("client = %+v", cl)
	}
}

// upstream: auth-js src/GoTrueAdminApi.ts _listOAuthClients
func TestAdminOAuthListClients(t *testing.T) {
	hdr := http.Header{"X-Total-Count": {"3"}, "Link": {`</admin/oauth/clients?page=2&per_page=2>; rel="next", </admin/oauth/clients?page=2&per_page=2>; rel="last"`}}
	c, got := adminTestServer(t, http.StatusOK, `{"aud":"authenticated","clients":[`+adminTestClientJSON+`]}`, hdr)
	out, err := c.Admin().OAuth().ListClients(context.Background(), &AdminPageParams{Page: 1, PerPage: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Clients) != 1 || out.NextPage != 2 || out.LastPage != 2 || out.Total != 3 {
		t.Errorf("out = %+v", out)
	}
	adminCheckClient(t, &out.Clients[0])
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/oauth/clients", "page=1&per_page=2", adminTestKey)

	body, h := adminAPIErrorBody("oauth_server_disabled", "disabled")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().OAuth().ListClients(context.Background(), nil)
	adminWantAPIError(t, err, 404, "oauth_server_disabled")
}

// upstream: auth-js src/GoTrueAdminApi.ts _createOAuthClient
func TestAdminOAuthCreateClient(t *testing.T) {
	c, got := adminTestServer(t, http.StatusCreated, adminTestClientJSON, nil)
	cl, err := c.Admin().OAuth().CreateClient(context.Background(), AdminCreateOAuthClientParams{
		ClientName:   "Acme",
		RedirectURIs: []string{"https://acme.example/cb"},
		Scope:        "openid email",
	})
	if err != nil {
		t.Fatal(err)
	}
	adminCheckClient(t, cl)
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/admin/oauth/clients", "", adminTestKey)
	adminJSONBody(t, r, `{"client_name":"Acme","redirect_uris":["https://acme.example/cb"],"scope":"openid email"}`)

	body, h := adminAPIErrorBody("validation_failed", "invalid redirect_uris")
	c, _ = adminTestServer(t, http.StatusBadRequest, body, h)
	_, err = c.Admin().OAuth().CreateClient(context.Background(), AdminCreateOAuthClientParams{ClientName: "x"})
	adminWantAPIError(t, err, 400, "validation_failed")
}

// upstream: auth-js src/GoTrueAdminApi.ts _getOAuthClient
func TestAdminOAuthGetClient(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestClientJSON, nil)
	cl, err := c.Admin().OAuth().GetClient(context.Background(), "cl_123")
	if err != nil {
		t.Fatal(err)
	}
	adminCheckClient(t, cl)
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/oauth/clients/cl_123", "", adminTestKey)

	// User-supplied IDs are path-escaped.
	c, got = adminTestServer(t, http.StatusOK, adminTestClientJSON, nil)
	if _, err := c.Admin().OAuth().GetClient(context.Background(), "../users"); err != nil {
		t.Fatal(err)
	}
	if p := adminOne(t, got).Path; p != "/auth/v1/admin/oauth/clients/..%2Fusers" {
		t.Errorf("path = %s", p)
	}
	if _, err := c.Admin().OAuth().GetClient(context.Background(), ""); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}

	body, h := adminAPIErrorBody("oauth_client_not_found", "not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().OAuth().GetClient(context.Background(), "nope")
	adminWantAPIError(t, err, 404, "oauth_client_not_found")
}

// upstream: auth-js src/GoTrueAdminApi.ts _updateOAuthClient
func TestAdminOAuthUpdateClient(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestClientJSON, nil)
	cl, err := c.Admin().OAuth().UpdateClient(context.Background(), "cl_123", AdminUpdateOAuthClientParams{
		ClientName: "Acme 2", LogoURI: "https://acme.example/logo.png",
	})
	if err != nil {
		t.Fatal(err)
	}
	adminCheckClient(t, cl)
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPut, "/auth/v1/admin/oauth/clients/cl_123", "", adminTestKey)
	adminJSONBody(t, r, `{"client_name":"Acme 2","logo_uri":"https://acme.example/logo.png"}`)

	body, h := adminAPIErrorBody("oauth_client_not_found", "not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().OAuth().UpdateClient(context.Background(), "cl_123", AdminUpdateOAuthClientParams{})
	adminWantAPIError(t, err, 404, "oauth_client_not_found")
}

// upstream: auth-js src/GoTrueAdminApi.ts _deleteOAuthClient
func TestAdminOAuthDeleteClient(t *testing.T) {
	c, got := adminTestServer(t, http.StatusNoContent, "", nil)
	if err := c.Admin().OAuth().DeleteClient(context.Background(), "cl_123"); err != nil {
		t.Fatal(err)
	}
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodDelete, "/auth/v1/admin/oauth/clients/cl_123", "", adminTestKey)
	if len(r.Body) != 0 {
		t.Errorf("unexpected body %q", r.Body)
	}
	body, h := adminAPIErrorBody("oauth_client_not_found", "not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	adminWantAPIError(t, c.Admin().OAuth().DeleteClient(context.Background(), "cl_123"), 404, "oauth_client_not_found")
}

// upstream: auth-js src/GoTrueAdminApi.ts _regenerateOAuthClientSecret
func TestAdminOAuthRegenerateClientSecret(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestClientJSON, nil)
	cl, err := c.Admin().OAuth().RegenerateClientSecret(context.Background(), "cl_123")
	if err != nil {
		t.Fatal(err)
	}
	adminCheckClient(t, cl)
	adminCheck(t, adminOne(t, got), http.MethodPost, "/auth/v1/admin/oauth/clients/cl_123/regenerate_secret", "", adminTestKey)

	body, h := adminAPIErrorBody("validation_failed", "public client")
	c, _ = adminTestServer(t, http.StatusBadRequest, body, h)
	_, err = c.Admin().OAuth().RegenerateClientSecret(context.Background(), "cl_123")
	adminWantAPIError(t, err, 400, "validation_failed")
}

func adminCheckProvider(t *testing.T, p *AdminCustomProvider) {
	t.Helper()
	if p.ID != "p1" || p.ProviderType != AdminCustomProviderOIDC || p.Identifier != "custom:acme" || !p.PKCEEnabled || !p.Enabled ||
		p.DiscoveryDocument == nil || p.DiscoveryDocument.JWKSURI != "https://id.acme.example/jwks" || p.AttributeMapping["email"] != "mail" {
		t.Errorf("provider = %+v", p)
	}
}

// upstream: auth-js src/GoTrueAdminApi.ts _listCustomProviders
func TestAdminListProviders(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, `{"providers":[`+adminTestProvJSON+`]}`, nil)
	ps, err := c.Admin().CustomProviders().ListProviders(context.Background(), &AdminListCustomProvidersParams{Type: AdminCustomProviderOIDC})
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 {
		t.Fatalf("providers = %+v", ps)
	}
	adminCheckProvider(t, &ps[0])
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/custom-providers", "type=oidc", adminTestKey)

	c, got = adminTestServer(t, http.StatusOK, `{}`, nil)
	ps, err = c.Admin().CustomProviders().ListProviders(context.Background(), nil)
	if err != nil || ps == nil || len(ps) != 0 {
		t.Errorf("ps = %v err = %v", ps, err)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/custom-providers", "", adminTestKey)

	body, h := adminAPIErrorBody("no_authorization", "forbidden")
	c, _ = adminTestServer(t, http.StatusForbidden, body, h)
	_, err = c.Admin().CustomProviders().ListProviders(context.Background(), nil)
	adminWantAPIError(t, err, 403, "no_authorization")
}

// upstream: auth-js src/GoTrueAdminApi.ts _createCustomProvider
func TestAdminCreateProvider(t *testing.T) {
	c, got := adminTestServer(t, http.StatusCreated, adminTestProvJSON, nil)
	on := true
	p, err := c.Admin().CustomProviders().CreateProvider(context.Background(), AdminCreateCustomProviderParams{
		ProviderType: AdminCustomProviderOIDC, Identifier: "custom:acme", Name: "Acme",
		ClientID: "cid", ClientSecret: "csecret", Issuer: "https://id.acme.example",
		PKCEEnabled: &on, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adminCheckProvider(t, p)
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/admin/custom-providers", "", adminTestKey)
	adminJSONBody(t, r, `{"provider_type":"oidc","identifier":"custom:acme","name":"Acme","client_id":"cid","client_secret":"csecret","scopes":["openid"],"pkce_enabled":true,"issuer":"https://id.acme.example"}`)

	body, h := adminAPIErrorBody("validation_failed", "dup")
	c, _ = adminTestServer(t, http.StatusBadRequest, body, h)
	_, err = c.Admin().CustomProviders().CreateProvider(context.Background(), AdminCreateCustomProviderParams{})
	adminWantAPIError(t, err, 400, "validation_failed")
}

// upstream: auth-js src/GoTrueAdminApi.ts _getCustomProvider
func TestAdminGetProvider(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestProvJSON, nil)
	p, err := c.Admin().CustomProviders().GetProvider(context.Background(), "custom:acme")
	if err != nil {
		t.Fatal(err)
	}
	adminCheckProvider(t, p)
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/custom-providers/custom:acme", "", adminTestKey)
	if _, err := c.Admin().CustomProviders().GetProvider(context.Background(), ""); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	body, h := adminAPIErrorBody("provider_not_found", "nf")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().CustomProviders().GetProvider(context.Background(), "custom:x")
	adminWantAPIError(t, err, 404, "provider_not_found")
}

// upstream: auth-js src/GoTrueAdminApi.ts _updateCustomProvider
func TestAdminUpdateProvider(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestProvJSON, nil)
	off := false
	p, err := c.Admin().CustomProviders().UpdateProvider(context.Background(), "custom:acme", AdminUpdateCustomProviderParams{
		Name: "Acme Inc", Enabled: &off, AuthorizationParams: map[string]string{"prompt": "consent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	adminCheckProvider(t, p)
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPut, "/auth/v1/admin/custom-providers/custom:acme", "", adminTestKey)
	adminJSONBody(t, r, `{"name":"Acme Inc","enabled":false,"authorization_params":{"prompt":"consent"}}`)

	body, h := adminAPIErrorBody("provider_not_found", "nf")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().CustomProviders().UpdateProvider(context.Background(), "custom:x", AdminUpdateCustomProviderParams{})
	adminWantAPIError(t, err, 404, "provider_not_found")
}

// upstream: auth-js src/GoTrueAdminApi.ts _deleteCustomProvider
func TestAdminDeleteProvider(t *testing.T) {
	c, got := adminTestServer(t, http.StatusNoContent, "", nil)
	if err := c.Admin().CustomProviders().DeleteProvider(context.Background(), "custom:acme"); err != nil {
		t.Fatal(err)
	}
	adminCheck(t, adminOne(t, got), http.MethodDelete, "/auth/v1/admin/custom-providers/custom:acme", "", adminTestKey)
	if err := c.Admin().CustomProviders().DeleteProvider(context.Background(), ""); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	body, h := adminAPIErrorBody("provider_not_found", "nf")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	adminWantAPIError(t, c.Admin().CustomProviders().DeleteProvider(context.Background(), "custom:x"), 404, "provider_not_found")
}

// upstream: auth-js src/GoTrueAdminApi.ts _adminListPasskeys (test/passkey.methods.test.ts admin.passkey)
func TestAdminListPasskeys(t *testing.T) {
	resp := `[{"id":"` + adminTestPasskeyID + `","friendly_name":"MacBook","created_at":"2026-01-01T00:00:00Z","last_used_at":"2026-02-01T00:00:00Z"}]`
	c, got := adminTestServer(t, http.StatusOK, resp, nil)
	ps, err := c.Admin().Passkeys().ListPasskeys(context.Background(), adminTestUserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].ID != adminTestPasskeyID || ps[0].FriendlyName != "MacBook" || ps[0].LastUsedAt == nil {
		t.Errorf("passkeys = %+v", ps)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/users/"+adminTestUserID+"/passkeys", "", adminTestKey)

	if _, err := c.Admin().Passkeys().ListPasskeys(context.Background(), "not-a-uuid"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	if len(got()) != 1 {
		t.Error("invalid ID reached server")
	}
	body, h := adminAPIErrorBody(ErrorCodeUserNotFound, "nf")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().Passkeys().ListPasskeys(context.Background(), adminTestUserID)
	adminWantAPIError(t, err, 404, ErrorCodeUserNotFound)
}

// upstream: auth-js src/GoTrueAdminApi.ts _adminDeletePasskey (test/passkey.methods.test.ts admin.passkey)
func TestAdminDeletePasskey(t *testing.T) {
	c, got := adminTestServer(t, http.StatusNoContent, "", nil)
	if err := c.Admin().Passkeys().DeletePasskey(context.Background(), adminTestUserID, adminTestPasskeyID); err != nil {
		t.Fatal(err)
	}
	adminCheck(t, adminOne(t, got), http.MethodDelete, "/auth/v1/admin/users/"+adminTestUserID+"/passkeys/"+adminTestPasskeyID, "", adminTestKey)

	if err := c.Admin().Passkeys().DeletePasskey(context.Background(), adminTestUserID, "not-a-uuid"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	if len(got()) != 1 {
		t.Error("invalid ID reached server")
	}
	body, h := adminAPIErrorBody("passkey_not_found", "Passkey not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	adminWantAPIError(t, c.Admin().Passkeys().DeletePasskey(context.Background(), adminTestUserID, adminTestPasskeyID), 404, "passkey_not_found")
}
