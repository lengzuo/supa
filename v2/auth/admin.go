package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// AdminAPI is the Auth admin API (GoTrueAdminApi in auth-js). Every call is
// authorized with the Client's API key, which must be a service-role or
// secret key. Never use it with a key that is exposed to end users.
//
// An *AdminAPI is safe for concurrent use.
type AdminAPI struct {
	c *Client
}

// Admin returns the admin API. It requires the Client to be configured with
// a service-role (or sb_secret_) key.
func (c *Client) Admin() *AdminAPI { return &AdminAPI{c: c} }

// MFA returns the admin MFA API (auth-js admin.mfa).
func (a *AdminAPI) MFA() *AdminMFAAPI { return &AdminMFAAPI{c: a.c} }

// OAuth returns the admin OAuth client API (auth-js admin.oauth).
func (a *AdminAPI) OAuth() *AdminOAuthAPI { return &AdminOAuthAPI{c: a.c} }

// CustomProviders returns the admin custom OAuth/OIDC provider API
// (auth-js admin.customProviders).
func (a *AdminAPI) CustomProviders() *AdminCustomProviderAPI {
	return &AdminCustomProviderAPI{c: a.c}
}

// Passkey returns the admin passkey API (auth-js admin.passkey).
func (a *AdminAPI) Passkey() *AdminPasskeyAPI { return &AdminPasskeyAPI{c: a.c} }

// adminUUIDPattern matches the UUIDs GoTrue uses for users, factors and
// passkeys (auth-js validateUUID).
var adminUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// adminValidateUUID rejects v client-side when it is not a UUID, so a
// malformed ID can never alter the request path.
func adminValidateUUID(name, v string) error {
	if !adminUUIDPattern.MatchString(v) {
		return fmt.Errorf("%w: %s must be a UUID", ErrInvalidArgument, name)
	}
	return nil
}

// adminRequest sends an admin request authorized with the API key and
// returns the response headers.
func (c *Client) adminRequest(ctx context.Context, req *transport.Request, out any) (http.Header, error) {
	// Admin calls are authorized with the API key (service role / secret
	// key), never with a stored user session. A custom Authorization header
	// in Config.Headers wins, matching auth-js where admin headers are
	// {Authorization: Bearer <key>, ...custom headers}. The transport gives
	// a per-request Token precedence over headers, so only set it when the
	// caller has not configured their own Authorization header.
	if !c.customAuth && req.Header.Get("Authorization") == "" {
		req.Token = c.cfg.APIKey
	}
	h, err := c.t.DoJSON(ctx, req, out)
	return h, toError(err)
}

// AdminSignOutScope selects which sessions AdminAPI.SignOut revokes.
type AdminSignOutScope string

const (
	// AdminSignOutScopeGlobal revokes every session of the user.
	AdminSignOutScopeGlobal AdminSignOutScope = "global"
	// AdminSignOutScopeLocal revokes only the session the JWT belongs to.
	AdminSignOutScopeLocal AdminSignOutScope = "local"
	// AdminSignOutScopeOthers revokes every session except the JWT's own.
	AdminSignOutScopeOthers AdminSignOutScope = "others"
)

// SignOut revokes the sessions of the user who owns jwt (an access token).
// An empty scope means AdminSignOutScopeGlobal. The request is authorized
// with jwt itself, not the API key.
func (a *AdminAPI) SignOut(ctx context.Context, jwt string, scope AdminSignOutScope) error {
	if scope == "" {
		scope = AdminSignOutScopeGlobal
	}
	switch scope {
	case AdminSignOutScopeGlobal, AdminSignOutScopeLocal, AdminSignOutScopeOthers:
	default:
		return fmt.Errorf("%w: scope must be one of global, local, others", ErrInvalidArgument)
	}
	if strings.TrimSpace(jwt) == "" {
		return fmt.Errorf("%w: jwt is required", ErrInvalidArgument)
	}
	req := &transport.Request{
		Method: http.MethodPost,
		Path:   "/logout",
		Query:  url.Values{"scope": {string(scope)}},
		Header: http.Header{transport.HeaderAuthorization: {"Bearer " + jwt}},
	}
	return a.c.request(ctx, req, nil)
}

// AdminInviteUserByEmailOptions are optional settings for
// AdminAPI.InviteUserByEmail.
type AdminInviteUserByEmailOptions struct {
	// Data is stored in the user's user_metadata.
	Data map[string]any
	// RedirectTo is the URL the invite link redirects to. It must be in the
	// project's redirect allow list.
	RedirectTo string
}

// InviteUserByEmail sends an invite link to email and returns the invited
// user. opts may be nil.
func (a *AdminAPI) InviteUserByEmail(ctx context.Context, email string, opts *AdminInviteUserByEmailOptions) (*User, error) {
	if opts == nil {
		opts = &AdminInviteUserByEmailOptions{}
	}
	body := struct {
		Email string         `json:"email"`
		Data  map[string]any `json:"data,omitempty"`
	}{Email: email, Data: opts.Data}
	req := &transport.Request{Method: http.MethodPost, Path: "/invite", Body: body, Query: adminRedirectQuery(opts.RedirectTo)}
	return a.c.adminUser(ctx, req)
}

func adminRedirectQuery(redirectTo string) url.Values {
	if redirectTo == "" {
		return nil
	}
	return url.Values{"redirect_to": {redirectTo}}
}

// adminUser sends req and decodes a user, accepting both a bare user
// object and one wrapped in {"user": ...}.
func (c *Client) adminUser(ctx context.Context, req *transport.Request) (*User, error) {
	var raw json.RawMessage
	if _, err := c.adminRequest(ctx, req, &raw); err != nil {
		return nil, err
	}
	return adminDecodeUser(raw)
}

func adminDecodeUser(raw json.RawMessage) (*User, error) {
	if isEmptyJSON(raw) {
		return nil, errors.New("auth: decode user: empty response body")
	}
	var wrapped struct {
		User json.RawMessage `json:"user"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("auth: decode user: %w", err)
	}
	if len(wrapped.User) > 0 && string(wrapped.User) != "null" {
		raw = wrapped.User
	}
	var u User
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, fmt.Errorf("auth: decode user: %w", err)
	}
	return &u, nil
}

// AdminGenerateLinkType is the kind of link AdminAPI.GenerateLink creates.
type AdminGenerateLinkType string

const (
	// AdminGenerateLinkTypeSignup creates a sign-up confirmation link.
	// Email and Password are required.
	AdminGenerateLinkTypeSignup AdminGenerateLinkType = "signup"
	// AdminGenerateLinkTypeInvite creates an invite link.
	AdminGenerateLinkTypeInvite AdminGenerateLinkType = "invite"
	// AdminGenerateLinkTypeMagicLink creates a magic sign-in link.
	AdminGenerateLinkTypeMagicLink AdminGenerateLinkType = "magiclink"
	// AdminGenerateLinkTypeRecovery creates a password recovery link.
	AdminGenerateLinkTypeRecovery AdminGenerateLinkType = "recovery"
	// AdminGenerateLinkTypeEmailChangeCurrent creates the email change link
	// sent to the current address. NewEmail is required.
	AdminGenerateLinkTypeEmailChangeCurrent AdminGenerateLinkType = "email_change_current"
	// AdminGenerateLinkTypeEmailChangeNew creates the email change link sent
	// to the new address. NewEmail is required.
	AdminGenerateLinkTypeEmailChangeNew AdminGenerateLinkType = "email_change_new"
)

// AdminGenerateLinkParams are the inputs to AdminAPI.GenerateLink.
type AdminGenerateLinkParams struct {
	// Type is the kind of link. Required.
	Type AdminGenerateLinkType `json:"type"`
	// Email is the user's email. Required.
	Email string `json:"email"`
	// Password is required for AdminGenerateLinkTypeSignup.
	Password string `json:"password,omitempty"`
	// NewEmail is required for the email change types.
	NewEmail string `json:"new_email,omitempty"`
	// Data is stored in user_metadata (signup, invite and magiclink only).
	Data map[string]any `json:"data,omitempty"`
	// RedirectTo is appended to the generated link. Sent as the
	// redirect_to query parameter.
	RedirectTo string `json:"-"`
}

// AdminGenerateLinkProperties describe a link produced by GenerateLink.
type AdminGenerateLinkProperties struct {
	// ActionLink is the link to send to the user.
	ActionLink string `json:"action_link"`
	// EmailOTP is the raw email OTP, for OTP-based verification.
	EmailOTP string `json:"email_otp"`
	// HashedToken is the hashed token in the action link.
	HashedToken string `json:"hashed_token"`
	// RedirectTo is the redirect URL in the action link.
	RedirectTo string `json:"redirect_to"`
	// VerificationType is the link's verification type.
	VerificationType AdminGenerateLinkType `json:"verification_type"`
}

// AdminGenerateLinkResponse is returned by AdminAPI.GenerateLink.
type AdminGenerateLinkResponse struct {
	Properties AdminGenerateLinkProperties
	User       *User
}

// GenerateLink generates an email link (signup, invite, magic link,
// recovery or email change) without sending it, so it can be delivered by
// a custom email system.
func (a *AdminAPI) GenerateLink(ctx context.Context, params AdminGenerateLinkParams) (*AdminGenerateLinkResponse, error) {
	req := &transport.Request{
		Method: http.MethodPost,
		Path:   "/admin/generate_link",
		Body:   params,
		Query:  adminRedirectQuery(params.RedirectTo),
	}
	var raw json.RawMessage
	if _, err := a.c.adminRequest(ctx, req, &raw); err != nil {
		return nil, err
	}
	if isEmptyJSON(raw) {
		return nil, errors.New("auth: decode generate_link response: empty body")
	}
	out := &AdminGenerateLinkResponse{}
	if err := json.Unmarshal(raw, &out.Properties); err != nil {
		return nil, fmt.Errorf("auth: decode generate_link response: %w", err)
	}
	// The link properties (secrets such as the OTP and hashed token) belong
	// to Properties only: strip them from the user payload before decoding,
	// so they do not linger in User.Raw (auth-js _generateLinkResponse).
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("auth: decode generate_link response: %w", err)
	}
	for _, k := range []string{"action_link", "email_otp", "hashed_token", "redirect_to", "verification_type"} {
		delete(fields, k)
	}
	userJSON, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("auth: decode generate_link response: %w", err)
	}
	var u User
	if err := json.Unmarshal(userJSON, &u); err != nil {
		return nil, fmt.Errorf("auth: decode generate_link response: %w", err)
	}
	out.User = &u
	return out, nil
}

// AdminUserAttributes are the fields an admin can set when creating or
// updating a user. Only non-zero fields are sent.
type AdminUserAttributes struct {
	// Email is the user's email.
	Email string `json:"email,omitempty"`
	// Phone is the user's phone number.
	Phone string `json:"phone,omitempty"`
	// Password is the user's password.
	Password string `json:"password,omitempty"`
	// CurrentPassword is the user's current password, when required.
	CurrentPassword string `json:"current_password,omitempty"`
	// Nonce is a reauthentication nonce, when required.
	Nonce string `json:"nonce,omitempty"`
	// UserMetadata maps to auth.users.raw_user_meta_data.
	UserMetadata map[string]any `json:"user_metadata,omitempty"`
	// AppMetadata maps to auth.users.raw_app_meta_data.
	AppMetadata map[string]any `json:"app_metadata,omitempty"`
	// EmailConfirm marks the email as confirmed (true) or unconfirmed
	// (false). Nil leaves it unchanged.
	EmailConfirm *bool `json:"email_confirm,omitempty"`
	// PhoneConfirm marks the phone as confirmed (true) or unconfirmed
	// (false). Nil leaves it unchanged.
	PhoneConfirm *bool `json:"phone_confirm,omitempty"`
	// BanDuration bans the user for a Go-style duration such as "24h", or
	// lifts a ban with "none".
	BanDuration string `json:"ban_duration,omitempty"`
	// Role is the role claim of the user's access tokens.
	Role string `json:"role,omitempty"`
	// PasswordHash imports an existing bcrypt, scrypt (firebase) or argon2
	// password hash.
	PasswordHash string `json:"password_hash,omitempty"`
	// ID overrides the generated user ID (create only).
	ID string `json:"id,omitempty"`
}

// CreateUser creates a user. It does not send a confirmation email.
func (a *AdminAPI) CreateUser(ctx context.Context, attrs AdminUserAttributes) (*User, error) {
	return a.c.adminUser(ctx, &transport.Request{Method: http.MethodPost, Path: "/admin/users", Body: attrs})
}

// AdminPageParams select a page of a paginated admin list. Zero values
// use the server defaults (page 1, 50 per page).
type AdminPageParams struct {
	// Page is the 1-based page number.
	Page int
	// PerPage is the number of items per page.
	PerPage int
}

func (p *AdminPageParams) query() url.Values {
	// auth-js always sends both parameters, empty when unset.
	q := url.Values{"page": {""}, "per_page": {""}}
	if p != nil {
		if p.Page != 0 {
			q.Set("page", strconv.Itoa(p.Page))
		}
		if p.PerPage != 0 {
			q.Set("per_page", strconv.Itoa(p.PerPage))
		}
	}
	return q
}

// AdminPagination is the pagination state parsed from the Link and
// X-Total-Count response headers of a list call.
type AdminPagination struct {
	// NextPage is the next page number, or 0 when this is the last page.
	NextPage int
	// LastPage is the last page number, or 0 when unknown.
	LastPage int
	// Total is the total number of items, or 0 when unknown.
	Total int
}

// adminParsePagination parses headers such as
//
//	Link: </admin/users?page=2&per_page=50>; rel="next", </admin/users?page=4&per_page=50>; rel="last"
//	X-Total-Count: 170
func adminParsePagination(h http.Header) AdminPagination {
	var p AdminPagination
	if h == nil {
		return p
	}
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("X-Total-Count"))); err == nil {
		p.Total = n
	}
	for _, link := range strings.Split(h.Get("Link"), ",") {
		target, params, ok := strings.Cut(link, ";")
		if !ok {
			continue
		}
		target = strings.TrimSpace(target)
		target = strings.TrimSuffix(strings.TrimPrefix(target, "<"), ">")
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		page, err := strconv.Atoi(u.Query().Get("page"))
		if err != nil {
			continue
		}
		var rel string
		for _, param := range strings.Split(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "rel") {
				rel = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
		switch rel {
		case "next":
			p.NextPage = page
		case "last":
			p.LastPage = page
		}
	}
	return p
}

// AdminListUsersResponse is one page of users.
type AdminListUsersResponse struct {
	Users []User `json:"users"`
	Aud   string `json:"aud"`
	AdminPagination
}

// ListUsers returns a page of users. params may be nil.
func (a *AdminAPI) ListUsers(ctx context.Context, params *AdminPageParams) (*AdminListUsersResponse, error) {
	var out AdminListUsersResponse
	h, err := a.c.adminRequest(ctx, &transport.Request{Method: http.MethodGet, Path: "/admin/users", Query: params.query()}, &out)
	if err != nil {
		return nil, err
	}
	out.AdminPagination = adminParsePagination(h)
	if out.Users == nil {
		out.Users = []User{}
	}
	return &out, nil
}

// GetUserByID returns the user with the given ID, which must be a UUID.
func (a *AdminAPI) GetUserByID(ctx context.Context, uid string) (*User, error) {
	if err := adminValidateUUID("user ID", uid); err != nil {
		return nil, err
	}
	return a.c.adminUser(ctx, &transport.Request{Method: http.MethodGet, Path: "/admin/users/" + pathSegment(uid)})
}

// UpdateUserByID updates the user with the given ID, which must be a UUID.
func (a *AdminAPI) UpdateUserByID(ctx context.Context, uid string, attrs AdminUserAttributes) (*User, error) {
	if err := adminValidateUUID("user ID", uid); err != nil {
		return nil, err
	}
	return a.c.adminUser(ctx, &transport.Request{Method: http.MethodPut, Path: "/admin/users/" + pathSegment(uid), Body: attrs})
}

// DeleteUser deletes the user with the given ID, which must be a UUID.
// When shouldSoftDelete is true the user is soft-deleted: it is marked
// deleted and its personal data is obfuscated, but the row is kept.
func (a *AdminAPI) DeleteUser(ctx context.Context, uid string, shouldSoftDelete bool) (*User, error) {
	if err := adminValidateUUID("user ID", uid); err != nil {
		return nil, err
	}
	body := struct {
		ShouldSoftDelete bool `json:"should_soft_delete"`
	}{shouldSoftDelete}
	return a.c.adminUser(ctx, &transport.Request{Method: http.MethodDelete, Path: "/admin/users/" + pathSegment(uid), Body: body})
}

// AdminMFAAPI manages users' MFA factors. Obtain it with AdminAPI.MFA.
type AdminMFAAPI struct {
	c *Client
}

// ListFactors returns every MFA factor of the user, whose ID must be a UUID.
func (m *AdminMFAAPI) ListFactors(ctx context.Context, userID string) ([]Factor, error) {
	if err := adminValidateUUID("user ID", userID); err != nil {
		return nil, err
	}
	var factors []Factor
	req := &transport.Request{Method: http.MethodGet, Path: "/admin/users/" + pathSegment(userID) + "/factors"}
	if _, err := m.c.adminRequest(ctx, req, &factors); err != nil {
		return nil, err
	}
	if factors == nil {
		factors = []Factor{}
	}
	return factors, nil
}

// DeleteFactor deletes the factor factorID of the user userID (both UUIDs)
// and returns the deleted factor as reported by the server (at least its
// ID).
func (m *AdminMFAAPI) DeleteFactor(ctx context.Context, userID, factorID string) (*Factor, error) {
	if err := adminValidateUUID("user ID", userID); err != nil {
		return nil, err
	}
	if err := adminValidateUUID("factor ID", factorID); err != nil {
		return nil, err
	}
	var f Factor
	req := &transport.Request{Method: http.MethodDelete, Path: "/admin/users/" + pathSegment(userID) + "/factors/" + pathSegment(factorID)}
	if _, err := m.c.adminRequest(ctx, req, &f); err != nil {
		return nil, err
	}
	return &f, nil
}
