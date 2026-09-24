package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// SignUpParams are the credentials for SignUp. Set exactly one of Email or
// Phone.
type SignUpParams struct {
	Email    string
	Phone    string
	Password string
	// Data is stored in the user's user_metadata.
	Data map[string]any
	// CaptchaToken is the captcha verification token, if captcha is enabled.
	CaptchaToken string
	// EmailRedirectTo is where the confirmation link redirects (email only).
	EmailRedirectTo string
	// Channel is the OTP channel for phone sign-ups: "sms" (default) or
	// "whatsapp".
	Channel string
}

// SignUp creates a new user (POST /signup). If email/phone confirmation is
// enabled the returned Session is nil until the user confirms; otherwise
// the session is stored and SIGNED_IN emitted. With FlowPKCE an email
// sign-up stores a code verifier for the confirmation redirect.
func (c *Client) SignUp(ctx context.Context, params SignUpParams) (*AuthResponse, error) {
	var body any
	var flow *pkceFlow
	var query url.Values
	switch {
	case params.Email != "":
		var err error
		if flow, err = c.maybeStartPKCE(ctx, false); err != nil {
			return nil, err
		}
		challenge, method := flowChallenge(flow)
		body = struct {
			Email               string             `json:"email"`
			Password            string             `json:"password"`
			Data                map[string]any     `json:"data"`
			Meta                gotrueMetaSecurity `json:"gotrue_meta_security"`
			CodeChallenge       *string            `json:"code_challenge"`
			CodeChallengeMethod *string            `json:"code_challenge_method"`
		}{params.Email, params.Password, orEmptyMap(params.Data), metaSecurity(params.CaptchaToken), challenge, method}
		query = redirectQuery(c.redirectWithFlowID(params.EmailRedirectTo, flow))
	case params.Phone != "":
		channel := params.Channel
		if channel == "" {
			channel = "sms"
		}
		body = struct {
			Phone    string             `json:"phone"`
			Password string             `json:"password"`
			Data     map[string]any     `json:"data"`
			Channel  string             `json:"channel"`
			Meta     gotrueMetaSecurity `json:"gotrue_meta_security"`
		}{params.Phone, params.Password, orEmptyMap(params.Data), channel, metaSecurity(params.CaptchaToken)}
	default:
		return nil, fmt.Errorf("%w: you must provide either an email or phone number and a password", ErrInvalidArgument)
	}
	resp, err := c.postSession(ctx, "/signup", query, "", body)
	if err != nil {
		c.removePKCEVerifier(ctx, flowIDOf(flow))
		return nil, err
	}
	if err := c.maybeCommit(ctx, resp, EventSignedIn); err != nil {
		return nil, err
	}
	return resp, nil
}

// SignInWithPasswordParams are the credentials for SignInWithPassword. Set
// exactly one of Email or Phone.
type SignInWithPasswordParams struct {
	Email        string
	Phone        string
	Password     string
	CaptchaToken string
}

// SignInWithPassword signs in with an email or phone and a password
// (POST /token?grant_type=password), stores the session and emits
// SIGNED_IN. AuthResponse.WeakPassword is set when the password no longer
// meets the strength policy.
func (c *Client) SignInWithPassword(ctx context.Context, params SignInWithPasswordParams) (*AuthResponse, error) {
	var body any
	switch {
	case params.Email != "":
		body = struct {
			Email    string             `json:"email"`
			Password string             `json:"password"`
			Meta     gotrueMetaSecurity `json:"gotrue_meta_security"`
		}{params.Email, params.Password, metaSecurity(params.CaptchaToken)}
	case params.Phone != "":
		body = struct {
			Phone    string             `json:"phone"`
			Password string             `json:"password"`
			Meta     gotrueMetaSecurity `json:"gotrue_meta_security"`
		}{params.Phone, params.Password, metaSecurity(params.CaptchaToken)}
	default:
		return nil, fmt.Errorf("%w: you must provide either an email or phone number and a password", ErrInvalidArgument)
	}
	return c.signInToken(ctx, "password", "", body, EventSignedIn)
}

// SignInWithOTPParams configure SignInWithOTP. Set exactly one of Email or
// Phone.
type SignInWithOTPParams struct {
	Email string
	Phone string
	// EmailRedirectTo is where the magic link redirects (email only).
	EmailRedirectTo string
	// ShouldCreateUser controls whether an unknown email/phone signs up a
	// new user. nil means true, as in supabase-js.
	ShouldCreateUser *bool
	// Data is stored in user_metadata when a user is created.
	Data         map[string]any
	CaptchaToken string
	// Channel is the phone OTP channel: "sms" (default) or "whatsapp".
	Channel string
}

// SignInWithOTP sends a magic link / one-time password to an email or
// phone (POST /otp). Complete the sign-in with VerifyOTP, or with
// ExchangeCodeForSession / GetSessionFromURL after the magic-link redirect.
// With FlowPKCE an email OTP stores a code verifier.
func (c *Client) SignInWithOTP(ctx context.Context, params SignInWithOTPParams) (*OTPResponse, error) {
	createUser := true
	if params.ShouldCreateUser != nil {
		createUser = *params.ShouldCreateUser
	}
	switch {
	case params.Email != "":
		flow, err := c.maybeStartPKCE(ctx, false)
		if err != nil {
			return nil, err
		}
		challenge, method := flowChallenge(flow)
		body := struct {
			Email               string             `json:"email"`
			Data                map[string]any     `json:"data"`
			CreateUser          bool               `json:"create_user"`
			Meta                gotrueMetaSecurity `json:"gotrue_meta_security"`
			CodeChallenge       *string            `json:"code_challenge"`
			CodeChallengeMethod *string            `json:"code_challenge_method"`
		}{params.Email, orEmptyMap(params.Data), createUser, metaSecurity(params.CaptchaToken), challenge, method}
		query := redirectQuery(c.redirectWithFlowID(params.EmailRedirectTo, flow))
		if err := c.call(ctx, http.MethodPost, "/otp", query, "", body, nil); err != nil {
			c.removePKCEVerifier(ctx, flowIDOf(flow))
			return nil, err
		}
		return &OTPResponse{}, nil
	case params.Phone != "":
		channel := params.Channel
		if channel == "" {
			channel = "sms"
		}
		body := struct {
			Phone      string             `json:"phone"`
			Data       map[string]any     `json:"data"`
			CreateUser bool               `json:"create_user"`
			Meta       gotrueMetaSecurity `json:"gotrue_meta_security"`
			Channel    string             `json:"channel"`
		}{params.Phone, orEmptyMap(params.Data), createUser, metaSecurity(params.CaptchaToken), channel}
		var out struct {
			MessageID string `json:"message_id"`
		}
		if err := c.call(ctx, http.MethodPost, "/otp", nil, "", body, &out); err != nil {
			return nil, err
		}
		return &OTPResponse{MessageID: out.MessageID}, nil
	default:
		return nil, fmt.Errorf("%w: you must provide either an email or phone number", ErrInvalidArgument)
	}
}

// OTP types accepted by VerifyOTP.
const (
	OTPTypeSMS         = "sms"
	OTPTypePhoneChange = "phone_change"
	OTPTypeSignup      = "signup"
	OTPTypeInvite      = "invite"
	OTPTypeMagicLink   = "magiclink"
	OTPTypeRecovery    = "recovery"
	OTPTypeEmailChange = "email_change"
	OTPTypeEmail       = "email"
)

// VerifyOTPParams verify a one-time password or token hash. Set Email or
// Phone with Token, or TokenHash alone (from an email template link).
type VerifyOTPParams struct {
	Email     string `json:"email,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Token     string `json:"token,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
	// Type is one of the OTPType* constants.
	Type string `json:"type"`
	// RedirectTo is sent as redirect_to (email only).
	RedirectTo   string `json:"-"`
	CaptchaToken string `json:"-"`
}

// VerifyOTP verifies an OTP or token hash (POST /verify). When the server
// returns a session it is stored and SIGNED_IN (PASSWORD_RECOVERY for type
// "recovery") emitted. Some verifications (e.g. the first of a secure
// email change) return neither user nor session.
func (c *Client) VerifyOTP(ctx context.Context, params VerifyOTPParams) (*AuthResponse, error) {
	if params.Type == "" || (params.TokenHash == "" && params.Token == "") {
		return nil, fmt.Errorf("%w: type and token (or token_hash) are required", ErrInvalidArgument)
	}
	body := struct {
		VerifyOTPParams
		Meta gotrueMetaSecurity `json:"gotrue_meta_security"`
	}{params, metaSecurity(params.CaptchaToken)}
	resp, err := c.postSession(ctx, "/verify", redirectQuery(params.RedirectTo), "", body)
	if err != nil {
		return nil, err
	}
	event := EventSignedIn
	if params.Type == OTPTypeRecovery {
		event = EventPasswordRecovery
	}
	if err := c.maybeCommit(ctx, resp, event); err != nil {
		return nil, err
	}
	return resp, nil
}

// SignInAnonymouslyParams configure SignInAnonymously.
type SignInAnonymouslyParams struct {
	// Data is stored in the anonymous user's user_metadata.
	Data         map[string]any
	CaptchaToken string
}

// SignInAnonymously creates an anonymous user (POST /signup with no
// credentials), stores the session and emits SIGNED_IN.
func (c *Client) SignInAnonymously(ctx context.Context, params SignInAnonymouslyParams) (*AuthResponse, error) {
	body := struct {
		Data map[string]any     `json:"data"`
		Meta gotrueMetaSecurity `json:"gotrue_meta_security"`
	}{orEmptyMap(params.Data), metaSecurity(params.CaptchaToken)}
	resp, err := c.postSession(ctx, "/signup", nil, "", body)
	if err != nil {
		return nil, err
	}
	if err := c.maybeCommit(ctx, resp, EventSignedIn); err != nil {
		return nil, err
	}
	return resp, nil
}

// SignInWithOAuthParams configure SignInWithOAuth and LinkIdentity.
type SignInWithOAuthParams struct {
	// Provider is the provider name, e.g. "google", "github", or
	// "custom:<id>" for a custom provider.
	Provider string
	// RedirectTo is where the provider flow returns.
	RedirectTo string
	// Scopes is a space-separated list of extra provider scopes.
	Scopes string
	// QueryParams are extra query parameters for the authorize URL.
	QueryParams map[string]string
}

// SignInWithOAuth returns the URL (GET /authorize) to send the user to for
// a third-party provider sign-in. No request is made. With FlowPKCE a code
// verifier is stored and the redirect carries a code for
// ExchangeCodeForSession; with FlowImplicit the redirect fragment carries
// the session (see GetSessionFromURL).
func (c *Client) SignInWithOAuth(ctx context.Context, params SignInWithOAuthParams) (*OAuthResponse, error) {
	if params.Provider == "" {
		return nil, fmt.Errorf("%w: provider is required", ErrInvalidArgument)
	}
	u, flow, err := c.providerURL(ctx, "/authorize", params, false)
	if err != nil {
		return nil, err
	}
	return &OAuthResponse{Provider: params.Provider, URL: u, FlowID: flowIDOf(flow)}, nil
}

// providerURL builds an authorize URL like auth-js _getUrlForProvider.
func (c *Client) providerURL(ctx context.Context, path string, params SignInWithOAuthParams, skipHTTPRedirect bool) (string, *pkceFlow, error) {
	redirectTo := params.RedirectTo
	flow, err := c.maybeStartPKCE(ctx, false)
	if err != nil {
		return "", nil, err
	}
	redirectTo = c.redirectWithFlowID(redirectTo, flow)
	parts := []string{"provider=" + encodeURIComponent(params.Provider)}
	if redirectTo != "" {
		parts = append(parts, "redirect_to="+encodeURIComponent(redirectTo))
	}
	if params.Scopes != "" {
		parts = append(parts, "scopes="+encodeURIComponent(params.Scopes))
	}
	if flow != nil {
		parts = append(parts, "code_challenge="+url.QueryEscape(flow.challenge), "code_challenge_method="+url.QueryEscape(flow.method))
	}
	if len(params.QueryParams) > 0 {
		keys := make([]string, 0, len(params.QueryParams))
		for k := range params.QueryParams {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(params.QueryParams[k]))
		}
	}
	if skipHTTPRedirect {
		parts = append(parts, "skip_http_redirect=true")
	}
	base, err := c.t.URL(path, nil)
	if err != nil {
		return "", nil, err
	}
	return base + "?" + strings.Join(parts, "&"), flow, nil
}

// SignInWithIDTokenParams sign in (or link) with a provider-issued OIDC ID
// token, e.g. from native Google or Apple sign-in.
type SignInWithIDTokenParams struct {
	// Provider is "google", "apple", "azure", "facebook", "kakao" or
	// "custom:<id>".
	Provider string `json:"provider"`
	// Token is the OIDC ID token.
	Token string `json:"id_token"`
	// AccessToken is the provider access token, required when the ID token
	// has an at_hash claim.
	AccessToken string `json:"access_token,omitempty"`
	// Nonce is the raw nonce, required when the ID token has a nonce claim.
	Nonce        string `json:"nonce,omitempty"`
	CaptchaToken string `json:"-"`
}

// SignInWithIDToken signs in with an OIDC ID token
// (POST /token?grant_type=id_token), stores the session and emits
// SIGNED_IN.
func (c *Client) SignInWithIDToken(ctx context.Context, params SignInWithIDTokenParams) (*AuthResponse, error) {
	if params.Provider == "" || params.Token == "" {
		return nil, fmt.Errorf("%w: provider and token are required", ErrInvalidArgument)
	}
	body := struct {
		SignInWithIDTokenParams
		Meta gotrueMetaSecurity `json:"gotrue_meta_security"`
	}{params, metaSecurity(params.CaptchaToken)}
	return c.signInToken(ctx, "id_token", "", body, EventSignedIn)
}

// SignInWithSSOParams start an enterprise SSO (SAML) sign-in. Set exactly
// one of ProviderID or Domain.
type SignInWithSSOParams struct {
	ProviderID   string
	Domain       string
	RedirectTo   string
	CaptchaToken string
}

// SignInWithSSO starts an SSO sign-in (POST /sso) and returns the identity
// provider URL to send the user to. With FlowPKCE a code verifier is
// stored.
func (c *Client) SignInWithSSO(ctx context.Context, params SignInWithSSOParams) (*SSOResponse, error) {
	if (params.ProviderID == "") == (params.Domain == "") {
		return nil, fmt.Errorf("%w: set exactly one of provider id or domain", ErrInvalidArgument)
	}
	flow, err := c.maybeStartPKCE(ctx, false)
	if err != nil {
		return nil, err
	}
	challenge, method := flowChallenge(flow)
	body := struct {
		ProviderID          string              `json:"provider_id,omitempty"`
		Domain              string              `json:"domain,omitempty"`
		RedirectTo          string              `json:"redirect_to,omitempty"`
		Meta                *gotrueMetaSecurity `json:"gotrue_meta_security,omitempty"`
		SkipHTTPRedirect    bool                `json:"skip_http_redirect"`
		CodeChallenge       *string             `json:"code_challenge"`
		CodeChallengeMethod *string             `json:"code_challenge_method"`
	}{params.ProviderID, params.Domain, c.redirectWithFlowID(params.RedirectTo, flow), optionalMeta(params.CaptchaToken), true, challenge, method}
	var out struct {
		URL string `json:"url"`
	}
	if err := c.call(ctx, http.MethodPost, "/sso", nil, "", body, &out); err != nil {
		c.removePKCEVerifier(ctx, flowIDOf(flow))
		return nil, err
	}
	return &SSOResponse{URL: out.URL, FlowID: flowIDOf(flow)}, nil
}

// ExchangeCodeOptions configure ExchangeCodeForSession.
type ExchangeCodeOptions struct {
	// FlowID selects the verifier of one specific pending PKCE flow (the
	// sb_flow_id redirect parameter or OAuthResponse.FlowID). When empty,
	// the verifier of the most recently started flow is used.
	FlowID string
	// NoStore makes the exchange stateless: the session is returned but not
	// stored in the Client and no event is emitted, and the code verifier
	// is removed from storage as soon as it has been read. Use it on a
	// server whose Client is shared between users, so one user's callback
	// never becomes the Client's session for later requests (the same
	// convention as passing an explicit access token).
	NoStore bool
}

// ExchangeCodeForSession exchanges a PKCE auth code from a redirect for a
// session (POST /token?grant_type=pkce) using the code verifier stored when
// the flow started, stores the session and emits SIGNED_IN
// (PASSWORD_RECOVERY for a password-reset flow), unless opts.NoStore is set.
// The verifier is consumed whether or not the exchange succeeds.
//
// Several PKCE flows may be pending at once (up to five): each flow's
// verifier lives in its own slot, and with a flow id only that slot is
// used, so one flow's callback can never consume another's verifier.
func (c *Client) ExchangeCodeForSession(ctx context.Context, authCode string, opts *ExchangeCodeOptions) (*AuthResponse, error) {
	if authCode == "" {
		return nil, fmt.Errorf("%w: auth code is required", ErrInvalidArgument)
	}
	flowID := ""
	if opts != nil && opts.FlowID != "" {
		if flowID = validPKCEFlowID(opts.FlowID); flowID == "" {
			// An invalid explicit flow id fails fast instead of borrowing
			// another flow's verifier.
			return nil, ErrPKCEVerifierMissing
		}
	}
	stored, err := c.retrievePKCEVerifier(ctx, flowID)
	if err != nil {
		return nil, fmt.Errorf("auth: load code verifier: %w", err)
	}
	noStore := opts != nil && opts.NoStore
	verifier, redirectType, _ := strings.Cut(stored, "/")
	if verifier == "" && c.cfg.FlowType == FlowPKCE {
		c.removePKCEVerifier(ctx, flowID)
		return nil, ErrPKCEVerifierMissing
	}
	if noStore {
		// Do not keep the verifier in shared storage for the round trip.
		c.removePKCEVerifier(ctx, flowID)
	}
	body := map[string]string{"auth_code": authCode, "code_verifier": verifier}
	resp, err := c.postSession(ctx, "/token", url.Values{"grant_type": {"pkce"}}, "", body)
	if !noStore {
		c.removePKCEVerifier(ctx, flowID)
	}
	if err != nil {
		return nil, err
	}
	if resp.Session == nil || resp.User == nil {
		return nil, ErrInvalidTokenResponse
	}
	resp.RedirectType = redirectType
	if noStore {
		return resp, nil
	}
	event := EventSignedIn
	if redirectType == OTPTypeRecovery {
		event = EventPasswordRecovery
	}
	if err := c.commitSession(ctx, resp.Session, event); err != nil {
		return nil, err
	}
	return resp, nil
}

// ResendParams configure Resend. Set Email for types "signup" and
// "email_change", Phone for "sms" and "phone_change".
type ResendParams struct {
	Type            string
	Email           string
	Phone           string
	EmailRedirectTo string
	CaptchaToken    string
}

// Resend re-sends a signup confirmation, email change, or phone OTP
// (POST /resend). With FlowPKCE an email resend stores a new verifier.
func (c *Client) Resend(ctx context.Context, params ResendParams) (*OTPResponse, error) {
	if params.Type == "" {
		return nil, fmt.Errorf("%w: type is required", ErrInvalidArgument)
	}
	switch {
	case params.Email != "":
		flow, err := c.maybeStartPKCE(ctx, false)
		if err != nil {
			return nil, err
		}
		challenge, method := flowChallenge(flow)
		body := struct {
			Email               string             `json:"email"`
			Type                string             `json:"type"`
			Meta                gotrueMetaSecurity `json:"gotrue_meta_security"`
			CodeChallenge       *string            `json:"code_challenge"`
			CodeChallengeMethod *string            `json:"code_challenge_method"`
		}{params.Email, params.Type, metaSecurity(params.CaptchaToken), challenge, method}
		query := redirectQuery(c.redirectWithFlowID(params.EmailRedirectTo, flow))
		if err := c.call(ctx, http.MethodPost, "/resend", query, "", body, nil); err != nil {
			c.removePKCEVerifier(ctx, flowIDOf(flow))
			return nil, err
		}
		return &OTPResponse{}, nil
	case params.Phone != "":
		body := struct {
			Phone string             `json:"phone"`
			Type  string             `json:"type"`
			Meta  gotrueMetaSecurity `json:"gotrue_meta_security"`
		}{params.Phone, params.Type, metaSecurity(params.CaptchaToken)}
		var out struct {
			MessageID string `json:"message_id"`
		}
		if err := c.call(ctx, http.MethodPost, "/resend", nil, "", body, &out); err != nil {
			return nil, err
		}
		return &OTPResponse{MessageID: out.MessageID}, nil
	default:
		return nil, fmt.Errorf("%w: you must provide either an email or phone number and a type", ErrInvalidArgument)
	}
}

// ResetPasswordForEmailParams configure ResetPasswordForEmail.
type ResetPasswordForEmailParams struct {
	Email string
	// RedirectTo is where the reset link sends the user; prompt for the
	// new password there and call UpdateUser.
	RedirectTo   string
	CaptchaToken string
}

// ResetPasswordForEmail sends a password-reset link (POST /recover). With
// FlowPKCE a verifier marked as a recovery flow is stored, so the later
// ExchangeCodeForSession emits PASSWORD_RECOVERY.
func (c *Client) ResetPasswordForEmail(ctx context.Context, params ResetPasswordForEmailParams) error {
	if params.Email == "" {
		return fmt.Errorf("%w: email is required", ErrInvalidArgument)
	}
	flow, err := c.maybeStartPKCE(ctx, true)
	if err != nil {
		return err
	}
	challenge, method := flowChallenge(flow)
	body := struct {
		Email               string             `json:"email"`
		CodeChallenge       *string            `json:"code_challenge"`
		CodeChallengeMethod *string            `json:"code_challenge_method"`
		Meta                gotrueMetaSecurity `json:"gotrue_meta_security"`
	}{params.Email, challenge, method, metaSecurity(params.CaptchaToken)}
	query := redirectQuery(c.redirectWithFlowID(params.RedirectTo, flow))
	if err := c.call(ctx, http.MethodPost, "/recover", query, "", body, nil); err != nil {
		c.removePKCEVerifier(ctx, flowIDOf(flow))
		return err
	}
	return nil
}

// postSession POSTs body and decodes a session response.
func (c *Client) postSession(ctx context.Context, path string, query url.Values, token string, body any) (*AuthResponse, error) {
	var raw json.RawMessage
	if err := c.call(ctx, http.MethodPost, path, query, token, body, &raw); err != nil {
		return nil, err
	}
	return c.decodeSessionResponse(raw)
}

// signInToken calls /token?grant_type=<grant>, requires a session and
// user in the response, stores the session and emits event.
func (c *Client) signInToken(ctx context.Context, grant, token string, body any, event AuthChangeEvent) (*AuthResponse, error) {
	resp, err := c.postSession(ctx, "/token", url.Values{"grant_type": {grant}}, token, body)
	if err != nil {
		return nil, err
	}
	if resp.Session == nil || resp.User == nil {
		return nil, ErrInvalidTokenResponse
	}
	if err := c.commitSession(ctx, resp.Session, event); err != nil {
		return nil, err
	}
	return resp, nil
}

// maybeCommit stores resp.Session, when present, and emits event.
func (c *Client) maybeCommit(ctx context.Context, resp *AuthResponse, event AuthChangeEvent) error {
	if resp.Session == nil {
		return nil
	}
	return c.commitSession(ctx, resp.Session, event)
}
