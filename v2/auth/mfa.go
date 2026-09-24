package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// MFAAPI is the multi-factor authentication API for the signed-in user
// (auth-js GoTrueMFAApi). Obtain one with Client.MFA.
//
// By default every call acts on the session stored in the Client (see
// GetSession) and fails with ErrSessionMissing when there is none. Server
// applications that handle many users should call WithAccessToken to act
// on behalf of a specific user's JWT instead.
//
// An *MFAAPI is immutable and safe for concurrent use.
type MFAAPI struct {
	c *Client
	// token, when non-empty, is used instead of the stored session.
	token string
}

// MFA returns the multi-factor authentication API.
func (c *Client) MFA() *MFAAPI { return &MFAAPI{c: c} }

// WithAccessToken returns a copy of m that authenticates every call with
// accessToken (a user's JWT) instead of the Client's stored session.
//
// In this mode Verify, ChallengeAndVerify and RecoveryCodes().Verify return
// the upgraded session but never store it in the Client or notify
// OnAuthStateChange listeners, because the token does not belong to the
// Client's own session. An empty accessToken restores the default
// stored-session behavior.
func (m *MFAAPI) WithAccessToken(accessToken string) *MFAAPI {
	return &MFAAPI{c: m.c, token: accessToken}
}

// MFAChannel is the messaging channel used to deliver a phone factor code.
type MFAChannel string

const (
	// MFAChannelSMS sends the code by SMS.
	MFAChannelSMS MFAChannel = "sms"
	// MFAChannelWhatsApp sends the code by WhatsApp.
	MFAChannelWhatsApp MFAChannel = "whatsapp"
)

// MFAWebAuthnCeremony distinguishes a WebAuthn registration ("create",
// used for an unverified factor) from an authentication ("request", used
// for a verified factor).
type MFAWebAuthnCeremony string

const (
	// MFAWebAuthnCreate is a registration ceremony
	// (navigator.credentials.create).
	MFAWebAuthnCreate MFAWebAuthnCeremony = "create"
	// MFAWebAuthnRequest is an authentication ceremony
	// (navigator.credentials.get).
	MFAWebAuthnRequest MFAWebAuthnCeremony = "request"
)

// MFAAssuranceLevel is an Authenticator Assurance Level, such as "aal1" or
// "aal2". The empty string means "unknown" (null in auth-js).
type MFAAssuranceLevel string

const (
	// MFAAssuranceLevel1 means the user signed in with a single factor.
	MFAAssuranceLevel1 MFAAssuranceLevel = "aal1"
	// MFAAssuranceLevel2 means the user verified a second factor.
	MFAAssuranceLevel2 MFAAssuranceLevel = "aal2"
)

// MFAEnrollParams are the parameters of MFAAPI.Enroll.
type MFAEnrollParams struct {
	// FactorType is the factor to enroll: FactorTypeTOTP, FactorTypePhone
	// or FactorTypeWebAuthn. Required.
	FactorType FactorType
	// FriendlyName is a human-readable name for the factor. Optional.
	FriendlyName string
	// Issuer is the domain the TOTP factor is enrolled with. TOTP only;
	// ignored for other factor types.
	Issuer string
	// Phone is the E.164 phone number for a phone factor. Phone only;
	// ignored for other factor types.
	Phone string
}

// MFAEnrollResponse describes a newly enrolled, unverified factor.
type MFAEnrollResponse struct {
	// ID is the ID of the enrolled factor. Pass it to Challenge.
	ID string `json:"id"`
	// Type is the factor type.
	Type FactorType `json:"type"`
	// FriendlyName is the factor's friendly name, if any.
	FriendlyName string `json:"friendly_name,omitempty"`
	// TOTP holds the TOTP secret material. Set for TOTP factors only.
	TOTP *MFATOTPEnrollment `json:"totp,omitempty"`
	// Phone is the factor's phone number. Set for phone factors only.
	Phone string `json:"phone,omitempty"`
}

// MFATOTPEnrollment is the secret material of a newly enrolled TOTP factor.
// All of its fields are secrets: never log them.
type MFATOTPEnrollment struct {
	// QRCode is an SVG QR code of URI, as a data URL
	// ("data:image/svg+xml;utf-8,<svg...>") that can be used directly as
	// an image source, like auth-js.
	QRCode string `json:"qr_code"`
	// Secret is the TOTP shared secret, for users who cannot scan QRCode.
	Secret string `json:"secret"`
	// URI is the otpauth:// URI encoded in QRCode.
	URI string `json:"uri"`
}

// MFAUnenrollParams are the parameters of MFAAPI.Unenroll.
type MFAUnenrollParams struct {
	// FactorID is the ID of the factor to remove. Required.
	FactorID string
}

// MFAUnenrollResponse is returned by MFAAPI.Unenroll and
// MFARecoveryCodesAPI.Unenroll.
type MFAUnenrollResponse struct {
	// ID is the ID of the removed factor.
	ID string `json:"id"`
}

// MFAWebAuthnRelyingParty identifies the WebAuthn relying party for a
// challenge.
type MFAWebAuthnRelyingParty struct {
	// RPID is the relying party ID (usually the site's domain). Required.
	RPID string `json:"rpId"`
	// RPOrigins are the origins allowed to complete the ceremony. Optional.
	RPOrigins []string `json:"rpOrigins,omitempty"`
}

// MFAChallengeParams are the parameters of MFAAPI.Challenge.
type MFAChallengeParams struct {
	// FactorID is the ID of the factor to challenge. Required.
	FactorID string `json:"factorId"`
	// Channel selects how a phone factor's code is delivered. Phone
	// factors only; the server defaults to SMS.
	Channel MFAChannel `json:"channel,omitempty"`
	// WebAuthn is required for WebAuthn factors and must be nil otherwise.
	WebAuthn *MFAWebAuthnRelyingParty `json:"webauthn,omitempty"`
}

// MFAChallengeResponse is a newly created challenge.
type MFAChallengeResponse struct {
	// ID is the challenge ID. Pass it to Verify.
	ID string `json:"id"`
	// Type is the type of the challenged factor.
	Type FactorType `json:"type"`
	// ExpiresAt is the Unix time (seconds) after which the challenge can no
	// longer be verified.
	ExpiresAt int64 `json:"expires_at"`
	// WebAuthn is set for WebAuthn factors.
	WebAuthn *MFAWebAuthnChallenge `json:"webauthn,omitempty"`
}

// MFAWebAuthnChallenge carries the options for a WebAuthn ceremony.
type MFAWebAuthnChallenge struct {
	// Type is MFAWebAuthnCreate for an unverified factor or
	// MFAWebAuthnRequest for a verified one.
	Type MFAWebAuthnCeremony `json:"type"`
	// CredentialOptions holds the server's options for the ceremony.
	CredentialOptions MFAWebAuthnCredentialOptions `json:"credential_options"`
}

// MFAWebAuthnCredentialOptions holds WebAuthn ceremony options.
type MFAWebAuthnCredentialOptions struct {
	// PublicKey is the PublicKeyCredentialCreationOptionsJSON (for
	// MFAWebAuthnCreate) or PublicKeyCredentialRequestOptionsJSON (for
	// MFAWebAuthnRequest) exactly as sent by the server, with binary fields
	// base64url-encoded. Hand it to the browser, which can pass it to
	// PublicKeyCredential.parseCreationOptionsFromJSON or
	// parseRequestOptionsFromJSON.
	PublicKey json.RawMessage `json:"publicKey"`
}

// MFAVerifyParams are the parameters of MFAAPI.Verify. Set Code for TOTP
// and phone factors, or WebAuthn for WebAuthn factors.
type MFAVerifyParams struct {
	// FactorID is the ID of the factor being verified. Required.
	FactorID string
	// ChallengeID is the ID returned by Challenge. Required.
	ChallengeID string
	// Code is the one-time code entered by the user (TOTP and phone).
	Code string
	// WebAuthn carries the browser's credential for WebAuthn factors.
	WebAuthn *MFAVerifyWebAuthnParams
}

// MFAVerifyWebAuthnParams carries the result of a browser WebAuthn
// ceremony for MFAAPI.Verify.
type MFAVerifyWebAuthnParams struct {
	// RPID is the relying party ID. Required.
	RPID string `json:"rpId"`
	// RPOrigins are the origins allowed to complete the ceremony. Optional.
	RPOrigins []string `json:"rpOrigins,omitempty"`
	// Type must match the challenge's MFAWebAuthnChallenge.Type.
	Type MFAWebAuthnCeremony `json:"type"`
	// CredentialResponse is the JSON serialization of the browser's
	// PublicKeyCredential (the result of credential.toJSON(), i.e. a
	// RegistrationResponseJSON or AuthenticationResponseJSON). It is sent
	// to the server unchanged. Required.
	CredentialResponse json.RawMessage `json:"credential_response"`
}

// MFAChallengeAndVerifyParams are the parameters of
// MFAAPI.ChallengeAndVerify.
type MFAChallengeAndVerifyParams struct {
	// FactorID is the ID of the TOTP factor. Required.
	FactorID string
	// Code is the one-time code from the user's authenticator app.
	Code string
}

// MFAListFactorsResponse groups the user's factors like auth-js
// listFactors.
type MFAListFactorsResponse struct {
	// All holds every factor, verified or not, including types this SDK
	// does not recognize.
	All []Factor `json:"all"`
	// TOTP holds the verified TOTP factors.
	TOTP []Factor `json:"totp"`
	// Phone holds the verified phone factors.
	Phone []Factor `json:"phone"`
	// WebAuthn holds the verified WebAuthn factors.
	WebAuthn []Factor `json:"webauthn"`
	// RecoveryCode holds the verified recovery-code factors.
	RecoveryCode []Factor `json:"recovery_code"`
}

// MFAAssuranceLevelResponse is returned by
// MFAAPI.GetAuthenticatorAssuranceLevel.
type MFAAssuranceLevelResponse struct {
	// CurrentLevel is the session's current level (the access token's
	// "aal" claim), or "" when unknown.
	CurrentLevel MFAAssuranceLevel `json:"currentLevel"`
	// NextLevel is the highest level the session can reach: "aal2" when
	// the user has a verified factor, otherwise CurrentLevel. When it is
	// higher than CurrentLevel the user should complete an MFA challenge.
	NextLevel MFAAssuranceLevel `json:"nextLevel"`
	// CurrentAuthenticationMethods lists the access token's "amr" claim.
	// Tokens whose amr claim uses the RFC 8176 string form yield entries
	// with only Method set.
	CurrentAuthenticationMethods []AMREntry `json:"currentAuthenticationMethods"`
}

// mfaAccessToken returns the token to authenticate a call with: the
// explicit token, or the stored session's access token.
func (m *MFAAPI) mfaAccessToken(ctx context.Context) (string, error) {
	if m.token != "" {
		return m.token, nil
	}
	s, err := m.c.GetSession(ctx)
	if err != nil {
		return "", err
	}
	if s == nil || s.AccessToken == "" {
		return "", ErrSessionMissing
	}
	return s.AccessToken, nil
}

// mfaDo performs an authenticated request on behalf of the current user.
func (m *MFAAPI) mfaDo(ctx context.Context, method, path string, body, out any) error {
	token, err := m.mfaAccessToken(ctx)
	if err != nil {
		return err
	}
	return m.c.request(ctx, &transport.Request{Method: method, Path: path, Body: body, Token: token}, out)
}

// mfaStoreVerified stores a session returned by an MFA verification and
// notifies listeners, unless m acts on an explicit access token.
func (m *MFAAPI) mfaStoreVerified(ctx context.Context, s *Session) error {
	if m.token != "" {
		if s.ExpiresAt == 0 && s.ExpiresIn > 0 {
			s.ExpiresAt = m.c.now().Unix() + s.ExpiresIn
		}
		return nil
	}
	m.c.sessionMu.Lock()
	err := m.c.saveSession(ctx, s)
	m.c.sessionMu.Unlock()
	if err != nil {
		return err
	}
	m.c.notify(EventMFAChallengeVerified, s)
	return nil
}

func mfaRequire(value, name string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidArgument, name)
	}
	return nil
}

// Enroll starts enrolling a new factor for the user (POST /factors). The
// factor is unverified until Verify succeeds for it. For TOTP factors the
// QR code is returned as a data URL, like auth-js.
func (m *MFAAPI) Enroll(ctx context.Context, params MFAEnrollParams) (*MFAEnrollResponse, error) {
	if err := mfaRequire(string(params.FactorType), "factor type"); err != nil {
		return nil, err
	}
	body := struct {
		FriendlyName string     `json:"friendly_name,omitempty"`
		FactorType   FactorType `json:"factor_type"`
		Phone        string     `json:"phone,omitempty"`
		Issuer       string     `json:"issuer,omitempty"`
	}{FriendlyName: params.FriendlyName, FactorType: params.FactorType}
	switch params.FactorType {
	case FactorTypePhone:
		body.Phone = params.Phone
	case FactorTypeTOTP:
		body.Issuer = params.Issuer
	}
	var out MFAEnrollResponse
	if err := m.mfaDo(ctx, http.MethodPost, "/factors", body, &out); err != nil {
		return nil, err
	}
	if params.FactorType == FactorTypeTOTP && out.Type == FactorTypeTOTP && out.TOTP != nil && out.TOTP.QRCode != "" {
		out.TOTP.QRCode = "data:image/svg+xml;utf-8," + out.TOTP.QRCode
	}
	return &out, nil
}

// Unenroll removes a factor (DELETE /factors/{id}). Removing a verified
// factor requires an aal2 session.
func (m *MFAAPI) Unenroll(ctx context.Context, params MFAUnenrollParams) (*MFAUnenrollResponse, error) {
	if err := mfaRequire(params.FactorID, "factor ID"); err != nil {
		return nil, err
	}
	var out MFAUnenrollResponse
	if err := m.mfaDo(ctx, http.MethodDelete, "/factors/"+url.PathEscape(params.FactorID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Challenge prepares a factor for verification (POST
// /factors/{id}/challenge). For phone factors it sends the code; for
// WebAuthn factors the response carries the options to pass to the
// browser's WebAuthn API.
func (m *MFAAPI) Challenge(ctx context.Context, params MFAChallengeParams) (*MFAChallengeResponse, error) {
	if err := mfaRequire(params.FactorID, "factor ID"); err != nil {
		return nil, err
	}
	if params.WebAuthn != nil {
		if err := mfaRequire(params.WebAuthn.RPID, "WebAuthn relying party ID"); err != nil {
			return nil, err
		}
	}
	var out MFAChallengeResponse
	path := "/factors/" + url.PathEscape(params.FactorID) + "/challenge"
	if err := m.mfaDo(ctx, http.MethodPost, path, params, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify verifies a challenge (POST /factors/{id}/verify). On success the
// session is upgraded to aal2: the returned session is stored in the
// Client and an EventMFAChallengeVerified event is emitted (unless m was
// created with WithAccessToken). Verifying a factor signs out the user's
// other sessions.
func (m *MFAAPI) Verify(ctx context.Context, params MFAVerifyParams) (*Session, error) {
	if err := mfaRequire(params.FactorID, "factor ID"); err != nil {
		return nil, err
	}
	if err := mfaRequire(params.ChallengeID, "challenge ID"); err != nil {
		return nil, err
	}
	body := struct {
		ChallengeID string                   `json:"challenge_id"`
		Code        *string                  `json:"code,omitempty"`
		WebAuthn    *MFAVerifyWebAuthnParams `json:"webauthn,omitempty"`
	}{ChallengeID: params.ChallengeID}
	if params.WebAuthn != nil {
		if err := mfaRequire(params.WebAuthn.RPID, "WebAuthn relying party ID"); err != nil {
			return nil, err
		}
		if params.WebAuthn.Type != MFAWebAuthnCreate && params.WebAuthn.Type != MFAWebAuthnRequest {
			return nil, fmt.Errorf("%w: WebAuthn type must be %q or %q", ErrInvalidArgument, MFAWebAuthnCreate, MFAWebAuthnRequest)
		}
		if len(params.WebAuthn.CredentialResponse) == 0 || !json.Valid(params.WebAuthn.CredentialResponse) {
			return nil, fmt.Errorf("%w: WebAuthn credential response must be valid JSON", ErrInvalidArgument)
		}
		body.WebAuthn = params.WebAuthn
	} else {
		code := params.Code
		body.Code = &code
	}
	var s Session
	path := "/factors/" + url.PathEscape(params.FactorID) + "/verify"
	if err := m.mfaDo(ctx, http.MethodPost, path, body, &s); err != nil {
		return nil, err
	}
	if err := m.mfaStoreVerified(ctx, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ChallengeAndVerify creates a challenge for a TOTP factor and verifies
// it with code in one call. It behaves like Challenge followed by Verify.
func (m *MFAAPI) ChallengeAndVerify(ctx context.Context, params MFAChallengeAndVerifyParams) (*Session, error) {
	ch, err := m.Challenge(ctx, MFAChallengeParams{FactorID: params.FactorID})
	if err != nil {
		return nil, err
	}
	return m.Verify(ctx, MFAVerifyParams{FactorID: params.FactorID, ChallengeID: ch.ID, Code: params.Code})
}

// ListFactors fetches the current user (GET /user) and returns their
// factors: All holds every factor, and the per-type lists hold only
// verified factors, like auth-js.
func (m *MFAAPI) ListFactors(ctx context.Context) (*MFAListFactorsResponse, error) {
	token, err := m.mfaAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	user, err := m.mfaGetUser(ctx, token)
	if err != nil {
		return nil, err
	}
	out := &MFAListFactorsResponse{
		All:          []Factor{},
		TOTP:         []Factor{},
		Phone:        []Factor{},
		WebAuthn:     []Factor{},
		RecoveryCode: []Factor{},
	}
	for _, f := range user.Factors {
		out.All = append(out.All, f)
		if f.Status != FactorStatusVerified {
			continue
		}
		switch f.FactorType {
		case FactorTypeTOTP:
			out.TOTP = append(out.TOTP, f)
		case FactorTypePhone:
			out.Phone = append(out.Phone, f)
		case FactorTypeWebAuthn:
			out.WebAuthn = append(out.WebAuthn, f)
		case FactorTypeRecoveryCode:
			out.RecoveryCode = append(out.RecoveryCode, f)
		}
	}
	return out, nil
}

// GetAuthenticatorAssuranceLevel reports the session's current and next
// Authenticator Assurance Level and its authentication methods, from the
// access token's "aal" and "amr" claims.
//
// Like auth-js, the stored-session mode makes no network request: it
// derives NextLevel from the factors on the stored session's user, and
// returns an empty response (and no error) when there is no session. When
// m was created with WithAccessToken, the user's factors are fetched with
// GET /user using that token.
//
// The token's signature is not verified; use it for UI decisions, not
// authorization.
func (m *MFAAPI) GetAuthenticatorAssuranceLevel(ctx context.Context) (*MFAAssuranceLevelResponse, error) {
	var (
		token   string
		factors []Factor
	)
	if m.token != "" {
		token = m.token
		// Decode first so a malformed token fails without a request.
		if _, err := mfaParseAccessToken(token); err != nil {
			return nil, err
		}
		user, err := m.mfaGetUser(ctx, token)
		if err != nil {
			return nil, err
		}
		factors = user.Factors
	} else {
		s, err := m.c.GetSession(ctx)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return &MFAAssuranceLevelResponse{CurrentAuthenticationMethods: []AMREntry{}}, nil
		}
		token = s.AccessToken
		if s.User != nil {
			factors = s.User.Factors
		}
	}
	claims, err := mfaParseAccessToken(token)
	if err != nil {
		return nil, err
	}
	out := &MFAAssuranceLevelResponse{
		CurrentLevel:                 claims.aal,
		NextLevel:                    claims.aal,
		CurrentAuthenticationMethods: claims.amr,
	}
	for _, f := range factors {
		if f.Status == FactorStatusVerified {
			out.NextLevel = MFAAssuranceLevel2
			break
		}
	}
	return out, nil
}

// mfaGetUser fetches the user that owns token (GET /user).
func (m *MFAAPI) mfaGetUser(ctx context.Context, token string) (*User, error) {
	var u User
	if err := m.c.request(ctx, &transport.Request{Method: http.MethodGet, Path: "/user", Token: token}, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// mfaTokenClaims holds the claims GetAuthenticatorAssuranceLevel needs.
type mfaTokenClaims struct {
	aal MFAAssuranceLevel
	amr []AMREntry
}

// mfaParseAccessToken extracts the aal and amr claims from an unverified
// JWT with decodeJWT. Because Claims.AMR only models the object form of
// amr ([{"method":"password","timestamp":1}]), a token that decodeJWT
// rejects is re-parsed by mfaParseClaimsLenient, which also accepts the
// RFC 8176 string form (["pwd"]) that custom access token hooks may emit.
func mfaParseAccessToken(token string) (*mfaTokenClaims, error) {
	jwt, err := decodeJWT(token)
	if err != nil {
		return mfaParseClaimsLenient(token)
	}
	amr := jwt.Claims.AMR
	if amr == nil {
		amr = []AMREntry{}
	}
	return &mfaTokenClaims{aal: MFAAssuranceLevel(jwt.Claims.AAL), amr: amr}, nil
}

// mfaParseClaimsLenient parses aal and amr, accepting both amr forms.
func mfaParseClaimsLenient(token string) (*mfaTokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	var raw struct {
		AAL any             `json:"aal"`
		AMR json.RawMessage `json:"amr"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, ErrInvalidJWT
	}
	out := &mfaTokenClaims{amr: []AMREntry{}}
	if s, ok := raw.AAL.(string); ok {
		out.aal = MFAAssuranceLevel(s)
	}
	if len(raw.AMR) == 0 || string(raw.AMR) == "null" {
		return out, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw.AMR, &items); err != nil {
		return nil, ErrInvalidJWT
	}
	for _, it := range items {
		var method string
		if err := json.Unmarshal(it, &method); err == nil {
			out.amr = append(out.amr, AMREntry{Method: method})
			continue
		}
		var e AMREntry
		if err := json.Unmarshal(it, &e); err != nil {
			return nil, ErrInvalidJWT
		}
		out.amr = append(out.amr, e)
	}
	return out, nil
}
