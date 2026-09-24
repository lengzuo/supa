package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	return &MFAAPI{c: m.c, token: strings.TrimSpace(accessToken)}
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

// mfaSession returns the token to authenticate a call with (the explicit
// token, or the stored session's access token) and the stored session it
// came from (nil for an explicit token).
func (m *MFAAPI) mfaSession(ctx context.Context) (string, *Session, error) {
	if m.token != "" {
		return m.token, nil, nil
	}
	s, err := m.c.GetSession(ctx)
	if err != nil {
		return "", nil, err
	}
	if s == nil || s.AccessToken == "" {
		return "", nil, ErrSessionMissing
	}
	return s.AccessToken, s, nil
}

// mfaDo performs an authenticated request on behalf of the current user.
func (m *MFAAPI) mfaDo(ctx context.Context, method, path string, body, out any) error {
	_, err := m.mfaDoBasis(ctx, method, path, body, out)
	return err
}

// mfaDoBasis is mfaDo that also returns the stored session the request was
// authenticated with (nil for an explicit token), for mfaStoreVerified.
func (m *MFAAPI) mfaDoBasis(ctx context.Context, method, path string, body, out any) (*Session, error) {
	token, basis, err := m.mfaSession(ctx)
	if err != nil {
		return nil, err
	}
	return basis, m.c.request(ctx, &transport.Request{Method: method, Path: path, Body: body, Token: token}, out)
}

// mfaStoreVerified stores a session returned by an MFA verification and
// notifies listeners, unless m acts on an explicit access token. The new
// aal2 session only replaces the stored session if that is still the one
// the verification was made with (same refresh or access token): a session
// signed out, or replaced, while the request was in flight is never
// resurrected or overwritten. The upgraded session is returned to the
// caller either way.
func (m *MFAAPI) mfaStoreVerified(ctx context.Context, basis *Session, s *Session) error {
	if s.ExpiresAt == 0 && s.ExpiresIn > 0 {
		s.ExpiresAt = m.c.now().Unix() + s.ExpiresIn
	}
	if m.token != "" || basis == nil {
		return nil
	}
	_, err := m.c.replaceSessionIfCurrent(ctx, basisOf(basis), s, EventMFAChallengeVerified)
	return err
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
	if err := m.mfaDo(ctx, http.MethodDelete, "/factors/"+pathSegment(params.FactorID), nil, &out); err != nil {
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
	path := "/factors/" + pathSegment(params.FactorID) + "/challenge"
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
		if err := mfaRequire(params.Code, "code"); err != nil {
			return nil, err
		}
		code := params.Code
		body.Code = &code
	}
	var s Session
	path := "/factors/" + pathSegment(params.FactorID) + "/verify"
	basis, err := m.mfaDoBasis(ctx, http.MethodPost, path, body, &s)
	if err != nil {
		return nil, err
	}
	if err := m.mfaStoreVerified(ctx, basis, &s); err != nil {
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
// verified factors, like auth-js. In stored-session mode, a
// session_not_found response removes the stored session (if it is still
// the one used) and emits SIGNED_OUT, like GetUser.
func (m *MFAAPI) ListFactors(ctx context.Context) (*MFAListFactorsResponse, error) {
	token, stored, err := m.mfaSession(ctx)
	if err != nil {
		return nil, err
	}
	user, err := m.mfaGetUser(ctx, token)
	if err != nil {
		if stored != nil && isSessionMissing(err) {
			// Like auth-js getUser: the session no longer exists server-side.
			// Remove it only if it is still the stored one.
			_, _ = m.c.clearSessionIf(ctx, func(s *Session) bool { return s.AccessToken == token })
		}
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
	var raw json.RawMessage
	if err := m.c.request(ctx, &transport.Request{Method: http.MethodGet, Path: "/user", Token: token}, &raw); err != nil {
		return nil, err
	}
	return decodeUser(raw)
}

// mfaTokenClaims holds the claims GetAuthenticatorAssuranceLevel needs.
type mfaTokenClaims struct {
	aal MFAAssuranceLevel
	amr []AMREntry
}

// mfaParseAccessToken extracts the aal and amr claims from an unverified
// JWT with decodeJWT. AMREntry accepts both the object form of amr
// ([{"method":"password","timestamp":1}]) and the RFC 8176 string form
// (["pwd"]) that custom access token hooks may emit.
func mfaParseAccessToken(token string) (*mfaTokenClaims, error) {
	jwt, err := decodeJWT(token)
	if err != nil {
		return nil, err
	}
	amr := jwt.Claims.AMR
	if amr == nil {
		amr = []AMREntry{}
	}
	return &mfaTokenClaims{aal: MFAAssuranceLevel(jwt.Claims.AAL), amr: amr}, nil
}
