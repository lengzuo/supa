package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PasskeyAPI registers, authenticates with and manages passkeys (WebAuthn
// credentials used as a first factor). Obtain it with Client.Passkey.
//
// The WebAuthn ceremony itself (navigator.credentials.create/get) runs in
// the user's browser or app. A server drives it in two steps:
//
//  1. Start (StartRegistration / StartAuthentication) returns a challenge
//     id and the PublicKeyCredential options JSON to hand to the browser.
//  2. Verify (VerifyRegistration / VerifyAuthentication) takes the
//     credential JSON the browser produced (the result of
//     PublicKeyCredential.toJSON(), i.e. RegistrationResponseJSON or
//     AuthenticationResponseJSON) together with the challenge id.
//
// Passkey support must be enabled for the project.
type PasskeyAPI struct {
	c *Client
}

// Passkey returns the passkey API of c.
func (c *Client) Passkey() *PasskeyAPI { return &PasskeyAPI{c: c} }

// PasskeyChallenge is a WebAuthn challenge issued by the Auth server.
type PasskeyChallenge struct {
	ChallengeID string `json:"challenge_id"`
	// Options is the PublicKeyCredentialCreationOptionsJSON (registration)
	// or PublicKeyCredentialRequestOptionsJSON (authentication) to pass to
	// the browser, e.g. PublicKeyCredential.parseCreationOptionsFromJSON.
	Options json.RawMessage `json:"options"`
	// ExpiresAt is the Unix time after which the challenge is unusable.
	ExpiresAt int64 `json:"expires_at"`
}

// Passkey is a registered passkey.
type Passkey struct {
	ID           string     `json:"id"`
	FriendlyName string     `json:"friendly_name,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// StartRegistration requests registration options for a new passkey of
// the user (POST /passkeys/registration/options). See "Token-taking
// methods" in the package documentation for accessToken.
func (p *PasskeyAPI) StartRegistration(ctx context.Context, accessToken string) (*PasskeyChallenge, error) {
	token, _, err := p.c.sessionToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	var out PasskeyChallenge
	if err := p.c.call(ctx, http.MethodPost, "/passkeys/registration/options", nil, token, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyPasskeyRegistrationParams complete a passkey registration.
type VerifyPasskeyRegistrationParams struct {
	// ChallengeID is PasskeyChallenge.ChallengeID from StartRegistration.
	ChallengeID string
	// Credential is the browser's RegistrationResponseJSON.
	Credential json.RawMessage
}

// VerifyRegistration verifies the browser's registration response and
// stores the passkey (POST /passkeys/registration/verify). Together with
// StartRegistration it is the server-side equivalent of supabase-js
// registerPasskey.
func (p *PasskeyAPI) VerifyRegistration(ctx context.Context, accessToken string, params VerifyPasskeyRegistrationParams) (*Passkey, error) {
	if params.ChallengeID == "" || len(params.Credential) == 0 {
		return nil, fmt.Errorf("%w: challenge id and credential are required", ErrInvalidArgument)
	}
	if !json.Valid(params.Credential) {
		return nil, fmt.Errorf("%w: credential is not valid JSON", ErrInvalidArgument)
	}
	token, _, err := p.c.sessionToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"challenge_id": params.ChallengeID, "credential": params.Credential}
	var out Passkey
	if err := p.c.call(ctx, http.MethodPost, "/passkeys/registration/verify", nil, token, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StartPasskeyAuthenticationParams configure StartAuthentication.
type StartPasskeyAuthenticationParams struct {
	CaptchaToken string
}

// StartAuthentication requests a sign-in challenge
// (POST /passkeys/authentication/options). No session is needed.
func (p *PasskeyAPI) StartAuthentication(ctx context.Context, params StartPasskeyAuthenticationParams) (*PasskeyChallenge, error) {
	body := struct {
		Meta gotrueMetaSecurity `json:"gotrue_meta_security"`
	}{metaSecurity(params.CaptchaToken)}
	var out PasskeyChallenge
	if err := p.c.call(ctx, http.MethodPost, "/passkeys/authentication/options", nil, "", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyPasskeyAuthenticationParams complete a passkey sign-in.
type VerifyPasskeyAuthenticationParams struct {
	// ChallengeID is PasskeyChallenge.ChallengeID from StartAuthentication.
	ChallengeID string
	// Credential is the browser's AuthenticationResponseJSON.
	Credential json.RawMessage
}

// VerifyAuthentication verifies the browser's assertion and signs the user
// in (POST /passkeys/authentication/verify); the session is stored and
// SIGNED_IN emitted. Together with StartAuthentication it is the
// server-side equivalent of supabase-js signInWithPasskey.
func (p *PasskeyAPI) VerifyAuthentication(ctx context.Context, params VerifyPasskeyAuthenticationParams) (*AuthResponse, error) {
	if params.ChallengeID == "" || len(params.Credential) == 0 {
		return nil, fmt.Errorf("%w: challenge id and credential are required", ErrInvalidArgument)
	}
	if !json.Valid(params.Credential) {
		return nil, fmt.Errorf("%w: credential is not valid JSON", ErrInvalidArgument)
	}
	body := map[string]any{"challenge_id": params.ChallengeID, "credential": params.Credential}
	return p.c.lockedSignIn(ctx, EventSignedIn, func() (*AuthResponse, error) {
		return p.c.postSession(ctx, "/passkeys/authentication/verify", nil, "", body)
	})
}

// List returns the user's passkeys (GET /passkeys).
func (p *PasskeyAPI) List(ctx context.Context, accessToken string) ([]Passkey, error) {
	token, _, err := p.c.sessionToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	out := []Passkey{}
	if err := p.c.call(ctx, http.MethodGet, "/passkeys", nil, token, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PasskeyUpdateParams rename a passkey.
type PasskeyUpdateParams struct {
	PasskeyID    string
	FriendlyName string
}

// Update renames one of the user's passkeys (PATCH /passkeys/{id}).
func (p *PasskeyAPI) Update(ctx context.Context, accessToken string, params PasskeyUpdateParams) (*Passkey, error) {
	if params.PasskeyID == "" {
		return nil, fmt.Errorf("%w: passkey id is required", ErrInvalidArgument)
	}
	token, _, err := p.c.sessionToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	body := map[string]string{"friendly_name": params.FriendlyName}
	var out Passkey
	if err := p.c.call(ctx, http.MethodPatch, "/passkeys/"+pathSegment(params.PasskeyID), nil, token, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete removes one of the user's passkeys (DELETE /passkeys/{id}).
func (p *PasskeyAPI) Delete(ctx context.Context, accessToken, passkeyID string) error {
	if passkeyID == "" {
		return fmt.Errorf("%w: passkey id is required", ErrInvalidArgument)
	}
	token, _, err := p.c.sessionToken(ctx, accessToken)
	if err != nil {
		return err
	}
	return p.c.call(ctx, http.MethodDelete, "/passkeys/"+pathSegment(passkeyID), nil, token, nil, nil)
}
