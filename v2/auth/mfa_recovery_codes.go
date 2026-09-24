package auth

import (
	"context"
	"net/http"
)

// MFARecoveryCodesAPI manages the user's MFA recovery codes (auth-js
// AuthMFARecoveryCodesApi): single-use backup codes that let a user reach
// aal2 when they cannot use their other factors. Obtain one with
// MFAAPI.RecoveryCodes.
//
// Experimental: this API mirrors an experimental auth-js API
// (experimental.recoveryCodes) and may change in a future release.
//
// This API is experimental on the server and must be enabled in the
// project's Auth settings; calls fail with an *Error otherwise.
//
// An *MFARecoveryCodesAPI is immutable and safe for concurrent use.
type MFARecoveryCodesAPI struct {
	m *MFAAPI
}

// RecoveryCodes returns the recovery codes API (experimental, see
// MFARecoveryCodesAPI). It authenticates the same
// way as m (stored session, or the token given to WithAccessToken).
func (m *MFAAPI) RecoveryCodes() *MFARecoveryCodesAPI { return &MFARecoveryCodesAPI{m: m} }

// MFARecoveryCodesGenerateParams are the parameters of
// MFARecoveryCodesAPI.Generate.
type MFARecoveryCodesGenerateParams struct {
	// FriendlyName names the recovery codes factor. Must be unique among
	// the user's factors. Optional; the server defaults to
	// "Recovery codes".
	FriendlyName string
}

// MFARecoveryCodesVerifyParams are the parameters of
// MFARecoveryCodesAPI.Verify.
type MFARecoveryCodesVerifyParams struct {
	// Code is one unused recovery code, exactly as entered by the user.
	// The server ignores letter case, whitespace and "-" separators.
	Code string
}

// MFARecoveryCodesStatus is the enrollment status of the user's recovery
// codes. It never contains code values.
type MFARecoveryCodesStatus struct {
	// ID is the recovery codes factor ID, as in User.Factors.
	ID string `json:"id"`
	// Type is always FactorTypeRecoveryCode.
	Type FactorType `json:"type"`
	// Total is the number of codes in the current set.
	Total int `json:"total"`
	// Remaining is the number of unused codes in the current set.
	Remaining int `json:"remaining"`
}

// MFARecoveryCodes is a newly generated set of recovery codes.
type MFARecoveryCodes struct {
	// ID is the recovery codes factor ID.
	ID string `json:"id"`
	// Type is always FactorTypeRecoveryCode.
	Type FactorType `json:"type"`
	// FriendlyName is the factor's friendly name.
	FriendlyName string `json:"friendly_name,omitempty"`
	// Total is the number of codes in the set.
	Total int `json:"total"`
	// Codes are the plaintext codes. They are returned exactly once and
	// cannot be retrieved again. They are secrets: never log them.
	Codes []string `json:"codes"`
}

// GetStatus returns the user's recovery codes status
// (GET /factors/recovery-codes).
func (r *MFARecoveryCodesAPI) GetStatus(ctx context.Context) (*MFARecoveryCodesStatus, error) {
	var out MFARecoveryCodesStatus
	if err := r.m.mfaDo(ctx, http.MethodGet, "/factors/recovery-codes", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Generate creates the user's recovery codes (POST /factors/recovery-codes).
// A request body is only sent when params.FriendlyName is set, like
// auth-js.
func (r *MFARecoveryCodesAPI) Generate(ctx context.Context, params MFARecoveryCodesGenerateParams) (*MFARecoveryCodes, error) {
	var body any
	if params.FriendlyName != "" {
		body = struct {
			FriendlyName string `json:"friendly_name"`
		}{params.FriendlyName}
	}
	var out MFARecoveryCodes
	if err := r.m.mfaDo(ctx, http.MethodPost, "/factors/recovery-codes", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify consumes one recovery code (POST /factors/recovery-codes/verify).
// On success the session is upgraded to aal2: the returned session is
// stored in the Client and an EventMFAChallengeVerified event is emitted
// (unless the API was created with WithAccessToken). The code is sent as
// typed, without client-side normalization.
func (r *MFARecoveryCodesAPI) Verify(ctx context.Context, params MFARecoveryCodesVerifyParams) (*Session, error) {
	if err := mfaRequire(params.Code, "recovery code"); err != nil {
		return nil, err
	}
	body := struct {
		Code string `json:"code"`
	}{params.Code}
	return r.m.mfaVerify(ctx, "/factors/recovery-codes/verify", body)
}

// Regenerate replaces the user's recovery codes with a new set
// (POST /factors/recovery-codes/regenerate). Previous codes stop working.
func (r *MFARecoveryCodesAPI) Regenerate(ctx context.Context) (*MFARecoveryCodes, error) {
	var out MFARecoveryCodes
	if err := r.m.mfaDo(ctx, http.MethodPost, "/factors/recovery-codes/regenerate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unenroll removes the user's recovery codes factor
// (DELETE /factors/recovery-codes).
func (r *MFARecoveryCodesAPI) Unenroll(ctx context.Context) (*MFAUnenrollResponse, error) {
	var out MFAUnenrollResponse
	if err := r.m.mfaDo(ctx, http.MethodDelete, "/factors/recovery-codes", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
