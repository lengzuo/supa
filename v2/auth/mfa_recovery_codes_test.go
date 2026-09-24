package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
)

var mfaTestRecoveryCodes = []string{"k4m6x7qp2ab5ht3z", "wze6r5npd4cmq7vt", "nq5v7xk2m6tp4wzs"}

// upstream: auth-js src/GoTrueClient.ts _getRecoveryCodesStatus
func TestMFARecoveryCodesGetStatus(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, map[string]any{"id": "rc-1", "type": "recovery_code", "total": 10, "remaining": 7})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	got, err := c.MFA().RecoveryCodes().GetStatus(context.Background())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	want := &MFARecoveryCodesStatus{ID: "rc-1", Type: FactorTypeRecoveryCode, Total: 10, Remaining: 7}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	r := fs.last(t)
	if r.Method != http.MethodGet || r.Path != "/auth/v1/factors/recovery-codes" || len(r.Body) != 0 {
		t.Errorf("request = %s %s body=%q", r.Method, r.Path, r.Body)
	}
	mfaAssertAuthed(t, r, "stored-access-token")
}

// upstream: auth-js src/GoTrueClient.ts _getRecoveryCodesStatus (errors)
func TestMFARecoveryCodesGetStatusErrors(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusNotFound, map[string]any{"code": "mfa_factor_not_found", "msg": "not enrolled"})
	})
	if _, err := c.MFA().RecoveryCodes().GetStatus(context.Background()); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("no session: err = %v", err)
	}
	if len(fs.all()) != 0 {
		t.Fatal("request sent without a session")
	}
	mfaSignIn(t, c, "stored-access-token", nil)
	_, err := c.MFA().RecoveryCodes().GetStatus(context.Background())
	mfaAssertAPIError(t, err, http.StatusNotFound, "mfa_factor_not_found")
}

// upstream: auth-js src/GoTrueClient.ts _generateRecoveryCodes
func TestMFARecoveryCodesGenerate(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, map[string]any{
			"id": "rc-1", "type": "recovery_code", "friendly_name": "Recovery codes", "total": 3, "codes": mfaTestRecoveryCodes,
		})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	rc := c.MFA().RecoveryCodes()

	// Without a name no body is sent.
	got, err := rc.Generate(context.Background(), MFARecoveryCodesGenerateParams{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	want := &MFARecoveryCodes{ID: "rc-1", Type: FactorTypeRecoveryCode, FriendlyName: "Recovery codes", Total: 3, Codes: mfaTestRecoveryCodes}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	r := fs.last(t)
	if r.Method != http.MethodPost || r.Path != "/auth/v1/factors/recovery-codes" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	if len(r.Body) != 0 || r.Header.Get("Content-Type") != "" {
		t.Errorf("unexpected body %q (Content-Type %q)", r.Body, r.Header.Get("Content-Type"))
	}
	mfaAssertAuthed(t, r, "stored-access-token")

	// With a name it is sent as friendly_name.
	if _, err := rc.Generate(context.Background(), MFARecoveryCodesGenerateParams{FriendlyName: "Backup"}); err != nil {
		t.Fatal(err)
	}
	mfaAssertJSONBody(t, fs.last(t), map[string]any{"friendly_name": "Backup"})
}

// upstream: auth-js src/GoTrueClient.ts _generateRecoveryCodes (errors)
func TestMFARecoveryCodesGenerateErrors(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": "mfa_recovery_codes_enroll_not_enabled", "msg": "disabled"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	_, err := c.MFA().RecoveryCodes().Generate(context.Background(), MFARecoveryCodesGenerateParams{})
	mfaAssertAPIError(t, err, http.StatusUnprocessableEntity, "mfa_recovery_codes_enroll_not_enabled")
}

// upstream: auth-js src/GoTrueClient.ts _verifyRecoveryCode
func TestMFARecoveryCodesVerify(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		resp := mfaVerifyResponse()
		resp["expires_at"] = 1900000000
		mfaWriteJSON(w, http.StatusOK, resp)
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	ev := mfaSubscribe(c)
	s, err := c.MFA().RecoveryCodes().Verify(context.Background(), MFARecoveryCodesVerifyParams{Code: "K4M6-X7QP 2AB5-ht3z"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r := fs.last(t)
	if r.Method != http.MethodPost || r.Path != "/auth/v1/factors/recovery-codes/verify" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	mfaAssertAuthed(t, r, "stored-access-token")
	// No client-side normalization.
	mfaAssertJSONBody(t, r, map[string]any{"code": "K4M6-X7QP 2AB5-ht3z"})
	if s.AccessToken != "aal2-access-token" || s.ExpiresAt != 1900000000 {
		t.Errorf("session = %+v", s)
	}
	stored, _ := c.loadSession(context.Background())
	if stored == nil || stored.AccessToken != "aal2-access-token" || stored.ExpiresAt != 1900000000 {
		t.Errorf("stored = %+v", stored)
	}
	events, last := ev.snapshot()
	if !reflect.DeepEqual(events, []AuthChangeEvent{EventMFAChallengeVerified}) || last == nil || last.AccessToken != "aal2-access-token" {
		t.Errorf("events = %v, session = %+v", events, last)
	}
}

// upstream: auth-js src/GoTrueClient.ts _verifyRecoveryCode (errors leave session untouched)
func TestMFARecoveryCodesVerifyErrors(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusTooManyRequests, map[string]any{"code": "mfa_recovery_codes_locked", "msg": "locked"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	ev := mfaSubscribe(c)
	_, err := c.MFA().RecoveryCodes().Verify(context.Background(), MFARecoveryCodesVerifyParams{Code: "wrong"})
	mfaAssertAPIError(t, err, http.StatusTooManyRequests, "mfa_recovery_codes_locked")
	stored, _ := c.loadSession(context.Background())
	if stored == nil || stored.AccessToken != "stored-access-token" {
		t.Errorf("stored session changed: %+v", stored)
	}
	if events, _ := ev.snapshot(); len(events) != 0 {
		t.Errorf("events = %v", events)
	}
	if _, err := c.MFA().RecoveryCodes().Verify(context.Background(), MFARecoveryCodesVerifyParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty code: err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _regenerateRecoveryCodes
func TestMFARecoveryCodesRegenerate(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, map[string]any{"id": "rc-1", "type": "recovery_code", "total": 3, "codes": mfaTestRecoveryCodes})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	got, err := c.MFA().RecoveryCodes().Regenerate(context.Background())
	if err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	if got.ID != "rc-1" || !reflect.DeepEqual(got.Codes, mfaTestRecoveryCodes) {
		t.Errorf("got %+v", got)
	}
	r := fs.last(t)
	if r.Method != http.MethodPost || r.Path != "/auth/v1/factors/recovery-codes/regenerate" || len(r.Body) != 0 {
		t.Errorf("request = %s %s body=%q", r.Method, r.Path, r.Body)
	}
	mfaAssertAuthed(t, r, "stored-access-token")
}

// upstream: auth-js src/GoTrueClient.ts _regenerateRecoveryCodes (errors)
func TestMFARecoveryCodesRegenerateErrors(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusForbidden, map[string]any{"code": "insufficient_aal", "msg": "AAL2 required"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	_, err := c.MFA().RecoveryCodes().Regenerate(context.Background())
	mfaAssertAPIError(t, err, http.StatusForbidden, "insufficient_aal")
}

// upstream: auth-js src/GoTrueClient.ts _unenrollRecoveryCodes
func TestMFARecoveryCodesUnenroll(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, map[string]any{"id": "rc-1"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	got, err := c.MFA().RecoveryCodes().Unenroll(context.Background())
	if err != nil {
		t.Fatalf("Unenroll: %v", err)
	}
	if got.ID != "rc-1" {
		t.Errorf("ID = %q", got.ID)
	}
	r := fs.last(t)
	if r.Method != http.MethodDelete || r.Path != "/auth/v1/factors/recovery-codes" || len(r.Body) != 0 {
		t.Errorf("request = %s %s body=%q", r.Method, r.Path, r.Body)
	}
	mfaAssertAuthed(t, r, "stored-access-token")
}

// upstream: auth-js src/GoTrueClient.ts _unenrollRecoveryCodes (errors, explicit token)
func TestMFARecoveryCodesUnenrollErrors(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusForbidden, map[string]any{"code": "insufficient_aal", "msg": "AAL2 required"})
	})
	_, err := c.MFA().WithAccessToken("caller-jwt").RecoveryCodes().Unenroll(context.Background())
	mfaAssertAPIError(t, err, http.StatusForbidden, "insufficient_aal")
	mfaAssertAuthed(t, fs.last(t), "caller-jwt")
}
