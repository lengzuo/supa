package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const mfaTestAPIKey = "test-anon-key"

// mfaRecorded is one request seen by the fake server.
type mfaRecorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// mfaJSON decodes the recorded body into a generic map.
func (r mfaRecorded) mfaJSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("request body is not a JSON object: %v (%q)", err, r.Body)
	}
	return m
}

type mfaFakeServer struct {
	mu   sync.Mutex
	reqs []mfaRecorded
}

func (f *mfaFakeServer) all() []mfaRecorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]mfaRecorded(nil), f.reqs...)
}

func (f *mfaFakeServer) last(t *testing.T) mfaRecorded {
	t.Helper()
	reqs := f.all()
	if len(reqs) == 0 {
		t.Fatal("no request was sent")
	}
	return reqs[len(reqs)-1]
}

// mfaNewTestClient starts a fake Auth server that answers with handler and
// returns a Client pointing at it.
func mfaNewTestClient(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*Client, *mfaFakeServer) {
	t.Helper()
	fs := &mfaFakeServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fs.mu.Lock()
		fs.reqs = append(fs.reqs, mfaRecorded{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery,
			Header: r.Header.Clone(), Body: body,
		})
		fs.mu.Unlock()
		w.Header().Set(APIVersionHeader, APIVersion)
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: mfaTestAPIKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, fs
}

func mfaWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// mfaJWT builds an unsigned JWT with claims.
func mfaJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("sig"))
}

// mfaSignIn stores a non-expiring fake session for a signed-in user.
func mfaSignIn(t *testing.T, c *Client, accessToken string, factors []Factor) *Session {
	t.Helper()
	s := &Session{
		AccessToken:  accessToken,
		RefreshToken: "stored-refresh-token",
		TokenType:    "bearer",
		ExpiresIn:    3600,
		ExpiresAt:    time.Now().Add(100 * 365 * 24 * time.Hour).Unix(),
		User:         &User{ID: "user-1", Aud: "authenticated", Factors: factors},
	}
	if err := c.saveSession(context.Background(), s); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	return s
}

// mfaAssertAuthed checks the common headers of a user-authenticated call.
func mfaAssertAuthed(t *testing.T, r mfaRecorded, token string) {
	t.Helper()
	if got := r.Header.Get("apikey"); got != mfaTestAPIKey {
		t.Errorf("apikey = %q, want %q", got, mfaTestAPIKey)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("Authorization = %q, want %q", got, "Bearer "+token)
	}
	if got := r.Header.Get(APIVersionHeader); got != APIVersion {
		t.Errorf("%s = %q, want %q", APIVersionHeader, got, APIVersion)
	}
}

func mfaAssertJSONBody(t *testing.T, r mfaRecorded, want map[string]any) {
	t.Helper()
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := r.mfaJSON(t); !reflect.DeepEqual(got, want) {
		t.Errorf("body = %#v, want %#v", got, want)
	}
}

func mfaAssertAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v (%T), want *Error", err, err)
	}
	if ae.StatusCode != status || ae.Code != code {
		t.Errorf("error status/code = %d/%q, want %d/%q", ae.StatusCode, ae.Code, status, code)
	}
}

// mfaEvents records auth events.
type mfaEvents struct {
	mu     sync.Mutex
	events []AuthChangeEvent
	last   *Session
}

func mfaSubscribe(c *Client) *mfaEvents {
	ev := &mfaEvents{}
	c.OnAuthStateChange(func(e AuthChangeEvent, s *Session) {
		ev.mu.Lock()
		ev.events = append(ev.events, e)
		ev.last = s
		ev.mu.Unlock()
	})
	return ev
}

func (e *mfaEvents) snapshot() ([]AuthChangeEvent, *Session) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]AuthChangeEvent(nil), e.events...), e.last
}

// mfaVerifyResponse is a realistic verify response.
func mfaVerifyResponse() map[string]any {
	return map[string]any{
		"access_token":  "aal2-access-token",
		"token_type":    "bearer",
		"expires_in":    3600,
		"refresh_token": "aal2-refresh-token",
		"user": map[string]any{
			"id":         "user-1",
			"aud":        "authenticated",
			"email":      "user@example.com",
			"created_at": "2026-01-01T00:00:00Z",
			"factors": []any{map[string]any{
				"id": "factor-1", "factor_type": "totp", "status": "verified",
				"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
			}},
		},
	}
}

// upstream: auth-js src/GoTrueClient.ts _enroll
func TestMFAEnroll(t *testing.T) {
	tests := []struct {
		name     string
		params   MFAEnrollParams
		resp     map[string]any
		wantBody map[string]any
		check    func(t *testing.T, got *MFAEnrollResponse)
	}{
		{
			name:   "totp",
			params: MFAEnrollParams{FactorType: FactorTypeTOTP, FriendlyName: "My app", Issuer: "example.com", Phone: "ignored"},
			resp: map[string]any{
				"id": "factor-1", "type": "totp", "friendly_name": "My app",
				"totp": map[string]any{"qr_code": "<svg></svg>", "secret": "SECRET", "uri": "otpauth://totp/x"},
			},
			wantBody: map[string]any{"friendly_name": "My app", "factor_type": "totp", "issuer": "example.com"},
			check: func(t *testing.T, got *MFAEnrollResponse) {
				want := &MFAEnrollResponse{
					ID: "factor-1", Type: FactorTypeTOTP, FriendlyName: "My app",
					TOTP: &MFATOTPEnrollment{QRCode: "data:image/svg+xml;utf-8,<svg></svg>", Secret: "SECRET", URI: "otpauth://totp/x"},
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %+v, want %+v", got, want)
				}
			},
		},
		{
			name:     "phone",
			params:   MFAEnrollParams{FactorType: FactorTypePhone, Phone: "+15555550100", Issuer: "ignored"},
			resp:     map[string]any{"id": "factor-2", "type": "phone", "phone": "+15555550100"},
			wantBody: map[string]any{"factor_type": "phone", "phone": "+15555550100"},
			check: func(t *testing.T, got *MFAEnrollResponse) {
				if got.ID != "factor-2" || got.Type != FactorTypePhone || got.Phone != "+15555550100" || got.TOTP != nil {
					t.Errorf("got %+v", got)
				}
			},
		},
		{
			name:     "webauthn",
			params:   MFAEnrollParams{FactorType: FactorTypeWebAuthn, FriendlyName: "Key"},
			resp:     map[string]any{"id": "factor-3", "type": "webauthn", "friendly_name": "Key"},
			wantBody: map[string]any{"factor_type": "webauthn", "friendly_name": "Key"},
			check: func(t *testing.T, got *MFAEnrollResponse) {
				if got.ID != "factor-3" || got.Type != FactorTypeWebAuthn || got.FriendlyName != "Key" {
					t.Errorf("got %+v", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				mfaWriteJSON(w, http.StatusOK, tt.resp)
			})
			mfaSignIn(t, c, "stored-access-token", nil)
			got, err := c.MFA().Enroll(context.Background(), tt.params)
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			r := fs.last(t)
			if r.Method != http.MethodPost || r.Path != "/auth/v1/factors" || r.Query != "" {
				t.Errorf("request = %s %s?%s", r.Method, r.Path, r.Query)
			}
			mfaAssertAuthed(t, r, "stored-access-token")
			mfaAssertJSONBody(t, r, tt.wantBody)
			tt.check(t, got)
		})
	}
}

// upstream: auth-js src/GoTrueClient.ts _enroll (error paths)
func TestMFAEnrollErrors(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": "mfa_factor_name_conflict", "msg": "name taken"})
	})

	// No session: fails before any request.
	if _, err := c.MFA().Enroll(context.Background(), MFAEnrollParams{FactorType: FactorTypeTOTP}); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("no session: err = %v, want ErrSessionMissing", err)
	}
	if n := len(fs.all()); n != 0 {
		t.Fatalf("sent %d requests without a session", n)
	}

	mfaSignIn(t, c, "stored-access-token", nil)
	if _, err := c.MFA().Enroll(context.Background(), MFAEnrollParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("missing factor type: err = %v", err)
	}
	_, err := c.MFA().Enroll(context.Background(), MFAEnrollParams{FactorType: FactorTypeTOTP})
	mfaAssertAPIError(t, err, http.StatusUnprocessableEntity, "mfa_factor_name_conflict")
}

// upstream: auth-js src/GoTrueClient.ts _unenroll
func TestMFAUnenroll(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, map[string]any{"id": "factor/1"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	got, err := c.MFA().Unenroll(context.Background(), MFAUnenrollParams{FactorID: "factor/1"})
	if err != nil {
		t.Fatalf("Unenroll: %v", err)
	}
	if got.ID != "factor/1" {
		t.Errorf("ID = %q", got.ID)
	}
	r := fs.last(t)
	if r.Method != http.MethodDelete || r.Path != "/auth/v1/factors/factor/1" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	if len(r.Body) != 0 {
		t.Errorf("unexpected body %q", r.Body)
	}
	mfaAssertAuthed(t, r, "stored-access-token")

	if _, err := c.MFA().Unenroll(context.Background(), MFAUnenrollParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty factor ID: err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _unenroll (path escaping and errors)
func TestMFAUnenrollEscapesAndErrors(t *testing.T) {
	var rawPath atomic.Value
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		rawPath.Store(r.URL.EscapedPath())
		mfaWriteJSON(w, http.StatusForbidden, map[string]any{"code": "insufficient_aal", "msg": "AAL2 required"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	_, err := c.MFA().Unenroll(context.Background(), MFAUnenrollParams{FactorID: "a/b?c"})
	mfaAssertAPIError(t, err, http.StatusForbidden, "insufficient_aal")
	if got, _ := rawPath.Load().(string); got != "/auth/v1/factors/a%2Fb%3Fc" {
		t.Errorf("escaped path = %q", got)
	}
}

// upstream: auth-js src/GoTrueClient.ts _challenge
func TestMFAChallenge(t *testing.T) {
	publicKey := `{"challenge":"Y2hhbGxlbmdl","rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"u","displayName":"u"},"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`
	tests := []struct {
		name     string
		params   MFAChallengeParams
		resp     string
		wantBody map[string]any
		check    func(t *testing.T, got *MFAChallengeResponse)
	}{
		{
			name:     "totp",
			params:   MFAChallengeParams{FactorID: "factor-1"},
			resp:     `{"id":"challenge-1","type":"totp","expires_at":1900000000}`,
			wantBody: map[string]any{"factorId": "factor-1"},
			check: func(t *testing.T, got *MFAChallengeResponse) {
				want := &MFAChallengeResponse{ID: "challenge-1", Type: FactorTypeTOTP, ExpiresAt: 1900000000}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %+v, want %+v", got, want)
				}
			},
		},
		{
			name:     "phone",
			params:   MFAChallengeParams{FactorID: "factor-1", Channel: MFAChannelWhatsApp},
			resp:     `{"id":"challenge-2","type":"phone","expires_at":1900000000}`,
			wantBody: map[string]any{"factorId": "factor-1", "channel": "whatsapp"},
			check: func(t *testing.T, got *MFAChallengeResponse) {
				if got.ID != "challenge-2" || got.Type != FactorTypePhone {
					t.Errorf("got %+v", got)
				}
			},
		},
		{
			name: "webauthn",
			params: MFAChallengeParams{FactorID: "factor-1", WebAuthn: &MFAWebAuthnRelyingParty{
				RPID: "example.com", RPOrigins: []string{"https://example.com"},
			}},
			resp: `{"id":"challenge-3","type":"webauthn","expires_at":1900000000,"webauthn":{"type":"create","credential_options":{"publicKey":` + publicKey + `}}}`,
			wantBody: map[string]any{"factorId": "factor-1", "webauthn": map[string]any{
				"rpId": "example.com", "rpOrigins": []any{"https://example.com"},
			}},
			check: func(t *testing.T, got *MFAChallengeResponse) {
				if got.WebAuthn == nil || got.WebAuthn.Type != MFAWebAuthnCreate {
					t.Fatalf("WebAuthn = %+v", got.WebAuthn)
				}
				if string(got.WebAuthn.CredentialOptions.PublicKey) != publicKey {
					t.Errorf("publicKey = %s", got.WebAuthn.CredentialOptions.PublicKey)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tt.resp)
			})
			mfaSignIn(t, c, "stored-access-token", nil)
			got, err := c.MFA().Challenge(context.Background(), tt.params)
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			r := fs.last(t)
			if r.Method != http.MethodPost || r.Path != "/auth/v1/factors/factor-1/challenge" {
				t.Errorf("request = %s %s", r.Method, r.Path)
			}
			mfaAssertAuthed(t, r, "stored-access-token")
			mfaAssertJSONBody(t, r, tt.wantBody)
			tt.check(t, got)
		})
	}
}

// upstream: auth-js src/GoTrueClient.ts _challenge (error paths)
func TestMFAChallengeErrors(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusNotFound, map[string]any{"code": "mfa_factor_not_found", "msg": "Factor not found"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	_, err := c.MFA().Challenge(context.Background(), MFAChallengeParams{FactorID: "nope"})
	mfaAssertAPIError(t, err, http.StatusNotFound, "mfa_factor_not_found")

	if _, err := c.MFA().Challenge(context.Background(), MFAChallengeParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("missing factor: err = %v", err)
	}
	if _, err := c.MFA().Challenge(context.Background(), MFAChallengeParams{FactorID: "f", WebAuthn: &MFAWebAuthnRelyingParty{}}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("missing rpId: err = %v", err)
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify
func TestMFAVerify(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, mfaVerifyResponse())
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	ev := mfaSubscribe(c)

	before := time.Now().Unix()
	s, err := c.MFA().Verify(context.Background(), MFAVerifyParams{FactorID: "factor-1", ChallengeID: "challenge-1", Code: "123456"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r := fs.last(t)
	if r.Method != http.MethodPost || r.Path != "/auth/v1/factors/factor-1/verify" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	mfaAssertAuthed(t, r, "stored-access-token")
	mfaAssertJSONBody(t, r, map[string]any{"challenge_id": "challenge-1", "code": "123456"})

	if s.AccessToken != "aal2-access-token" || s.RefreshToken != "aal2-refresh-token" || s.User == nil || len(s.User.Factors) != 1 {
		t.Errorf("session = %+v", s)
	}
	if s.ExpiresAt < before+3600 || s.ExpiresAt > time.Now().Unix()+3600 {
		t.Errorf("ExpiresAt = %d, want now+3600", s.ExpiresAt)
	}
	stored, err := c.loadSession(context.Background())
	if err != nil || stored == nil || stored.AccessToken != "aal2-access-token" {
		t.Fatalf("stored session = %+v, %v", stored, err)
	}
	events, last := ev.snapshot()
	if !reflect.DeepEqual(events, []AuthChangeEvent{EventMFAChallengeVerified}) {
		t.Errorf("events = %v", events)
	}
	if last == nil || last.AccessToken != "aal2-access-token" {
		t.Errorf("event session = %+v", last)
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify (server expires_at wins)
func TestMFAVerifyKeepsServerExpiresAt(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		resp := mfaVerifyResponse()
		resp["expires_at"] = 1900000000
		mfaWriteJSON(w, http.StatusOK, resp)
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	s, err := c.MFA().Verify(context.Background(), MFAVerifyParams{FactorID: "f", ChallengeID: "c", Code: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if s.ExpiresAt != 1900000000 {
		t.Errorf("ExpiresAt = %d", s.ExpiresAt)
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify (webauthn credential_response)
func TestMFAVerifyWebAuthn(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, mfaVerifyResponse())
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	cred := json.RawMessage(`{"id":"cred","rawId":"cred","type":"public-key","response":{"authenticatorData":"YQ","clientDataJSON":"Yg","signature":"Yw"},"clientExtensionResults":{}}`)
	_, err := c.MFA().Verify(context.Background(), MFAVerifyParams{
		FactorID: "factor-1", ChallengeID: "challenge-1",
		WebAuthn: &MFAVerifyWebAuthnParams{RPID: "example.com", RPOrigins: []string{"https://example.com"}, Type: MFAWebAuthnRequest, CredentialResponse: cred},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var credMap map[string]any
	_ = json.Unmarshal(cred, &credMap)
	mfaAssertJSONBody(t, fs.last(t), map[string]any{
		"challenge_id": "challenge-1",
		"webauthn": map[string]any{
			"rpId": "example.com", "rpOrigins": []any{"https://example.com"},
			"type": "request", "credential_response": credMap,
		},
	})

	bad := []MFAVerifyWebAuthnParams{
		{Type: MFAWebAuthnCreate, CredentialResponse: cred},
		{RPID: "x", Type: "bogus", CredentialResponse: cred},
		{RPID: "x", Type: MFAWebAuthnCreate},
		{RPID: "x", Type: MFAWebAuthnCreate, CredentialResponse: json.RawMessage(`{nope`)},
	}
	for i := range bad {
		if _, err := c.MFA().Verify(context.Background(), MFAVerifyParams{FactorID: "f", ChallengeID: "c", WebAuthn: &bad[i]}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("bad[%d]: err = %v, want ErrInvalidArgument", i, err)
		}
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify (error paths)
func TestMFAVerifyErrors(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusUnprocessableEntity, map[string]any{"code": ErrorCodeMFAVerificationFailed, "msg": "Invalid TOTP code entered"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	ev := mfaSubscribe(c)
	_, err := c.MFA().Verify(context.Background(), MFAVerifyParams{FactorID: "f", ChallengeID: "c", Code: "000000"})
	mfaAssertAPIError(t, err, http.StatusUnprocessableEntity, ErrorCodeMFAVerificationFailed)
	stored, _ := c.loadSession(context.Background())
	if stored == nil || stored.AccessToken != "stored-access-token" {
		t.Errorf("stored session changed: %+v", stored)
	}
	if events, _ := ev.snapshot(); len(events) != 0 {
		t.Errorf("events = %v", events)
	}
	for _, p := range []MFAVerifyParams{{ChallengeID: "c"}, {FactorID: "f"}} {
		if _, err := c.MFA().Verify(context.Background(), p); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%+v: err = %v", p, err)
		}
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify (explicit JWT, server-side use)
func TestMFAWithAccessToken(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, mfaVerifyResponse())
	})
	ev := mfaSubscribe(c)
	s, err := c.MFA().WithAccessToken("caller-jwt").Verify(context.Background(), MFAVerifyParams{FactorID: "f", ChallengeID: "c", Code: "1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	mfaAssertAuthed(t, fs.last(t), "caller-jwt")
	if s.AccessToken != "aal2-access-token" || s.ExpiresAt == 0 {
		t.Errorf("session = %+v", s)
	}
	if stored, _ := c.loadSession(context.Background()); stored != nil {
		t.Errorf("token mode stored a session: %+v", stored)
	}
	if events, _ := ev.snapshot(); len(events) != 0 {
		t.Errorf("token mode emitted events: %v", events)
	}
}

// upstream: auth-js src/GoTrueClient.ts _challengeAndVerify
func TestMFAChallengeAndVerify(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/challenge") {
			mfaWriteJSON(w, http.StatusOK, map[string]any{"id": "challenge-9", "type": "totp", "expires_at": 1900000000})
			return
		}
		mfaWriteJSON(w, http.StatusOK, mfaVerifyResponse())
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	s, err := c.MFA().ChallengeAndVerify(context.Background(), MFAChallengeAndVerifyParams{FactorID: "factor-1", Code: "654321"})
	if err != nil {
		t.Fatalf("ChallengeAndVerify: %v", err)
	}
	if s.AccessToken != "aal2-access-token" {
		t.Errorf("session = %+v", s)
	}
	reqs := fs.all()
	if len(reqs) != 2 {
		t.Fatalf("sent %d requests, want 2", len(reqs))
	}
	if reqs[0].Path != "/auth/v1/factors/factor-1/challenge" {
		t.Errorf("first path = %s", reqs[0].Path)
	}
	mfaAssertJSONBody(t, reqs[0], map[string]any{"factorId": "factor-1"})
	if reqs[1].Path != "/auth/v1/factors/factor-1/verify" {
		t.Errorf("second path = %s", reqs[1].Path)
	}
	mfaAssertJSONBody(t, reqs[1], map[string]any{"challenge_id": "challenge-9", "code": "654321"})
	mfaAssertAuthed(t, reqs[1], "stored-access-token")
}

// upstream: auth-js src/GoTrueClient.ts _challengeAndVerify (challenge failure)
func TestMFAChallengeAndVerifyChallengeError(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusNotFound, map[string]any{"code": "mfa_factor_not_found", "msg": "not found"})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	_, err := c.MFA().ChallengeAndVerify(context.Background(), MFAChallengeAndVerifyParams{FactorID: "f", Code: "1"})
	mfaAssertAPIError(t, err, http.StatusNotFound, "mfa_factor_not_found")
	if n := len(fs.all()); n != 1 {
		t.Errorf("sent %d requests, want 1 (no verify)", n)
	}
}

// upstream: auth-js src/GoTrueClient.ts _listFactors
func TestMFAListFactors(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		f := func(id, typ, status string) map[string]any {
			return map[string]any{"id": id, "factor_type": typ, "status": status,
				"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}
		}
		mfaWriteJSON(w, http.StatusOK, map[string]any{
			"id": "user-1", "aud": "authenticated", "created_at": "2026-01-01T00:00:00Z",
			"factors": []any{
				f("t1", "totp", "verified"),
				f("t2", "totp", "unverified"),
				f("p1", "phone", "verified"),
				f("w1", "webauthn", "verified"),
				f("r1", "recovery_code", "verified"),
				f("x1", "future_type", "verified"),
			},
		})
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	got, err := c.MFA().ListFactors(context.Background())
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	r := fs.last(t)
	if r.Method != http.MethodGet || r.Path != "/auth/v1/user" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	mfaAssertAuthed(t, r, "stored-access-token")
	ids := func(fs []Factor) []string {
		out := []string{}
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return out
	}
	checks := map[string][2][]string{
		"all":           {ids(got.All), {"t1", "t2", "p1", "w1", "r1", "x1"}},
		"totp":          {ids(got.TOTP), {"t1"}},
		"phone":         {ids(got.Phone), {"p1"}},
		"webauthn":      {ids(got.WebAuthn), {"w1"}},
		"recovery_code": {ids(got.RecoveryCode), {"r1"}},
	}
	for name, c := range checks {
		if !reflect.DeepEqual(c[0], c[1]) {
			t.Errorf("%s = %v, want %v", name, c[0], c[1])
		}
	}
}

// upstream: auth-js src/GoTrueClient.ts _listFactors (no factors, errors)
func TestMFAListFactorsEmptyAndErrors(t *testing.T) {
	var fail atomic.Bool
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			mfaWriteJSON(w, http.StatusUnauthorized, map[string]any{"code": "bad_jwt", "msg": "invalid JWT"})
			return
		}
		mfaWriteJSON(w, http.StatusOK, map[string]any{"id": "user-1", "aud": "authenticated", "created_at": "2026-01-01T00:00:00Z"})
	})
	if _, err := c.MFA().ListFactors(context.Background()); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("no session: err = %v", err)
	}
	mfaSignIn(t, c, "stored-access-token", nil)
	got, err := c.MFA().ListFactors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.All == nil || len(got.All) != 0 || got.TOTP == nil || got.RecoveryCode == nil {
		t.Errorf("want empty non-nil lists, got %+v", got)
	}
	fail.Store(true)
	_, err = c.MFA().ListFactors(context.Background())
	mfaAssertAPIError(t, err, http.StatusUnauthorized, "bad_jwt")
}

// upstream: auth-js src/GoTrueClient.ts _getAuthenticatorAssuranceLevel (session path)
func TestMFAGetAuthenticatorAssuranceLevel(t *testing.T) {
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	})
	ctx := context.Background()

	// No session: empty levels, no error.
	got, err := c.MFA().GetAuthenticatorAssuranceLevel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentLevel != "" || got.NextLevel != "" || got.CurrentAuthenticationMethods == nil || len(got.CurrentAuthenticationMethods) != 0 {
		t.Errorf("no session: got %+v", got)
	}

	// aal1 token, no verified factors.
	tok := mfaJWT(t, map[string]any{"sub": "user-1", "aal": "aal1", "amr": []any{map[string]any{"method": "password", "timestamp": 1700000000}}})
	mfaSignIn(t, c, tok, []Factor{{ID: "f", FactorType: FactorTypeTOTP, Status: FactorStatusUnverified}})
	got, err = c.MFA().GetAuthenticatorAssuranceLevel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := &MFAAssuranceLevelResponse{
		CurrentLevel: MFAAssuranceLevel1, NextLevel: MFAAssuranceLevel1,
		CurrentAuthenticationMethods: []AMREntry{{Method: "password", Timestamp: 1700000000}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unverified factor: got %+v, want %+v", got, want)
	}

	// aal1 token with a verified factor: next level is aal2.
	mfaSignIn(t, c, tok, []Factor{{ID: "f", FactorType: FactorTypeTOTP, Status: FactorStatusVerified}})
	got, err = c.MFA().GetAuthenticatorAssuranceLevel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.CurrentLevel != MFAAssuranceLevel1 || got.NextLevel != MFAAssuranceLevel2 {
		t.Errorf("verified factor: got %+v", got)
	}

	// RFC 8176 string amr and missing aal.
	tok = mfaJWT(t, map[string]any{"sub": "user-1", "amr": []any{"pwd", "otp"}})
	mfaSignIn(t, c, tok, nil)
	got, err = c.MFA().GetAuthenticatorAssuranceLevel(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want = &MFAAssuranceLevelResponse{CurrentAuthenticationMethods: []AMREntry{{Method: "pwd"}, {Method: "otp"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("string amr: got %+v, want %+v", got, want)
	}

	// Malformed token.
	mfaSignIn(t, c, "not-a-jwt", nil)
	if _, err := c.MFA().GetAuthenticatorAssuranceLevel(ctx); !errors.Is(err, ErrInvalidJWT) {
		t.Errorf("malformed: err = %v", err)
	}
	if n := len(fs.all()); n != 0 {
		t.Errorf("session path sent %d requests", n)
	}
}

// upstream: auth-js src/GoTrueClient.ts _getAuthenticatorAssuranceLevel (jwt path)
func TestMFAGetAuthenticatorAssuranceLevelWithToken(t *testing.T) {
	var fail atomic.Bool
	c, fs := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			mfaWriteJSON(w, http.StatusUnauthorized, map[string]any{"code": "bad_jwt", "msg": "invalid JWT"})
			return
		}
		mfaWriteJSON(w, http.StatusOK, map[string]any{
			"id": "user-1", "aud": "authenticated", "created_at": "2026-01-01T00:00:00Z",
			"factors": []any{map[string]any{"id": "f", "factor_type": "phone", "status": "verified",
				"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}},
		})
	})
	tok := mfaJWT(t, map[string]any{"sub": "user-1", "aal": "aal1"})
	got, err := c.MFA().WithAccessToken(tok).GetAuthenticatorAssuranceLevel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	if r.Method != http.MethodGet || r.Path != "/auth/v1/user" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	mfaAssertAuthed(t, r, tok)
	want := &MFAAssuranceLevelResponse{CurrentLevel: MFAAssuranceLevel1, NextLevel: MFAAssuranceLevel2, CurrentAuthenticationMethods: []AMREntry{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}

	fail.Store(true)
	_, err = c.MFA().WithAccessToken(tok).GetAuthenticatorAssuranceLevel(context.Background())
	mfaAssertAPIError(t, err, http.StatusUnauthorized, "bad_jwt")

	n := len(fs.all())
	if _, err := c.MFA().WithAccessToken("bad").GetAuthenticatorAssuranceLevel(context.Background()); !errors.Is(err, ErrInvalidJWT) {
		t.Errorf("malformed: err = %v", err)
	}
	if len(fs.all()) != n {
		t.Error("malformed token triggered a request")
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify (context cancellation)
func TestMFAContextCanceled(t *testing.T) {
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mfaWriteJSON(w, http.StatusOK, mfaVerifyResponse())
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.MFA().Verify(ctx, MFAVerifyParams{FactorID: "f", ChallengeID: "c", Code: "1"}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	stored, _ := c.loadSession(context.Background())
	if stored == nil || stored.AccessToken != "stored-access-token" {
		t.Errorf("stored session changed: %+v", stored)
	}
}

// upstream: auth-js src/GoTrueClient.ts _verify (concurrent use)
func TestMFAConcurrentVerify(t *testing.T) {
	// Hold every verify request until all 8 have arrived, so all of them
	// were authenticated with the same (original) stored session.
	const n = 8
	var arrived atomic.Int32
	allIn := make(chan struct{})
	c, _ := mfaNewTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if arrived.Add(1) == n {
			close(allIn)
		}
		<-allIn
		mfaWriteJSON(w, http.StatusOK, mfaVerifyResponse())
	})
	mfaSignIn(t, c, "stored-access-token", nil)
	ev := mfaSubscribe(c)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.MFA().Verify(context.Background(), MFAVerifyParams{FactorID: "f", ChallengeID: "c", Code: "1"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// All verifications started from the same stored session; the first
	// write-back replaces it, so the others (whose basis is no longer the
	// stored session) must not overwrite it again.
	if events, _ := ev.snapshot(); len(events) != 1 {
		t.Errorf("got %d events, want 1", len(events))
	}
	if stored, _ := c.loadSession(context.Background()); stored == nil || stored.AccessToken == "stored-access-token" {
		t.Errorf("stored session not upgraded: %+v", stored)
	}
}
