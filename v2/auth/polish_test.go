package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lengzuo/supa/v2/internal/transport"
)

// upstream: auth-js src/lib/fetch.ts handleError
func TestToError(t *testing.T) {
	versioned := http.Header{APIVersionHeader: {APIVersion}}
	for _, tc := range []struct {
		name      string
		status    int
		header    http.Header
		body      string
		msg       string
		code      string
		retryable bool
		reasons   []string
	}{
		{"cloudflare non-JSON", 520, nil, "<html>oops</html>", "HTTP 520", "", true, nil},
		{"503 non-JSON uses status text", 503, nil, "down", "Service Unavailable", "", true, nil},
		{"5xx code ignored", 503, versioned, `{"code":"over_request_rate_limit","msg":"busy"}`, "busy", "", true, nil},
		{"code from header version", 400, versioned, `{"code":"otp_expired","msg":"expired","error_code":"other"}`, "expired", "otp_expired", false, nil},
		{"code needs version header", 400, nil, `{"code":"otp_expired","error_code":"legacy","msg":"m"}`, "m", "legacy", false, nil},
		{"badly typed code keeps message and error_code", 400, versioned, `{"code":123,"msg":"bad","error_code":"otp_expired"}`, "bad", "otp_expired", false, nil},
		{"badly typed msg falls back", 400, nil, `{"msg":5,"message":"from message"}`, "from message", "", false, nil},
		{"error_description then error", 400, nil, `{"error":"invalid_grant","error_description":"desc"}`, "desc", "", false, nil},
		{"weak password with code", 422, versioned, `{"code":"weak_password","msg":"weak","weak_password":{"reasons":["length"]}}`, "weak", ErrorCodeWeakPassword, false, []string{"length"}},
		{"legacy weak password", 422, nil, `{"msg":"weak","weak_password":{"reasons":["pwned"]}}`, "weak", ErrorCodeWeakPassword, false, []string{"pwned"}},
		{"weak password bad reasons type", 422, versioned, `{"code":"weak_password","msg":"weak","weak_password":{"reasons":"x"}}`, "weak", ErrorCodeWeakPassword, false, []string{}},
		{"plain text 4xx", 400, nil, "plain text", "plain text", "", false, nil},
		{"JSON non-object", 400, nil, `["x"]`, `["x"]`, "", false, nil},
		{"empty 4xx body", 404, nil, "", "Not Found", "", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := tc.header
			if hdr == nil {
				hdr = http.Header{}
			}
			err := toError(&transport.HTTPError{StatusCode: tc.status, Header: hdr, Body: []byte(tc.body)})
			var ae *Error
			if !errors.As(err, &ae) {
				t.Fatalf("err = %T", err)
			}
			if ae.Message != tc.msg || ae.Code != tc.code || ae.Retryable != tc.retryable || ae.StatusCode != tc.status {
				t.Fatalf("got %+v", ae)
			}
			if tc.reasons != nil && (len(ae.WeakPasswordReasons) != len(tc.reasons) || (len(tc.reasons) > 0 && ae.WeakPasswordReasons[0] != tc.reasons[0])) {
				t.Fatalf("reasons = %v", ae.WeakPasswordReasons)
			}
		})
	}
	netErr := errors.New("dial tcp: refused")
	if got := toError(netErr); got != netErr || !isRetryable(got) {
		t.Fatalf("network error changed: %v", got)
	}
	// session_not_found matches ErrSessionMissing, like AuthSessionMissingError.
	snf := toError(&transport.HTTPError{StatusCode: 403, Header: versioned, Body: []byte(`{"code":"session_not_found","msg":"gone"}`)})
	if !errors.Is(snf, ErrSessionMissing) || !errors.Is(snf, &Error{Code: ErrorCodeSessionNotFound}) {
		t.Fatalf("session_not_found does not match ErrSessionMissing: %v", snf)
	}
	if errors.Is(ErrSessionMissing, &Error{Code: ErrorCodeSessionNotFound}) {
		t.Fatal("matching must be one-directional")
	}
}

// upstream: auth-js GoTrueClient hasCustomAuthorizationHeader (header keys are case-insensitive)
func TestLowercaseAuthorizationHeader(t *testing.T) {
	var mu sync.Mutex
	var got [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Values("Authorization"))
		mu.Unlock()
		coreJSON(w, 200, coreUser("11111111-1111-1111-1111-111111111111"))
	}))
	defer srv.Close()
	userHeaders := http.Header{"authorization": {"Bearer custom"}} // non-canonical key
	c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: coreAPIKey, Headers: userHeaders})
	if err != nil {
		t.Fatal(err)
	}
	if !c.customAuth || c.cfg.Headers.Get("Authorization") != "Bearer custom" {
		t.Fatal("custom Authorization not detected")
	}
	userHeaders.Set("X-Later", "mutation") // the client keeps its own copy
	if c.cfg.Headers.Get("X-Later") != "" {
		t.Fatal("client shares the caller's header map")
	}
	ctx := context.Background()
	if _, err := c.Admin().GetUserByID(ctx, "11111111-1111-1111-1111-111111111111"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetUser(ctx, ""); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for i, vs := range got {
		if len(vs) != 1 || vs[0] != "Bearer custom" {
			t.Fatalf("request %d Authorization = %q", i, vs)
		}
	}
}

// upstream: auth-js src/lib/types.ts User (unknown fields round-trip through storage)
func TestUserJSONRoundTrip(t *testing.T) {
	var u User
	in := `{"id":"u1","aud":"authenticated","email":"a@b.c","created_at":"","updated_at":"","custom_field":{"x":1},"app_metadata":{}}`
	if err := json.Unmarshal([]byte(in), &u); err != nil {
		t.Fatal(err)
	}
	if !u.CreatedAt.IsZero() || u.UpdatedAt != nil {
		t.Fatalf("timestamps = %v %v", u.CreatedAt, u.UpdatedAt)
	}
	u.Email = "new@b.c"
	out, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if m["email"] != "new@b.c" || m["custom_field"] == nil {
		t.Fatalf("marshal = %s", out)
	}
	if _, ok := m["user_metadata"]; ok {
		t.Fatalf("empty metadata not omitted: %s", out)
	}

	// Through saveSession / loadSession.
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		s := coreSession("at", "rt", 3600)
		s["user"].(map[string]any)["custom_field"] = "kept"
		coreJSON(w, 200, s)
	})
	c := srv.client(t)
	if _, err := c.SignInAnonymously(context.Background(), SignInAnonymouslyParams{}); err != nil {
		t.Fatal(err)
	}
	st := coreStored(t, c)
	var raw map[string]any
	_ = json.Unmarshal(st.User.Raw, &raw)
	if raw["custom_field"] != "kept" {
		t.Fatalf("unmodelled field lost in storage: %s", st.User.Raw)
	}
}

// Every user-supplied path segment is escaped, including dot segments.
func TestPathSegmentEscaping(t *testing.T) {
	var mu sync.Mutex
	var uris []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		uris = append(uris, r.RequestURI)
		mu.Unlock()
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: coreAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	calls := []struct {
		name string
		call func()
		want string
	}{
		{"identity", func() { _ = c.UnlinkIdentity(ctx, "jwt", "..") }, "/auth/v1/user/identities/%2E%2E"},
		{"passkey delete", func() { _ = c.Passkey().Delete(ctx, "jwt", ".") }, "/auth/v1/passkeys/%2E"},
		{"passkey update", func() {
			_, _ = c.Passkey().Update(ctx, "jwt", PasskeyUpdateParams{PasskeyID: "a/../b", FriendlyName: "x"})
		}, "/auth/v1/passkeys/a%2F..%2Fb"},
		{"mfa unenroll", func() {
			_, _ = c.MFA().WithAccessToken("jwt").Unenroll(ctx, MFAUnenrollParams{FactorID: ".."})
		}, "/auth/v1/factors/%2E%2E"},
		{"mfa challenge", func() {
			_, _ = c.MFA().WithAccessToken("jwt").Challenge(ctx, MFAChallengeParams{FactorID: ".."})
		}, "/auth/v1/factors/%2E%2E/challenge"},
		{"admin oauth client", func() { _ = c.Admin().OAuth().DeleteClient(ctx, "..") }, "/auth/v1/admin/oauth/clients/%2E%2E"},
		{"custom provider", func() { _ = c.Admin().CustomProviders().DeleteProvider(ctx, "..") }, "/auth/v1/admin/custom-providers/%2E%2E"},
		{"oauth authorization", func() {
			_, _ = c.OAuth().WithAccessToken("jwt").GetAuthorizationDetails(ctx, "..")
		}, "/auth/v1/oauth/authorizations/%2E%2E"},
	}
	for _, tc := range calls {
		mu.Lock()
		uris = nil
		mu.Unlock()
		tc.call()
		mu.Lock()
		got := append([]string(nil), uris...)
		mu.Unlock()
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: RequestURI = %v, want %s", tc.name, got, tc.want)
		}
	}
}

// upstream: auth-js src/lib/fetch.ts _generateLinkResponse (link secrets are not part of the user)
func TestAdminGenerateLinkStripsSecretsFromUser(t *testing.T) {
	body := `{"id":"11111111-1111-1111-1111-111111111111","aud":"authenticated","email":"a@b.c",
		"action_link":"https://x/verify?token=secret","email_otp":"123456","hashed_token":"hashed",
		"redirect_to":"https://app","verification_type":"magiclink","created_at":"2024-01-01T00:00:00Z"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: coreAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Admin().GenerateLink(context.Background(), AdminGenerateLinkParams{Type: AdminGenerateLinkTypeMagicLink, Email: "a@b.c"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Properties.EmailOTP != "123456" || resp.Properties.HashedToken != "hashed" {
		t.Fatalf("properties = %+v", resp.Properties)
	}
	raw := string(resp.User.Raw)
	for _, secret := range []string{"secret", "123456", "hashed", "email_otp", "action_link", "verification_type", "redirect_to"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("user Raw still contains %q: %s", secret, raw)
		}
	}
	if resp.User.ActionLink != "" || resp.User.Email != "a@b.c" {
		t.Fatalf("user = %+v", resp.User)
	}
}

// Admin user-returning calls reject an empty or null 200 body.
func TestAdminEmptyUserBody(t *testing.T) {
	for _, body := range []string{"", "null", " null "} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
		c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: coreAPIKey})
		if err != nil {
			t.Fatal(err)
		}
		u, err := c.Admin().GetUserByID(context.Background(), "11111111-1111-1111-1111-111111111111")
		if err == nil || u != nil {
			t.Errorf("body %q: GetUserByID = %v, %v", body, u, err)
		}
		if _, err := c.Admin().GenerateLink(context.Background(), AdminGenerateLinkParams{Type: AdminGenerateLinkTypeMagicLink, Email: "a@b.c"}); err == nil {
			t.Errorf("body %q: GenerateLink returned no error", body)
		}
		if _, err := c.GetUser(context.Background(), "jwt"); err == nil {
			t.Errorf("body %q: GetUser returned no error", body)
		}
		srv.Close()
	}
}

// upstream: auth-js GoTrueAdminApi.ts createOAuthClient (optional fields omitted)
func TestAdminCreateOAuthClientOmitsEmptyRedirectURIs(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"client_id":"c1"}`)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: coreAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Admin().OAuth().CreateClient(context.Background(), AdminCreateOAuthClientParams{ClientName: "x"})
	if _, ok := got["redirect_uris"]; ok {
		t.Fatalf("redirect_uris sent: %v", got)
	}
}

// upstream: auth-js src/GoTrueClient.ts _listFactors -> getUser (session_not_found signs out)
func TestMFAListFactorsSessionNotFound(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) {
		coreJSON(w, 403, map[string]any{"code": ErrorCodeSessionNotFound, "msg": "gone"})
	})
	c := srv.client(t)
	coreStoreSession(t, c, "dead-at", "rt", time.Now().Add(time.Hour))
	ev := coreWatch(c)
	if _, err := c.MFA().ListFactors(context.Background()); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("err = %v", err)
	}
	if coreStored(t, c) != nil {
		t.Fatal("dead session kept")
	}
	coreAssertEvents(t, ev, EventSignedOut)

	// Explicit token mode never touches storage.
	coreStoreSession(t, c, "other-at", "rt2", time.Now().Add(time.Hour))
	if _, err := c.MFA().WithAccessToken("jwt").ListFactors(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if coreStored(t, c) == nil {
		t.Fatal("explicit-token call removed the stored session")
	}
}

// MFA input validation: blank tokens and empty codes.
func TestMFAInputValidation(t *testing.T) {
	srv := newCoreServer(t, func(w http.ResponseWriter, r *coreReq) { coreJSON(w, 200, map[string]any{}) })
	c := srv.client(t)
	if m := c.MFA().WithAccessToken("   "); m.token != "" {
		t.Fatalf("blank token kept: %q", m.token)
	}
	if _, err := c.MFA().WithAccessToken("   ").ListFactors(context.Background()); !errors.Is(err, ErrSessionMissing) {
		t.Fatalf("blank token should fall back to the (missing) stored session: %v", err)
	}
	_, err := c.MFA().WithAccessToken("jwt").Verify(context.Background(), MFAVerifyParams{FactorID: "f", ChallengeID: "c"})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
	if len(srv.requests()) != 0 {
		t.Fatal("request sent")
	}
}
