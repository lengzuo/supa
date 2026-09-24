package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const (
	adminTestKey      = "service-role-key"
	adminTestUserID   = "8a4c1b2e-1f2d-4c5b-9e7a-0d1c2b3a4f5e"
	adminTestFactorID = "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
	adminTestUserJSON = `{"id":"8a4c1b2e-1f2d-4c5b-9e7a-0d1c2b3a4f5e","aud":"authenticated","role":"authenticated","email":"jane@example.com","app_metadata":{"provider":"email"},"user_metadata":{"name":"Jane"},"created_at":"2024-05-01T10:00:00Z"}`
)

// adminRecorded is one request seen by the test server.
type adminRecorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// adminTestServer starts a server replying with status/body (and extra
// headers) and returns a Client pointed at it plus the recorded requests.
func adminTestServer(t *testing.T, status int, body string, hdr http.Header) (*Client, func() []adminRecorded) {
	t.Helper()
	var mu sync.Mutex
	var reqs []adminRecorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, adminRecorded{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Clone(), b})
		mu.Unlock()
		for k, vs := range hdr {
			w.Header()[k] = vs
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{URL: srv.URL + "/auth/v1", APIKey: adminTestKey})
	if err != nil {
		t.Fatal(err)
	}
	return c, func() []adminRecorded {
		mu.Lock()
		defer mu.Unlock()
		return append([]adminRecorded(nil), reqs...)
	}
}

// adminOne returns the single recorded request, failing otherwise.
func adminOne(t *testing.T, got func() []adminRecorded) adminRecorded {
	t.Helper()
	rs := got()
	if len(rs) != 1 {
		t.Fatalf("got %d requests, want 1", len(rs))
	}
	return rs[0]
}

// adminCheck asserts method, path, query and the admin auth headers.
func adminCheck(t *testing.T, r adminRecorded, method, path, query, bearer string) {
	t.Helper()
	if r.Method != method {
		t.Errorf("method = %s, want %s", r.Method, method)
	}
	if r.Path != path {
		t.Errorf("path = %s, want %s", r.Path, path)
	}
	if r.Query != query {
		t.Errorf("query = %q, want %q", r.Query, query)
	}
	if got := r.Header.Get("apikey"); got != adminTestKey {
		t.Errorf("apikey = %q", got)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+bearer {
		t.Errorf("Authorization = %q, want Bearer %s", got, bearer)
	}
	if got := r.Header.Get(APIVersionHeader); got != APIVersion {
		t.Errorf("%s = %q", APIVersionHeader, got)
	}
}

// adminJSONBody asserts the request body equals want (as JSON).
func adminJSONBody(t *testing.T, r adminRecorded, want string) {
	t.Helper()
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var got, exp any
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	if err := json.Unmarshal([]byte(want), &exp); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("body = %s, want %s", r.Body, want)
	}
}

// adminWantAPIError asserts err is an *Error with status and code.
func adminWantAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T), want *Error", err, err)
	}
	if ae.StatusCode != status || ae.Code != code {
		t.Errorf("got status %d code %q, want %d %q", ae.StatusCode, ae.Code, status, code)
	}
}

func adminAPIErrorBody(code, msg string) (string, http.Header) {
	return `{"code":"` + code + `","msg":"` + msg + `"}`, http.Header{APIVersionHeader: {APIVersion}}
}

// upstream: auth-js src/GoTrueAdminApi.ts signOut
func TestAdminSignOut(t *testing.T) {
	c, got := adminTestServer(t, http.StatusNoContent, "", nil)
	if err := c.Admin().SignOut(context.Background(), "user-jwt", ""); err != nil {
		t.Fatal(err)
	}
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/logout", "scope=global", "user-jwt")

	c, got = adminTestServer(t, http.StatusNoContent, "", nil)
	if err := c.Admin().SignOut(context.Background(), "user-jwt", AdminSignOutScopeOthers); err != nil {
		t.Fatal(err)
	}
	adminCheck(t, adminOne(t, got), http.MethodPost, "/auth/v1/logout", "scope=others", "user-jwt")

	if err := c.Admin().SignOut(context.Background(), "user-jwt", "bogus"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("invalid scope: err = %v", err)
	}
	if err := c.Admin().SignOut(context.Background(), "", AdminSignOutScopeLocal); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty jwt: err = %v", err)
	}

	body, h := adminAPIErrorBody(ErrorCodeBadJWT, "invalid JWT")
	c, _ = adminTestServer(t, http.StatusUnauthorized, body, h)
	adminWantAPIError(t, c.Admin().SignOut(context.Background(), "bad", AdminSignOutScopeLocal), 401, ErrorCodeBadJWT)
}

// upstream: auth-js src/GoTrueAdminApi.ts inviteUserByEmail
func TestAdminInviteUserByEmail(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	u, err := c.Admin().InviteUserByEmail(context.Background(), "jane@example.com", &AdminInviteUserByEmailOptions{
		Data:       map[string]any{"name": "Jane"},
		RedirectTo: "https://app.example.com/welcome",
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != adminTestUserID || u.Email != "jane@example.com" || u.UserMetadata["name"] != "Jane" {
		t.Errorf("user = %+v", u)
	}
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/invite", "redirect_to=https%3A%2F%2Fapp.example.com%2Fwelcome", adminTestKey)
	adminJSONBody(t, r, `{"email":"jane@example.com","data":{"name":"Jane"}}`)

	c, got = adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	if _, err := c.Admin().InviteUserByEmail(context.Background(), "jane@example.com", nil); err != nil {
		t.Fatal(err)
	}
	r = adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/invite", "", adminTestKey)
	adminJSONBody(t, r, `{"email":"jane@example.com"}`)

	body, h := adminAPIErrorBody("email_address_invalid", "invalid email")
	c, _ = adminTestServer(t, http.StatusBadRequest, body, h)
	_, err = c.Admin().InviteUserByEmail(context.Background(), "nope", nil)
	adminWantAPIError(t, err, 400, "email_address_invalid")
}

// upstream: auth-js src/GoTrueAdminApi.ts generateLink
func TestAdminGenerateLink(t *testing.T) {
	resp := `{"id":"8a4c1b2e-1f2d-4c5b-9e7a-0d1c2b3a4f5e","aud":"authenticated","email":"jane@example.com","app_metadata":{},"user_metadata":{},"created_at":"2024-05-01T10:00:00Z",
		"action_link":"https://x.supabase.co/auth/v1/verify?token=abc&type=signup","email_otp":"123456","hashed_token":"abc","redirect_to":"https://app.example.com","verification_type":"signup"}`
	c, got := adminTestServer(t, http.StatusOK, resp, nil)
	out, err := c.Admin().GenerateLink(context.Background(), AdminGenerateLinkParams{
		Type:       AdminGenerateLinkTypeSignup,
		Email:      "jane@example.com",
		Password:   "s3cret-pass",
		Data:       map[string]any{"plan": "pro"},
		RedirectTo: "https://app.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantProps := AdminGenerateLinkProperties{
		ActionLink: "https://x.supabase.co/auth/v1/verify?token=abc&type=signup", EmailOTP: "123456",
		HashedToken: "abc", RedirectTo: "https://app.example.com", VerificationType: AdminGenerateLinkTypeSignup,
	}
	if out.Properties != wantProps {
		t.Errorf("properties = %+v", out.Properties)
	}
	if out.User == nil || out.User.ID != adminTestUserID || out.User.ActionLink != "" {
		t.Errorf("user = %+v", out.User)
	}
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/admin/generate_link", "redirect_to=https%3A%2F%2Fapp.example.com", adminTestKey)
	adminJSONBody(t, r, `{"type":"signup","email":"jane@example.com","password":"s3cret-pass","data":{"plan":"pro"}}`)

	// email change: newEmail becomes new_email.
	c, got = adminTestServer(t, http.StatusOK, resp, nil)
	if _, err := c.Admin().GenerateLink(context.Background(), AdminGenerateLinkParams{
		Type: AdminGenerateLinkTypeEmailChangeCurrent, Email: "jane@example.com", NewEmail: "new@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	r = adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/admin/generate_link", "", adminTestKey)
	adminJSONBody(t, r, `{"type":"email_change_current","email":"jane@example.com","new_email":"new@example.com"}`)

	body, h := adminAPIErrorBody("validation_failed", "bad email")
	c, _ = adminTestServer(t, http.StatusUnprocessableEntity, body, h)
	_, err = c.Admin().GenerateLink(context.Background(), AdminGenerateLinkParams{Type: AdminGenerateLinkTypeMagicLink, Email: "x"})
	adminWantAPIError(t, err, 422, "validation_failed")
}

// upstream: auth-js src/GoTrueAdminApi.ts createUser
func TestAdminCreateUser(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	confirm := true
	u, err := c.Admin().CreateUser(context.Background(), AdminUserAttributes{
		Email:        "jane@example.com",
		Password:     "s3cret-pass",
		EmailConfirm: &confirm,
		UserMetadata: map[string]any{"name": "Jane"},
		AppMetadata:  map[string]any{"roles": []any{"admin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != adminTestUserID || u.AppMetadata["provider"] != "email" {
		t.Errorf("user = %+v", u)
	}
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPost, "/auth/v1/admin/users", "", adminTestKey)
	adminJSONBody(t, r, `{"email":"jane@example.com","password":"s3cret-pass","email_confirm":true,"user_metadata":{"name":"Jane"},"app_metadata":{"roles":["admin"]}}`)

	body, h := adminAPIErrorBody(ErrorCodeUserAlreadyExists, "exists")
	c, _ = adminTestServer(t, http.StatusUnprocessableEntity, body, h)
	_, err = c.Admin().CreateUser(context.Background(), AdminUserAttributes{Email: "jane@example.com"})
	adminWantAPIError(t, err, 422, ErrorCodeUserAlreadyExists)
	if !errors.Is(err, &Error{Code: ErrorCodeUserAlreadyExists}) {
		t.Error("errors.Is by code failed")
	}
}

// upstream: auth-js src/GoTrueAdminApi.ts listUsers
func TestAdminListUsers(t *testing.T) {
	hdr := http.Header{
		"X-Total-Count": {"170"},
		"Link":          {`</admin/users?page=3&per_page=50>; rel="next", </admin/users?page=12&per_page=50>; rel="last"`},
	}
	c, got := adminTestServer(t, http.StatusOK, `{"aud":"authenticated","users":[`+adminTestUserJSON+`]}`, hdr)
	out, err := c.Admin().ListUsers(context.Background(), &AdminPageParams{Page: 2, PerPage: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Users) != 1 || out.Users[0].ID != adminTestUserID || out.Aud != "authenticated" {
		t.Errorf("out = %+v", out)
	}
	// Multi-digit pages are parsed in full (auth-js only reads one digit).
	if out.NextPage != 3 || out.LastPage != 12 || out.Total != 170 {
		t.Errorf("pagination = %+v", out.AdminPagination)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/users", "page=2&per_page=50", adminTestKey)

	// No params: both query params sent empty, as auth-js does.
	c, got = adminTestServer(t, http.StatusOK, `{"aud":"authenticated","users":[]}`, nil)
	out, err = c.Admin().ListUsers(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Users == nil || out.NextPage != 0 || out.LastPage != 0 || out.Total != 0 {
		t.Errorf("out = %+v", out)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/users", "page=&per_page=", adminTestKey)

	body, h := adminAPIErrorBody("validation_failed", "bad page")
	c, _ = adminTestServer(t, http.StatusBadRequest, body, h)
	_, err = c.Admin().ListUsers(context.Background(), &AdminPageParams{Page: -1})
	adminWantAPIError(t, err, 400, "validation_failed")
}

func TestAdminParsePagination(t *testing.T) {
	tests := []struct {
		name string
		h    http.Header
		want AdminPagination
	}{
		{"nil", nil, AdminPagination{}},
		{"last only", http.Header{"Link": {`</admin/users?page=1&per_page=50>; rel="last"`}, "X-Total-Count": {"3"}}, AdminPagination{LastPage: 1, Total: 3}},
		{"garbage", http.Header{"Link": {`nonsense, <::bad>; rel="next"`}, "X-Total-Count": {"x"}}, AdminPagination{}},
		{"unquoted rel", http.Header{"Link": {`<https://h/auth/v1/admin/users?per_page=2&page=7>;rel=next`}}, AdminPagination{NextPage: 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := adminParsePagination(tt.h); got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

// upstream: auth-js src/GoTrueAdminApi.ts getUserById
func TestAdminGetUserByID(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	u, err := c.Admin().GetUserByID(context.Background(), adminTestUserID)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != adminTestUserID || u.CreatedAt.IsZero() || len(u.Raw) == 0 {
		t.Errorf("user = %+v", u)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/users/"+adminTestUserID, "", adminTestKey)

	for _, bad := range []string{"", "not-a-uuid", "../settings", adminTestUserID + "/factors"} {
		if _, err := c.Admin().GetUserByID(context.Background(), bad); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("GetUserByID(%q) err = %v", bad, err)
		}
	}
	if n := len(got()); n != 1 {
		t.Errorf("invalid IDs reached the server: %d requests", n)
	}

	body, h := adminAPIErrorBody(ErrorCodeUserNotFound, "User not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().GetUserByID(context.Background(), adminTestUserID)
	adminWantAPIError(t, err, 404, ErrorCodeUserNotFound)
}

// upstream: auth-js src/GoTrueAdminApi.ts updateUserById
func TestAdminUpdateUserByID(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	unconfirm := false
	if _, err := c.Admin().UpdateUserByID(context.Background(), adminTestUserID, AdminUserAttributes{
		Email: "new@example.com", BanDuration: "24h", Role: "editor", PhoneConfirm: &unconfirm,
	}); err != nil {
		t.Fatal(err)
	}
	r := adminOne(t, got)
	adminCheck(t, r, http.MethodPut, "/auth/v1/admin/users/"+adminTestUserID, "", adminTestKey)
	adminJSONBody(t, r, `{"email":"new@example.com","ban_duration":"24h","role":"editor","phone_confirm":false}`)

	if _, err := c.Admin().UpdateUserByID(context.Background(), "x", AdminUserAttributes{}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}

	body, h := adminAPIErrorBody(ErrorCodeUserNotFound, "User not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err := c.Admin().UpdateUserByID(context.Background(), adminTestUserID, AdminUserAttributes{Role: "x"})
	adminWantAPIError(t, err, 404, ErrorCodeUserNotFound)
}

// upstream: auth-js src/GoTrueAdminApi.ts deleteUser
func TestAdminDeleteUser(t *testing.T) {
	for _, soft := range []bool{false, true} {
		c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
		u, err := c.Admin().DeleteUser(context.Background(), adminTestUserID, soft)
		if err != nil {
			t.Fatal(err)
		}
		if u.ID != adminTestUserID {
			t.Errorf("user = %+v", u)
		}
		r := adminOne(t, got)
		adminCheck(t, r, http.MethodDelete, "/auth/v1/admin/users/"+adminTestUserID, "", adminTestKey)
		if soft {
			adminJSONBody(t, r, `{"should_soft_delete":true}`)
		} else {
			adminJSONBody(t, r, `{"should_soft_delete":false}`)
		}
	}
	c, got := adminTestServer(t, http.StatusOK, "{}", nil)
	if _, err := c.Admin().DeleteUser(context.Background(), "123", false); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	if len(got()) != 0 {
		t.Error("request sent for invalid ID")
	}
	body, h := adminAPIErrorBody(ErrorCodeUserNotFound, "User not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err := c.Admin().DeleteUser(context.Background(), adminTestUserID, false)
	adminWantAPIError(t, err, 404, ErrorCodeUserNotFound)
}

// upstream: auth-js src/GoTrueAdminApi.ts _listFactors
func TestAdminMFAListFactors(t *testing.T) {
	resp := `[{"id":"1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f","friendly_name":"phone","factor_type":"totp","status":"verified","created_at":"2024-05-01T10:00:00Z","updated_at":"2024-05-01T10:00:00Z"}]`
	c, got := adminTestServer(t, http.StatusOK, resp, nil)
	fs, err := c.Admin().MFA().ListFactors(context.Background(), adminTestUserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != adminTestFactorID || fs[0].FactorType != FactorTypeTOTP || fs[0].Status != FactorStatusVerified {
		t.Errorf("factors = %+v", fs)
	}
	adminCheck(t, adminOne(t, got), http.MethodGet, "/auth/v1/admin/users/"+adminTestUserID+"/factors", "", adminTestKey)

	if _, err := c.Admin().MFA().ListFactors(context.Background(), "nope"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	body, h := adminAPIErrorBody(ErrorCodeUserNotFound, "User not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().MFA().ListFactors(context.Background(), adminTestUserID)
	adminWantAPIError(t, err, 404, ErrorCodeUserNotFound)
}

// upstream: auth-js src/GoTrueAdminApi.ts _deleteFactor
func TestAdminMFADeleteFactor(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, `{"id":"`+adminTestFactorID+`"}`, nil)
	f, err := c.Admin().MFA().DeleteFactor(context.Background(), adminTestUserID, adminTestFactorID)
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != adminTestFactorID {
		t.Errorf("factor = %+v", f)
	}
	adminCheck(t, adminOne(t, got), http.MethodDelete, "/auth/v1/admin/users/"+adminTestUserID+"/factors/"+adminTestFactorID, "", adminTestKey)

	if _, err := c.Admin().MFA().DeleteFactor(context.Background(), adminTestUserID, "bad"); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	if _, err := c.Admin().MFA().DeleteFactor(context.Background(), "bad", adminTestFactorID); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
	body, h := adminAPIErrorBody("mfa_factor_not_found", "not found")
	c, _ = adminTestServer(t, http.StatusNotFound, body, h)
	_, err = c.Admin().MFA().DeleteFactor(context.Background(), adminTestUserID, adminTestFactorID)
	adminWantAPIError(t, err, 404, "mfa_factor_not_found")
}

func TestAdminContextCanceled(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Admin().GetUserByID(ctx, adminTestUserID)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if err := c.Admin().OAuth().DeleteClient(ctx, "abc"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if len(got()) != 0 {
		t.Error("request reached server after cancel")
	}
}

// Admin calls must use the API key even when a custom Authorization
// header is not configured, and honour one when it is (auth-js merges
// caller headers into the admin headers).
func TestAdminCustomAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, adminTestUserJSON)
	}))
	defer srv.Close()
	c, err := New(Config{URL: srv.URL, APIKey: adminTestKey, Headers: http.Header{"Authorization": {"Bearer custom"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Admin().GetUserByID(context.Background(), adminTestUserID); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer custom" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestAdminConcurrentUse(t *testing.T) {
	c, got := adminTestServer(t, http.StatusOK, adminTestUserJSON, nil)
	admin := c.Admin()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := admin.GetUserByID(context.Background(), adminTestUserID); err != nil {
				t.Error(err)
			}
			_ = c.Admin().SignOut(context.Background(), "jwt", AdminSignOutScopeLocal)
		}()
	}
	wg.Wait()
	for _, r := range got() {
		auth := r.Header.Get("Authorization")
		if strings.HasSuffix(r.Path, "/logout") != (auth == "Bearer jwt") {
			t.Errorf("%s %s used Authorization %q", r.Method, r.Path, auth)
		}
	}
}
