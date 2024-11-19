package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type authAPI interface {
	ResetPasswordForEmail(ctx context.Context, body ResetPasswordForEmailRequest) error
	RefreshToken(ctx context.Context, refreshToken string) (*AuthDetailResp, error)
	SignInAnonymously(ctx context.Context, body SignInAnonymousRequest) (*AuthDetailResp, error)
	SignInWithIDToken(ctx context.Context, body SignInWithIDTokenRequest) (*AuthDetailResp, error)
	SignInWithOAuth(ctx context.Context, body OAuthSignInRequest) (string, error)
	SignInWithOTP(ctx context.Context, body SignInRequest) error
	SignInWithPassword(ctx context.Context, body SignInRequest) (*AuthDetailResp, error)
	SignOut(ctx context.Context, token string) error
	SignUp(ctx context.Context, credentials SignUpRequest) (*AuthDetailResp, error)
	User(ctx context.Context, token string) (*User, error)
	UpdateUser(ctx context.Context, token string, body UpdateUserRequest) (*User, error)
	Verify(ctx context.Context, body VerifyRequest) (*AuthDetailResp, error)
}

type Auth struct {
	apiKey     string
	authHost   string
	httpClient Sender
}

type AuthOption func(c *Auth)

func WithAuthClient(httpClient *http.Client, header map[string]string) AuthOption {
	return func(c *Auth) {
		c.httpClient = newRequester(httpClient, header)
	}
}

func NewAuth(apiKey, authHost string, options ...AuthOption) *Auth {
	impl := &Auth{
		apiKey:     apiKey,
		authHost:   authHost,
		httpClient: defaultSender(httpTimeout, make(map[string]string)),
	}
	for _, opt := range options {
		opt(impl)
	}
	return impl
}

// ResetPasswordForEmail sends a password reset request to an email address. This method supports the PKCE flow.
func (i Auth) ResetPasswordForEmail(ctx context.Context, body ResetPasswordForEmailRequest) error {
	reqURL := fmt.Sprintf("%s/recover", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in reset password for email httpclient call with err: %s", err)
		return err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in reset password for email due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

// SignInWithOTP log in a user using magiclink or a one-time password (OTP).
func (i Auth) SignInWithOTP(ctx context.Context, body SignInRequest) error {
	reqURL := fmt.Sprintf("%s/otp", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in sign in with OTP httpclient call with err: %s", err)
		return err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in get sign in with otp due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

// SignInWithPassword log in an existing user with an email and password or phone and password.
func (i Auth) SignInWithPassword(ctx context.Context, body SignInRequest) (*AuthDetailResp, error) {
	reqURL := fmt.Sprintf("%s/token?grant_type=password", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in sign in with password httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in sign in with password due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Error("failed in unmarshal Auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// SignUp creates a new user.
func (i Auth) SignUp(ctx context.Context, body SignUpRequest) (*AuthDetailResp, error) {
	reqURL := fmt.Sprintf("%s/signup", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in sign up httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in sign up due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Error("failed in unmarshal Auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// User gets the current user details if there is an existing session. This method
// performs a network request to the Supabase Auth server, so the returned
// value is authentic and can be used to base authorization rules on.
func (i Auth) User(ctx context.Context, token string) (*User, error) {
	reqURL := fmt.Sprintf("%s/user", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodGet, nil, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(HeaderAuthorization.String(), fmt.Sprintf("%s %s", authPrefix, token))
	})
	if err != nil {
		logger.Error("failed in user httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in get user due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var user *User
	err = json.Unmarshal(httpResp.Body.Bytes(), &user)
	if err != nil {
		logger.Error("failed in unmarshal user json with err: %s", err)
		return nil, err
	}
	return user, nil
}

// UpdateUser updates user data for a logged in user.
func (i Auth) UpdateUser(ctx context.Context, token string, body UpdateUserRequest) (*User, error) {
	reqURL := fmt.Sprintf("%s/user", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPut, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(HeaderAuthorization.String(), fmt.Sprintf("%s %s", authPrefix, token))
	})
	if err != nil {
		logger.Error("failed in update user httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in update user due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var user *User
	err = json.Unmarshal(httpResp.Body.Bytes(), &user)
	if err != nil {
		logger.Error("failed in unmarshal update user json with err: %s", err)
		return nil, err
	}
	return user, nil
}

// SignOut sign user out
func (i Auth) SignOut(ctx context.Context, token string) error {
	reqURL := fmt.Sprintf("%s/logout?scope=global", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, nil, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(HeaderAuthorization.String(), fmt.Sprintf("%s %s", authPrefix, token))
	})
	if err != nil {
		logger.Error("failed in sign out httpclient call with err: %s", err)
		return err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in sign out due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

func (i Auth) Verify(ctx context.Context, body VerifyRequest) (*AuthDetailResp, error) {
	reqURL := fmt.Sprintf("%s/verify", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in verify httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in verify due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Error("failed in unmarshal Auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// RefreshToken uses to generates a new JWT token.
func (i Auth) RefreshToken(ctx context.Context, refreshToken string) (*AuthDetailResp, error) {
	body := RefreshTokenReq{
		RefreshToken: refreshToken,
	}
	reqURL := fmt.Sprintf("%s/token?grant_type=refresh_token", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in refresh token httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in refresh token due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Error("failed in unmarshal Auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// SignInWithOAuth log in an existing user via a third-party provider.
func (i Auth) SignInWithOAuth(ctx context.Context, body OAuthSignInRequest) (string, error) {
	authURL, err := url.Parse(fmt.Sprintf("%s/authorize", i.authHost))
	if err != nil {
		logger.Error("failed in url parse with err: %s", err)
		return "", err
	}
	qs, err := Values(body)
	if err != nil {
		logger.Error("failed in convert qs with err: %s", err)
		return "", err
	}
	authURL.RawQuery = qs.Encode()
	return authURL.String(), nil
}

// SignInAnonymously use to create a new anonymous user.
func (i Auth) SignInAnonymously(ctx context.Context, body SignInAnonymousRequest) (*AuthDetailResp, error) {
	signUpReq := SignUpRequest{
		Data:               body.Data,
		GotrueMetaSecurity: body.GotrueMetaSecurity,
	}
	return i.SignUp(ctx, signUpReq)
}

// SignInWithIDToken allows signing in with an OIDC ID token. The authentication provider used should be enabled and configured.
func (i Auth) SignInWithIDToken(ctx context.Context, body SignInWithIDTokenRequest) (*AuthDetailResp, error) {
	reqURL := fmt.Sprintf("%s/token?grant_type=id_token", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, body, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Error("failed in sign in with id token httpclient call with err: %s", err)
		return nil, err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in sign in with id token due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Error("failed in unmarshal Auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}
