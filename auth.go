package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/go-querystring/query"
	"github.com/lengzuo/supa/dto"
	"github.com/lengzuo/supa/pkg/catch"
	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/utils/enum"
)

type authAPI interface {
	RefreshToken(ctx context.Context, refreshToken string) (*dto.AuthDetailResp, error)
	SignInWithIDToken(ctx context.Context, body dto.SignInWithIDTokenRequest) (*dto.AuthDetailResp, error)
	SignInWithOAuth(ctx context.Context, body dto.OAuthSignInRequest) (string, error)
	SignInWithOTP(ctx context.Context, body dto.SignInRequest, redirectURL string) error
	SignInWithPassword(ctx context.Context, body dto.SignInRequest) (*dto.AuthDetailResp, error)
	SignOut(ctx context.Context, token string) error
	SignUp(ctx context.Context, credentials dto.SignUpRequest) (*dto.AuthDetailResp, error)
	User(ctx context.Context, token string) (*dto.User, error)
	Verify(ctx context.Context, body dto.VerifyRequest) (*dto.AuthDetailResp, error)
}

type auth struct {
	client
}

func newAuth(c client) *auth {
	return &auth{c}
}

// SignInWithOTP log in a user using magiclink or a one-time password (OTP).
func (i auth) SignInWithOTP(ctx context.Context, body dto.SignInRequest, redirectURL string) error {
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal sign in with otp request with err: %s", err)
		return err
	}
	reqURL := fmt.Sprintf("%s/otp", i.authHost)
	if redirectURL != "" {
		reqURL += "?redirect_to=" + url.QueryEscape(redirectURL)
	}
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in sign in with OTP httpclient call with err: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in get sign in with otp due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

// SignInWithPassword log in an existing user with an email and password or phone and password.
func (i auth) SignInWithPassword(ctx context.Context, body dto.SignInRequest) (*dto.AuthDetailResp, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal sign in with password request with err: %s", err)
		return nil, err
	}
	reqURL := fmt.Sprintf("%s/token?grant_type=password", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in sign in with password httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign in with password due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// SignUp creates a new user.
func (i auth) SignUp(ctx context.Context, body dto.SignUpRequest) (*dto.AuthDetailResp, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal sign up request with err: %s", err)
		return nil, err
	}
	reqURL := fmt.Sprintf("%s/signup", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in sign up httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign up due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// User gets the current user details if there is an existing session. This method
// performs a network request to the Supabase Auth server, so the returned
// value is authentic and can be used to base authorization rules on.
func (i auth) User(ctx context.Context, token string) (*dto.User, error) {
	reqURL := fmt.Sprintf("%s/user", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodGet, nil, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(enum.Authorization.String(), fmt.Sprintf("%s %s", authPrefix, token))
	})
	if err != nil {
		logger.Logger.Error("failed in user httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in get user due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var user *dto.User
	err = json.Unmarshal(httpResp.Body.Bytes(), &user)
	if err != nil {
		logger.Logger.Error("failed in unmarshal user json with err: %s", err)
		return nil, err
	}
	return user, nil
}

// SignOut sign user out
func (i auth) SignOut(ctx context.Context, token string) error {
	reqURL := fmt.Sprintf("%s/logout?scope=global", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, nil, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(authPrefix, token)
	})
	if err != nil {
		logger.Logger.Error("failed in sign out httpclient call with err: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign out due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

func (i auth) Verify(ctx context.Context, body dto.VerifyRequest) (*dto.AuthDetailResp, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal verify request with err: %s", err)
		return nil, err
	}
	reqURL := fmt.Sprintf("%s/verify", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in verify httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in verify due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// RefreshToken uses to generates a new JWT token.
func (i auth) RefreshToken(ctx context.Context, refreshToken string) (*dto.AuthDetailResp, error) {
	body := dto.RefreshTokenReq{
		RefreshToken: refreshToken,
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal refresh token request with err: %s", err)
		return nil, err
	}
	reqURL := fmt.Sprintf("%s/token?grant_type=refresh_token", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in refresh token httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in refresh token due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

// SignInWithOAuth log in an existing user via a third-party provider.
func (i auth) SignInWithOAuth(ctx context.Context, body dto.OAuthSignInRequest) (string, error) {
	authURL, err := url.Parse(fmt.Sprintf("%s/authorize", i.authHost))
	if err != nil {
		logger.Logger.Error("failed in url parse with err: %s", err)
		return "", err
	}
	qs, err := query.Values(body)
	if err != nil {
		logger.Logger.Error("failed in convert qs with err: %s", err)
		return "", err
	}
	authURL.RawQuery = qs.Encode()
	return authURL.String(), nil
}

// SignInWithIDToken allows signing in with an OIDC ID token. The authentication provider used should be enabled and configured.
func (i auth) SignInWithIDToken(ctx context.Context, body dto.SignInWithIDTokenRequest) (*dto.AuthDetailResp, error) {
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal sign in with id token request with err: %s", err)
		return nil, err
	}
	reqURL := fmt.Sprintf("%s/token?grant_type=id_token", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in sign in with id token httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign in with id token due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal auth detail json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}
