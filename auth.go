package supabase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lengzuo/supa/dto"
	"github.com/lengzuo/supa/pkg/catch"
	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/utils/common/check"
)

var (
	ErrPasswordEmpty     = errors.New("password is required")
	ErrEmailOrPhoneEmpty = errors.New("you must provide either an email or phone number and a password")
)

type authAPI interface {
	SignInWithOTP(ctx context.Context, body dto.SignInRequest, redirectURL string) error
	SignInWithPassword(ctx context.Context, body dto.SignInRequest) (*dto.AuthDetailResp, error)
	Verify(ctx context.Context, body dto.VerifyRequest) (dto.AuthDetailResp, error)
	User(ctx context.Context, token string) (dto.User, error)
	SignOut(ctx context.Context, token string) error
	SignUp(ctx context.Context, credentials dto.SignUpRequest) (dto.AuthDetailResp, error)
}

type auth struct {
	client
}

func newAuth(c client) *auth {
	return &auth{c}
}

// SignInWithOTP allow user to sign in with otp
func (i auth) SignInWithOTP(ctx context.Context, body dto.SignInRequest, redirectURL string) error {
	if check.Empty(body.Email) && check.Empty(body.Phone) {
		return ErrEmailOrPhoneEmpty
	}
	reqBody, _ := json.Marshal(body)
	reqURL := fmt.Sprintf("%s/otp", i.authHost)
	if redirectURL != "" {
		reqURL += "?redirect_to=" + url.QueryEscape(redirectURL)
	}
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in get sign in with otp due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

func (i auth) SignInWithPassword(ctx context.Context, body dto.SignInRequest) (*dto.AuthDetailResp, error) {
	if check.Empty(body.Email) && check.Empty(body.Phone) {
		return nil, ErrEmailOrPhoneEmpty
	}
	if check.Empty(body.Password) {
		return nil, ErrPasswordEmpty
	}
	reqBody, _ := json.Marshal(body)
	reqURL := fmt.Sprintf("%s/token?grant_type=password", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return nil, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign in with password due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return nil, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail *dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal user json with err: %s", err)
		return nil, err
	}
	return authDetail, nil
}

func (i auth) SignUp(ctx context.Context, credentials dto.SignUpRequest) (dto.AuthDetailResp, error) {
	reqBody, _ := json.Marshal(credentials)
	reqURL := fmt.Sprintf("%s/signup", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return dto.AuthDetailResp{}, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign up due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return dto.AuthDetailResp{}, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal user json with err: %s", err)
		return dto.AuthDetailResp{}, err
	}
	return authDetail, nil
}

func (i auth) User(ctx context.Context, token string) (dto.User, error) {
	reqURL := fmt.Sprintf("%s/user", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodGet, nil, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(authPrefix, token)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return dto.User{}, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in get user due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return dto.User{}, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var user dto.User
	err = json.Unmarshal(httpResp.Body.Bytes(), &user)
	if err != nil {
		logger.Logger.Error("failed in unmarshal user json with err: %s", err)
		return dto.User{}, err
	}
	return user, nil
}

func (i auth) SignOut(ctx context.Context, token string) error {
	reqURL := fmt.Sprintf("%s/logout?scope=global", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, nil, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(authPrefix, token)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign out due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

func (i auth) Verify(ctx context.Context, body dto.VerifyRequest) (dto.AuthDetailResp, error) {
	reqBody, _ := json.Marshal(body)
	reqURL := fmt.Sprintf("%s/verify", i.authHost)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, reqBody, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return dto.AuthDetailResp{}, err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in verify due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		return dto.AuthDetailResp{}, catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	var authDetail dto.AuthDetailResp
	err = json.Unmarshal(httpResp.Body.Bytes(), &authDetail)
	if err != nil {
		logger.Logger.Error("failed in unmarshal user json with err: %s", err)
		return dto.AuthDetailResp{}, err
	}
	return authDetail, nil
}
