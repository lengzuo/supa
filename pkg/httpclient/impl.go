package httpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/utils/common"
)

const (
	headerContentType = "Content-Type"
	headerAccept      = "Accept"
	applicationJSON   = "application/json;charset=UTF-8"
)

type Sender interface {
	Call(ctx context.Context, fullUrl, method string, body any, customHeaders HeaderSetter) (*Resp, error)
	Upload(ctx context.Context, fullUrl, method string, file io.Reader, customHeaders HeaderSetter) (*Resp, error)
}

type HeaderSetter func(req *http.Request)

type client struct {
	httpClient *http.Client
}

// New to create client pool
func New(timeout time.Duration) *client {
	if timeout <= 0 {
		panic("timeout must be specific > 0")
	}
	return &client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 1000,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: timeout,
				DisableKeepAlives:   false,
			},
			Timeout: timeout,
		},
	}
}

func IsHTTPSuccess(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

func printBody(body []byte) []byte {
	if body == nil || len(body) == 0 {
		return nil
	}
	return body[:common.Min(500, len(body))]
}

func printHeader(header http.Header) []byte {
	headerBytes, err := json.Marshal(header)
	if err == nil {
		return headerBytes
	}
	return nil
}

func (c client) Call(ctx context.Context, fullUrl, method string, body any, customHeaders HeaderSetter) (*Resp, error) {
	qs, err := Values(body)
	if err != nil {
		logger.Logger.Error("failed in retrieving query string with err: %s", err)
		return nil, err
	}
	if len(qs) > 0 {
		fullUrl += "?" + qs.Encode()
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Logger.Error("failed in marshal request with err: %s", err)
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, fullUrl, bytes.NewBuffer(reqBody))
	if err != nil {
		logger.Logger.Error("failed in new request with context with err: %s", err)
		return nil, err
	}
	httpReq.Header.Set(headerContentType, applicationJSON)
	httpReq.Header.Set(headerAccept, applicationJSON)
	customHeaders(httpReq)

	var httpResp *http.Response
	logger.Logger.Debug("-------> %s %s: header:%s body:%s", method, fullUrl, printHeader(httpReq.Header), printBody(reqBody))
	httpResp, err = c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	jsonBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logger.Logger.Error("failed in read all with err: %s", err)
		return nil, err
	}
	respBody := *bytes.NewBuffer(jsonBytes)
	logger.Logger.Debug("<------- %s: %d: %s", fullUrl, httpResp.StatusCode, respBody.Bytes())
	return &Resp{
		Body:       respBody,
		Header:     httpResp.Header,
		StatusCode: httpResp.StatusCode,
	}, nil
}

func (c client) Upload(ctx context.Context, fullUrl, method string, file io.Reader, customHeaders HeaderSetter) (*Resp, error) {
	fileData := bufio.NewReader(file)
	httpReq, err := http.NewRequestWithContext(ctx, method, fullUrl, fileData)
	if err != nil {
		logger.Logger.Error("failed in new request with context with err: %s", err)
		return nil, err
	}
	customHeaders(httpReq)

	var httpResp *http.Response
	logger.Logger.Debug("-------> %s %s: header:%s", method, fullUrl, printHeader(httpReq.Header))
	httpResp, err = c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	jsonBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logger.Logger.Error("failed in read all with err: %s", err)
		return nil, err
	}
	respBody := *bytes.NewBuffer(jsonBytes)
	logger.Logger.Debug("<------- %s: %d: %s", fullUrl, httpResp.StatusCode, respBody.Bytes())
	return &Resp{
		Body:       respBody,
		Header:     httpResp.Header,
		StatusCode: httpResp.StatusCode,
	}, nil
}
