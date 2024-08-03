package supabase

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
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

type requester struct {
	httpClient   *http.Client
	customHeader http.Header
}

// newRequester to create httpClient pool
func newRequester(httpClient *http.Client, customHeader map[string]string) *requester {
	header := make(http.Header)
	for k, v := range customHeader {
		header.Set(k, v)
	}
	return &requester{
		httpClient:   httpClient,
		customHeader: header,
	}
}

func isHTTPSuccess(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

func printBody(body []byte) []byte {
	if body == nil || len(body) == 0 {
		return nil
	}
	return body[:min(500, len(body))]
}

func printHeader(header http.Header) []byte {
	headerBytes, err := json.Marshal(header)
	if err == nil {
		return headerBytes
	}
	return nil
}

func (c requester) Call(ctx context.Context, fullUrl, method string, body any, customHeaders HeaderSetter) (*Resp, error) {
	qs, err := Values(body)
	if err != nil {
		logger.Error("failed in retrieving query string with err: %s", err)
		return nil, err
	}
	if len(qs) > 0 {
		fullUrl += "?" + qs.Encode()
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		logger.Error("failed in marshal request with err: %s", err)
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, fullUrl, bytes.NewBuffer(reqBody))
	if err != nil {
		logger.Error("failed in new request with context with err: %s", err)
		return nil, err
	}
	httpReq.Header = c.customHeader
	httpReq.Header.Set(headerContentType, applicationJSON)
	httpReq.Header.Set(headerAccept, applicationJSON)
	customHeaders(httpReq)

	var httpResp *http.Response
	logger.Debug("-------> %s %s: header:%s body:%s", method, fullUrl, printHeader(httpReq.Header), printBody(reqBody))
	httpResp, err = c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	jsonBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logger.Error("failed in read all with err: %s", err)
		return nil, err
	}
	respBody := *bytes.NewBuffer(jsonBytes)
	logger.Debug("<------- %s: %d: %s", fullUrl, httpResp.StatusCode, respBody.Bytes())
	return &Resp{
		Body:       respBody,
		Header:     httpResp.Header,
		StatusCode: httpResp.StatusCode,
	}, nil
}

func (c requester) Upload(ctx context.Context, fullUrl, method string, file io.Reader, customHeaders HeaderSetter) (*Resp, error) {
	fileData := bufio.NewReader(file)
	httpReq, err := http.NewRequestWithContext(ctx, method, fullUrl, fileData)
	if err != nil {
		logger.Error("failed in new request with context with err: %s", err)
		return nil, err
	}
	httpReq.Header = c.customHeader
	customHeaders(httpReq)

	var httpResp *http.Response
	logger.Debug("-------> %s %s: header:%s", method, fullUrl, printHeader(httpReq.Header))
	httpResp, err = c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	jsonBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logger.Error("failed in read all with err: %s", err)
		return nil, err
	}
	respBody := *bytes.NewBuffer(jsonBytes)
	logger.Debug("<------- %s: %d: %s", fullUrl, httpResp.StatusCode, respBody.Bytes())
	return &Resp{
		Body:       respBody,
		Header:     httpResp.Header,
		StatusCode: httpResp.StatusCode,
	}, nil
}
