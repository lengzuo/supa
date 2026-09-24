package supabase

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	headerContentType = "Content-Type"
	headerAccept      = "Accept"
	applicationJSON   = "application/json;charset=UTF-8"

	redacted = "[REDACTED]"
)

type Sender interface {
	Call(ctx context.Context, fullUrl, method string, body any, customHeaders HeaderSetter) (*Resp, error)
	Upload(ctx context.Context, fullUrl, method string, file io.Reader, customHeaders HeaderSetter) (*Resp, error)
}

type HeaderSetter func(req *http.Request)

type requester struct {
	httpClient *http.Client
	// customHeader is shared by every request made through this requester and
	// must never be mutated after construction; use requestHeader to get a
	// per-request copy.
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

// requestHeader returns a fresh copy of the requester's default headers, so
// that per-request mutations (e.g. a user's Authorization token) never leak
// into other, possibly concurrent, requests.
func (c requester) requestHeader() http.Header {
	if c.customHeader == nil {
		return make(http.Header)
	}
	return c.customHeader.Clone()
}

func isHTTPSuccess(statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices
}

// sensitiveHeaders are headers whose values must never be logged. Keys are in
// canonical MIME header form.
var sensitiveHeaders = map[string]struct{}{
	"Authorization":       {},
	"Apikey":              {},
	"Proxy-Authorization": {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"X-Api-Key":           {},
}

// sensitiveQueryParams are query parameters (lower-cased) whose values must
// never be logged.
var sensitiveQueryParams = map[string]struct{}{
	"access_token":  {},
	"refresh_token": {},
	"id_token":      {},
	"token":         {},
	"token_hash":    {},
	"apikey":        {},
	"api_key":       {},
	"password":      {},
	"code":          {},
	"code_verifier": {},
	"nonce":         {},
	"secret":        {},
}

// printHeader renders headers for debug logging with the values of
// credential-bearing headers redacted.
func printHeader(header http.Header) string {
	safe := make(map[string][]string, len(header))
	for k, v := range header {
		if _, ok := sensitiveHeaders[http.CanonicalHeaderKey(k)]; ok {
			safe[k] = []string{redacted}
			continue
		}
		safe[k] = v
	}
	headerBytes, err := json.Marshal(safe)
	if err != nil {
		return ""
	}
	return string(headerBytes)
}

// printURL renders a URL for debug logging with user info and the values of
// sensitive query parameters redacted.
func printURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Don't risk logging an unparseable URL that may contain secrets.
		return redacted
	}
	if u.User != nil {
		u.User = url.User(redacted)
	}
	if u.RawQuery == "" {
		return u.String()
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		u.RawQuery = redacted
		return u.String()
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		_, sensitive := sensitiveQueryParams[strings.ToLower(k)]
		for _, v := range q[k] {
			if sensitive {
				v = redacted
			}
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	u.RawQuery = strings.Join(parts, "&")
	return u.String()
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
	httpReq.Header = c.requestHeader()
	httpReq.Header.Set(headerContentType, applicationJSON)
	httpReq.Header.Set(headerAccept, applicationJSON)
	customHeaders(httpReq)

	return c.do(httpReq, method, fullUrl)
}

func (c requester) Upload(ctx context.Context, fullUrl, method string, file io.Reader, customHeaders HeaderSetter) (*Resp, error) {
	fileData := bufio.NewReader(file)
	httpReq, err := http.NewRequestWithContext(ctx, method, fullUrl, fileData)
	if err != nil {
		logger.Error("failed in new request with context with err: %s", err)
		return nil, err
	}
	httpReq.Header = c.requestHeader()
	customHeaders(httpReq)

	return c.do(httpReq, method, fullUrl)
}

// do sends the request and reads the whole response. Request and response
// bodies are never logged since they may carry passwords and tokens.
func (c requester) do(httpReq *http.Request, method, fullUrl string) (*Resp, error) {
	logURL := printURL(fullUrl)
	logger.Debug("-------> %s %s: header:%s", method, logURL, printHeader(httpReq.Header))
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// The client wraps transport errors in *url.Error carrying the full
		// URL; redact it since callers commonly log the error.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			urlErr.URL = logURL
		}
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	jsonBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logger.Error("failed in read all with err: %s", err)
		return nil, err
	}
	respBody := *bytes.NewBuffer(jsonBytes)
	logger.Debug("<------- %s %s: %d (%d bytes)", method, logURL, httpResp.StatusCode, len(jsonBytes))
	return &Resp{
		Body:       respBody,
		Header:     httpResp.Header,
		StatusCode: httpResp.StatusCode,
	}, nil
}
