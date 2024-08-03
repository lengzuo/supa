package supabase

import (
	"context"
	"encoding/json"
	"net/http"
)

type RpcRequestBuilder struct {
	client     *PostgresClient
	path       string
	header     http.Header
	httpMethod string
	params     interface{}
}

func (c *PostgresClient) RPC(f string, params interface{}, opts ...HeaderOption) *RpcRequestBuilder {
	header := c.defaultHeaders.Clone()
	for _, opt := range opts {
		header.Set(opt.Key, opt.Value)
	}
	return &RpcRequestBuilder{
		client:     c,
		path:       "/rpc/" + f,
		header:     header,
		httpMethod: http.MethodPost,
		params:     params,
	}
}

func (r *RpcRequestBuilder) Execute(ctx context.Context, result interface{}) error {
	fullUrl := r.client.baseURL
	fullUrl.Path += r.path
	httpResp, err := r.client.httpClient.Call(ctx, fullUrl.String(), r.httpMethod, r.params, func(req *http.Request) {
		for k, values := range r.header {
			for i := range values {
				req.Header.Set(k, values[i])
			}
		}
	})
	if err != nil {
		logger.Error("failed in httpclient call with err: %s", err)
		return err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in sign in with password due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		var reqError PostgresError
		if err = json.Unmarshal(httpResp.Body.Bytes(), &reqError); err != nil {
			return err
		}
		reqError.HTTPStatusCode = httpResp.StatusCode
		return &reqError
	}
	if httpResp.StatusCode != http.StatusNoContent && result != nil {
		if err = json.Unmarshal(httpResp.Body.Bytes(), result); err != nil {
			return err
		}
	}
	return nil
}
