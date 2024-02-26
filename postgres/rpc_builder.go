package postgres

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
)

type RpcRequestBuilder struct {
	client     *Client
	path       string
	header     http.Header
	httpMethod string
	params     interface{}
}

func (c *Client) RPC(f string, params interface{}) *RpcRequestBuilder {
	return &RpcRequestBuilder{
		client:     c,
		path:       "/rpc/" + f,
		header:     http.Header{},
		httpMethod: http.MethodPost,
		params:     params,
	}
}

func (r *RpcRequestBuilder) Execute(ctx context.Context, result interface{}) error {
	fullUrl := r.client.baseURL
	fullUrl.Path += r.path
	httpResp, err := r.client.httpClient.Call(ctx, fullUrl.String(), r.httpMethod, r.params, func(req *http.Request) {
		for k, values := range r.client.defaultHeaders {
			for i := range values {
				req.Header.Set(k, values[i])
			}
		}
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign in with password due to err: %s", httpResp.StatusCode, httpResp.Body.String())
		var reqError Error
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
