package postgres

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
)

type RequestBuilder struct {
	client *Client
	path   string
	params url.Values
	header http.Header
}

// Select starts building a SELECT request with the specified columns.
func (b *RequestBuilder) Select(columns ...string) *SelectRequestBuilder {
	b.params.Set("select", strings.Join(columns, ","))
	return &SelectRequestBuilder{
		FilterRequestBuilder{
			QueryRequestBuilder: QueryRequestBuilder{
				client:     b.client,
				path:       b.path,
				httpMethod: http.MethodGet,
				header:     b.header,
				params:     b.params,
			},
			negateNext: false,
		},
	}
}

// Insert starts building an INSERT request with the provided JSON data.
func (b *RequestBuilder) Insert(json interface{}) *QueryRequestBuilder {
	// Return result after insert
	b.header.Set("Prefer", "return=representation")
	// Return single instead of array after insert
	b.header.Set("Accept", "application/vnd.pgrst.object+json")
	return &QueryRequestBuilder{
		client:     b.client,
		path:       b.path,
		httpMethod: http.MethodPost,
		json:       json,
		params:     b.params,
		header:     b.header,
	}
}

// Upsert starts building an UPSERT request with the provided JSON data.
func (b *RequestBuilder) Upsert(json interface{}) *QueryRequestBuilder {
	b.header.Set("Prefer", "return=representation,resolution=merge-duplicates")
	return &QueryRequestBuilder{
		client:     b.client,
		path:       b.path,
		httpMethod: http.MethodPost,
		json:       json,
		params:     b.params,
		header:     b.header,
	}
}

// Update starts building an UPDATE request with the provided JSON data.
func (b *RequestBuilder) Update(json interface{}) *FilterRequestBuilder {
	b.header.Set("Prefer", "return=representation")
	return &FilterRequestBuilder{
		QueryRequestBuilder: QueryRequestBuilder{
			client:     b.client,
			path:       b.path,
			httpMethod: http.MethodPatch,
			json:       json,
			params:     b.params,
			header:     b.header,
		},
		negateNext: false,
	}
}

// Delete starts building a DELETE request.
func (b *RequestBuilder) Delete() *FilterRequestBuilder {
	return &FilterRequestBuilder{
		QueryRequestBuilder: QueryRequestBuilder{
			client:     b.client,
			path:       b.path,
			httpMethod: http.MethodDelete,
			json:       nil,
			params:     b.params,
			header:     b.header,
		},
		negateNext: false,
	}
}

// QueryRequestBuilder represents a builder for query requests.
type QueryRequestBuilder struct {
	client     *Client
	params     url.Values
	header     http.Header
	path       string
	httpMethod string
	json       interface{}
}

// Execute sends the query request with the provided context and unmarshal the response JSON into the provided object.
func (b *QueryRequestBuilder) Execute(ctx context.Context, result interface{}) error {
	fullUrl := b.client.baseURL
	fullUrl.Path += b.path
	fullUrl.RawQuery = b.params.Encode()
	httpResp, err := b.client.httpClient.Call(ctx, fullUrl.String(), b.httpMethod, b.json, func(req *http.Request) {
		for k, values := range b.client.defaultHeaders {
			for i := range values {
				req.Header.Set(k, values[i])
			}
		}
		for k, values := range b.header {
			for i := range values {
				req.Header.Set(k, values[i])
			}
		}
		if result == nil {
			req.Header.Set("Accept", "")
			req.Header.Set("Prefer", "")
		}
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with err: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in execute with context due to err: %s", httpResp.StatusCode, httpResp.Body.String())
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
