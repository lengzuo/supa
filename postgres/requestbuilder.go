package postgres

import (
	"context"
	"encoding/json"
	"fmt"
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

// ExecuteWithContext sends the query request with the provided context and unmarshal the response JSON into the provided object.
func (b *QueryRequestBuilder) ExecuteWithContext(ctx context.Context, result interface{}) error {
	query, err := url.QueryUnescape(b.params.Encode())
	if err != nil {
		return err
	}
	fullUrl := b.client.baseURL
	fullUrl.Path += b.path
	fullUrl.RawQuery = query
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

// FilterRequestBuilder represents a builder for filter requests.
type FilterRequestBuilder struct {
	QueryRequestBuilder
	negateNext bool
}

// Not negates the next filter condition.
func (b *FilterRequestBuilder) Not() *FilterRequestBuilder {
	b.negateNext = true
	return b
}

// Filter adds a filter condition to the request.
func (b *FilterRequestBuilder) Filter(column, operator, criteria string) *FilterRequestBuilder {
	if b.negateNext {
		b.negateNext = false
		operator = "not." + operator
	}
	b.params.Add(column, operator+"."+criteria)
	return b
}

// Eq adds an equality filter condition to the request.
func (b *FilterRequestBuilder) Eq(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "eq", value)
}

// Single Retrieves only one row from the result. The total result set must be one row
// (e.g., by using Limit). Otherwise, this will result in an error.
func (b *FilterRequestBuilder) Single() *FilterRequestBuilder {
	b.header.Set("Accept", "application/vnd.pgrst.object+json")
	return b
}

// Gt adds a greater-than filter condition to the request.
func (b *FilterRequestBuilder) Gt(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "gt", value)
}

// Gte adds a greater-than-or-equal filter condition to the request.
func (b *FilterRequestBuilder) Gte(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "gte", value)
}

// Lt adds a less-than filter condition to the request.
func (b *FilterRequestBuilder) Lt(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "lt", value)
}

// Lte adds a less-than-or-equal filter condition to the request.
func (b *FilterRequestBuilder) Lte(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "lte", value)
}

// Like adds a LIKE filter condition to the request.
func (b *FilterRequestBuilder) Like(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "like", value)
}

// Ilike adds a ILIKE filter condition to the request.
func (b *FilterRequestBuilder) Ilike(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "ilike", value)
}

// Is adds an IS filter condition to the request.
func (b *FilterRequestBuilder) Is(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "is", value)
}

// In adds an IN filter condition to the request.
func (b *FilterRequestBuilder) In(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "in", fmt.Sprintf("(%s)", strings.Join(sanitized, ",")))
}

// Neq adds a not-equal filter condition to the request.
func (b *FilterRequestBuilder) Neq(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "neq", value)
}

// Fts adds a full-text search filter condition to the request.
func (b *FilterRequestBuilder) Fts(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "fts", value)
}

// Plfts adds a phrase-level full-text search filter condition to the request.
func (b *FilterRequestBuilder) Plfts(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "plfts", value)
}

// Wfts adds a word-level full-text search filter condition to the request.
func (b *FilterRequestBuilder) Wfts(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "wfts", value)
}

// Cs adds a contains set filter condition to the request.
func (b *FilterRequestBuilder) Cs(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "cs", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}

// Cd adds a contained by set filter condition to the request.
func (b *FilterRequestBuilder) Cd(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "cd", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}

// Ov adds an overlaps set filter condition to the request.
func (b *FilterRequestBuilder) Ov(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "ov", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}

// Sl adds a strictly left of filter condition to the request.
func (b *FilterRequestBuilder) Sl(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "sl", fmt.Sprintf("(%d,%d)", from, to))
}

// Sr adds a strictly right of filter condition to the request.
func (b *FilterRequestBuilder) Sr(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "sr", fmt.Sprintf("(%d,%d)", from, to))
}

// Nxl adds a not strictly left of filter condition to the request.
func (b *FilterRequestBuilder) Nxl(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "nxl", fmt.Sprintf("(%d,%d)", from, to))
}

// Nxr adds a not strictly right of filter condition to the request.
func (b *FilterRequestBuilder) Nxr(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "nxr", fmt.Sprintf("(%d,%d)", from, to))
}

// Ad adds an adjacent to filter condition to the request.
func (b *FilterRequestBuilder) Ad(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "ad", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}
