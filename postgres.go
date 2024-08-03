package supabase

import (
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const (
	connectionTimeout = 15 * time.Second
	restAPIPath       = "/rest/v1"
	authHeader        = "Authorization"
)

type PostgresAPI interface {
	From(table string, opts ...HeaderOption) *RequestBuilder
	RPC(f string, params interface{}, opts ...HeaderOption) *RpcRequestBuilder
}

// PostgresClient refer from https://github.com/supabase/postgrest-js/blob/master/src/PostgrestClient.ts
type PostgresClient struct {
	baseURL        url.URL
	defaultHeaders http.Header
	httpClient     Sender
}

type HeaderOption struct {
	Key   string
	Value string
}

func AuthToken(token string) HeaderOption {
	return HeaderOption{
		Key:   authHeader,
		Value: "Bearer " + token,
	}
}

func NewPostgres(projectRef string, opts ...PostgresOption) *PostgresClient {
	apiHost := fmt.Sprintf(apiHostFormat, projectRef)
	base, err := url.Parse(apiHost + restAPIPath)
	if err != nil {
		panic(fmt.Sprintf("invalid url provided in postgres new"))
	}
	impl := &PostgresClient{
		httpClient:     defaultSender(connectionTimeout, make(map[string]string)),
		baseURL:        *base,
		defaultHeaders: make(http.Header),
	}
	for _, opt := range opts {
		opt(impl)
	}
	return impl
}

func (c *PostgresClient) From(table string, opts ...HeaderOption) *RequestBuilder {
	header := c.defaultHeaders.Clone()
	for _, opt := range opts {
		header.Set(opt.Key, opt.Value)
	}
	return &RequestBuilder{
		client: c,
		path:   "/" + table,
		header: header,
		params: url.Values{},
	}
}

func (c *PostgresClient) addHeader(key string, value string) {
	c.defaultHeaders.Set(key, value)
}
