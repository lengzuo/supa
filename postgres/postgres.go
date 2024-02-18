package postgres

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/utils/enum"
)

const (
	applicationJson   = "application/json;charset=UTF-8"
	connectionTimeout = 15 * time.Second
)

type API interface {
	From(table string) *RequestBuilder
	RPC(f string, params interface{}) *RpcRequestBuilder
}

// Client refer from https://github.com/supabase/postgrest-js/blob/master/src/PostgrestClient.ts
type Client struct {
	baseURL        *url.URL
	defaultHeaders http.Header
	httpClient     httpclient.Sender
	debug          bool
}

type Option func(c *Client)

func WithToken(token string) Option {
	return func(c *Client) {
		c.addHeader(enum.Authorization.String(), "Bearer "+token)
	}
}

func With(field, value string) Option {
	return func(c *Client) {
		c.addHeader(field, value)
	}
}

func WithBasicAuth(username, password string) Option {
	return func(c *Client) {
		c.addHeader(enum.Authorization.String(), "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
}

func New(baseURL string, opts ...Option) *Client {
	base, err := url.Parse(baseURL)
	if err != nil {
		panic(fmt.Sprintf("invalid url provided in postgres new"))
	}
	c := Client{
		httpClient:     httpclient.New(connectionTimeout),
		baseURL:        base,
		defaultHeaders: make(http.Header),
	}
	for _, opt := range opts {
		opt(&c)
	}
	return &c
}

func (c *Client) From(table string) *RequestBuilder {
	return &RequestBuilder{
		client: c,
		path:   "/" + table,
		header: http.Header{},
		params: url.Values{},
	}
}

func (c *Client) headers() http.Header {
	return c.defaultHeaders.Clone()
}

func (c *Client) addHeader(key string, value string) {
	c.defaultHeaders.Set(key, value)
}
