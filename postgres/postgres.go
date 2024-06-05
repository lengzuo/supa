package postgres

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/utils/common"
	"github.com/lengzuo/supa/utils/enum"
)

const (
	connectionTimeout = 15 * time.Second
	restAPIPath       = "/rest/v1"
)

type API interface {
	From(table string, opts ...HeaderOption) *RequestBuilder
	RPC(f string, params interface{}, opts ...HeaderOption) *RpcRequestBuilder
}

// Client refer from https://github.com/supabase/postgrest-js/blob/master/src/PostgrestClient.ts
type Client struct {
	baseURL        url.URL
	defaultHeaders http.Header
	httpClient     httpclient.Sender
	debug          bool
}

type HeaderOption struct {
	Key   string
	Value string
}

func AuthToken(token string) HeaderOption {
	return HeaderOption{
		Key:   enum.Authorization.String(),
		Value: "Bearer " + token,
	}
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

func New(projectRef string, proxy string, opts ...Option) *Client {
	apiHost := fmt.Sprintf(common.APIHostFormat, projectRef)
	base, err := url.Parse(apiHost + restAPIPath)
	if err != nil {
		panic(fmt.Sprintf("invalid url provided in postgres new"))
	}
	c := Client{
		httpClient:     httpclient.New(connectionTimeout, proxy),
		baseURL:        *base,
		defaultHeaders: make(http.Header),
	}
	for _, opt := range opts {
		opt(&c)
	}
	return &c
}

func (c *Client) From(table string, opts ...HeaderOption) *RequestBuilder {
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

func (c *Client) addHeader(key string, value string) {
	c.defaultHeaders.Set(key, value)
}
