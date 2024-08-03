package supabase

import "net/http"

type HTTPOption func(c *clientConfig)

func WithHeader(header map[string]string) HTTPOption {
	return func(c *clientConfig) {
		c.httpHeader = header
	}
}

func WithClient(httpClient *http.Client) HTTPOption {
	return func(c *clientConfig) {
		c.httpClient = httpClient
	}
}
