package supabase

import (
	"encoding/base64"
	"net/http"
)

type PostgresOption func(c *PostgresClient)

func WithToken(token string) PostgresOption {
	return func(c *PostgresClient) {
		c.addHeader(authHeader, "Bearer "+token)
	}
}

func With(field, value string) PostgresOption {
	return func(c *PostgresClient) {
		c.addHeader(field, value)
	}
}

func WithBasicAuth(username, password string) PostgresOption {
	return func(c *PostgresClient) {
		c.addHeader(authHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
}

func WithPostgresClient(httpClient *http.Client, header map[string]string) PostgresOption {
	return func(c *PostgresClient) {
		c.httpClient = newRequester(httpClient, header)
	}
}
