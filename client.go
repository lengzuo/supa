package supabase

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type clientConfig struct {
	httpClient *http.Client
	httpHeader map[string]string
	schema     string
}

const (
	authorizationHeader = "apiKey"
	httpTimeout         = 20 * time.Second
	authAPIPath         = "/auth/v1"
	storageAPIPath      = "/storage/v1"
	authPrefix          = "Bearer"
)

type Client struct {
	// Auth refer from https://github.com/supabase/gotrue-js/blob/master/src/GoTrueClient.ts and https://github.com/supabase/gotrue-js/blob/master/src/GoTrueAdminApi.ts
	Auth authAPI
	// DB refer from https://github.com/nedpals/supabase-go/tree/master
	DB PostgresAPI
	// Storage
	Storage storageAPI
}

func New(cfg Config) (*Client, error) {
	if len(strings.TrimSpace(cfg.ApiKey)) == 0 {
		return nil, ErrEmptyApiKey
	}
	// Singleton logger
	newLogger(cfg.Debug)

	apiHost := fmt.Sprintf(apiHostFormat, cfg.ProjectRef)

	supaDB := NewPostgres(
		cfg.ProjectRef,
		WithToken(cfg.ApiKey),
		With(authorizationHeader, cfg.ApiKey),
	)
	for _, opt := range cfg.PostgresOptions {
		opt(supaDB)
	}

	return &Client{
		Auth:    NewAuth(cfg.ApiKey, apiHost+authAPIPath, cfg.AuthOptions...),
		DB:      supaDB,
		Storage: NewStorage(cfg.ApiKey, apiHost+storageAPIPath, cfg.Bucket, cfg.StorageOptions...),
	}, nil
}

func defaultSender(timeout time.Duration, header map[string]string) Sender {
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1000,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: timeout,
			DisableKeepAlives:   false,
		},
		Timeout: timeout,
	}
	return newRequester(httpClient, header)
}
