package supabase

import (
	"fmt"
	"strings"
	"time"

	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/postgres"
	"github.com/lengzuo/supa/utils/common"
)

type client struct {
	httpClient  httpclient.Sender
	apiKey      string
	authHost    string
	storageHost string
	debug       bool
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
	DB postgres.API
	// Storage
	Storage storageAPI
}

func New(cfg Config) (*Client, error) {
	if len(strings.TrimSpace(cfg.ApiKey)) == 0 {
		return nil, common.ErrEmptyApiKey
	}
	// Singleton logger
	logger.New(cfg.Debug)

	apiHost := fmt.Sprintf(common.APIHostFormat, cfg.ProjectRef)
	httpClient := httpclient.New(httpTimeout, cfg.Proxy)

	authClient := client{
		httpClient:  httpClient,
		apiKey:      cfg.ApiKey,
		authHost:    apiHost + authAPIPath,
		storageHost: apiHost + storageAPIPath,
	}
	supaDB := postgres.New(
		cfg.ProjectRef,
		cfg.Proxy,
		postgres.WithToken(cfg.ApiKey),
		postgres.With(authorizationHeader, cfg.ApiKey),
	)
	return &Client{
		Auth:    newAuth(authClient),
		DB:      supaDB,
		Storage: newStorage(authClient, cfg.Bucket),
	}, nil
}
