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

const (
	authorizationHeader = "apiKey"
	httpTimeout         = 20 * time.Second
	apiHostFormat       = "https://%s.supabase.co"
	authApiPath         = "/auth/v1"
	restApiPath         = "/rest/v1"
	authPrefix          = "Bearer"
)

type Client struct {
	// Auth refer from https://github.com/supabase/gotrue-js/blob/master/src/GoTrueClient.ts and https://github.com/supabase/gotrue-js/blob/master/src/GoTrueAdminApi.ts
	Auth authAPI
	// DB refer from https://github.com/nedpals/supabase-go/tree/master
	DB postgres.API
	//storage storageAPI
}

func New(cfg Config) (*Client, error) {
	if len(strings.TrimSpace(cfg.ApiKey)) == 0 {
		return nil, common.ErrEmptyApiKey
	}
	// Singleton logger
	logger.New(cfg.Debug)

	apiHost := fmt.Sprintf(apiHostFormat, cfg.ProjectRef)
	httpClient := httpclient.New(httpTimeout)

	authClient := client{
		httpClient: httpClient,
		apiKey:     cfg.ApiKey,
		authHost:   apiHost + authApiPath,
		restHost:   apiHost + restApiPath,
	}
	supaDB := postgres.New(
		authClient.restHost,
		postgres.WithToken(cfg.ApiKey),
		postgres.With(authorizationHeader, cfg.ApiKey),
	)
	return &Client{
		Auth: newAuth(authClient),
		DB:   supaDB,
		//storage: newStorage(authClient, cfg.Bucket),
	}, nil
}
