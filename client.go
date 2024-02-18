package supabase

import (
	"github.com/lengzuo/supa/pkg/httpclient"
)

type client struct {
	httpClient  httpclient.Sender
	apiKey      string
	authHost    string
	restHost    string
	storageHost string
	debug       bool
}
