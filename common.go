package supabase

import (
	"bytes"
	"net/http"
)

const (
	apiHostFormat = "https://%s.supabase.co"
)

type Resp struct {
	Body       bytes.Buffer
	Header     http.Header
	StatusCode int
}

type StreamResp struct {
	Response *http.Response
}

func (s StreamResp) Close() error {
	return s.Response.Body.Close()
}
