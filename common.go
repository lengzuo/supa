package supabase

import (
	"bytes"
	"net/http"

	"golang.org/x/exp/constraints"
)

const (
	apiHostFormat = "https://%s.supabase.co"
)

func min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

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
