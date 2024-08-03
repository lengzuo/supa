package supabase

import "errors"

type Exception interface {
	Error() string
	StatusCode() int
}

var ErrEmptyApiKey = errors.New("apiKey is mandatory")

type externalErr struct {
	body       []byte
	statusCode int
}

func External(body []byte, statusCode int) Exception {
	return &externalErr{
		body:       body,
		statusCode: statusCode,
	}
}

func (b externalErr) Error() string {
	return string(b.body)
}

func (b externalErr) StatusCode() int {
	return b.statusCode
}

type PostgresError struct {
	Code           string `json:"code"`
	Details        string `json:"details"`
	Hint           string `json:"hint"`
	HTTPStatusCode int    `json:"-"`
	Message        string `json:"message"`
}

func (rq *PostgresError) Error() string {
	return rq.Code + ": " + rq.Message
}
