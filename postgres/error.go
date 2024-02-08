package postgres

type Error struct {
	Code           string `json:"code"`
	Details        string `json:"details"`
	Hint           string `json:"hint"`
	HTTPStatusCode int    `json:"-"`
	Message        string `json:"message"`
}

func (rq *Error) Error() string {
	return rq.Code + ": " + rq.Message
}
