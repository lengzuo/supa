package catch

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
