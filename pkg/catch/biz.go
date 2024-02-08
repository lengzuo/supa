package catch

type bizErr struct {
	err        error
	statusCode int
}

func Biz(err error, statusCode int) Exception {
	return &bizErr{
		err:        err,
		statusCode: statusCode,
	}
}

func (b bizErr) Error() string {
	return b.err.Error()
}

func (b bizErr) StatusCode() int {
	return b.statusCode
}
