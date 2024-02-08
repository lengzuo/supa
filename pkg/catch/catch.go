package catch

type Exception interface {
	Error() string
	StatusCode() int
}
