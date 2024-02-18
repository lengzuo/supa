package enum

type Header uint8

const (
	Authorization Header = iota
	ContentType
	Accept
)

func (v Header) String() string {
	return [...]string{"Authorization", "Content-Type", "Accept"}[v]
}
