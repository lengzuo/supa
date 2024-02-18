package enum

type Order uint8

const (
	OrderAsc Order = iota
	OrderDesc
)

func (v Order) String() string {
	return [...]string{"asc", "desc"}[v]
}
