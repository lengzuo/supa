package common

import (
	"golang.org/x/exp/constraints"
)

const (
	TimeFormatDB  = "2006-01-02T15:04:05"
	APIHostFormat = "https://%s.supabase.co"
)

func Min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}
