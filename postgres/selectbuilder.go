package postgres

import (
	"fmt"
	"strconv"

	"github.com/lengzuo/supa/utils/enum"
)

//https://github.com/supabase/postgrest-js/blob/master/src/PostgrestTransformBuilder.ts#L191

type SelectRequestBuilder struct {
	FilterRequestBuilder
}

// Order sets the ordering column and direction for the SELECT request.
func (b *SelectRequestBuilder) Order(column string, order enum.Order) *SelectRequestBuilder {
	b.params.Set("order", column+"."+order.String())
	return b
}

// Range sets the range of rows to be returned for the SELECT request.
func (b *SelectRequestBuilder) Range(from, to int) *SelectRequestBuilder {
	b.params.Set("range", fmt.Sprintf("%d-%d", from, to))
	return b
}

// Limit the query result by `count`.
func (b *SelectRequestBuilder) Limit(count int) *SelectRequestBuilder {
	b.params.Set("limit", strconv.Itoa(count))
	return b
}
