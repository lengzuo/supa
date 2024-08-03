package supabase

import (
	"fmt"
	"strconv"
)

//https://github.com/supabase/postgrest-js/blob/master/src/PostgrestTransformBuilder.ts#L191

type SelectRequestBuilder struct {
	FilterRequestBuilder
}

// Order sets the ordering column and direction for the SELECT request.
func (b *SelectRequestBuilder) Order(column string, order Order) *SelectRequestBuilder {
	b.params.Set("order", column+"."+order.String())
	return b
}

// Range sets the range of rows to be returned for the SELECT request. Range is consist of offset and limit
func (b *SelectRequestBuilder) Range(from, to int) *SelectRequestBuilder {
	b.params.Set("offset", fmt.Sprintf("%d", from))
	b.params.Set("limit", fmt.Sprintf("%d", to-from+1))
	return b
}

// Limit the query result by `count`.
func (b *SelectRequestBuilder) Limit(count int) *SelectRequestBuilder {
	b.params.Set("limit", strconv.Itoa(count))
	return b
}

// Offset skips specified number of rows.
func (b *SelectRequestBuilder) Offset(number int) *SelectRequestBuilder {
	b.params.Set("offset", strconv.Itoa(number))
	return b
}
