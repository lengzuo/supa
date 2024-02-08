package postgres

import (
	"fmt"
	"strconv"
)

//https://github.com/supabase/postgrest-js/blob/master/src/PostgrestTransformBuilder.ts#L191

type SelectRequestBuilder struct {
	FilterRequestBuilder
}

// OrderBy sets the ordering column and direction for the SELECT request.
func (b *SelectRequestBuilder) OrderBy(column, direction string) *SelectRequestBuilder {
	b.params.Set("order", column+"."+direction)
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
