package supabase

import (
	"fmt"
	"strings"
)

// FilterRequestBuilder represents a builder for filter requests.
type FilterRequestBuilder struct {
	QueryRequestBuilder
	negateNext bool
}

// Not negates the next filter condition.
func (b *FilterRequestBuilder) Not() *FilterRequestBuilder {
	b.negateNext = true
	return b
}

// Filter adds a filter condition to the request.
func (b *FilterRequestBuilder) Filter(column, operator, criteria string) *FilterRequestBuilder {
	if b.negateNext {
		b.negateNext = false
		operator = "not." + operator
	}
	b.params.Add(column, operator+"."+criteria)
	return b
}

// Eq adds an equality filter condition to the request.
func (b *FilterRequestBuilder) Eq(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "eq", value)
}

// Single Retrieves only one row from the result. The total result set must be one row
// (e.g., by using Limit). Otherwise, this will result in an error.
func (b *FilterRequestBuilder) Single() *FilterRequestBuilder {
	b.header.Set("Accept", "application/vnd.pgrst.object+json")
	return b
}

// Gt adds a greater-than filter condition to the request.
func (b *FilterRequestBuilder) Gt(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "gt", value)
}

// Gte adds a greater-than-or-equal filter condition to the request.
func (b *FilterRequestBuilder) Gte(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "gte", value)
}

// Lt adds a less-than filter condition to the request.
func (b *FilterRequestBuilder) Lt(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "lt", value)
}

// Lte adds a less-than-or-equal filter condition to the request.
func (b *FilterRequestBuilder) Lte(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "lte", value)
}

// Like adds a LIKE filter condition to the request.
func (b *FilterRequestBuilder) Like(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "like", value)
}

// Ilike adds a ILIKE filter condition to the request.
func (b *FilterRequestBuilder) Ilike(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "ilike", value)
}

// Is adds an IS filter condition to the request.
func (b *FilterRequestBuilder) Is(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "is", value)
}

// In adds an IN filter condition to the request.
func (b *FilterRequestBuilder) In(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "in", fmt.Sprintf("(%s)", strings.Join(sanitized, ",")))
}

// Neq adds a not-equal filter condition to the request.
func (b *FilterRequestBuilder) Neq(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "neq", value)
}

// Fts adds a full-text search filter condition to the request.
func (b *FilterRequestBuilder) Fts(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "fts", value)
}

// Plfts adds a phrase-level full-text search filter condition to the request.
func (b *FilterRequestBuilder) Plfts(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "plfts", value)
}

// Wfts adds a word-level full-text search filter condition to the request.
func (b *FilterRequestBuilder) Wfts(column, value string) *FilterRequestBuilder {
	return b.Filter(column, "wfts", value)
}

// Cs adds a contains set filter condition to the request.
func (b *FilterRequestBuilder) Cs(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "cs", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}

// Cd adds a contained by set filter condition to the request.
func (b *FilterRequestBuilder) Cd(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "cd", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}

// Ov adds an overlaps set filter condition to the request.
func (b *FilterRequestBuilder) Ov(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "ov", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}

// Sl adds a strictly left of filter condition to the request.
func (b *FilterRequestBuilder) Sl(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "sl", fmt.Sprintf("(%d,%d)", from, to))
}

// Sr adds a strictly right of filter condition to the request.
func (b *FilterRequestBuilder) Sr(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "sr", fmt.Sprintf("(%d,%d)", from, to))
}

// Nxl adds a not strictly left of filter condition to the request.
func (b *FilterRequestBuilder) Nxl(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "nxl", fmt.Sprintf("(%d,%d)", from, to))
}

// Nxr adds a not strictly right of filter condition to the request.
func (b *FilterRequestBuilder) Nxr(column string, from, to int) *FilterRequestBuilder {
	return b.Filter(column, "nxr", fmt.Sprintf("(%d,%d)", from, to))
}

// Ad adds an adjacent to filter condition to the request.
func (b *FilterRequestBuilder) Ad(column string, values []string) *FilterRequestBuilder {
	sanitized := make([]string, len(values))
	for i, value := range values {
		sanitized[i] = value
	}
	return b.Filter(column, "ad", fmt.Sprintf("{%s}", strings.Join(sanitized, ",")))
}
