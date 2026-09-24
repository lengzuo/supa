package storage

import (
	"strings"
)

const upperHex = "0123456789ABCDEF"

// encodeURI mirrors JavaScript's encodeURI: it percent-encodes every byte
// except ASCII letters, digits and ;,/?:@&=+$-_.!~*'()#. Upstream builds
// public and signed URLs with it, so the Go SDK produces identical URLs.
func encodeURI(s string) string {
	return percentEncode(s, func(c byte) bool {
		return isAlnum(c) || strings.IndexByte(";,/?:@&=+$-_.!~*'()#", c) >= 0
	}, false)
}

// formQuery is an ordered application/x-www-form-urlencoded builder that
// mirrors JavaScript's URLSearchParams serialization (insertion order,
// space as '+', and only *-._ left unescaped besides letters and digits).
type formQuery struct {
	keys, values []string
}

// set replaces the value of key, keeping its original position.
func (q *formQuery) set(key, value string) {
	for i, k := range q.keys {
		if k == key {
			q.values[i] = value
			return
		}
	}
	q.keys = append(q.keys, key)
	q.values = append(q.values, value)
}

func (q *formQuery) encode() string {
	var b strings.Builder
	for i, k := range q.keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(formEncode(k))
		b.WriteByte('=')
		b.WriteString(formEncode(q.values[i]))
	}
	return b.String()
}

func formEncode(s string) string {
	return percentEncode(s, func(c byte) bool {
		return isAlnum(c) || c == '*' || c == '-' || c == '.' || c == '_'
	}, true)
}

func isAlnum(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}

func percentEncode(s string, keep func(byte) bool, spaceAsPlus bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case keep(c):
			b.WriteByte(c)
		case spaceAsPlus && c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&15])
		}
	}
	return b.String()
}

// trimLeadingSlashes strips all leading slashes, like storage-js
// _getFinalPath.
func trimLeadingSlashes(p string) string {
	return strings.TrimLeft(p, "/")
}

// removeEmptyFolders mirrors storage-js _removeEmptyFolders: it drops one
// leading and one trailing slash and collapses repeated slashes.
func removeEmptyFolders(p string) string {
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}
