package executor

import (
	"strings"
	"sync"
)

// URLBuilder provides pooled string building for URL construction
type URLBuilder struct {
	sb strings.Builder
}

var urlBuilderPool = sync.Pool{
	New: func() any {
		return &URLBuilder{
			sb: strings.Builder{},
		}
	},
}

// GetURLBuilder returns a pooled URLBuilder
func GetURLBuilder() *URLBuilder {
	return urlBuilderPool.Get().(*URLBuilder)
}

// Release returns the builder to the pool
func (b *URLBuilder) Release() {
	b.sb.Reset()
	urlBuilderPool.Put(b)
}

// WriteString appends a string
func (b *URLBuilder) WriteString(s string) {
	b.sb.WriteString(s)
}

// String returns the built string
func (b *URLBuilder) String() string {
	return b.sb.String()
}

// Grow pre-allocates capacity
func (b *URLBuilder) Grow(n int) {
	b.sb.Grow(n)
}
