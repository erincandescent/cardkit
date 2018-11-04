package dshl

import (
	"context"
)

type Args []Value

func (a Args) Get(i int, ctx ...context.Context) interface{} {
	if len(a) <= i {
		return nil
	}
	return a[i].Get(ctx...)
}

func (a Args) Chan(i int) <-chan interface{} {
	if len(a) <= i {
		return nil
	}
	return a[i].Chan()
}

func (a Args) String(i int, ctx ...context.Context) string {
	if len(a) <= i {
		return ""
	}
	return a[i].String(ctx...)
}

func (a Args) Strings(ctx ...context.Context) []string {
	out := make([]string, len(a))
	for i, v := range a {
		out[i] = v.String(ctx...)
	}
	return out
}

func (a Args) Int64(i int, ctx ...context.Context) (int64, error) {
	if len(a) <= i {
		return 0, nil
	}
	return a[i].Int64(ctx...)
}

func (a Args) UInt64(i int, ctx ...context.Context) (uint64, error) {
	if len(a) <= i {
		return 0, nil
	}
	return a[i].UInt64(ctx...)
}
