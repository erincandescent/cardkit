package dshl

import (
	"context"
)

// Wraps a value received from the commandline or another argument.
// This exists to abstract away the difference between values and streams of values, allowing
// you to build pipeline constructions without needlessly complicating the simple (and much
// more common) use case of Just Passing A Dang String.
type Value struct {
	v  interface{}        // wrapped value
	ch <-chan interface{} // wrapped channel
}

// Wraps a value or list of values in a Value.
func Wrap(v interface{}) Value {
	return Value{v: v}
}

// Wraps a channel of values in a Value.
func WrapChan(ch <-chan interface{}) Value {
	return Value{ch: ch}
}

// Returns a channel for reading values. This will always return a channel - if the Value wraps
// a channel, that channel is returned, otherwise a buffered channel is returned that reads the
// wrapped value(s).
func (v Value) Chan() <-chan interface{} {
	if v.ch != nil {
		return v.ch
	}
	ch := make(chan interface{}, 1)
	ch <- v.v
	close(ch)
	return ch
}

// Returns the value; if the value wraps a channel, this will be the first value read from it.
func (v Value) Get(ctx_ ...context.Context) interface{} {
	ctx := context.Background()
	if len(ctx_) > 0 {
		ctx = ctx_[0]
	}
	if v.v == nil && v.ch != nil {
		select {
		case val := <-v.ch:
			v.v = val
		case <-ctx.Done():
		}
	}
	return v.v
}

func (v Value) String(ctx ...context.Context) string {
	return ToString(v.Get(ctx...))
}

func (v Value) Int64(ctx ...context.Context) (int64, error) {
	return ToInt64(v.Get(ctx...))
}

func (v Value) UInt64(ctx ...context.Context) (uint64, error) {
	return ToUInt64(v.Get(ctx...))
}
