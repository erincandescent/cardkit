// Package TLV provides utilities for working with SIMPLE-TLV
// structures
package tlv

import (
	"github.com/pkg/errors"
)

// Put appends a TLV to a buffer
func Put(buf []byte, tag byte, data []byte) ([]byte, error) {
	l := len(data)
	switch {
	case l < 255:
		buf = append(buf, tag, byte(l), byte(l))
	case l < 65536:
		buf = append(buf, tag, 0xFF, byte(l>>8), byte(l))
	default:
		return nil, errors.New("TLV too long")
	}
	return append(buf, data...), nil
}

// Get gets the next TLV from a buffer
func Get(data []byte, tag byte, optional bool) (body, rest []byte, err error) {
	if len(data) < 2 || data[0] != tag {
		if optional {
			return nil, data, nil
		} else {
			return nil, nil, errors.Errorf("Missing tag %x (have %s)", tag, data)
		}
	}

	l := int(data[1])
	if l == 0xFF {
		if len(data) < 4 {
			return nil, nil, errors.New("Truncated tag/length")
		}

		l = int(data[2])<<8 | int(data[3])

		data = data[4:]
	} else {
		data = data[2:]
	}

	return data[:l], data[l:], nil
}
