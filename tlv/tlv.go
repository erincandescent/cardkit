// Package TLV provides utilities for working with TLV
// structures
package tlv

import (
	"bytes"

	"github.com/pkg/errors"
)

// Put appends a TLV to a buffer
func Put(buf, tag, data []byte) ([]byte, error) {
	buf = append(buf, tag...)

	l := len(data)
	switch {
	case l < 128:
		buf = append(buf, byte(l))
	case l < 256:
		buf = append(buf, 0x81, byte(l))
	case l < 65536:
		buf = append(buf, 0x82, byte(l>>8), byte(l))
	default:
		return nil, errors.New("TLV too long")
	}

	return append(buf, data...), nil
}

// Get gets the next TLV from a buffer
func Get(data []byte, tag []byte, optional bool) (body, rest []byte, err error) {
	if len(data) < len(tag) || !bytes.Equal(data[0:len(tag)], tag) {
		if optional {
			return nil, data, nil
		} else {
			return nil, nil, errors.Errorf("Missing tag %x (have %s)", tag, data)
		}
	}

	data = data[len(tag):]

	if len(data) < 1 {
		return nil, nil, errors.New("Truncated tag/length")
	}

	l := int(data[0])
	switch {
	case l < 0x80:
		data = data[1:]

	case l == 0x81:
		if len(data) < 2 {
			return nil, nil, errors.New("Truncated length")
		}
		l = int(data[1])
		data = data[2:]

	case l == 0x82:
		if len(data) < 3 {
			return nil, nil, errors.New("Truncated length")
		}
		l = int(data[1])<<8 | int(data[2])
		data = data[3:]

	default:
		// Sanity: Smart cards shouldn't be returning >64kB
		// or indefinite length objects
		return nil, nil, errors.New("Invalid length")
	}

	if len(data) < l {
		return nil, nil, errors.New("Truncated data")
	}

	return data[:l], data[l:], nil
}
