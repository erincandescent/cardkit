// package ber provides utilities for working with BER encoded data structures
package ber

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func PackTag(tag uint32) []byte {
	switch {
	case tag <= 0xFF:
		return []byte{byte(tag)}
	case tag <= 0xFFFF:
		return []byte{byte(tag >> 8), byte(tag)}
	case tag <= 0xFFFFFF:
		return []byte{byte(tag >> 16), byte(tag >> 8), byte(tag)}
	default:
		return []byte{byte(tag >> 24), byte(tag >> 16), byte(tag >> 8), byte(tag)}
	}
}

// Put appends a TLV to a buffer
func Put(buf []byte, tag uint32, data []byte) ([]byte, error) {
	buf = append(buf, PackTag(tag)...)

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
func Get(data []byte, tag uint32, optional bool) (body, rest []byte, err error) {
	packedTag := PackTag(tag)

	if len(data) < len(packedTag) || !bytes.Equal(data[0:len(packedTag)], packedTag) {
		if optional {
			return nil, data, nil
		} else {
			return nil, nil, errors.Errorf("Missing tag %x (have %s)", tag, data)
		}
	}

	data = data[len(packedTag):]

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

var binaryMarshalerType = reflect.TypeOf((*encoding.BinaryMarshaler)(nil)).Elem()
var byteSliceType = reflect.TypeOf([]byte{})

type Mode uint

const (
	ModeDefault Mode = iota
	ModeBER
	ModeBinaryBig
	ModeBinaryLittle
	ModeASN1
)

type fieldInfo struct {
	Tag  uint32
	Mode Mode
}

func parseTag(tag string) (fieldInfo, error) {
	f := fieldInfo{}

	parts := strings.Split(tag, ",")

	tagVal, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return f, errors.Wrap(err, "Parsing tag")
	}
	f.Tag = uint32(tagVal)

	for _, v := range parts[1:] {
		switch v {
		case "ber":
			f.Mode = ModeBER
		case "bin_big", "big":
			f.Mode = ModeBinaryBig
		case "bin_little", "little":
			f.Mode = ModeBinaryLittle
		case "asn1":
			f.Mode = ModeASN1
		default:
			return f, errors.Errorf("Unknown tag part %s", v)
		}
	}

	return f, nil
}

func Marshal(obj interface{}) ([]byte, error) {
	return MarshalValue(reflect.ValueOf(obj))
}

func MarshalValue(val reflect.Value) ([]byte, error) {
	for val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		return marshalStruct(val)

	// case reflect.Array, reflect.Slice:
	// 	var buf []byte
	// 	for i := 0; i < val.Len(); i++ {
	// 		v, err := MarshalValue(val.Index(i))
	// 		if err != nil {
	// 			return nil, err
	// 		}
	// 		buf = append(buf, v...)
	// 	}
	// 	return buf, nil

	default:
		return nil, errors.Errorf("Unable to marshal %s", val.Kind())
	}
}

func marshalStruct(val reflect.Value) ([]byte, error) {
	var buf []byte
	t := val.Type()

	for i := 0; i < t.NumField(); i++ {
		var b []byte
		f := t.Field(i)
		v := val.Field(i)
		ft := f.Type

		if f.Anonymous {
			b, err := marshalStruct(v)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
			continue
		} else if ft.Kind() == reflect.Ptr {
			if v.IsNil() {
				continue
			}

			ft = ft.Elem()
			v = v.Elem()
		}

		tag := f.Tag.Get("ber")
		if tag == "" {
			return nil, errors.Errorf("Field %s missing ber tag", f.Name)
		} else if tag == "-" {
			continue
		}

		info, err := parseTag(tag)
		if err != nil {
			return nil, errors.Wrapf(err, "Parsing %s", f.Name)
		}

		switch info.Mode {
		case ModeDefault:
			if ft == byteSliceType {
				b = v.Interface().([]byte)
			} else if bm, ok := v.Interface().(encoding.BinaryMarshaler); ok {
				b, err = bm.MarshalBinary()
			} else {
				return nil, errors.Errorf("Please specify how to marshal field %s (%s)", f.Name, ft)
			}

		case ModeBER:
			b, err = MarshalValue(v)

		case ModeBinaryBig, ModeBinaryLittle:
			var (
				buf bytes.Buffer
				ord binary.ByteOrder = binary.BigEndian
			)
			if info.Mode == ModeBinaryLittle {
				ord = binary.LittleEndian
			}

			err = binary.Write(&buf, ord, v.Interface())
			b = buf.Bytes()

		}

		if err != nil {
			return nil, errors.Wrapf(err, "Marshaling %s", f.Name)
		}

		buf, err = Put(buf, info.Tag, b)
		if err != nil {
			return nil, errors.Errorf("Packing %s", f.Name)
		}
	}

	return buf, nil
}

func Unmarshal(buf []byte, obj interface{}) error {
	return UnmarshalValue(buf, reflect.ValueOf(obj))
}

func UnmarshalValue(buf []byte, val reflect.Value) error {
	for val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		b, err := unmarshalStruct(buf, val)
		if err != nil {
			return err
		} else if len(b) > 0 {
			return errors.New("Trailing garbage")
		}
		return nil

	default:
		return errors.Errorf("Unable to unmarshal %s", val.Kind())
	}
}

func unmarshalStruct(buf []byte, val reflect.Value) ([]byte, error) {
	var err error
	t := val.Type()

	for i := 0; i < t.NumField(); i++ {
		var b []byte
		f := t.Field(i)
		v := val.Field(i)
		ft := f.Type
		optional := false
		if f.Anonymous {
			buf, err = unmarshalStruct(buf, v)
			if err != nil {
				return nil, err
			}
			continue
		} else if ft.Kind() == reflect.Ptr {
			optional = true
		}

		tag := f.Tag.Get("ber")
		if tag == "" {
			return nil, errors.Errorf("Field %s missing ber tag", f.Name)
		} else if tag == "-" {
			continue
		}

		info, err := parseTag(tag)
		if err != nil {
			return nil, errors.Wrapf(err, "Parsing %s", f.Name)
		}

		b, buf, err = Get(buf, info.Tag, optional)
		if err != nil {
			return nil, errors.Wrapf(err, "Parsing %s", f.Name)
		}

		if b == nil {
			// Skip optional
			continue
		}

		if optional {
			ft = ft.Elem()
			v.Set(reflect.New(ft))
			v = v.Elem()
		}

		switch info.Mode {
		case ModeDefault:
			if ft == byteSliceType {
				v.SetBytes(b)
			} else if bm, ok := v.Interface().(encoding.BinaryUnmarshaler); ok {
				err = bm.UnmarshalBinary(b)
			} else {
				return nil, errors.Errorf("Please specify how to unmarshal field %s (%s)", f.Name, ft)
			}

		case ModeBER:
			err = UnmarshalValue(b, v)

		case ModeBinaryBig, ModeBinaryLittle:
			var ord binary.ByteOrder = binary.BigEndian
			if info.Mode == ModeBinaryLittle {
				ord = binary.LittleEndian
			}

			buf := bytes.NewReader(b)
			err = binary.Read(buf, ord, v.Interface())
			if buf.Len() > 0 {
				return nil, errors.Errorf("Trailing garbage in %s", f.Name)
			}
		}

		if err != nil {
			return nil, errors.Wrapf(err, "Marshaling %s", f.Name)
		}
	}

	return buf, nil
}
