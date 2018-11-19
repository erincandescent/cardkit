// package ber provides utilities for working with BER encoded data structures
package ber

import (
	"bytes"
	"encoding"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Pack a tag into a byte array
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

// NextTag gets the next tag from data
func NextTag(data []byte) (tag uint32, rest []byte, err error) {
	if len(data) == 0 {
		err = io.EOF
		return
	}

	if (data[0] & 0x1F) == 0x1F {
		// Long tag
		tag = uint32(data[0])
		rest = data[1:]
		for {
			if len(rest) == 0 {
				err = io.EOF
			}

			tag = tag<<8 | uint32(rest[0])
			rest = rest[1:]

			if (tag & 0x80) == 0x00 {
				break
			}
		}
	} else {
		// Short tag
		tag = uint32(data[0])
		rest = data[1:]
	}

	return
}

// NextLength reads a length value from the buffer
func NextLength(data []byte) (length int, rest []byte, err error) {
	switch {
	case len(data) == 0:
		err = io.EOF

	case data[0] < 0x80:
		length = int(data[0])
		rest = data[1:]

	case data[0] == 0x81:
		if len(data) < 2 {
			err = io.EOF
		} else {
			length = int(data[1])
			rest = data[2:]
		}

	case data[0] == 0x82:
		if len(data) < 3 {
			err = io.EOF
		} else {
			length = int(data[1])<<8 | int(data[2])
			rest = data[3:]
		}

	default:
		// Only 1 & 2 byte lengths can be expected from smart cards
		// so don't support longer formats
		err = errors.Errorf("Length format 0x%x unsupported", data[0])
	}
	return
}

// Next reads the next TLV from the buffer
func Next(data []byte) (tag uint32, body, rest []byte, err error) {
	var length int

	tag, rest, err = NextTag(data)
	if err != nil {
		return
	}

	length, rest, err = NextLength(rest)
	if err != nil {
		return
	}

	if len(rest) < length {
		err = io.EOF
		return
	}

	body = rest[0:length]
	rest = rest[length:]

	return
}

// Get gets a specific TLV from the buffer
func Get(data []byte, tag uint32, optional bool) (body, rest []byte, err error) {
	var readTag uint32
	readTag, body, rest, err = Next(data)

	if err != nil {
		return
	} else if optional && readTag != tag {
		body = nil
		rest = data
		return
	} else if readTag != tag {
		err = errors.Errorf("Missing tag %x (have %x)", tag, readTag)
	}

	return
}

var binaryMarshalerType = reflect.TypeOf((*encoding.BinaryMarshaler)(nil)).Elem()
var byteSliceType = reflect.TypeOf([]byte{})
var stringType = reflect.TypeOf("")

type mode uint

const (
	modeDefault mode = iota
	modeBER
	modeBinaryBig
	modeBinaryLittle
	modeASN1
)

type fieldInfo struct {
	Tag  uint32
	Mode mode
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
			f.Mode = modeBER
		case "bin_big", "big":
			f.Mode = modeBinaryBig
		case "bin_little", "little":
			f.Mode = modeBinaryLittle
		case "asn1":
			f.Mode = modeASN1
		default:
			return f, errors.Errorf("Unknown tag part %s", v)
		}
	}

	return f, nil
}

// Marshal marshals an object as BER/DER
//
// The specified object must be a structure. Members will
// be iterated and automatically BER encoded. The struct will
// not itself be enclosed in a tag
//
// Any unnamed struct member will be inlined directly. Pointer values are
// considered optional: nil will not be marshalled, and on unmarshalling absence
// shall be treated as nil
//
// Struct members must be tagged with the `ber` tag. If this tag
// is set to `-`, then the field will be skipped. Otherwise, it
// should be a smartcard style/wire-format hex tag as opposed to the
// ASN.1 format tags used by the Go marshal/asn.1 package
//
// The tag value may be followed by any of a number of comma separated
// flag values. These can be:
//
// * One of an encoding control flag. Valid encoding control flags are
//
//   * `ber`: Marshal the nested object as if by a recursive call to Marshal
//   * `big` or `bin_big`: Marshal the nested object using encoding/binary in
//      big endian
//   * `little` or `bin_little`: Same but little endian
//   * `asn1`: Marshal the nested object using encoding/asn1
//
// If no encoding control flag is specified, then
//
// * `[]byte` or `string` is encoded directly
// * All other types are required to implement MarshalBinary
func Marshal(obj interface{}) ([]byte, error) {
	return MarshalValue(reflect.ValueOf(obj))
}

// MarshalsValue marshals a reflect.Value
func MarshalValue(val reflect.Value) ([]byte, error) {
	for val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		return marshalStruct(val)

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
		case modeDefault:
			if ft == byteSliceType {
				b = v.Interface().([]byte)
			} else if ft == stringType {
				b = []byte(v.Interface().(string))
			} else if bm, ok := v.Interface().(encoding.BinaryMarshaler); ok {
				b, err = bm.MarshalBinary()
			} else {
				return nil, errors.Errorf("Please specify how to marshal field %s (%s)", f.Name, ft)
			}

		case modeBER:
			b, err = MarshalValue(v)

		case modeASN1:
			b, err = asn1.Marshal(v.Interface())

		case modeBinaryBig, modeBinaryLittle:
			var (
				buf bytes.Buffer
				ord binary.ByteOrder = binary.BigEndian
			)
			if info.Mode == modeBinaryLittle {
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

// Unmarshal unmarshals buf into `obj`
func Unmarshal(buf []byte, obj interface{}) error {
	return UnmarshalValue(buf, reflect.ValueOf(obj))
}

// UnmarshalValue unmarshals into a reflect.Value
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
		case modeDefault:
			if ft == byteSliceType {
				v.SetBytes(b)
			} else if ft == stringType {
				v.SetString(string(b))
			} else if bm, ok := v.Addr().Interface().(encoding.BinaryUnmarshaler); ok {
				err = bm.UnmarshalBinary(b)
			} else {
				return nil, errors.Errorf("Please specify how to unmarshal field %s (%s)", f.Name, ft)
			}

		case modeBER:
			err = UnmarshalValue(b, v)

		case modeASN1:
			b, err = asn1.Unmarshal(b, v.Interface())
			if len(b) > 0 {
				return nil, errors.Errorf("%d bytes of trailing garbage in %s", len(b), f.Name)
			}

		case modeBinaryBig, modeBinaryLittle:
			var ord binary.ByteOrder = binary.BigEndian
			if info.Mode == modeBinaryLittle {
				ord = binary.LittleEndian
			}

			buf := bytes.NewReader(b)
			err = binary.Read(buf, ord, v.Addr().Interface())
			if buf.Len() > 0 {
				return nil, errors.Errorf("%d bytes of trailing garbage in %s (%d bytes)", buf.Len(), f.Name, len(b))
			}
		}

		if err != nil {
			return nil, errors.Wrapf(err, "Marshaling %s", f.Name)
		}
	}

	return buf, nil
}
