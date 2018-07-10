package card

import "errors"

type ReqAPDU struct {
	Cla  byte
	Ins  byte
	P1   byte
	P2   byte
	Data []byte
	Le   uint
}

func (apdu ReqAPDU) Serialize() ([]byte, error) {
	buf := []byte{apdu.Cla, apdu.Ins, apdu.P1, apdu.P2}

	Lc := len(apdu.Data)

	if Lc > 65535 || apdu.Le > 65536 {
		return nil, errors.New("Lc or Le too long")
	}

	extended := Lc > 255 || apdu.Le > 256

	if Lc > 0 {
		if !extended {
			buf = append(buf, byte(Lc))
		} else {
			buf = append(buf, 0x00, byte(Lc>>8), byte(Lc))
		}
		buf = append(buf, apdu.Data...)

		if apdu.Le > 0 {
			if !extended {
				buf = append(buf, byte(apdu.Le))
			} else {
				buf = append(buf, byte(apdu.Le>>8), byte(apdu.Le))
			}
		}
	} else if apdu.Le > 0 {
		if extended {
			buf = append(buf, 0x00, byte(apdu.Le>>8), byte(apdu.Le))
		} else {
			buf = append(buf, byte(apdu.Le))
		}
	}

	return buf, nil
}

type RespAPDU struct {
	SW1  byte
	SW2  byte
	Data []byte
}

func ParseRespAPDU(data []byte) (RespAPDU, error) {
	resp := RespAPDU{}

	if len(data) < 2 {
		return resp, errors.New("Response APDU too short")
	}

	resp.Data = data[:len(data)-2]
	resp.SW1 = data[len(data)-2]
	resp.SW2 = data[len(data)-1]
	return resp, nil
}
