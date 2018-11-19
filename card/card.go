// package card provides interfaces for accdssing smartcards
package card

// Card represents a single card
// Card wraps a Transport providing higher level operations
type Card struct {
	Transport
}

// FileID references a 16-bit smartcard file ID
type FileID uint16

const (
	MF        FileID = 0x3F00
	CurrentEF FileID = 0x0000
	CurrentDF FileID = 0x3FFF
)

// New constructs a new card on the specified transport
func New(transport string) (*Card, error) {
	t, err := CreateTransport(transport)
	if err != nil {
		return nil, err
	}

	return &Card{t}, nil
}

// Command composes an APDU to send to the card,
// handling breaking large requests over multiple
// request and response packages if necessary
func (c *Card) Command(cla, ins, p1, p2 byte, data []byte, le uint) ([]byte, error) {
	var respData []byte
	var req ReqAPDU

	for len(data) > 255 {
		req = ReqAPDU{
			Cla:  cla | 0x10,
			Ins:  ins,
			P1:   p1,
			P2:   p2,
			Data: data[0:255],
			Le:   0,
		}
		resp, err := c.Transact(req)
		if err != nil {
			return nil, err
		} else if !(resp.SW1 == 0x90 && resp.SW2 == 00) {
			return nil, ErrorFromAPDU(resp)
		}
		data = data[255:]
	}

	req = ReqAPDU{
		Cla:  cla,
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
		Le:   le,
	}

	for {
		resp, err := c.Transact(req)

		respData = append(respData, resp.Data...)

		if err != nil {
			return nil, err
		} else if resp.SW1 == 0x90 && resp.SW2 == 0x00 {
			break
		} else if resp.SW1 == 0x6C {
			req.Le = uint(resp.SW2)
			if req.Le == 0 {
				req.Le = 256
			}
		} else if resp.SW1 == 0x61 {
			if resp.SW2 == 0 {
				le = 256
			} else {
				le = uint(resp.SW2)
			}

			req = ReqAPDU{
				Cla:  cla,
				Ins:  0xC0,
				P1:   0x00,
				P2:   0x00,
				Data: []byte{},
				Le:   le,
			}
		} else {
			return nil, ErrorFromAPDU(resp)
		}
	}

	return respData, nil
}

// SelectDF selects a Dedicated File
func (c *Card) SelectDF(name []byte) ([]byte, error) {
	return c.Command(0x00, 0xA4, 0x04, 0x00, name, 256)
}

// GetFileData returns the data contained in the specified file,
// including the specified request
func (c *Card) GetFileData(name FileID, body []byte) ([]byte, error) {
	return c.Command(0x00, 0xCB, byte(name>>8), byte(name), body, 256)
}

// PutFileData puts data in the specified file
func (c *Card) PutFileData(name FileID, body []byte) error {
	_, err := c.Command(0x00, 0xDB, byte(name>>8), byte(name), body, 0)
	return err
}

func (c *Card) Verify(id byte, pin []byte) error {
	_, err := c.Command(0x00, 0x20, 0x00, id, pin, 0)
	return err
}
