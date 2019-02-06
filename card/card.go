// package card provides interfaces for accdssing smartcards
package card

import "github.com/erincandescent/cardkit/transport"

type ReqAPDU = transport.ReqAPDU
type RespAPDU = transport.RespAPDU

// Card represents a single card
// Card wraps a Transport providing higher level operations
type Card struct {
	T transport.Transport
}

// FileID references a 16-bit smartcard file ID
type FileID uint16

const (
	MF        FileID = 0x3F00
	CurrentEF FileID = 0x0000
	CurrentDF FileID = 0x3FFF
)

// New constructs a new card on the specified transport
func New(transportStr string) (*Card, error) {
	t, err := transport.CreateTransport(transportStr)
	if err != nil {
		return nil, err
	}

	return &Card{t}, nil
}

func (c *Card) Lock() error {
	return c.T.Lock()
}

func (c *Card) Unlock() error {
	return c.T.Unlock()
}

// Transact sends a request to the card and gets a response
// Unlike the raw Transport implementation, this one will fragment
// and reassemble large APDUs
func (c *Card) Transact(req ReqAPDU) (RespAPDU, error) {
	data := req.Data[:]
	for len(data) > 255 {
		sresp, err := c.T.Transact(ReqAPDU{
			Cla:  req.Cla | 0x10,
			Ins:  req.Ins,
			P1:   req.P1,
			P2:   req.P2,
			Data: data[0:255],
			Le:   0,
		})

		if err != nil || !sresp.OK() {
			return sresp, err
		}

		data = data[255:]
	}

	var respData []byte
	req.Data = data

	for {
		sresp, err := c.T.Transact(req)
		respData = append(respData, sresp.Data...)

		if err != nil {
			// Error, just return it
			return sresp, err
		} else if sresp.OK() {
			sresp.Data = respData
			return sresp, nil
		} else if sresp.SW1 == 0x6C {
			// Our Le was wrong, re-send request with exact
			// value
			if sresp.SW2 == 0 {
				req.Le = 256
			} else {
				req.Le = uint(sresp.SW2)
			}
		} else if sresp.SW1 == 0x61 {
			// More data remains, fetch the rest
			req.Ins = 0xC0 // GET MORE DATA
			req.P1 = 0x00
			req.P2 = 0x00
			req.Data = nil
			if sresp.SW2 == 0 {
				req.Le = 256
			} else {
				req.Le = uint(sresp.SW2)
			}
		} else {
			// Other error
			return sresp, nil
		}
	}
}

// Command is an easy interface for building APDUs
func (c *Card) Command(cla, ins, p1, p2 byte, data []byte, le uint) ([]byte, error) {
	resp, err := c.Transact(ReqAPDU{
		Cla:  cla,
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
		Le:   le,
	})
	if err != nil {
		return nil, err
	} else if resp.OK() {
		return resp.Data, nil
	} else {
		return nil, ErrorFromAPDU(resp)
	}
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

func (c *Card) GetDataObject(name uint32) ([]byte, error) {
	return c.Command(0x00, 0xCA, byte(name>>8), byte(name), nil, 256)
}

func (c *Card) PutDataObject(name uint32, buf []byte) error {
	_, err := c.Command(0x00, 0xDA, byte(name>>8), byte(name), buf, 256)
	return err
}

func (c *Card) Verify(id byte, pin []byte) error {
	_, err := c.Command(0x00, 0x20, 0x00, id, pin, 0)
	return err
}
