package transport

import (
	"log"

	"github.com/pkg/errors"
)

type debugTransport struct {
	Base Transport
}

var _ Transport = &debugTransport{}

// NewDebugTransport creates a new debug transport
func NewDebugTransport(params string) (Transport, error) {
	if params == "" {
		return nil, errors.New("Debug transport requires params")
	}

	base, err := CreateTransport(params)
	if err != nil {
		return nil, err
	}

	return &debugTransport{base}, nil
}

func (self *debugTransport) Lock() error {
	return self.Base.Lock()
}

func (self *debugTransport) Unlock() (errs error) {
	return self.Base.Unlock()
}

func chunks(buf []byte, sz int) (bufs [][]byte) {
	for len(buf) > sz {
		bufs = append(bufs, buf[0:sz])
		buf = buf[sz:]
	}
	return append(bufs, buf)
}

func (self *debugTransport) Transact(req ReqAPDU) (RespAPDU, error) {
	reqBits := chunks(req.Data, 32)
	if len(reqBits) == 1 {
		log.Printf("-> %02x %02x %02x %02x | %-64x | %02x\n", req.Cla, req.Ins, req.P1, req.P2, reqBits[0], req.Le)
	} else {
		log.Printf("-> %02x %02x %02x %02x | %-64x |\n", req.Cla, req.Ins, req.P1, req.P2, reqBits[0])
		for i := 1; i < len(reqBits)-1; i++ {
			log.Printf("->             | %-64x |\n", reqBits[i])
		}
		log.Printf("->             | %-64x | %02x \n", reqBits[len(reqBits)-1], req.Le)
	}

	resp, err := self.Base.Transact(req)
	if err == nil {
		bits := chunks(resp.Data, 32)
		log.Printf("<- %04x        | %-64x |\n", uint(resp.SW1)<<8|uint(resp.SW2), bits[0])
		for i := 1; i < len(bits); i++ {
			log.Printf("<-             | %-64x |\n", bits[i])
		}
	} else {
		log.Printf("<- Error: %s\n", err)
	}
	return resp, err
}

func init() {
	RegisterTransport("debug", NewDebugTransport)
}
