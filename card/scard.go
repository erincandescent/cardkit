package card

import (
	"sync"

	"github.com/ebfe/scard"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

type scardTransport struct {
	m   sync.Mutex
	c   *scard.Card
	ctx *scard.Context
}

var _ Transport = &scardTransport{}

// NewSCardTransport creates a new connection via the SCard API
func NewSCardTransport(name string) (Transport, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, errors.Wrap(err, "Establishing context")
	}

	defer func() {
		if ctx != nil {
			multierr.Append(err, ctx.Release())
		}
	}()

	if len(name) == 0 {
		var rdrs []string
		rdrs, err := ctx.ListReaders()
		if err != nil {
			return nil, errors.Wrap(err, "Getting reader list")
		}

		switch len(rdrs) {
		case 0:
			return nil, errors.New("No reader connected")
		case 1:
			name = rdrs[0]
		default:
			msg := "Multiple readers connected - please specify one of"
			for _, n := range rdrs {
				msg = msg + "\n * '" + n + "'"
			}
			return nil, errors.New(msg)
		}
	}

	card, err := ctx.Connect(name, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return nil, errors.Wrap(err, "Connecting to reader")
	}

	transport := &scardTransport{
		m:   sync.Mutex{},
		c:   card,
		ctx: ctx,
	}

	ctx = nil

	return transport, nil
}

func (self *scardTransport) Lock() error {
	self.m.Lock()
	err := self.c.BeginTransaction()
	if err != nil {
		self.m.Unlock()
	}
	return err
}

func (self *scardTransport) Unlock() error {
	defer self.m.Unlock()
	return self.c.EndTransaction(scard.LeaveCard)
}
func (self *scardTransport) Transact(req ReqAPDU) (RespAPDU, error) {
	buf, err := req.Serialize()
	if err != nil {
		return RespAPDU{}, errors.Wrap(err, "Serializing APDU")
	}

	resp, err := self.c.Transmit(buf)
	if err != nil {
		return RespAPDU{}, errors.Wrap(err, "Talking to SCard")
	}

	return ParseRespAPDU(resp)
}

func init() {
	RegisterTransport("scard", NewSCardTransport)
}
