package card

import (
	"encoding/hex"
	"net"
	"os/user"
	"path"
	"sync"

	"github.com/foxcpp/go-assuan/client"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

type scDaemonTransport struct {
	m sync.Mutex
	s *client.Session
}

var _ Transport = &scDaemonTransport{}

// NewSCDaemonTransport creates a smartcard connection
// via GNUPG's SCDaemon service
func NewSCDaemonTransport(socket string) (Transport, error) {
	if len(socket) == 0 {
		u, err := user.Current()
		if err != nil {
			return nil, err
		}

		socket = path.Join(u.HomeDir, ".gnupg", "S.scdaemon")
	}

	pipe, err := net.Dial("unix", socket)
	if err != nil {
		return nil, err
	}

	sess, err := client.Init(pipe)
	if err != nil {
		return nil, err
	}

	return &scDaemonTransport{s: sess}, nil
}

func (self *scDaemonTransport) Lock() error {
	self.m.Lock()
	// Lock connection to prevent contention from other
	// users
	_, err := self.s.SimpleCmd("LOCK", "--wait")
	return err
}

func (self *scDaemonTransport) Unlock() (errs error) {
	// Reset SCDaemon's internal state
	// This informs it that its' internal state may be out
	// of sync wth the card's, which is likely because we have
	// been issuing our own APDUs
	_, err := self.s.SimpleCmd("RESET", "")
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	// Release to allow others to use
	_, err = self.s.SimpleCmd("UNLOCK", "")
	if err != nil {
		errs = multierr.Append(errs, err)
	}

	self.m.Unlock()

	return errs
}
func (self *scDaemonTransport) Transact(req ReqAPDU) (RespAPDU, error) {
	buf, err := req.Serialize()
	if err != nil {
		return RespAPDU{}, errors.Wrap(err, "Serializing APDU")
	}

	resp, err := self.s.SimpleCmd("APDU", hex.EncodeToString(buf))
	if err != nil {
		return RespAPDU{}, errors.Wrap(err, "Talking to SCDaemon")
	}

	return ParseRespAPDU(resp)
}

func init() {
	RegisterTransport("scdaemon", NewSCDaemonTransport)
}
