// Package transport defines smart card transports
package transport

import (
	"context"
	"strings"

	"github.com/pkg/errors"
)

type OnReaderStateChange func(ctx context.Context, states []ReaderState)

type Transport interface {
	Info() TransportInfo
	Readers() []ReaderState
	OnReaderStateChange(ctx context.Context, cb OnReaderStateChange)
	ConnectCard(ID string) (Card, error)
	Close()
}

type TransportInfo struct {
	// ID of the transport, which can be used to construct
	// new instances
	ID string

	// DisplayName is a human readable name for the transport
	DisplayName string
}

type ReaderState struct {
	// ID of the Reader, which can be used to connect to cards
	ID string

	// CardInserted indicates that a card is present in the reader
	CardInserted bool

	// ATR is the ATR of the inserted card (if one is inserted)
	ATR []byte
}

type Card interface {
	// Lock locks the card for exclusive use.
	// You should minimize the amount of time you lock
	// cards for (as this prevents other applications
	// from using the card) but it is necessary around multiple
	// command operations
	Lock() error

	// Unlock unlocks the card
	Unlock() error

	// Transact sends a request to the card and gets a response
	Transact(ReqAPDU) (RespAPDU, error)

	// Close connection to the card
	Close() error
}

type TransportFactory func(params string) (Transport, error)

var transports map[string]TransportFactory = map[string]TransportFactory{}

// RegisterTransport registers a transport factory
func RegisterTransport(name string, factory TransportFactory) {
	transports[name] = factory
}

// New creates a transport from a description.
// If the description contains a colon, then the part
// preceding the colon is interpreted as a driver name and
// the portion following as parameters. If no colon is
// present, then the entire description is interpreted as a
// driver name
func New(descr string) (Transport, error) {
	var name, param string

	if ix := strings.Index(descr, ":"); ix != -1 {
		name = descr[:ix]
		param = descr[ix+1:]
	} else {
		name = descr
		param = ""
	}

	if factory, ok := transports[name]; ok {
		return factory(param)
	} else {
		return nil, errors.Errorf("Unable to create smart card transport with name \"%s\"", name)
	}
}
