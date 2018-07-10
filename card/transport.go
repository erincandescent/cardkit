package card

import (
	"strings"

	"github.com/pkg/errors"
)

type Transport interface {
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
}

type TransportFactory func(params string) (Transport, error)

var transports map[string]TransportFactory = map[string]TransportFactory{}

// RegisterTransport registers a transport factory
func RegisterTransport(name string, factory TransportFactory) {
	transports[name] = factory
}

// CreateTransport creates a transport from a description.
// If the description contains a colon, then the part
// preceding the colon is interpreted as a driver name and
// the portion following as parameters. If no colon is
// present, then the entire description is interpreted as a
// driver name
func CreateTransport(descr string) (Transport, error) {
	var name, param string

	if ix := strings.Index(descr, ":"); ix != -1 {
		name = descr[ix:]
		param = descr[:ix]
	} else {
		name = descr
		param = ""
	}

	if factory, ok := transports[name]; ok {
		return factory(param)
	} else {
		return nil, errors.Errorf("Unable to create smart card transport with string \"%s\"", descr)
	}
}
