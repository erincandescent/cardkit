package transport

import (
	"context"
	"sync"
	"time"

	"github.com/ebfe/scard"
	"github.com/pkg/errors"
)

type scardTransport struct {
	// The smartcard context itself
	ctx *scard.Context

	// Lock around [ctx], the scard context
	// Before performing any commands,
	// * This lock must be held, and
	// * polling must be false
	// * you must have incremented acquirers
	ctxLock *sync.Mutex

	// Signalled each time the poller releases use of the context (i.e. polling
	// becomes false)
	ctxCond *sync.Cond

	// Signalled each time the context is about to go idle (i.e. acquirers
	// becomes 0), to permit the poller to start
	ctxRelCond *sync.Cond

	// polling is set whenever the poller is polling the context for status
	// changes. If this is set, even if you have acquired ctxLock, you must not
	// call the scard API
	polling bool

	// acquirers is incremented whenever a client wants to use the context
	acquirers int

	// Last state of the readers as determined by the poller and signalled to
	// the listeners. Hold [listenerLock] before reading this
	state []ReaderState

	// Lock over the listeners and state maps. Held whenever invoking reader
	// state change callbacks
	listenerLock *sync.Mutex

	// Signalled each time [state] changes. Use this to poll for reader changes
	listenerCond *sync.Cond

	// Registered reader state change listeners
	listeners map[context.Context]OnReaderStateChange
}

func NewSCardTransport(params string) (Transport, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, errors.Wrap(err, "Establishing context")
	}

	tr := &scardTransport{
		ctx:       ctx,
		listeners: make(map[context.Context]OnReaderStateChange),
	}
	tr.ctxLock = new(sync.Mutex)
	tr.ctxCond = sync.NewCond(tr.ctxLock)
	tr.ctxRelCond = sync.NewCond(tr.ctxLock)
	tr.listenerLock = new(sync.Mutex)
	tr.listenerCond = sync.NewCond(tr.listenerLock)

	// Before returning, ensure that the poller runs at least once so that the
	// caller can get a list of readers
	tr.listenerLock.Lock()
	defer tr.listenerLock.Unlock()
	go tr.pollState()
	tr.listenerCond.Wait()

	return tr, nil
}

// Acquire the transport. This means that "polling" will be false and you can
// invoke methods on [t.ctx]. You must first hold [t.ctxLock], and balance this
// with a call to [t.release]
func (t *scardTransport) acquire() error {
	t.acquirers++

	for t.polling {
		err := t.ctx.Cancel()
		if err != nil {
			t.acquirers--
			return err
		}
		t.ctxCond.Wait()
	}
	return nil
}

// Release the transport - this means that somebody else (including the poller)
// may use it
func (t *scardTransport) release() {
	t.acquirers--
	if t.acquirers == 0 {
		t.ctxRelCond.Signal()
	}
}

// Lock the transport and ensure the background poller is not operating.
// Locks [ctxLock] then calls [acquire]
func (t *scardTransport) acquireLock() error {
	t.ctxLock.Lock()
	if err := t.acquire(); err != nil {
		t.ctxLock.Unlock()
		return err
	}
	return nil
}

// Release the transport (to the poller/another user) then unlock [ctxLock]
func (t *scardTransport) releaseUnlock() {
	t.release()
	t.ctxLock.Unlock()
}

// Backgroudn poller - Blocks inside scard until state changes, or a
// cancellation occurs (in which case it will release the context until free)
func (t *scardTransport) pollState() {
	t.ctxLock.Lock()
	var oldReaderStates []scard.ReaderState
	for {
		rdrs, err := t.ctx.ListReaders()
		if err != nil {
			panic(err)
		}

		readerStates := make([]scard.ReaderState, len(rdrs)+1)
		for i, rdr := range rdrs {
			readerStates[i].Reader = rdr
			for _, v := range oldReaderStates {
				if v.Reader == rdr {
					readerStates[i] = v
					readerStates[i].CurrentState = v.EventState
					break
				}
			}
		}
		readerStates[len(rdrs)] = scard.ReaderState{
			Reader: "\\\\?PnP?\\Notification",
		}

		for t.acquirers > 0 {
			t.ctxRelCond.Wait()
		}
		t.polling = true
		t.ctxLock.Unlock()

		err = t.ctx.GetStatusChange(readerStates, time.Minute)
		switch err {
		case nil:
		case scard.ErrCancelled, scard.ErrTimeout:
			t.ctxLock.Lock()
			t.polling = false
			t.ctxCond.Signal()
			continue
		default:
			panic(err)
		}

		t.ctxLock.Lock()
		t.polling = false
		t.ctxLock.Unlock()

		oldReaderStates = readerStates
		state := make([]ReaderState, 0, len(readerStates))
		for _, rdr := range readerStates {
			if (rdr.EventState&scard.StateUnavailable) != 0 ||
				rdr.Reader == "\\\\?PnP?\\Notification" {
				continue
			}

			state = append(state, ReaderState{
				ID:           rdr.Reader,
				CardInserted: (rdr.EventState & scard.StatePresent) != 0,
				ATR:          rdr.Atr,
			})
		}

		t.listenerLock.Lock()
		t.state = state
		t.listenerCond.Signal()

		for ctx, l := range t.listeners {
			go l(ctx, state)
		}
		t.listenerLock.Unlock()
		t.ctxLock.Lock()
	}
}

func (t *scardTransport) Info() TransportInfo {
	return TransportInfo{
		ID:          "scard",
		DisplayName: "SCard",
	}
}

func (t *scardTransport) Readers() []ReaderState {
	t.listenerLock.Lock()
	defer t.listenerLock.Unlock()
	return t.state
}

func (t *scardTransport) OnReaderStateChange(ctx context.Context, cb OnReaderStateChange) {
	t.listenerLock.Lock()
	st := t.state
	t.listeners[ctx] = cb
	cb(ctx, st)

	go func() {
		select {
		case <-ctx.Done():
			t.listenerLock.Lock()
			delete(t.listeners, ctx)
			t.listenerLock.Unlock()
		}
	}()

	t.listenerLock.Unlock()
}

func (t *scardTransport) ConnectCard(ID string) (Card, error) {
	if err := t.acquireLock(); err != nil {
		return nil, err
	}
	defer t.releaseUnlock()

	card, err := t.ctx.Connect(ID, scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		return nil, errors.Wrap(err, "Connecting to reader")
	}

	return &scardCard{
		t:      t,
		m:      sync.Mutex{},
		locked: false,
		c:      card,
	}, nil
}

func (t *scardTransport) Close() {

}

type scardCard struct {
	t      *scardTransport
	m      sync.Mutex
	locked bool
	c      *scard.Card
}

func (self *scardCard) Lock() error {
	self.m.Lock()
	defer self.m.Unlock()

	if err := self.t.acquireLock(); err != nil {
		return err
	}

	if err := self.c.BeginTransaction(); err != nil {
		self.t.releaseUnlock()
		return err
	}

	self.locked = true
	return nil
}

func (self *scardCard) Unlock() error {
	self.m.Lock()
	defer self.m.Unlock()
	defer self.t.releaseUnlock()
	self.locked = false

	return self.c.EndTransaction(scard.LeaveCard)
}

func (self *scardCard) transact(buf []byte) ([]byte, error) {
	self.m.Lock()
	defer self.m.Unlock()

	if !self.locked {
		if err := self.t.acquireLock(); err != nil {
			return nil, err
		}
		defer self.t.releaseUnlock()
	}

	return self.c.Transmit(buf)
}

func (self *scardCard) Transact(req ReqAPDU) (RespAPDU, error) {
	buf, err := req.Serialize()
	if err != nil {
		return RespAPDU{}, errors.Wrap(err, "Serializing APDU")
	}

	resp, err := self.transact(buf)

	if err != nil {
		return RespAPDU{}, errors.Wrap(err, "Talking to SCard")
	}

	return ParseRespAPDU(resp)
}

func (self *scardCard) Close() error {
	if err := self.t.acquireLock(); err != nil {
		return err
	}
	defer self.t.releaseUnlock()
	return self.c.Disconnect(scard.LeaveCard)
}

func init() {
	RegisterTransport("scard", NewSCardTransport)
}
