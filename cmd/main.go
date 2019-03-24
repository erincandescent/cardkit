package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/dshl"
	"github.com/erincandescent/cardkit/transport"
	"github.com/spf13/pflag"
)

/*

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

*/
func MainCmd() {
	ctx := context.Background()

	pflag.SetInterspersed(false)
	transportPath := pflag.String("transport", "scard", "SmartCard transport")
	pflag.Parse()

	t, err := transport.New(*transportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating smart card transport:", err)
		os.Exit(1)
	}

	tinfo := t.Info()
	fmt.Printf("Using transport '%s' (%s)\n", tinfo.DisplayName, tinfo.ID)

	readers := t.Readers()
	if len(readers) == 0 {
		fmt.Fprintln(os.Stderr, "No reader found")
		os.Exit(1)
	} else if len(readers) > 1 {
		fmt.Printf("%d readers found: \n", len(readers))
		for _, v := range readers {
			state := "empty"
			if v.CardInserted {
				state = "card inserted"
			}

			fmt.Printf(" - %s (%s)\n", v.ID, state)
		}
	}

	fmt.Printf("Using reader '%s'\n", readers[0].ID)
	c, err := t.ConnectCard(readers[0].ID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error connecting to reader: ", err)
		os.Exit(1)
	}

	ctx = withCardTransport(ctx, &cardTransport{
		T: t,
		C: &card.Card{c},
	})

	sh := dshl.New()
	sh.Scope.PS1 = dshl.NewPS1("ck> ", "! ck> ")
	sh.AddCommand(readerCmd)
	sh.AddCommand(openpgpCmd)
	sh.AddCommand(pivCmd)
	sh.AddCommand(rawCmd)

	if len(pflag.Args()) > 1 {
		sh.Exec(ctx, pflag.Args())
	} else {
		sh.Run(ctx)
	}
}
