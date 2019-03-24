package cmd

import (
	"context"
	"fmt"

	"github.com/erincandescent/cardkit/dshl"
	"github.com/pkg/errors"
)

var readerCmd *simpleCommand

func readerCmdF(ctx context.Context, args []string) (interface{}, error) {
	ct := getCardTransport(ctx)

	switch len(args) {
	case 0:
		readers := ct.T.Readers()
		fmt.Printf("%d available readers: \n", len(readers))
		for _, v := range readers {
			fmt.Printf(" * '%s'\n", v.ID)
		}
		return nil, nil

	case 1:
		c, err := ct.T.ConnectCard(args[0])
		if err != nil {
			return nil, err
		}

		err = ct.C.C.Close()
		ct.C.C = c
		return nil, err

	default:
		return nil, errors.New("reader requires only 1 argument")
	}
}

func init() {
	readerCmd = newSimpleCommand(dshl.CommandInfo{
		Name:  "reader",
		Short: "Change reader",
	}, readerCmdF)
}
