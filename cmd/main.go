package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/erincandescent/cardkit/card"
	"github.com/liclac/dshl"
	"github.com/spf13/pflag"
)

func MainCmd() {
	pflag.SetInterspersed(false)
	transportPath := pflag.String("transport", "scdaemon", "SmartCard transport")
	pflag.Parse()

	card, err := card.New(*transportPath)
	if err != nil {
		fmt.Fprint(os.Stderr, "Error creating smart card transport:", err)
		os.Exit(1)
	}
	card.Lock()
	defer card.Unlock()

	ctx := context.Background()
	ctx = withCard(ctx, card)

	sh := dshl.New()
	sh.PS1 = dshl.NewPS1("ck> ", "! ck> ")
	sh.AddCommand(pivCmd)

	if len(os.Args) > 1 {
		sh.Exec(ctx, os.Args[1:])
	} else {
		sh.Run(ctx)
	}
}
