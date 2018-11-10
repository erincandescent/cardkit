package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/dshl"
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
	sh.Scope.PS1 = dshl.NewPS1("ck> ", "! ck> ")
	sh.AddCommand(pivCmd)
	sh.AddCommand(rawCmd)

	if len(pflag.Args()) > 1 {
		sh.Exec(ctx, pflag.Args())
	} else {
		sh.Run(ctx)
	}
}
