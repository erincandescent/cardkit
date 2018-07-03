package main

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/liclac/dshl"
)

type helloWorldCommand struct{}

func (helloWorldCommand) CommandInfo() dshl.CommandInfo {
	return dshl.CommandInfo{
		Name: "hello",
	}
}

func (helloWorldCommand) Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("", 0)
	flags.StringP("say", "s", "Hello", "what to say")
	return flags
}

func (helloWorldCommand) Call(ctx context.Context, flags *pflag.FlagSet, args []string) (interface{}, error) {
	who := "World"
	if len(args) > 0 {
		who = args[0]
	}
	say, err := flags.GetString("say")
	if err != nil {
		return nil, err
	}
	return say + ", " + who, nil
}

func main() {
	sh := dshl.New()
	sh.AddCommand(&helloWorldCommand{})

	if err := sh.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "=> ERROR: %s\n", err)
		os.Exit(1)
	}
}
