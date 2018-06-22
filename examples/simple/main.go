package main

import (
	"context"
	"fmt"
	"os"

	"github.com/liclac/dshl"
)

type helloWorldCommand struct{}

func (helloWorldCommand) CommandInfo() dshl.CommandInfo {
	return dshl.CommandInfo{
		Name: "hello",
	}
}

func (helloWorldCommand) Call(ctx context.Context, args []string) (interface{}, error) {
	who := "World"
	if len(args) > 0 {
		who = args[0]
	}
	return "Hello, " + who, nil
}

func main() {
	sh := dshl.New()
	sh.AddCommand(&helloWorldCommand{})

	if err := sh.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "=> ERROR: %s\n", err)
		os.Exit(1)
	}
}
