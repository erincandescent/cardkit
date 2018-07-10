package cmd

import (
	"context"

	"github.com/liclac/dshl"
	"github.com/spf13/pflag"
)

type simpleCommand struct {
	info dshl.CommandInfo
	fn   func(context.Context, []string) (interface{}, error)
}

func newSimpleCommand(
	name string,
	fn func(context.Context, []string) (interface{}, error)) *simpleCommand {

	return &simpleCommand{dshl.CommandInfo{Name: name}, fn}
}

func (c *simpleCommand) addSubcommands(cmd ...dshl.Command) {
	c.info.Subcommands = append(c.info.Subcommands, cmd...)
}

func (c *simpleCommand) CommandInfo() dshl.CommandInfo {
	return c.info
}

func (c *simpleCommand) Flags() *pflag.FlagSet {
	return nil
}

func (c *simpleCommand) Call(ctx context.Context, _ *pflag.FlagSet, args []string) (interface{}, error) {
	return c.fn(ctx, args)
}
