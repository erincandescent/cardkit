package dshl

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

var _ Command = HelpCommand{}

type HelpCommand struct {
}

func (c HelpCommand) CommandInfo() CommandInfo {
	return CommandInfo{
		Name:  "help",
		Args:  "[command]",
		Short: "Display help",
		Long:  "Display help for the shell or a specific command.",
	}
}

func (c HelpCommand) Flags() *pflag.FlagSet {
	return nil
}

func (c HelpCommand) Call(ctx context.Context, flags *pflag.FlagSet, args Args) (interface{}, error) {
	if len(args) == 0 {
		c.ShowIndex(ctx)
		return nil, nil
	}
	return nil, c.ShowCommand(ctx, args)
}

func (c HelpCommand) ShowIndex(ctx context.Context) {
	sh := GetShell(ctx)
	fmt.Fprintf(os.Stderr, "Available commands:\n")
	fmt.Fprintf(os.Stderr, "\n")

	cmdMaxWidth := 0
	cmdNames := make([]string, len(sh.commands))
	cmds := make(map[string]*cmdReg, len(cmdNames))
	for i, cmd := range sh.commands {
		name := cmd.info.Name
		if len(name) > cmdMaxWidth {
			cmdMaxWidth = len(name)
		}
		cmdNames[i] = name
		cmds[name] = cmd
	}
	sort.Strings(cmdNames)
	for _, cmdName := range cmdNames {
		cmd := cmds[cmdName]
		fmt.Fprintf(os.Stderr, "  % -*s   %s\n", cmdMaxWidth, cmd.info.Name, cmd.info.Short)
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Try: help [command] for more information\n")
}

func (c HelpCommand) ShowCommand(ctx context.Context, args Args) error {
	sh := GetShell(ctx)
	argStrs := args.Strings()
	cmd, _ := sh.Lookup([]string(argStrs))
	if cmd == nil {
		return errors.Errorf("not found: %s", strings.Join([]string(argStrs), " "))
	}
	info := cmd.CommandInfo()
	flags := cmd.Flags()
	if flags == nil {
		flags = pflag.NewFlagSet(info.Name, 0)
	}
	fmt.Fprintf(os.Stderr, "Usage: %s %s\n", info.Name, info.Args)
	if info.Long != "" {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "%s\n", info.Long)
	}
	if flagUsages := flags.FlagUsages(); flagUsages != "" {
		fmt.Fprintf(os.Stderr, "\n")
		flags.PrintDefaults()
	}
	return nil
}
