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
		Usage: "[command]",
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
	cmdNames := []string{}
	cmds := map[string]Command{}
	for k, v := range sh.Scope.All() {
		cmd, ok := v.(Command)
		if !ok {
			continue
		}
		if len(k) > cmdMaxWidth {
			cmdMaxWidth = len(k)
		}
		cmdNames = append(cmdNames, k)
		cmds[k] = cmd
	}
	sort.Strings(cmdNames)
	for _, cmdName := range cmdNames {
		cmd := cmds[cmdName]
		info := cmd.CommandInfo()
		fmt.Fprintf(os.Stderr, "  % -*s   %s\n", cmdMaxWidth, info.Name, info.Short)
	}
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Try: help [command] for more information\n")
}

func (c HelpCommand) ShowCommand(ctx context.Context, args Args) error {
	sh := GetShell(ctx)
	argStrs := args.Strings()
	cmd, _, err := sh.Lookup([]string(argStrs))
	if err != nil {
		return err
	}
	if cmd == nil {
		return errors.Errorf("not found: %s", strings.Join([]string(argStrs), " "))
	}
	info := cmd.CommandInfo()
	flags := cmd.Flags()
	if flags == nil {
		flags = pflag.NewFlagSet(info.Name, 0)
	}
	fmt.Fprintf(os.Stderr, "Usage: %s %s\n", info.Name, info.Usage)
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
