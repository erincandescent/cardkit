package dshl

import (
	"context"

	"github.com/spf13/pflag"
)

type CommandInfo struct {
	Name  string
	Args  string
	Short string
	Long  string

	Subcommands []Command
}

type Command interface {
	// Returns a CommandInfo struct describing this command.
	CommandInfo() CommandInfo

	// Returns flags for the command. If nil, arguments are passed verbatim.
	Flags() *pflag.FlagSet

	// Invokes the command. Returns a return value (if any), which will be printed.
	// In the future, it will be possible to assign return values to variables.
	Call(ctx context.Context, flags *pflag.FlagSet, args Args) (interface{}, error)
}
