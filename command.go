package dshl

import (
	"context"
)

type CommandInfo struct {
	Name string
}

type Command interface {
	// Returns a CommandInfo struct describing this command.
	CommandInfo() CommandInfo

	// Invokes the command. Returns a return value (if any), which will be printed.
	// In the future, it will be possible to assign return values to variables.
	Call(ctx context.Context, args []string) (interface{}, error)
}
