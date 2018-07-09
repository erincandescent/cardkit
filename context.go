package dshl

import "context"

type ctxKey string

const (
	ctxKeyShell ctxKey = "shell"
)

// Attaches a Shell to a context. This is done automatically in command handlers invoked from
// Shell.Run, Shell.Eval, Shell.Exec or Shell.Call.
func WithShell(ctx context.Context, sh *Shell) context.Context {
	return context.WithValue(ctx, ctxKeyShell, sh)
}

// Returns the current shell. This is always available inside command handlers, or if you've previously called WithShell.
func GetShell(ctx context.Context) *Shell {
	sh, _ := ctx.Value(ctxKeyShell).(*Shell)
	return sh
}
