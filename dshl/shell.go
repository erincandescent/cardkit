package dshl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alecthomas/chroma/quick"
	"github.com/fatih/color"
	"github.com/peterh/liner"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

var (
	ErrorColor = color.New(color.FgRed, color.Bold)
)

type Shell struct {
	liner *liner.State
	Scope *Scope
}

func New() *Shell {
	sh := &Shell{Scope: &Scope{PS1: DefaultPS1}}
	sh.Scope.Set("help", HelpCommand{})
	return sh
}

func (sh *Shell) Run(ctx context.Context) (rerr error) {
	if sh.liner == nil {
		sh.liner = liner.NewLiner()
		sh.liner.SetMultiLineMode(true)
		sh.liner.SetTabCompletionStyle(liner.TabPrints)
		defer func() { rerr = multierr.Append(rerr, sh.liner.Close()) }()
	}

	var lasterr error
	for {
		line, err := sh.Prompt(sh.Scope.PS1(lasterr))
		if err != nil {
			if err == liner.ErrPromptAborted {
				continue
			}
			if err == io.EOF {
				fmt.Println("")

				// Find a Modal scope to pop, if any.
				scope := sh.Scope
				var modalScope *Scope
				for scope != nil {
					if scope.Modal {
						modalScope = scope
						break
					}
					scope = scope.Parent
				}
				if modalScope != nil {
					sh.PopScope(modalScope)
					continue
				}
				break
			}
			return err
		}

		var v interface{}
		v, lasterr = sh.Eval(ctx, line)
		sh.DumpError(sh.Dump(v))
		sh.DumpError(lasterr)
	}

	return nil
}

func (sh *Shell) AddCommand(cmd Command) {
	sh.Scope.Set(cmd.CommandInfo().Name, cmd)
}

func (sh *Shell) PushScope() *Scope {
	sh.Scope = sh.Scope.Child()
	return sh.Scope
}

func (sh *Shell) PopScope(s *Scope) *Scope {
	sh.Scope = s.Parent
	return sh.Scope
}

func (sh *Shell) Prompt(ps1 string) (string, error) {
	return sh.liner.Prompt(ps1)
}

func (sh *Shell) PasswordPrompt(ps1 string) (string, error) {
	return sh.liner.PasswordPrompt(ps1)
}

func (sh *Shell) Lookup(args []string) (Command, []string, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	cmdName := args[0]
	v := sh.Scope.Get(cmdName)
	if v == nil {
		return nil, nil, nil
	}
	cmd, ok := v.(Command)
	if !ok {
		return nil, nil, errors.Errorf("%s is not callable (%t)", cmdName, v)
	}
	return sh.lookupSubcommand(cmd, args[1:])
}

func (sh *Shell) lookupSubcommand(cmd Command, args []string) (Command, []string, error) {
	if len(args) == 0 {
		return cmd, args, nil
	}
	info := cmd.CommandInfo()
	for _, sub := range info.Subcommands {
		if args[0] == sub.CommandInfo().Name {
			return sh.lookupSubcommand(sub, args[1:])
		}
	}
	return cmd, args, nil
}

func (sh *Shell) Eval(ctx context.Context, line string) (interface{}, error) {
	args, err := SplitWords(line)
	if err != nil {
		return nil, err
	}
	return sh.Exec(ctx, args)
}

func (sh *Shell) Exec(ctx context.Context, words []string) (interface{}, error) {
	if len(words) == 0 {
		return nil, nil
	}

	cmd, rest, err := sh.Lookup(words)
	if err != nil {
		return nil, err
	}
	if cmd == nil {
		return nil, errors.Errorf("command not found: %s", words[0])
	}

	return sh.Call(ctx, cmd, rest)
}

func (sh *Shell) Call(ctx context.Context, cmd Command, args []string) (interface{}, error) {
	ctx = WithShell(ctx, sh)

	flags := cmd.Flags()
	if flags != nil {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		args = flags.Args()
	}

	values := make(Args, len(args))
	for i, arg := range args {
		values[i] = Wrap(arg)
	}
	return cmd.Call(ctx, flags, values)
}

func (sh *Shell) Dump(retval interface{}) error {
	switch v := retval.(type) {
	case nil:
	case string:
		fmt.Println(v)
	default:
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		if err := quick.Highlight(&buf, string(data), "json", "tty", "default"); err != nil {
			return err
		}
		fmt.Println(buf.String())
	}
	return nil
}

func (sh *Shell) DumpError(err error) {
	if err != nil {
		ErrorColor.Fprintln(os.Stderr, err.Error())
	}
}
