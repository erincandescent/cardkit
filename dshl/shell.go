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

type cmdReg struct {
	info CommandInfo
	cmd  Command
	sub  []*cmdReg
}

func (reg *cmdReg) Matches(name string) bool {
	return reg.info.Name == name
}

func findReg(regs []*cmdReg, name string) *cmdReg {
	for _, reg := range regs {
		if reg.Matches(name) {
			return reg
		}
	}
	return nil
}

type Shell struct {
	liner    *liner.State
	commands []*cmdReg

	PS1 PS1
}

func New() *Shell {
	sh := &Shell{PS1: DefaultPS1}
	sh.AddCommand(HelpCommand{})
	return sh
}

func (sh *Shell) Subshell() *Shell {
	subsh := New()
	subsh.liner = sh.liner
	return subsh
}

func (sh *Shell) AddCommand(cmd Command) {
	sh.commands = append(sh.commands, sh.cmdReg(cmd))
}

func (sh *Shell) cmdReg(cmd Command) *cmdReg {
	reg := &cmdReg{info: cmd.CommandInfo(), cmd: cmd}
	for _, sub := range reg.info.Subcommands {
		reg.sub = append(reg.sub, sh.cmdReg(sub))
	}
	return reg
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
		line, err := sh.Prompt(sh.PS1(lasterr))
		if err != nil {
			if err == liner.ErrPromptAborted {
				continue
			}
			if err == io.EOF {
				fmt.Println("")
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

func (sh *Shell) Prompt(ps1 string) (string, error) {
	return sh.liner.Prompt(ps1)
}

func (sh *Shell) PasswordPrompt(ps1 string) (string, error) {
	return sh.liner.PasswordPrompt(ps1)
}

func (sh *Shell) Lookup(args []string) (Command, []string) {
	return sh.lookup(sh.commands, args)
}

func (sh *Shell) lookup(regs []*cmdReg, args []string) (Command, []string) {
	if len(args) == 0 {
		return nil, nil
	}

	cmdName := args[0]
	args = args[1:]
	if reg := findReg(regs, cmdName); reg != nil {
		if sub, rest := sh.lookup(reg.sub, args); sub != nil {
			return sub, rest
		}
		return reg.cmd, args
	}
	return nil, nil
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

	cmd, rest := sh.Lookup(words)
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
