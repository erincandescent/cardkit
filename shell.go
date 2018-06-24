package dshl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/fatih/color"
	"github.com/mattn/go-shellwords"
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
}

type Shell struct {
	lin *liner.State

	commands []*cmdReg
}

func New() *Shell {
	lin := liner.NewLiner()
	lin.SetMultiLineMode(true)
	lin.SetTabCompletionStyle(liner.TabPrints)
	return &Shell{lin: lin}
}

func (sh *Shell) AddCommand(cmd Command) {
	sh.commands = append(sh.commands, &cmdReg{cmd.CommandInfo(), cmd})
}

func (sh *Shell) Run(ctx context.Context) error {
	var lasterr error
	for {
		line, err := sh.lin.Prompt("> ")
		if err != nil {
			if err == liner.ErrPromptAborted {
				continue
			}
			if err == io.EOF {
				break
			}
			return err
		}

		lasterr = sh.Eval(ctx, line)
		if lasterr != nil {
			ErrorColor.Fprintln(os.Stderr, lasterr.Error())
		}
	}

	return nil
}

func (sh *Shell) Parse(line string) (string, []string, error) {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return "", nil, nil
	}

	words, err := shellwords.Parse(line)
	if err != nil {
		return "", nil, err
	}
	return words[0], words[1:], nil
}

func (sh *Shell) Lookup(cmdName string) Command {
	for _, cmd := range sh.commands {
		if cmd.info.Name == cmdName {
			return cmd.cmd
		}
	}
	return nil
}

func (sh *Shell) Eval(ctx context.Context, line string) error {
	cmdName, args, err := sh.Parse(line)
	if err != nil {
		return err
	}
	return sh.Exec(ctx, cmdName, args...)
}

func (sh *Shell) Exec(ctx context.Context, cmdName string, args ...string) error {
	cmd := sh.Lookup(cmdName)
	if cmd == nil {
		return errors.Errorf("command not found: %s", cmdName)
	}

	retval, reterr := cmd.Call(ctx, args)

	switch v := retval.(type) {
	case nil:
	case string:
		fmt.Println(v)
	default:
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			reterr = multierr.Append(reterr, err)
		}
		var buf bytes.Buffer
		if err := quick.Highlight(&buf, string(data), "json", "tty", "default"); err != nil {
			reterr = multierr.Append(reterr, err)
		}
		fmt.Println(buf.String())
	}

	return reterr
}
