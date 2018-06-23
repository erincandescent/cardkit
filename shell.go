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

		lasterr = sh.Exec(ctx, line)
		if lasterr != nil {
			ErrorColor.Fprintln(os.Stderr, lasterr.Error())
		}
	}

	return nil
}

func (sh *Shell) Parse(line string) (Command, []string, error) {
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return nil, nil, nil
	}

	words, err := shellwords.Parse(line)
	if err != nil {
		return nil, nil, err
	}
	cmdName := words[0]
	args := words[1:]

	for _, cmd := range sh.commands {
		if cmd.info.Name == cmdName {
			return cmd.cmd, args, nil
		}
	}
	return nil, nil, errors.Errorf("unrecognised command: %s", cmdName)
}

func (sh *Shell) Eval(ctx context.Context, line string) (interface{}, error) {
	cmd, args, err := sh.Parse(line)
	if err != nil {
		return nil, err
	}
	if cmd == nil {
		return nil, nil
	}

	return cmd.Call(ctx, args)
}

func (sh *Shell) Exec(ctx context.Context, line string) error {
	retval, err := sh.Eval(ctx, line)
	if err != nil {
		return err
	}

	switch v := retval.(type) {
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
