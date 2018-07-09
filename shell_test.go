package dshl

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

type testCmd struct {
	info  CommandInfo
	flags *pflag.FlagSet
	fn    func(context.Context, *pflag.FlagSet, []Value) (interface{}, error)
}

func (cmd *testCmd) CommandInfo() CommandInfo {
	return cmd.info
}

func (cmd *testCmd) Flags() *pflag.FlagSet {
	return cmd.flags
}

func (cmd *testCmd) Call(ctx context.Context, flags *pflag.FlagSet, args []Value) (interface{}, error) {
	return cmd.fn(ctx, flags, args)
}

func TestShellEval(t *testing.T) {
	sh := New()
	sh.AddCommand(&testCmd{
		info: CommandInfo{
			Name: "test",
			Subcommands: []Command{
				&testCmd{
					info: CommandInfo{Name: "sub"},
					fn: func(ctx context.Context, flags *pflag.FlagSet, args []Value) (interface{}, error) {
						if len(args) == 1 {
							return args[0].String(ctx), nil
						}
						return nil, errors.Errorf("wrong number of args: %d", len(args))
					},
				},
			},
		},
		fn: func(ctx context.Context, flags *pflag.FlagSet, args []Value) (interface{}, error) {
			out := make([]string, len(args))
			for i, arg := range args {
				out[i] = arg.String(ctx)
			}
			return args, nil
		},
	})
	sh.AddCommand(&testCmd{
		info: CommandInfo{Name: "flag"},
		flags: func() (flags *pflag.FlagSet) {
			flags = pflag.NewFlagSet("", 0)
			flags.IntP("val", "v", 0, "int flag")
			return
		}(),
		fn: func(ctx context.Context, flags *pflag.FlagSet, args []Value) (interface{}, error) {
			return flags.GetInt("val")
		},
	})

	t.Run("Top-level", func(t *testing.T) {
		v, err := sh.Eval(context.Background(), `test`)
		assert.NoError(t, err)
		assert.Equal(t, []string{}, v)

		t.Run("Arg", func(t *testing.T) {
			v, err := sh.Eval(context.Background(), `test hi`)
			assert.NoError(t, err)
			assert.Equal(t, []string{"hi"}, v)
		})

		t.Run("Args", func(t *testing.T) {
			v, err := sh.Eval(context.Background(), `test hi bye`)
			assert.NoError(t, err)
			assert.Equal(t, []string{"hi", "bye"}, v)
		})
	})

	t.Run("Subcommand", func(t *testing.T) {
		_, err := sh.Eval(context.Background(), `test sub`)
		assert.EqualError(t, err, "wrong number of args: 0")

		t.Run("Arg", func(t *testing.T) {
			v, err := sh.Eval(context.Background(), `test sub hi`)
			assert.NoError(t, err)
			assert.Equal(t, "hi", v)
		})

		t.Run("Args", func(t *testing.T) {
			_, err := sh.Eval(context.Background(), `test sub hi bye`)
			assert.EqualError(t, err, "wrong number of args: 2")
		})
	})

	t.Run("Flags", func(t *testing.T) {
		v, err := sh.Eval(context.Background(), `flag --val=123`)
		assert.NoError(t, err)
		assert.Equal(t, 123, v)

		t.Run("Invalid Value", func(t *testing.T) {
			_, err := sh.Eval(context.Background(), `flag --val=h`)
			assert.EqualError(t, err, "invalid argument \"h\" for \"-v, --val\" flag: strconv.ParseInt: parsing \"h\": invalid syntax")
		})

		t.Run("Invalid Flag", func(t *testing.T) {
			_, err := sh.Eval(context.Background(), `flag --uwu=123`)
			assert.EqualError(t, err, "unknown flag: --uwu")
		})
	})

	t.Run("Empty", func(t *testing.T) {
		v, err := sh.Eval(context.Background(), ``)
		assert.Nil(t, v)
		assert.NoError(t, err)
	})

	t.Run("Not Found", func(t *testing.T) {
		_, err := sh.Eval(context.Background(), `weh`)
		assert.EqualError(t, err, "command not found: weh")
	})

	t.Run("Unparseable", func(t *testing.T) {
		_, err := sh.Eval(context.Background(), `"`)
		assert.EqualError(t, err, "invalid command line string")
	})
}
