package dshl

import (
	"context"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type testCmd struct {
	Info CommandInfo
	Fn   func(context.Context, []string) (interface{}, error)
}

func (cmd *testCmd) CommandInfo() CommandInfo {
	return cmd.Info
}

func (cmd *testCmd) Call(ctx context.Context, args []string) (interface{}, error) {
	return cmd.Fn(ctx, args)
}

func TestShellLookup(t *testing.T) {
	sh := New()
	sh.AddCommand(&testCmd{
		Info: CommandInfo{
			Name: "test",
			Subcommands: []Command{
				&testCmd{
					Info: CommandInfo{Name: "sub"},
					Fn: func(ctx context.Context, args []string) (interface{}, error) {
						if len(args) == 1 {
							return args[0], nil
						}
						return nil, errors.Errorf("wrong number of args: %d", len(args))
					},
				},
			},
		},
		Fn: func(ctx context.Context, args []string) (interface{}, error) {
			return args, nil
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
}
