package cmd

import (
	"context"
	"encoding/hex"
	"strconv"

	"github.com/erincandescent/cardkit/dshl"
	"github.com/pkg/errors"
)

var rawCmd *simpleCommand

func rawSelectDFCmd(ctx context.Context, args []string) (interface{}, error) {
	if len(args) != 1 {
		return nil, errors.New("Usage: selectdf <DF name>")
	}

	path, err := hex.DecodeString(args[0])
	if err != nil {
		return nil, err
	}

	res, err := getCard(ctx).SelectDF(path)
	if err != nil {
		return nil, err
	}

	return hex.EncodeToString(res), nil
}

func rawVerifyCmd(ctx context.Context, args []string) (interface{}, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, errors.New("Usage: verify <PIN ID> [PIN]")
	}

	pin_id, err := strconv.ParseUint(args[0], 16, 8)
	if err != nil {
		return nil, errors.Wrap(err, "Parsing pin ID")
	}

	var pin string
	if len(args) >= 2 {
		pin = args[1]
	} else {
		pin, err = dshl.GetShell(ctx).PasswordPrompt("PIN")
		if err != nil {
			return nil, err
		}
	}

	return nil, getCard(ctx).Verify(byte(pin_id), []byte(pin))
}

func rawApduCmd(ctx context.Context, args []string) (interface{}, error) {
	//cla, ins, p1, p2 byte, data []byte, le uint

	var err error
	var cla, ins, p1, p2 uint64
	var data []byte

	switch len(args) {
	case 5:
		data, err = hex.DecodeString(args[4])
		if err != nil {
			return nil, errors.Wrap(err, "Parsing data")
		}
		fallthrough
	case 4:
		p2, err = strconv.ParseUint(args[3], 16, 8)
		if err != nil {
			return nil, errors.Wrap(err, "Parsing P2")
		}

		p1, err = strconv.ParseUint(args[2], 16, 8)
		if err != nil {
			return nil, errors.Wrap(err, "Parsing P1")
		}

		ins, err = strconv.ParseUint(args[1], 16, 8)
		if err != nil {
			return nil, errors.Wrap(err, "Parsing INS")
		}

		cla, err = strconv.ParseUint(args[0], 16, 8)
		if err != nil {
			return nil, errors.Wrap(err, "Parsing CLA")
		}

	default:
		return nil, errors.New("Usage: apdu <cla> <ins> <p1> <p2> [data]")
	}

	res, err := getCard(ctx).Command(byte(cla), byte(ins), byte(p1), byte(p2), data, 256)
	if err != nil {
		return nil, err
	}
	return hex.EncodeToString(res), nil
}

func init() {
	rawCmd = newSimpleCommand(dshl.CommandInfo{
		Name:  "raw",
		Short: "Raw command interaction tools",
	}, func(ctx context.Context, args []string) (interface{}, error) {
		sh := dshl.GetShell(ctx)
		scope := sh.PushScope()
		scope.PS1 = dshl.NewPS1("raw> ", "! raw> ")
		scope.Modal = true
		for _, c := range rawCmd.info.Subcommands {
			sh.AddCommand(c)
		}

		if len(args) > 0 {
			defer sh.PopScope(scope)
			return sh.Exec(ctx, args)
		}
		return nil, nil
	})

	rawCmd.addSubcommands(
		newSimpleCommand(dshl.CommandInfo{Name: "selectdf"}, rawSelectDFCmd),
		newSimpleCommand(dshl.CommandInfo{Name: "verify"}, rawVerifyCmd),
		newSimpleCommand(dshl.CommandInfo{Name: "apdu"}, rawApduCmd),
	)
}
