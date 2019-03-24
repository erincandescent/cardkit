package cmd

import (
	"context"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/transport"
)

type ctxKey int

const (
	ctxKeyCardTransport = iota
)

type cardTransport struct {
	T transport.Transport
	C *card.Card
}

func withCardTransport(ctx context.Context, ct *cardTransport) context.Context {
	return context.WithValue(ctx, ctxKeyCardTransport, ct)
}

func getCardTransport(ctx context.Context) *cardTransport {
	return ctx.Value(ctxKeyCardTransport).(*cardTransport)
}

func getCard(ctx context.Context) *card.Card {
	return getCardTransport(ctx).C
}
