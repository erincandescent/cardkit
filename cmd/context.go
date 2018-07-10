package cmd

import (
	"context"

	"github.com/erincandescent/cardkit/card"
)

type ctxKey int

const (
	ctxKeyCard = iota
)

func withCard(ctx context.Context, card *card.Card) context.Context {
	return context.WithValue(ctx, ctxKeyCard, card)
}

func getCard(ctx context.Context) *card.Card {
	return ctx.Value(ctxKeyCard).(*card.Card)
}
