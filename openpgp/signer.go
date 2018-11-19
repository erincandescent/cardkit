package openpgp

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/rsapad"
)

type cardSigner struct {
	card   *card.Card
	pubKey crypto.PublicKey
	key    Key
	prompt func(c *card.Card) error
}

// NewSigner creates a signer which is backed by the card
//
// pubKey is the public key of the key that will be used for signing
// key is the key slot of said key
// prompt will be called if an authentication required error is returned
// and may be used to prompt the cardholder for a PIN
func NewSigner(
	card *card.Card,
	pubKey crypto.PublicKey,
	key Key,
	prompt func(c *card.Card) error,
) crypto.Signer {
	return &cardSigner{
		card:   card,
		pubKey: pubKey,
		key:    key,
		prompt: prompt,
	}
}

// Public returns the underlying public key
func (cs *cardSigner) Public() crypto.PublicKey {
	return cs.pubKey
}

// Sign signs digest using the card
func (cs *cardSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if _, ok := cs.pubKey.(*rsa.PublicKey); ok {
		if _, ok := opts.(*rsa.PSSOptions); ok {
			return nil, errors.New("OpenPGP Card does not support PSS padding")
		} else {
			digest, err = rsapad.DigestInfoWrap(opts.HashFunc(), digest)
		}
		if err != nil {
			return nil, err
		}
	}

	for {
		var buf []byte
		var err error

		switch cs.key {
		case SigKey:
			buf, err = ComputeDigitalSignature(cs.card, digest)
		default:
			err = errors.New("Invalid key")
		}

		switch {
		case card.IsLoginRequired(err):
			if cs.prompt != nil {
				err = cs.prompt(cs.card)
			}

			if err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		default:
			return buf, nil
		}
	}
}
