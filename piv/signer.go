package piv

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/rsapad"
)

type cardSigner struct {
	card   *card.Card
	pubKey crypto.PublicKey
	key    KeyID
	alg    AlgorithmID
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
	key KeyID,
	prompt func(c *card.Card) error,
) (crypto.Signer, error) {
	alg, err := AlgorithmFromPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return &cardSigner{
		card:   card,
		pubKey: pubKey,
		key:    key,
		alg:    alg,
		prompt: prompt,
	}, nil
}

// Public returns the underlying public key
func (cs *cardSigner) Public() crypto.PublicKey {
	return cs.pubKey
}

// Sign signs digest using the card
func (cs *cardSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	algInfo := cs.alg.GetInfo()
	if algInfo.PublicKeyAlgorithm == x509.RSA {
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			digest, err = rsapad.PadPSS(rand, cs.pubKey.(*rsa.PublicKey), pss.HashFunc(), digest, pss)
		} else {
			digest, err = rsapad.PadSignPKCS1v15(cs.pubKey.(*rsa.PublicKey), opts.HashFunc(), digest)
		}
		if err != nil {
			return nil, err
		}
	}

	for {
		buf, err := Sign(cs.card, cs.key, cs.alg, digest)
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
