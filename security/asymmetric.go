package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"github.com/erincandescent/cardkit/ber"
	"github.com/pkg/errors"
)

// PublicKeyTag is the common tag used for public key objects
const PublicKeyTag = 0x7F49

type rsaPubKey struct {
	AlgOid *[]byte `ber:"06"`
	Mod    []byte  `ber:"81"`
	Exp    []byte  `ber:"82"`
}

type ecdsaPubKey struct {
	AlgOid *[]byte `ber:"06"`
	Points []byte  `ber:"86"`
}

// ParseRSAPublicKey parses an RSA public key body
func ParseRSAPublicKey(buf []byte) (*rsa.PublicKey, error) {
	var mod, exp big.Int
	pk := &rsaPubKey{}

	err := ber.Unmarshal(buf, pk)
	if err != nil {
		return nil, errors.Wrap(err, "Getting RSA Key")
	}

	mod.SetBytes(pk.Mod)
	exp.SetBytes(pk.Exp)
	if !exp.IsInt64() {
		return nil, errors.New("RSA Public exponent too big")
	}

	return &rsa.PublicKey{N: &mod, E: int(exp.Int64())}, nil
}

// ParseECDSAPublicKey parses an ECDSA public key body
func ParseECDSAPublicKey(curve elliptic.Curve, buf []byte) (*ecdsa.PublicKey, error) {
	ek := &ecdsaPubKey{}

	err := ber.Unmarshal(buf, ek)
	if err != nil {
		return nil, errors.Wrap(err, "Getting ECDSA key")
	}

	x, y := elliptic.Unmarshal(curve, ek.Points)
	if x == nil {
		return nil, errors.New("Error unmarshalling card ECDSA key")
	}

	return &ecdsa.PublicKey{curve, x, y}, nil
}
