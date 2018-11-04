package piv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"strings"

	"github.com/erincandescent/cardkit/ber"
	"github.com/pkg/errors"
)

// Algorithm encodes a PIV cryptographic algorithm
type AlgorithmID byte

// AlgorithmInfo is information about an Algorithm
type AlgorithmInfo struct {
	// ID is the PIV algorithm identifier
	ID AlgorithmID
	// Name is a human readable name of the algorithm
	Name string
	// Asymmetric is whether this is an asymemetric algorithm
	Asymmetric bool
	// For asymmetric keys, x509 Public Key Algorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
}

const (
	TripleDES   AlgorithmID = 0x00
	TripleDES_B AlgorithmID = 0x03
	RSA_1024    AlgorithmID = 0x06
	RSA_2048    AlgorithmID = 0x07
	AES_128     AlgorithmID = 0x08
	AES_192     AlgorithmID = 0x0A
	AES_256     AlgorithmID = 0x0C
	ECC_P256    AlgorithmID = 0x11
	ECC_P384    AlgorithmID = 0x14
	SM_CS2      AlgorithmID = 0x27
	SM_CS7      AlgorithmID = 0x2E
)

var algorithms = []AlgorithmInfo{
	AlgorithmInfo{TripleDES, "3DES", false, x509.UnknownPublicKeyAlgorithm},
	AlgorithmInfo{TripleDES_B, "3DES-B", false, x509.UnknownPublicKeyAlgorithm},
	AlgorithmInfo{RSA_1024, "RSA-1024", true, x509.RSA},
	AlgorithmInfo{RSA_2048, "RSA-2048", true, x509.RSA},
	AlgorithmInfo{AES_128, "AES-128", false, x509.UnknownPublicKeyAlgorithm},
	AlgorithmInfo{AES_192, "AES-192", false, x509.UnknownPublicKeyAlgorithm},
	AlgorithmInfo{AES_256, "AES-256", false, x509.UnknownPublicKeyAlgorithm},
	AlgorithmInfo{ECC_P256, "P-256", true, x509.ECDSA},
	AlgorithmInfo{ECC_P384, "P-384", true, x509.ECDSA},
}

// GetAlgorithmInfo returns the information for a named algorithm
func GetAlgorithmInfo(name string) (AlgorithmInfo, error) {
	for _, v := range algorithms {
		if strings.EqualFold(name, v.Name) {
			return v, nil
		}
	}
	return AlgorithmInfo{}, errors.Errorf("Unknown algorithm '%s'", name)
}

// GetAlgorithmID returns the ID of a named algorihm
func GetAlgorithmID(name string) (AlgorithmID, error) {
	info, err := GetAlgorithmInfo(name)
	return info.ID, err
}

// GetInfo returns the info on this algorithm
func (a AlgorithmID) GetInfo() AlgorithmInfo {
	for _, v := range algorithms {
		if v.ID == a {
			return v
		}
	}
	return AlgorithmInfo{}
}

type rsaPubKey struct {
	Mod []byte `ber:"81"`
	Exp []byte `ber:"82"`
}

type ecdsaPubKey struct {
	Points []byte `ber:"86"`
}

// ParsePublicKey parses a buffer into a public key for this algorithm
func (a AlgorithmID) ParsePublicKey(buf []byte) (crypto.PublicKey, error) {
	switch a {
	case RSA_1024, RSA_2048:
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

	case ECC_P256, ECC_P384:
		c := elliptic.P256()
		if a == ECC_P384 {
			c = elliptic.P384()
		}

		ek := &ecdsaPubKey{}

		err := ber.Unmarshal(buf, ek)
		if err != nil {
			return nil, errors.Wrap(err, "Getting ECDSA key")
		}

		x, y, err := ellipticUnmarshal(c, ek.Points)
		if err != nil {
			return nil, errors.Wrap(err, "Error unmarshalling card ECDSA key")
		}

		return &ecdsa.PublicKey{c, x, y}, nil
	}
	return nil, errors.Errorf("Non-Asymmetric algorithm keys (%x %s) cannot be parsed", byte(a), a.GetInfo().Name)
}

func ellipticUnmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int, err error) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		err = errors.Errorf("Incorrect length (Expected %d, got %d)", 1+2*byteLen, len(data))
		return
	}
	if data[0] != 4 { // uncompressed form
		err = errors.New("Point is not uncompressed")
		return
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil, errors.New("point >= p")
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("Point is not on curve")
	}
	return
}

// AlgorithmFromPublicKey returns a card algorithm for a public key
func AlgorithmFromPublicKey(k crypto.PublicKey) (AlgorithmID, error) {
	switch k := k.(type) {
	case *rsa.PublicKey:
		l := k.N.BitLen()
		switch {
		case l <= 1024:
			return RSA_1024, nil
		case l <= 2048:
			return RSA_2048, nil
		default:
			return AlgorithmID(00), errors.New("RSA key too big")
		}

	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return ECC_P256, nil
		case elliptic.P384():
			return ECC_P384, nil
		default:
			return AlgorithmID(00), errors.New("Unsupported ECDSA curve")
		}

	default:
		return AlgorithmID(00), errors.New("Unsupported key type")
	}
}
