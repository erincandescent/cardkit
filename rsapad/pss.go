// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rsapad implements RSA padding, extracted from the
// standard library.
//
// The Go standard library implements RSA padding as part of
// RSA signing/encryption but does not expose these primitives
// separately. Smart cards implement the signing/encryption but
// not padding portions of RSA, so we must perform padding
// manually
package rsapad

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"hash"
	"io"
)

func saltLength(opts *rsa.PSSOptions) int {
	if opts == nil {
		return rsa.PSSSaltLengthAuto
	}
	return opts.SaltLength
}

// PadPSS calculates PSS padding
func PadPSS(rand io.Reader, pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, opts *rsa.PSSOptions) ([]byte, error) {
	saltLength := saltLength(opts)
	switch saltLength {
	case rsa.PSSSaltLengthAuto:
		saltLength = (pub.N.BitLen()+7)/8 - 2 - hash.Size()
	case rsa.PSSSaltLengthEqualsHash:
		saltLength = hash.Size()
	}

	if opts != nil && opts.Hash != 0 {
		hash = opts.Hash
	}

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand, salt); err != nil {
		return nil, err
	}
	return emsaPSSEncode(hashed, pub.N.BitLen()-1, salt, hash.New())
}

func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash hash.Hash) ([]byte, error) {
	// See [1], section 9.1.1
	hLen := hash.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

	if len(mHash) != hLen {
		return nil, errors.New("crypto/rsa: input must be hashed message")
	}

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

	if emLen < hLen+sLen+2 {
		return nil, errors.New("crypto/rsa: encoding error")
	}

	em := make([]byte, emLen)
	db := em[:emLen-sLen-hLen-2+1+sLen]
	h := em[emLen-sLen-hLen-2+1+sLen : emLen-1]

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

	var prefix [8]byte

	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h = hash.Sum(h[:0])
	hash.Reset()

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

	db[emLen-sLen-hLen-2] = 0x01
	copy(db[emLen-sLen-hLen-1:], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

	mgf1XOR(db, hash, h)

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

	db[0] &= (0xFF >> uint(8*emLen-emBits))

	// 12. Let EM = maskedDB || H || 0xbc.
	em[emLen-1] = 0xBC

	// 13. Output EM.
	return em, nil
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS#1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}
