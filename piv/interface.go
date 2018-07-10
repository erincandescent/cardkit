// package piv provides an interface to FIPS-201 PIV smartcards
package piv

import (
	"crypto"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/tlv"
	"github.com/pkg/errors"
)

// AID is the PIV Application ID
var AID = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00}

// SelectApp selects the PIV application
func SelectApp(c *card.Card) error {
	_, err := c.SelectDF(AID)
	return err
}

// GetObject retrieves the object with the specified tag from the card
func GetObject(c *card.Card, tag []byte) ([]byte, error) {
	var req []byte

	req, err := tlv.Put(req, []byte{0x5C}, tag)
	if err != nil {
		return nil, err
	}

	resp, err := c.GetFileData(card.CurrentDF, req)
	if err != nil {
		return nil, errors.Wrap(err, "Getting object")
	}

	data, rest, err := tlv.Get(resp, []byte{0x53}, false)
	if err != nil {
		return nil, errors.Wrap(err, "Getting object body")
	}

	if len(rest) > 0 {
		return nil, errors.New("Data tag doesn't cover whole response")
	}
	return data, nil
}

// SetObject stores the object with the specified tag on the card
func SetObject(c *card.Card, tag, data []byte) error {
	var req []byte
	req, err := tlv.Put(req, []byte{0x5C}, tag)
	if err != nil {
		return err
	}
	req, err = tlv.Put(req, []byte{0x53}, data)
	if err != nil {
		return err
	}

	return c.PutFileData(card.CurrentDF, req)
}

// GetCertificate retrieves the certificate associated
// with the specified key ID from the card
func GetCertificate(card *card.Card, key KeyID) (Certificate, error) {
	info := key.GetInfo()
	data, err := GetObject(card, info.Tag)
	if err != nil {
		return Certificate{}, errors.Wrap(err, "Getting certificate")
	}

	return ParseCertificate(data)
}

// SetCertificate stores the specified certificate on the card
func SetCertificate(c *card.Card, key KeyID, cert Certificate) error {
	info := key.GetInfo()
	certBytes, err := cert.Serialize()
	if err != nil {
		return err
	}

	return SetObject(c, info.Tag, certBytes)
}

// Login attempts a card login.
// If pin is empty, will return an error indicating the
// number of PIN attempts remaining
func Login(c *card.Card, pinId PinID, pin []byte) error {
	if len(pin) != 0 {
		for len(pin) < 8 {
			pin = append(pin, 0xFF)
		}
		if len(pin) > 8 {
			return errors.New("PIN cannot be > 8 characters")
		}
	}

	_, err := c.Command(0x00, 0x20, 0x00, byte(pinId), pin, 0)
	return err
}

// Logout signs the user out of the car
func Logout(c *card.Card) error {
	_, err := c.Command(0x00, 0x20, 0xFF, byte(ApplicationPIN), nil, 0)
	if err != nil && card.IsStatus(err, 0x6A80) {
		// The PIV spec documents the above for logout. However, the YubiKey 4
		// reports an error in the data field when we attempt it. On the other
		// hand, the YK4 does reset login state when we reselect the applet,
		// so do that
		err = SelectApp(c)
	}
	return err
}

// GenerateKey generates a new key on the card, returning
// the new publc key. The returned public key is not stored
// anywhere - you must store it somewhere (e.g. by using the
// card to self sign a certificate and storing that!)
func GenerateKey(c *card.Card, key KeyID, alg AlgorithmID) (crypto.PublicKey, error) {
	req, err := tlv.Put(nil, []byte{0x80}, []byte{byte(alg)})
	if err != nil {
		return nil, err
	}
	req, err = tlv.Put(nil, []byte{0xAC}, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Command(0x00, 0x47, 0x00, byte(key), req, 256)
	if err != nil {
		return nil, err
	}

	body, _, err := tlv.Get(resp, []byte{0x7F, 0x49}, false)
	if err != nil {
		return nil, err
	}

	return alg.ParsePublicKey(body)
}

// Manage logs in using the card admin PIN
func Manage(c *card.Card, key []byte) error {
	cipher, err := des.NewTripleDESCipher(key)

	resp, err := c.Command(0x00, 0x87, byte(TripleDES), 0x9B, []byte{0x7C, 0x02, 0x81, 0x00}, 256)
	if err != nil {
		return errors.Wrap(err, "Getting challenge")
	}

	body, _, err := tlv.Get(resp, []byte{0x7C}, false)
	if err != nil {
		return err
	}

	cardChallenge, _, err := tlv.Get(body, []byte{0x81}, false)
	if err != nil {
		return err
	}

	cipher.Encrypt(cardChallenge, cardChallenge)
	ourChallenge := make([]byte, 8)
	_, err = rand.Read(ourChallenge)
	if err != nil {
		return err
	}

	req, err := tlv.Put(nil, []byte{0x82}, cardChallenge)
	if err != nil {
		return err
	}
	req, err = tlv.Put(req, []byte{0x81}, ourChallenge)
	if err != nil {
		return err
	}
	req, err = tlv.Put(nil, []byte{0x7C}, req)

	resp, err = c.Command(0x00, 0x87, byte(TripleDES), 0x9B, req, 256)
	if err != nil {
		return errors.Wrap(err, "Responding to challenge")
	}

	body, _, err = tlv.Get(resp, []byte{0x7C}, false)
	if err != nil {
		return err
	}

	cardResp, _, err := tlv.Get(body, []byte{0x82}, false)
	if err != nil {
		return err
	}

	cipher.Encrypt(ourChallenge, ourChallenge)
	if subtle.ConstantTimeCompare(ourChallenge, cardResp) == 0 {
		return errors.Errorf("Card failed challenge (%x != %x)", ourChallenge, cardResp)
	}

	return nil
}

// Sign signs the specified challenge
func Sign(c *card.Card, key KeyID, alg AlgorithmID, challenge []byte) ([]byte, error) {
	challenge, err := tlv.Put(nil, []byte{0x81}, challenge)
	if err != nil {
		return nil, err
	}
	challenge, err = tlv.Put(nil, []byte{0x7C}, challenge)
	if err != nil {
		return nil, err
	}

	resp, err := c.Command(0x00, 0x87, byte(alg), byte(key), challenge, 256)
	if err != nil {
		return nil, err
	}
	body, _, err := tlv.Get(resp, []byte{0x7C}, false)
	if err != nil {
		return nil, err
	}
	resp, _, err = tlv.Get(body, []byte{0x82}, false)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// YubicoAttest asks the card to return the attestation
// certificate for the specified key (YubiKey 4 specific)
func YubicoAttest(c *card.Card, key KeyID) ([]byte, error) {
	return c.Command(0x00, 0xf9, byte(key), 0x00, nil, 256)
}
