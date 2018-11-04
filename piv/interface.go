// package piv provides an interface to FIPS-201 PIV smartcards
package piv

import (
	"crypto"
	"crypto/des"
	"crypto/rand"
	"crypto/subtle"

	"github.com/erincandescent/cardkit/ber"
	"github.com/erincandescent/cardkit/card"
	"github.com/pkg/errors"
)

// AID is the PIV Application ID
var AID = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00}

const (
	ObjectTagTag             = 0x5C
	ObjectDataTag            = 0x53
	KeyAlgorithmTag          = 0x80
	GenerateKeyControlTag    = 0xAC
	PublicKeyTag             = 0x7F49
	DynamicAuthenticationTag = 0x7C
)

/*
Witness '80' C Demonstration of knowledge of a fact without revealing
the fact. An empty witness is a request for a witness.
Challenge '81' C One or more random numbers or byte sequences to be
used in the authentication protocol.
Response '82' C A sequence of bytes encoding a response step in an
authentication protocol.
Exponentiation '85' C A parameter used in ECDH key agreement protocol
*/
type DynamicAuthentication struct {
	Witness        *[]byte `ber:"80"`
	Response       *[]byte `ber:"82"`
	Challenge      *[]byte `ber:"81"`
	Exponentiation *[]byte `ber:"85"`
}

func (r *DynamicAuthentication) Pack() ([]byte, error) {
	req, err := ber.Marshal(r)
	if err != nil {
		return nil, err
	}
	return ber.Put(nil, DynamicAuthenticationTag, req)
}

func (r *DynamicAuthentication) Unpack(buf []byte) error {
	rsp, rst, err := ber.Get(buf, DynamicAuthenticationTag, false)
	if err != nil {
		return err
	} else if len(rst) > 0 {
		return errors.New("Junk at end of DynamicAuthentication")
	}
	return ber.Unmarshal(rsp, r)
}

// SelectApp selects the PIV application
func SelectApp(c *card.Card) error {
	_, err := c.SelectDF(AID)
	return err
}

// GetObject retrieves the object with the specified tag from the card
func GetObject(c *card.Card, tag uint32) ([]byte, error) {
	var req []byte

	req, err := ber.Put(req, ObjectTagTag, ber.PackTag(tag))
	if err != nil {
		return nil, err
	}

	resp, err := c.GetFileData(card.CurrentDF, req)
	if err != nil {
		return nil, errors.Wrap(err, "Getting object")
	}

	data, rest, err := ber.Get(resp, ObjectDataTag, false)
	if err != nil {
		return nil, errors.Wrap(err, "Getting object body")
	}

	if len(rest) > 0 {
		return nil, errors.New("Data tag doesn't cover whole response")
	}
	return data, nil
}

// SetObject stores the object with the specified tag on the card
func SetObject(c *card.Card, tag uint32, data []byte) error {
	req, err := ber.Put(nil, ObjectTagTag, ber.PackTag(tag))
	if err != nil {
		return err
	}
	req, err = ber.Put(req, ObjectDataTag, data)
	if err != nil {
		return err
	}

	return c.PutFileData(card.CurrentDF, req)
}

// GetCertificate retrieves the certificate associated
// with the specified key ID from the card
func GetCertificate(card *card.Card, key KeyID) (*Certificate, error) {
	info := key.GetInfo()
	data, err := GetObject(card, info.Tag)
	if err != nil {
		return nil, errors.Wrap(err, "Getting certificate")
	}

	cert := &Certificate{}
	return cert, cert.UnmarshalBinary(data)
}

// SetCertificate stores the specified certificate on the card
func SetCertificate(c *card.Card, key KeyID, cert Certificate) error {
	info := key.GetInfo()
	certBytes, err := cert.MarshalBinary()
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

// Logout signs the user out of the card
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
	req, err := ber.Put(nil, KeyAlgorithmTag, []byte{byte(alg)})
	if err != nil {
		return nil, err
	}
	req, err = ber.Put(nil, GenerateKeyControlTag, req)
	if err != nil {
		return nil, err
	}

	resp, err := c.Command(0x00, 0x47, 0x00, byte(key), req, 256)
	if err != nil {
		return nil, err
	}

	body, _, err := ber.Get(resp, PublicKeyTag, false)
	if err != nil {
		return nil, err
	}

	return alg.ParsePublicKey(body)
}

func GeneralAuthenticate(c *card.Card, alg AlgorithmID, key KeyID, req DynamicAuthentication) (*DynamicAuthentication, error) {
	reqBuf, err := req.Pack()
	if err != nil {
		return nil, err
	}

	resp, err := c.Command(0x00, 0x87, byte(alg), byte(key), reqBuf, 256)
	if err != nil {
		return nil, err
	}

	respBuf := &DynamicAuthentication{}
	return respBuf, respBuf.Unpack(resp)
}

// Manage logs in using the card admin PIN
func Manage(c *card.Card, key []byte) error {
	cipher, err := des.NewTripleDESCipher(key)
	req := DynamicAuthentication{
		Challenge: &[]byte{},
	}

	resp, err := GeneralAuthenticate(c, TripleDES, ManagementKey, req)
	if err != nil {
		return errors.Wrap(err, "Getting challenge")
	}

	cipher.Encrypt(*resp.Challenge, *resp.Challenge)
	ourChallenge := make([]byte, 8)
	_, err = rand.Read(ourChallenge)
	if err != nil {
		return err
	}

	req = DynamicAuthentication{
		Challenge: &ourChallenge,
		Response:  resp.Challenge,
	}

	resp, err = GeneralAuthenticate(c, TripleDES, ManagementKey, req)
	if err != nil {
		return errors.Wrap(err, "Getting response")
	}

	cipher.Encrypt(ourChallenge, ourChallenge)
	if subtle.ConstantTimeCompare(ourChallenge, *resp.Response) == 0 {
		return errors.Errorf("Card failed challenge (%x != %x)", ourChallenge, *resp.Response)
	}

	return nil
}

// Sign signs the specified challenge
func Sign(c *card.Card, key KeyID, alg AlgorithmID, challenge []byte) ([]byte, error) {
	req := DynamicAuthentication{
		Challenge: &challenge,
	}

	resp, err := GeneralAuthenticate(c, alg, key, req)
	if err != nil {
		return nil, err
	}

	if resp.Response == nil {
		return nil, errors.New("No response from card")
	}

	return *resp.Response, err
}

// YubicoAttest asks the card to return the attestation
// certificate for the specified key (YubiKey 4 specific)
func YubicoAttest(c *card.Card, key KeyID) ([]byte, error) {
	return c.Command(0x00, 0xf9, byte(key), 0x00, nil, 256)
}
