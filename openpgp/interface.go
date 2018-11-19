package openpgp

import (
	"crypto"

	"github.com/erincandescent/cardkit/ber"
	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/security"
	"github.com/pkg/errors"
	"golang.org/x/crypto/openpgp/packet"
)

// AID is the OpenPGP Application ID
var AID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

// Tags
const (
	Tag_PrivateUse0101           = 0x0101
	Tag_PrivateUse0102           = 0x0102
	Tag_PrivateUse0103           = 0x0103
	Tag_PrivateUse0104           = 0x0104
	Tag_ApplicationID            = 0x4F
	Tag_LoginData                = 0x5E
	Tag_PublicKeyURL             = 0x5F50
	Tag_HistoricalBytes          = 0x5F52
	Tag_ExtendedLengthInfo       = 0x7F66
	Tag_GeneralFeatureManagement = 0x7F74
	Tag_CardholderRelatedData    = 0x0065
	Tag_ApplicationReferenceData = 0x6E
	Tag_DiscretionaryDataObjects = 0x73
	Tag_ExtendedCapabilities     = 0xC0
	Tag_AlgorithmAttributes_Sig  = 0xC1
	Tag_ALgorithmAttributes_Dec  = 0xC2
	Tag_AlgorithmAttributes_Aut  = 0xC3
	Tag_PasswordStatusBytes      = 0xC4
	Tag_Fingerprints             = 0xC5
	Tag_CAFingerprints           = 0xC6
	Tag_KeyGenerationTImestamps  = 0xCD
	Tag_UserInteractionFlag_Sig  = 0xD6
	Tag_UserInteractionFlag_Dec  = 0xD7
	Tag_UserInteractionFlag_Aut  = 0xD8
	Tag_SecuritySupportTemplate  = 0x7A
	Tag_DigitalSignatureCounter  = 0x93
	Tag_CardholderCertificate    = 0x7F21
	Tag_KDFDataObject            = 0xF9
)

// File IDs
// Access using card.(Get|Set)FileData
const (
	File_PrivateUse0101 = Tag_PrivateUse0101
	File_PrivateUse0102 = Tag_PrivateUse0102
	File_PrivateUse0103 = Tag_PrivateUse0103
	File_PrivateUse0104 = Tag_PrivateUse0104

	File_ApplicationID = Tag_ApplicationID
	File_LoginData     = Tag_LoginData
	File_PublicKeyURL  = Tag_PublicKeyURL

	File_HistoricalBytes    = Tag_HistoricalBytes
	File_ExtendedLengthInfo = Tag_ExtendedLengthInfo

	File_CardholderRelatedData    = Tag_CardholderRelatedData
	File_ApplicationReferenceData = Tag_ApplicationReferenceData

	File_UserInteractionFlag_Sig = Tag_UserInteractionFlag_Sig
	File_UserInteractionFlag_Dec = Tag_UserInteractionFlag_Dec
	File_UserInteractionFlag_Aut = Tag_UserInteractionFlag_Aut
	File_SecuritySupportTemplate = Tag_SecuritySupportTemplate
	File_CardholderCertificate   = Tag_CardholderCertificate
	File_KDFDataObject           = Tag_KDFDataObject

	// PUT only

	File_SigFingerprint = 0xC7
	File_EncFingerprint = 0xC8
	File_AutFingerprint = 0xC9

	File_SigCAFingerprint = 0xCA
	File_EncCAFingerprint = 0xCB
	File_AutCAFingerprint = 0xCC

	File_SigGenerationTimestamp = 0xCE
	File_EncGenerationTimestamp = 0xCF
	File_AutGenerationTimestamp = 0xD0
)

// SelectApp selects the PIV application
func SelectApp(c *card.Card) error {
	_, err := c.SelectDF(AID)
	return err
}

// Terminate shall send a TERMINATE DF command to the card
// This will clear all state of the application, if permitted
// (Permitted if pin blocked)
func Terminate(c *card.Card) error {
	_, err := c.Command(0x00, 0xE6, 0x00, 0x00, nil, 0)
	return err
}

// Activate shall send an ACTIVATE DF command to the card
// If the application is currently uninitialized, it will
// initialize it. If it is initialized, does nothing
func Activate(c *card.Card) error {
	_, err := c.Command(0x00, 0x44, 0x00, 0x00, nil, 0)
	return err
}

// PinID identifies one of the three card PINs
type PinID byte

const (
	// MainPIN is PW1, used for most authentication purposes
	MainPin PinID = 0x81
	// SigningPin is PW1, used for signing
	SigningPin PinID = 0x82
	// AdminPin is PW3, used for card admin
	AdminPin PinID = 0x83
)

// Login will execute a VERIFY command against the card to verify a PIN
func Login(c *card.Card, pinID PinID, pin []byte) error {
	_, err := c.Command(0x00, 0x20, 0x00, byte(pinID), pin, 0)
	return err
}

// LoginStatus will return the PIN verification status for a given PIN
// Returns nil if authenticated, an error which matches
// card.PinAttempts if not
func LoginStatus(c *card.Card, pinID PinID) error {
	_, err := c.Command(0x00, 0x20, 0x00, byte(pinID), nil, 0)
	return err
}

// Logout Clears verification status for a given pin
func Logout(c *card.Card, pinID PinID) error {
	_, err := c.Command(0x00, 0x20, 0xFF, byte(pinID), nil, 0)
	return err
}

// GetApplicationReferenceData returns the Application Reference Data object
func GetApplicationReferenceData(c *card.Card) (*ApplicationReferenceData, error) {
	ardBuf, err := c.GetDataObject(Tag_ApplicationReferenceData)
	if err != nil {
		return nil, errors.Wrap(err, "Getting Application Reference Data")
	}

	ard := &ApplicationReferenceData{}
	if err := ard.UnmarshalBinary(ardBuf); err != nil {
		return nil, errors.Wrap(err, "Unmarshalling Application Reference Data")
	}

	return ard, nil
}

func publicKeyOperation(c *card.Card, k Key, algAttr AlgorithmAttributes, p1 byte) (crypto.PublicKey, error) {
	dt, _ := ber.Put(nil, uint32(k), []byte{})
	buf, err := c.Command(0x00, 0x47, p1, 0x00, dt, 256)
	if err != nil {
		return nil, err
	}

	pki, _, err := ber.Get(buf, security.PublicKeyTag, false)
	if err != nil {
		return nil, err
	}

	switch algAttr.Algorithm {
	case packet.PubKeyAlgoRSA:
		return security.ParseRSAPublicKey(pki)

	default:
		return nil, errors.Errorf("Unknown algorithm %d", algAttr.Algorithm)
	}

	return nil, nil
}

// GetPublicKey retrieves a public key from the card
func GetPublicKey(c *card.Card, k Key, algAttr AlgorithmAttributes) (crypto.PublicKey, error) {
	return publicKeyOperation(c, k, algAttr, 0x81)
}

// GeneratePublicKey generates a new public key on the card
func GeneratePublicKey(c *card.Card, k Key, algAttr AlgorithmAttributes) (crypto.PublicKey, error) {
	return publicKeyOperation(c, k, algAttr, 0x80)
}

func ComputeDigitalSignature(c *card.Card, data []byte) ([]byte, error) {
	return c.Command(0x00, 0x2A, 0x9E, 0x9A, data, 256)
}
