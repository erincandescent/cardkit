package openpgp

import (
	"encoding/json"
	"errors"
	"strings"

	"fmt"
	"strconv"

	"github.com/erincandescent/cardkit/ber"
	"golang.org/x/crypto/openpgp/packet"
)

// Tag 0x65
type CardholderRelatedData struct {
	Name               string `ber:"5B"`
	LanguagePreference string `ber:"5F2D"`
	Sex                string `ber:"5F35"`
}

func (d CardholderRelatedData) MarshalBinary() ([]byte, error) {
	buf, err := ber.Marshal(d)
	if err != nil {
		return nil, err
	}

	return ber.Put(nil, 0x65, buf)
}

func (crd *CardholderRelatedData) UnmarshalBinary(buf []byte) error {
	body, _, err := ber.Get(buf, 0x65, false)
	if err != nil {
		return err
	}

	return ber.Unmarshal(body, crd)
}

/*
6e App Reference Data
 | - 4f App ID
 | - 5f52 Historical Bytes
 | - 7f74 General Feature Management
 |   | - 81
 | - 73 Discretionary Data Objects
 |   | - C0 Ext Caps
 |   | - C1 Alg Attr, Sig
 |   | - C2 Alg Attr, Enc
 |   | - C3 Alg Attr, Aut
 |   | - C4 PW Status Bytes
 |   | - C5 Fingerprints (Sig Enc Aut)
 |   | - C6 CA Fingerprints (Sig Enc Aut)
 |   | - CD Generation Date/Timestamps
*/

type ApplicationReferenceData struct {
	ApplicationID            []byte                   `ber:"4f"`
	HistoricalBytes          []byte                   `ber:"5f52"`
	GeneralFeatureManagement GeneralFeatureManagement `ber:"7f74,ber"`
	DiscretionaryDataObjects DiscretionaryDataObjects `ber:"73,ber"`
}

func (ard ApplicationReferenceData) MarshalBinary() ([]byte, error) {
	body, err := ber.Marshal(ard)
	if err != nil {
		return nil, err
	}

	return ber.Put(nil, Tag_ApplicationReferenceData, body)
}

func (ard *ApplicationReferenceData) UnmarshalBinary(buf []byte) error {
	body, _, err := ber.Get(buf, Tag_ApplicationReferenceData, false)
	if err != nil {
		return err
	}
	return ber.Unmarshal(body, ard)
}

type GeneralFeatureManagement struct {
	UserInteractionFlags []byte `ber:"81"`
}

type DiscretionaryDataObjects struct {
	ExtendedCapabilities   ExtendedCapabilities `ber:"C0,big"`
	SigAlgorithmAttributes AlgorithmAttributes  `ber:"C1"`
	EncAlgorithmAttributes AlgorithmAttributes  `ber:"C2"`
	AutAlgorithmAttributes AlgorithmAttributes  `ber:"C3"`
	PasswordStatus         []byte               `ber:"C4"`
	Fingerprints           KeyFingerprints      `ber:"C5,big"`
	CAFingerprints         KeyFingerprints      `ber:"C6,big"`
	GenerationTimestamps   GenerationTimestamps `ber:"CD,big"`
}

type ExtendedCapabilities struct {
	Capabilities                     CapabilityFlags          `json:"capabilities"`
	SecureMessagingAlgorithm         SecureMessagingAlgorithm `json:"secure_messaging_algorithm,omitempty"`
	GetChallengeMaxLen               uint16                   `json:"get_challenge_max_length,omitempty"`
	CardholderCertificateMaxLen      uint16                   `json:"cardholder_certificate_max_length,omitempty"`
	SpecialDOMaxLen                  uint16                   `json:"specal_do_max_length,omitempty"`
	PinBlock2FormatSupported         bool                     `json:"pin_block_2_supported,omitempty"`
	ManageSecurityEnvEncDecSupported bool                     `json:"manage_security_env_enc_dec_supported,omitempty"`
}

type CapabilityFlags byte

const (
	Cap_SecureMessaging                 CapabilityFlags = 1 << 7
	Cap_GetChallenge                    CapabilityFlags = 1 << 6
	Cap_KeyImport                       CapabilityFlags = 1 << 5
	Cap_PWStatusChangable               CapabilityFlags = 1 << 4
	Cap_PrivateUseObjects               CapabilityFlags = 1 << 3
	Cap_AlgorithmAttributesChangable    CapabilityFlags = 1 << 2
	Cap_EncryptDecryptAES               CapabilityFlags = 1 << 1
	Cap_KeyDerivationFunctionDataObject CapabilityFlags = 1 << 0
)

func (flags CapabilityFlags) ToStringList() (list []string) {
	if (flags & Cap_SecureMessaging) != 0 {
		list = append(list, "sm")
	}
	if (flags & Cap_GetChallenge) != 0 {
		list = append(list, "getchallenge")
	}
	if (flags & Cap_KeyImport) != 0 {
		list = append(list, "keyimp")
	}
	if (flags & Cap_PWStatusChangable) != 0 {
		list = append(list, "pwstatchange")
	}
	if (flags & Cap_PrivateUseObjects) != 0 {
		list = append(list, "privateuseobj")
	}
	if (flags & Cap_AlgorithmAttributesChangable) != 0 {
		list = append(list, "algattrchange")
	}
	if (flags & Cap_EncryptDecryptAES) != 0 {
		list = append(list, "aes")
	}
	if (flags & Cap_KeyDerivationFunctionDataObject) != 0 {
		list = append(list, "kdfobj")
	}
	return
}

func (flags CapabilityFlags) String() string {
	list := flags.ToStringList()
	return strings.Join(list, " ")
}

func (flags CapabilityFlags) MarshalJSON() ([]byte, error) {
	list := flags.ToStringList()
	return json.Marshal(list)
}

func (flags *CapabilityFlags) UnmarshalJSON(buf []byte) error {
	var list []string
	if err := json.Unmarshal(buf, &list); err != nil {
		return err
	}

	*flags = CapabilityFlags(0)
	for _, e := range list {
		switch e {
		case "sm":
			*flags |= Cap_SecureMessaging
		case "getchallenge":
			*flags |= Cap_GetChallenge
		case "keyimp":
			*flags |= Cap_KeyImport
		case "pwstatchange":
			*flags |= Cap_PWStatusChangable
		case "privateuseobj":
			*flags |= Cap_PrivateUseObjects
		case "algattrchange":
			*flags |= Cap_AlgorithmAttributesChangable
		case "aes":
			*flags |= Cap_EncryptDecryptAES
		case "kdfobj":
			*flags |= Cap_KeyDerivationFunctionDataObject
		default:
			return fmt.Errorf("Unsupported capability flag '%s'", e)
		}
	}
	return nil
}

type SecureMessagingAlgorithm byte

const (
	SecureMessagingAlgorithm_Undefined SecureMessagingAlgorithm = 0
	SecureMessagingAlgorithm_AES128    SecureMessagingAlgorithm = 1
	SecureMessagingAlgorithm_AES256    SecureMessagingAlgorithm = 2
	SecureMessagingAlgorithm_SCP11b    SecureMessagingAlgorithm = 3
)

func (sma SecureMessagingAlgorithm) String() string {
	switch sma {
	case SecureMessagingAlgorithm_Undefined:
		return "undefined"
	case SecureMessagingAlgorithm_AES128:
		return "aes128"
	case SecureMessagingAlgorithm_AES256:
		return "aes256"
	case SecureMessagingAlgorithm_SCP11b:
		return "scp11b"
	default:
		return fmt.Sprintf("%d", int(sma))
	}
}

func (sma SecureMessagingAlgorithm) MarshalText() ([]byte, error) {
	return []byte(sma.String()), nil
}

func (sma *SecureMessagingAlgorithm) UnmarshalText(str []byte) error {
	switch string(str) {
	case "undefined":
		*sma = SecureMessagingAlgorithm_Undefined
	case "aes128":
		*sma = SecureMessagingAlgorithm_AES128
	case "aes256":
		*sma = SecureMessagingAlgorithm_AES256
	case "scp11b":
		*sma = SecureMessagingAlgorithm_SCP11b
	default:
		res, err := strconv.ParseUint(string(str), 0, 8)
		if err == nil {
			*sma = SecureMessagingAlgorithm(res)
		}
		return err
	}
	return nil
}

type KeyData struct {
	AlgorithmAttributes AlgorithmAttributes
	Fingerprint         []byte
	CAFingerprint       []byte
	GenerationTimestamp uint32
}

func (ddo *DiscretionaryDataObjects) GetAlgorithmAttributesForKey(key Key) AlgorithmAttributes {
	switch key {
	case SigKey:
		return ddo.SigAlgorithmAttributes
	case EncKey:
		return ddo.EncAlgorithmAttributes
	case AutKey:
		return ddo.AutAlgorithmAttributes
	default:
		return AlgorithmAttributes{}
	}
}

func (ddo *DiscretionaryDataObjects) GetKeyData(key Key) KeyData {
	return KeyData{
		AlgorithmAttributes: ddo.GetAlgorithmAttributesForKey(key),
		Fingerprint:         ddo.Fingerprints.GetForKey(key),
		CAFingerprint:       ddo.CAFingerprints.GetForKey(key),
		GenerationTimestamp: ddo.GenerationTimestamps.GetForKey(key),
	}
}

type AlgorithmAttributes struct {
	Algorithm packet.PublicKeyAlgorithm
	Data      []byte
}

func (a AlgorithmAttributes) MarshalBinary() ([]byte, error) {
	return append([]byte{byte(a.Algorithm)}, a.Data...), nil
}

func (a *AlgorithmAttributes) UnmarshalBinary(buf []byte) error {
	if len(buf) < 1 {
		return errors.New("Algorithm Attributes too short")
	}

	a.Algorithm = packet.PublicKeyAlgorithm(buf[0])
	a.Data = buf[1:]
	return nil
}

func AlgorithmName(alg packet.PublicKeyAlgorithm) string {
	switch alg {
	case packet.PubKeyAlgoRSA:
		return "RSA"
	case packet.PubKeyAlgoRSAEncryptOnly:
		return "RSA (Enc)"
	case packet.PubKeyAlgoRSASignOnly:
		return "RSA (Sig)"
	case packet.PubKeyAlgoElGamal:
		return "ElGamal"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	default:
		return fmt.Sprintf("<%d>", int(alg))
	}
}

type RSAAttributes struct {
	ModulusLength        uint16
	PublicExponentLength uint16
	ImportFormat         byte
}

type KeyFingerprints struct {
	Sig [20]byte
	Enc [20]byte
	Aut [20]byte
}

func (fp *KeyFingerprints) GetForKey(key Key) []byte {
	switch key {
	case SigKey:
		return fp.Sig[:]
	case EncKey:
		return fp.Enc[:]
	case AutKey:
		return fp.Aut[:]
	default:
		return nil
	}
}

func (fp *KeyFingerprints) SetForKey(key Key, fpr []byte) {
	switch key {
	case SigKey:
		copy(fp.Sig[:], fpr[0:20])
	case EncKey:
		copy(fp.Enc[:], fpr[0:20])
	case AutKey:
		copy(fp.Aut[:], fpr[0:20])
	}
}

type GenerationTimestamps struct {
	Sig uint32
	Enc uint32
	Aut uint32
}

func (ts *GenerationTimestamps) GetForKey(key Key) uint32 {
	switch key {
	case SigKey:
		return ts.Sig
	case EncKey:
		return ts.Enc
	case AutKey:
		return ts.Aut
	default:
		return 0
	}

}

func (ts *GenerationTimestamps) SetForKey(key Key, s uint32) {
	switch key {
	case SigKey:
		ts.Sig = s
	case EncKey:
		ts.Enc = s
	case AutKey:
		ts.Aut = s
	}
}
