package piv

import (
	"strings"

	"github.com/pkg/errors"
)

// PinID represents a PIN identifier
type PinID byte

const (
	GlobalPIN      PinID = 0x00
	ApplicationPIN PinID = 0x80
)

// KeyID represents a key identifier
type KeyID byte

// KeyInfo represents information about a key
type KeyInfo struct {
	ID    KeyID
	Short string
	Name  string
	Tag   []byte
}

const (
	// User authentication key (For signing challenges, login required)
	AuthenticationKey KeyID = 0x9A
	// Signing key (For signing documents, PIN required)
	SigningKey KeyID = 0x9C
	// Encryption key
	KeyManagementKey KeyID = 0x9D
	// Card holder authentication key (login *not* required)
	CardAuthenticationKey KeyID = 0x9E
	// Yubico attestation key slot
	// For YubiKey 4s, this slot contains the key which will be used to
	// sign card generated keys.
	YubicoAttestationKey KeyID = 0xF9
)

// RetiredKeyManagementKey returns the ID of one of the 20 retired key management keys
func RetiredKeyManagementKey(num int) (KeyID, error) {
	if num < 20 {
		return KeyID(byte(0x82 + num)), nil
	} else {
		return KeyID(0), errors.Errorf("Invalid retired key management key %d (Should be 0-15)", num)
	}
}

var Keys = []KeyInfo{
	KeyInfo{AuthenticationKey, "auth", "Authentication", []byte{0x5F, 0xC1, 0x05}},
	KeyInfo{SigningKey, "sign", "Signing", []byte{0x5F, 0xC1, 0x0A}},
	KeyInfo{KeyManagementKey, "encryption", "Encryption (Key Management Key)", []byte{0x5F, 0xC1, 0x0B}},
	KeyInfo{CardAuthenticationKey, "cardauth", "Card Authentication", []byte{0x5F, 0xC1, 0x01}},
	KeyInfo{YubicoAttestationKey, "yk-attestation", "Certificate Attestation", []byte{0x5f, 0xff, 0x01}},
}

// GetKeyInfo gets information about the named key
func GetKeyInfo(name string) (KeyInfo, error) {
	for _, v := range Keys {
		if strings.EqualFold(name, v.Short) {
			return v, nil
		}
	}

	return KeyInfo{}, errors.Errorf("Unknown key slot '%s'", name)
}

// GetKeyID gets a key ID from a name
func GetKeyID(name string) (KeyID, error) {
	info, err := GetKeyInfo(name)
	return info.ID, err
}

// GetInfo gets information about this key ID
func (k KeyID) GetInfo() KeyInfo {
	for _, v := range Keys {
		if v.ID == k {
			return v
		}
	}
	return KeyInfo{}
}
