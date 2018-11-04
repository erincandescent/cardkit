package piv

import (
	"fmt"
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
	Tag   uint32
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

	ManagementKey KeyID = 0x9B
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
	KeyInfo{AuthenticationKey, "auth", "Authentication", 0x5FC105},
	KeyInfo{SigningKey, "sign", "Signing", 0x5FC10A},
	KeyInfo{KeyManagementKey, "encryption", "Encryption (Key Management Key)", 0x5FC10B},
	KeyInfo{CardAuthenticationKey, "cardauth", "Card Authentication", 0x5FC101},
	KeyInfo{YubicoAttestationKey, "yk-attestation", "Certificate Attestation", 0x5FFF01},
}

func init() {
	for i := 0; i < 20; i++ {
		id, err := RetiredKeyManagementKey(i)
		if err != nil {
			panic(err)
		}

		Keys = append(Keys, KeyInfo{
			ID:    id,
			Short: fmt.Sprintf("rkm%d", i),
			Name:  fmt.Sprintf("Retired Key Management Key %d", i),
			Tag:   uint32(0x5FC10D + i),
		})
	}
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
