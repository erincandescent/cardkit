package openpgp

import (
	"errors"
	"time"
)

type Key int

type KeyInfo struct {
	Key             Key
	Name            string
	FingerprintID   uint32
	CAFingerprintID uint32
	TimestampID     uint32
}

const (
	SigningKey        Key = 0xB6
	EncryptionKey     Key = 0xB8
	DecryptionKey         = EncryptionKey
	AuthenticationKey Key = 0xA4

	SigKey = SigningKey
	EncKey = EncryptionKey
	DecKey = DecryptionKey
	AutKey = AuthenticationKey
)

var Keys = []KeyInfo{
	KeyInfo{AuthenticationKey, "authentication", File_AutFingerprint, File_AutCAFingerprint, File_AutGenerationTimestamp},
	KeyInfo{EncryptionKey, "encryption", File_EncFingerprint, File_EncCAFingerprint, File_EncGenerationTimestamp},
	KeyInfo{SigningKey, "signing", File_SigFingerprint, File_SigCAFingerprint, File_SigGenerationTimestamp},
}

func GetKeyInfo(name string) (KeyInfo, error) {
	for _, v := range Keys {
		if name == v.Name {
			return v, nil
		}
	}

	return KeyInfo{}, errors.New("Unknown key")
}

func (k Key) GetInfo() KeyInfo {
	for _, v := range Keys {
		if v.Key == k {
			return v
		}
	}
	panic("Unknown key")
}

func (k Key) GetFingerprint(fps KeyFingerprints) []byte {
	switch k {
	case SigKey:
		return fps.Sig[:]
	case EncKey:
		return fps.Enc[:]
	case AutKey:
		return fps.Aut[:]
	default:
		return nil
	}
}

func (k Key) GetCreationTimestamp(gts GenerationTimestamps) time.Time {
	var ts uint32
	switch k {
	case SigKey:
		ts = gts.Sig
	case EncKey:
		ts = gts.Enc
	case AutKey:
		ts = gts.Aut
	}

	return time.Unix(int64(ts), 0)
}
