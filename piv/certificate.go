package piv

import (
	"crypto/x509"

	"github.com/erincandescent/cardkit/tlv"
	"github.com/pkg/errors"
)

// Certificate represents a PIV certificate structure
type Certificate struct {
	// Certificate contains the X.509 certificate
	Certificate []byte
	// CertInfo contains the certificate info byte
	CertInfo []byte
	// MSCUID returns the MSCUUD
	MSCUID []byte
	// EDC contains the error detection code (should be 0 on PIV cards)
	EDC []byte
}

func ParseCertificate(buf []byte) (Certificate, error) {
	var err error
	var c Certificate

	c.Certificate, buf, err = tlv.Get(buf, []byte{0x70}, false)
	if err != nil {
		return c, errors.Wrap(err, "Certificate")
	}

	c.CertInfo, buf, err = tlv.Get(buf, []byte{0x71}, true)
	if err != nil {
		return c, errors.Wrap(err, "CertInfo")
	}
	c.MSCUID, buf, err = tlv.Get(buf, []byte{0x72}, true)
	if err != nil {
		return c, errors.Wrap(err, "MSCUID")
	}
	c.EDC, buf, err = tlv.Get(buf, []byte{0xFE}, true)
	if err != nil {
		return c, errors.Wrap(err, "EDC")
	}
	return c, nil
}

// ParseX509Certificate parses the certificate blob as an X.509 certificate
func (c Certificate) ParseX509Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Certificate)
}

// Serialize serializes the certificate into a buffer
func (c Certificate) Serialize() ([]byte, error) {
	buf, err := tlv.Put(nil, []byte{0x70}, c.Certificate)
	if err != nil {
		return nil, err
	}
	buf, err = tlv.Put(buf, []byte{0x71}, c.CertInfo)
	if err != nil {
		return nil, err
	}
	if len(c.MSCUID) > 0 {
		buf, err = tlv.Put(buf, []byte{0x72}, c.MSCUID)
		if err != nil {
			return nil, err
		}
	}
	return tlv.Put(buf, []byte{0xFE}, c.EDC)
}
