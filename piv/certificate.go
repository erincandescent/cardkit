package piv

import (
	"crypto/x509"

	"github.com/erincandescent/cardkit/ber"
)

// Certificate represents a PIV certificate structure
type Certificate struct {
	// Certificate contains the X.509 certificate
	Certificate []byte `ber:"70"`
	// CertInfo contains the certificate info byte
	CertInfo []byte `ber:"71"`
	// MSCUID returns the MSCUUD
	MSCUID []byte `ber:"72"`
	// EDC contains the error detection code (should be 0 on PIV cards)
	EDC []byte `ber:"FE"`
}

func (c Certificate) MarshalBinary() ([]byte, error) {
	return ber.Marshal(c)
}

func (c *Certificate) UnmarshalBinary(buf []byte) error {
	return ber.Unmarshal(buf, c)
}

// ParseX509Certificate parses the certificate blob as an X.509 certificate
func (c Certificate) ParseX509Certificate() (*x509.Certificate, error) {
	return x509.ParseCertificate(c.Certificate)
}
