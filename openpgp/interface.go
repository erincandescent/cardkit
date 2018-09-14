package openpgp

import "github.com/erincandescent/cardkit/card"

// AID is the OpenPGP Application ID
var AID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

// SelectApp selects the PIV application
func SelectApp(c *card.Card) error {
	_, err := c.SelectDF(AID)
	return err
}
