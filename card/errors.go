package card

import "fmt"

type CardError struct {
	SW uint16
}

var _ error = CardError{}

// ErrorFromAPDU constructs a CardError from a response APDU
func ErrorFromAPDU(apdu RespAPDU) CardError {
	return CardError{SW: uint16(apdu.SW1)<<8 | uint16(apdu.SW2)}
}

// IsStatus checks if the error is a card error and, if so,
// the status word matches sw
func IsStatus(e error, sw uint16) bool {
	if e, ok := e.(CardError); ok {
		return e.SW == sw
	}
	return false
}

// IsLoginRequred checks if an error is a CardError representing
// a login required error
func IsLoginRequired(e error) bool {
	return IsStatus(e, 0x6982)
}

// PinAttempts returns the number of PIN attempts remaining from
// an error.
// If this is not a PIN attempts remaining error, returns -1
func PinAttempts(e error) int {
	if e, ok := e.(CardError); ok {
		if (e.SW & 0xFFF0) == 0x63C0 {
			return int(e.SW & 0xF)
		} else if e.SW == 0x6983 {
			return 0
		}
	}
	return -1
}

// Error returns a textual description of an error
func (e CardError) Error() string {
	desc := "Unknown"
	switch {
	// 62xx Warning, NVMem unchanged
	case e.SW == 0x6281: //
		desc = "Data corrupted"
	case e.SW == 0x6282:
		desc = "EOF"
	case e.SW == 0x6283:
		desc = "File deactivated"
	case e.SW == 0x6284:
		desc = "Bad file control information"
	case e.SW == 0x6285:
		desc = "Selected file in termination state"
	case e.SW == 0x6286:
		desc = "No input data available from card sensor"

	// 63xx Warning, NVMem changed
	case e.SW == 0x6381:
		desc = "File full"
	case (e.SW & 0xFFF0) == 0x63C0:
		desc = fmt.Sprintf("%d PIN attempts remainining", e.SW&0xF)

	// 64xx Error, NVMem unchanged
	case e.SW == 0x6400:
		desc = "Execution error"
	case e.SW == 0x6401:
		desc = "Immediate response required"

	// 65xx Error, NVMem changed
	case e.SW == 0x6581:
		desc = "Memory failure"

	// 68xx Functions in CLA not supported
	case e.SW == 0x6881:
		desc = "Logical channel not supported"
	case e.SW == 0x6882:
		desc = "Secure messaging not supported"
	case e.SW == 0x6883:
		desc = "Last command of chain expected"
	case e.SW == 0x6884:
		desc = "Command chaining not supported"

	// 69xx bad instruction (nice.)
	case e.SW == 0x6981:
		desc = "Command incompatible with file structure"
	case e.SW == 0x6982:
		desc = "Security satus not satisfied"
	case e.SW == 0x6983:
		desc = "Authentication method blocked"
	case e.SW == 0x6984:
		desc = "Reference data unusable"
	case e.SW == 0x6985:
		desc = "Conditions of use not satisified"
	case e.SW == 0x6986:
		desc = "Command not allowed (no current EF)"
	case e.SW == 0x6987:
		desc = "Expected secure messaging data objects missing"
	case e.SW == 0x6988:
		desc = "Incorrect secure messaging data objects"

	// 6Axx General errors
	case e.SW == 0x6A80:
		desc = "Invalid parameters in data field"
	case e.SW == 0x6A81:
		desc = "Function not supported"
	case e.SW == 0x6A82:
		desc = "File or application not found"
	case e.SW == 0x6A83:
		desc = "Record not found"
	case e.SW == 0x6A84:
		desc = "Not enough memory space in file"
	case e.SW == 0x6A85:
		desc = "Nc inconsistent with TLV structure"
	case e.SW == 0x6A86:
		desc = "Incorrect parameters in P1/P2"
	case e.SW == 0x6A87:
		desc = "Nc inconsistent with P1/P2"
	case e.SW == 0x6A88:
		desc = "Reference/d data not found"
	case e.SW == 0x6A89:
		desc = "File already exists"
	case e.SW == 0x6A8A:
		desc = "DF name already exists"

	}

	return fmt.Sprintf("Card error %04x: %s", e.SW, desc)
}
