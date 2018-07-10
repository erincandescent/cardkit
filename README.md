CardKit: Smart Card Utilities
=============================

CardKit is a Go library and program for interacting 
with smartcards. The library can be divided into four
categories:

 * The `card` package contains utilities for formulating
   and parsing APDUs and interacting with smartcards via
   various drivers
 * The `piv` package contains code for interacting with
   FIPS-201 PIV ("Personal Identity Verification")
   applets
 * Utility packages, such as `rsapad` (which handles RSA
   padding separately from signing, a separation not 
   normally provided by the Go crypto libraries), and the
   `tlv` package for parsing the smartcard Basic TLV format

Finally, a command line interface is provided for managing
smartcards which use one of the above protocols