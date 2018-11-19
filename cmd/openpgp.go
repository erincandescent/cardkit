package cmd

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/openpgp"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
	pgp "golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/erincandescent/cardkit/dshl"
)

var openpgpCmd *simpleCommand

func openpgpSelectCmd(ctx context.Context, args []string) (interface{}, error) {
	return nil, openpgp.SelectApp(getCard(ctx))
}

func openpgpTerminateCmd(ctx context.Context, args []string) (interface{}, error) {
	return nil, openpgp.Terminate(getCard(ctx))
}

func openpgpActivateCmd(ctx context.Context, args []string) (interface{}, error) {
	return nil, openpgp.Activate(getCard(ctx))
}

func openpgpInfoCmd(ctx context.Context, args []string) (interface{}, error) {
	card := getCard(ctx)

	crdBuf, err := card.GetDataObject(openpgp.Tag_CardholderRelatedData)
	if err != nil {
		return nil, errors.Wrap(err, "Getting Cardholder Related Data")
	}

	ardBuf, err := card.GetDataObject(openpgp.Tag_ApplicationReferenceData)
	if err != nil {
		return nil, errors.Wrap(err, "Getting Application Reference Data")
	}

	url, err := card.GetDataObject(openpgp.Tag_PublicKeyURL)
	if err != nil {
		return nil, errors.Wrap(err, "Getting cardholder public key URL")
	}

	crd := &openpgp.CardholderRelatedData{}
	ard := &openpgp.ApplicationReferenceData{}

	if err := crd.UnmarshalBinary(crdBuf); err != nil {
		return nil, errors.Wrap(err, "Unmarshalling Cardholder Related Data")
	}

	if err := ard.UnmarshalBinary(ardBuf); err != nil {
		return nil, errors.Wrap(err, "Unmarshalling Application Reference Data")
	}

	ddo := ard.DiscretionaryDataObjects

	fmt.Println("Application ID:       ", hex.EncodeToString(ard.ApplicationID))
	fmt.Println("Historical Bytes:     ", hex.EncodeToString(ard.HistoricalBytes))
	fmt.Println("Capabilities:         ", ddo.ExtendedCapabilities.Capabilities)
	if (ddo.ExtendedCapabilities.Capabilities & openpgp.Cap_SecureMessaging) != 0 {
		fmt.Println("Secure Messaging Alg: ", ddo.ExtendedCapabilities.SecureMessagingAlgorithm)
	}
	if (ddo.ExtendedCapabilities.Capabilities & openpgp.Cap_GetChallenge) != 0 {
		fmt.Println("Get Challenge Max:    ", ddo.ExtendedCapabilities.GetChallengeMaxLen, " bytes")
	}
	fmt.Println("x.509 Cert Max Len:   ", ddo.ExtendedCapabilities.CardholderCertificateMaxLen, " bytes")
	fmt.Println("Special Obj Max Len:  ", ddo.ExtendedCapabilities.SpecialDOMaxLen, " bytes")
	if ddo.ExtendedCapabilities.PinBlock2FormatSupported {
		fmt.Println("PIN Block 2 format supported")
	}
	if ddo.ExtendedCapabilities.ManageSecurityEnvEncDecSupported {
		fmt.Println("Manage Security Environment supported")
	}

	fmt.Println()

	fmt.Println("Name:                 ", crd.Name)
	fmt.Println("URL:                  ", string(url))
	fmt.Println("Language Preference:  ", crd.LanguagePreference)
	fmt.Println("Sex:                  ", crd.Sex)

	fmt.Println()

	for _, k := range openpgp.Keys {
		info := ddo.GetKeyData(k.Key)

		fmt.Printf("%s key:\n", k.Name)
		fmt.Printf("  Algorithm:      %s\n", openpgp.AlgorithmName(info.AlgorithmAttributes.Algorithm))
		fmt.Printf("  Fingerprint:    %x\n", info.Fingerprint)
		fmt.Printf("  CA Fingerprint: %x\n", info.CAFingerprint)
		fmt.Printf("  Generated:      %s\n", time.Unix(int64(info.GenerationTimestamp), 0))
		fmt.Printf("\n")
	}

	return nil, nil
}

func openpgpGetKeyCmd(ctx context.Context, args []string) (interface{}, error) {
	card := getCard(ctx)
	if len(args) != 1 {
		return nil, errors.New("Usage: cardkit openpgp getkey <name>")
	}

	keyinfo, err := openpgp.GetKeyInfo(args[0])
	if err != nil {
		return nil, err
	}

	ardBuf, err := card.GetDataObject(openpgp.Tag_ApplicationReferenceData)
	if err != nil {
		return nil, errors.Wrap(err, "Getting Application Reference Data")
	}

	ard := &openpgp.ApplicationReferenceData{}
	if err := ard.UnmarshalBinary(ardBuf); err != nil {
		return nil, errors.Wrap(err, "Unmarshalling Application Reference Data")
	}

	algAttr := ard.DiscretionaryDataObjects.GetAlgorithmAttributesForKey(keyinfo.Key)

	pubKey, err := openpgp.GetPublicKey(card, keyinfo.Key, algAttr)
	if err != nil {
		return nil, err
	}

	ber, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: ber,
	})), nil
}

func openpgpGenKeyCmd(ctx context.Context, args []string) (interface{}, error) {
	card := getCard(ctx)
	if len(args) != 1 {
		return nil, errors.New("Usage: cardkit openpgp getkey <name>")
	}

	keyinfo, err := openpgp.GetKeyInfo(args[0])
	if err != nil {
		return nil, err
	}

	ard, err := openpgp.GetApplicationReferenceData(card)
	if err != nil {
		return nil, err
	}

	algAttr := ard.DiscretionaryDataObjects.GetAlgorithmAttributesForKey(keyinfo.Key)

	pubKey, err := openpgp.GeneratePublicKey(card, keyinfo.Key, algAttr)
	if err != nil {
		return nil, err
	}

	if algAttr.Algorithm != packet.PubKeyAlgoRSA {
		return nil, errors.New("Unsupported algorithm")
	}
	pk := packet.NewRSAPublicKey(time.Now(), pubKey.(*rsa.PublicKey))

	err = card.PutDataObject(keyinfo.FingerprintID, pk.Fingerprint[:])
	if err != nil {
		return nil, errors.Wrap(err, "Setting fingerprint")
	}

	tsBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tsBuf, uint32(pk.CreationTime.Unix()))

	err = card.PutDataObject(keyinfo.TimestampID, tsBuf)
	if err != nil {
		return nil, errors.Wrap(err, "Setting timestamp")
	}

	ber, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: ber,
	})), nil
}

func openpgpLoginCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)

	var pinID openpgp.PinID

	switch len(args) {
	case 0:
		pinID = openpgp.MainPin
	case 1, 2:
		switch args[0] {
		case "main":
			pinID = openpgp.MainPin
		case "signing":
			pinID = openpgp.SigningPin
		case "admin":
			pinID = openpgp.AdminPin
		default:
			return nil, errors.New("Unknown PIN")
		}

	default:
		return nil, errors.New("Usage: login [pin ID] [pin]")
	}

	if len(args) == 2 {
		return nil, openpgp.Login(c, pinID, []byte(args[1]))
	} else {
		prompt := "PIN: "
		for {
			pin, err := dshl.GetShell(ctx).PasswordPrompt(prompt)
			if err != nil {
				return nil, err
			}

			err = openpgp.Login(c, pinID, []byte(pin))

			if card.PinAttempts(err) > 0 {
				prompt = fmt.Sprintf("PIN (%d attempts remaining): ", card.PinAttempts(err))
			} else {
				return nil, err
			}
		}
	}
}

func getKey(card *card.Card, ard *openpgp.ApplicationReferenceData, key openpgp.Key) (crypto.PublicKey, error) {
	algAttr := ard.DiscretionaryDataObjects.GetAlgorithmAttributesForKey(key)
	return openpgp.GetPublicKey(card, key, algAttr)
}

func configFromKey(kd openpgp.KeyData) *packet.Config {
	creationTime := time.Unix(int64(kd.GenerationTimestamp), 0)

	return &packet.Config{
		Rand: hkdf.Expand(sha256.New, kd.Fingerprint, nil),
		Time: func() time.Time {
			return creationTime
		},
	}
}

func openpgpInteractiveLogin(ctx context.Context, pinID openpgp.PinID) (err error) {
	c := getCard(ctx)
	var pin string

	// err = openpgp.LoginStatus(c, pinID)
	for {
		prompt := "PIN: "
		switch {
		case card.PinAttempts(err) != -1:
			n := card.PinAttempts(err)
			if n == 0 {
				return errors.New("PIN blocked")
			}
			prompt = fmt.Sprintf("PIN (%d attempts remaining): ", n)

		case err != nil:
			return err
		}

		pin, err = dshl.GetShell(ctx).PasswordPrompt(prompt)
		if err != nil {
			return err
		}

		err = openpgp.Login(c, pinID, []byte(pin))
		if err != nil {
			continue
		}
		break
	}
	return nil
}

func openpgpMakeKeyCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	shell := dshl.GetShell(ctx)

	name, err := shell.Prompt("Name:    ")
	if err != nil {
		return nil, err
	}

	email, err := shell.Prompt("Email:   ")
	if err != nil {
		return nil, err
	}

	comment, err := shell.Prompt("Comment: ")
	if err != nil {
		return nil, err
	}

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.New("User ID contains invalid characters")
	}

	ard, err := openpgp.GetApplicationReferenceData(c)
	if err != nil {
		return nil, err
	}

	certKey, err := getKey(c, ard, openpgp.SigKey)
	if err != nil {
		return nil, errors.Wrap(err, "Getting signing key")
	}

	encKey, err := getKey(c, ard, openpgp.EncKey)
	if err != nil {
		return nil, errors.Wrap(err, "Getting encryption key")
	}

	autKey, err := getKey(c, ard, openpgp.AutKey)
	if err != nil {
		return nil, errors.Wrap(err, "Getting authentication key")
	}

	certKeyData := ard.DiscretionaryDataObjects.GetKeyData(openpgp.SigKey)
	certConf := configFromKey(certKeyData)

	signer := openpgp.NewSigner(c, certKey, openpgp.SigKey, func(_ *card.Card) error {
		return openpgpInteractiveLogin(ctx, openpgp.MainPin)
	})

	e := &pgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(certConf.Now(), certKey.(*rsa.PublicKey)),
		PrivateKey: packet.NewSignerPrivateKey(certConf.Now(), signer),
		Identities: make(map[string]*pgp.Identity),
	}

	isPrimaryId := true
	e.Identities[uid.Id] = &pgp.Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: certConf.Now(),
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         certConf.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	err = e.Identities[uid.Id].SelfSignature.SignUserId(uid.Id, e.PrimaryKey, e.PrivateKey, certConf)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating self signature")
	}

	e.Subkeys = make([]pgp.Subkey, 2)

	// Encryption subkey
	encKeyData := ard.DiscretionaryDataObjects.GetKeyData(openpgp.EncKey)
	encConf := configFromKey(encKeyData)
	e.Subkeys[0] = pgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(encConf.Now(), encKey.(*rsa.PublicKey)),
		PrivateKey: nil,
		Sig: &packet.Signature{
			CreationTime:              encConf.Now(),
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      certConf.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
		},
	}
	e.Subkeys[0].PublicKey.IsSubkey = true
	err = e.Subkeys[0].Sig.SignKey(e.Subkeys[0].PublicKey, e.PrivateKey, encConf)
	if err != nil {
		return nil, err
	}

	// Authentication subkey
	autKeyData := ard.DiscretionaryDataObjects.GetKeyData(openpgp.AutKey)
	autConf := configFromKey(autKeyData)
	e.Subkeys[1] = pgp.Subkey{
		PublicKey:  packet.NewRSAPublicKey(autConf.Now(), autKey.(*rsa.PublicKey)),
		PrivateKey: nil,
		Sig: &packet.Signature{
			CreationTime:              autConf.Now(),
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      certConf.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
		},
	}
	e.Subkeys[1].PublicKey.IsSubkey = true
	err = e.Subkeys[1].Sig.SignKey(e.Subkeys[1].PublicKey, e.PrivateKey, autConf)
	if err != nil {
		return nil, err
	}

	// Marshal
	buf := &bytes.Buffer{}
	w, err := armor.Encode(buf, pgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}

	if err := e.Serialize(w); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return string(buf.Bytes()), nil
}

func init() {
	openpgpCmd = newSimpleCommand(dshl.CommandInfo{
		Name:  "openpgp",
		Short: "Low level OpenPGP commands",
	}, func(ctx context.Context, args []string) (interface{}, error) {
		sh := dshl.GetShell(ctx)
		scope := sh.PushScope()
		scope.PS1 = dshl.NewPS1("pgp> ", "! pgp> ")
		scope.Modal = true
		for _, c := range openpgpCmd.info.Subcommands {
			sh.AddCommand(c)
		}

		if len(args) > 0 {
			defer sh.PopScope(scope)
			return sh.Exec(ctx, args)
		}
		return nil, nil
	})

	openpgpCmd.addSubcommands(
		newSimpleCommand(dshl.CommandInfo{
			Name:  "select",
			Short: "Selects the OpenPGP application",
			Long:  "Sends a SELECT Dedicated File command to the card with the OpenPGP AID",
		}, openpgpSelectCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "info",
			Short: "Retrieves info from the OpenPGP application",
			Long:  "Retrieves cardholder and Application Reference info from the OpenPGP application",
		}, openpgpInfoCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "getkey",
			Short: "Gets a public key from the OpenPGP application",
			Long:  "Gets a public key from the OpenPGP application (returning it in PEM format)",
		}, openpgpGetKeyCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "genkey",
			Short: "Generates a key on the OpenPGP application",
			Long:  "Generates a key on the OpenPGP application (returning it in PEM format)",
		}, openpgpGenKeyCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "terminate",
			Short: "Terminates the card application (erases all keys!)",
			Long:  "Terminates the application and returns the card to factory original state",
		}, openpgpTerminateCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "activate",
			Short: "Activates the card application (takes it out of a reset state)",
			Long:  "Activates the card application (prepares it for use)",
		}, openpgpActivateCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "login",
			Short: "Login to the card using a PIN",
			Long:  "Login to the card using a PIN",
		}, openpgpLoginCmd),

		newSimpleCommand(dshl.CommandInfo{
			Name:  "makekey",
			Short: "Makes an OpenPGP key from the card keys",
			Long:  "Makes an OpenPGP key from the card keys",
		}, openpgpMakeKeyCmd),
	)
}
