// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"

	"github.com/cloudflare/cfssl/api/signhandler"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/erincandescent/cardkit/card"
	"github.com/erincandescent/cardkit/piv"
	"github.com/liclac/dshl"
	"github.com/pkg/errors"
)

var pivCmd *simpleCommand

func pivSelectCmd(ctx context.Context, args []string) (interface{}, error) {
	return nil, piv.SelectApp(getCard(ctx))
}

func pivGetCertCmd(ctx context.Context, args []string) (interface{}, error) {
	card := getCard(ctx)
	if len(args) != 1 {
		return nil, errors.New("usage: cardkit piv getcert <key slot>")
	}

	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	cert, err := piv.GetCertificate(card, key)
	if err != nil {
		return nil, err
	}

	f, _ := os.Create("cert.der")
	f.Write(cert.Certificate)

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate,
	})), nil
}

func pivPutCertCmd(ctx context.Context, args []string) (interface{}, error) {
	card := getCard(ctx)
	if len(args) != 2 {
		return nil, errors.New("Usage: cardkit piv putcert <key slot> <certificate file>")
	}

	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	f, err := os.Open(args[1])
	if err != nil {
		return nil, errors.Wrap(err, "Opening "+args[1])
	}

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errors.Wrap(err, "Reading certificate")
	}

	blk, _ := pem.Decode(buf)
	if blk == nil {
		return nil, errors.New("Unable to parse PEM certificate file?")
	}

	pivCert := piv.Certificate{
		Certificate: blk.Bytes,
		CertInfo:    []byte{0x00},
	}

	err = piv.SetCertificate(card, key, pivCert)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func pivGenKeyCmd(ctx context.Context, args []string) (interface{}, error) {
	card := getCard(ctx)
	if len(args) != 2 {
		return nil, errors.New("Usage: cardkit piv genkey <key slot> <algorithm>")
	}

	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	alg, err := piv.GetAlgorithmID(args[1])
	if err != nil {
		return nil, err
	}

	pubKey, err := piv.GenerateKey(card, key, alg)
	if err != nil {
		return nil, err
	}

	ber, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  alg.GetInfo().PublicKeyAlgorithm.String() + " PUBLIC KEY",
		Bytes: ber,
	}), nil
}

func pivGenCsrCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	if len(args) < 2 || len(args) > 3 {
		return nil, errors.New("Usage: cardkit piv gencsr <key slot> <alg> [csr file]")
	}

	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	alg, err := piv.GetAlgorithmID(args[1])
	if err != nil {
		return nil, err
	}

	var tmpl csr.CertificateRequest
	if len(args) >= 3 {
		f, err := os.Open(args[2])
		if err != nil {
			return nil, err
		}
		defer f.Close()

		csrJson, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}

		if err = json.Unmarshal(csrJson, &tmpl); err != nil {
			return nil, err
		}
	} else {
		tmpl.CN = fmt.Sprintf("Card %s Key", alg.GetInfo().Name)
	}

	pubKey, err := piv.GenerateKey(c, key, alg)
	if err != nil {
		return nil, err
	}

	signer, err := piv.NewSigner(c, pubKey, key, func(_ *card.Card) error {
		return pivInteractiveLogin(ctx)
	})
	if err != nil {
		return nil, err
	}

	pem, err := csr.Generate(signer, &tmpl)
	if err != nil {
		return nil, err
	}

	return string(pem), nil
}

func pivGenCertCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	if len(args) != 2 {
		return nil, errors.New("Usage: cardkit piv gencert <key slot> <algorithm>")
	}

	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	alg, err := piv.GetAlgorithmID(args[1])
	if err != nil {
		return nil, err
	}

	pubKey, err := piv.GenerateKey(c, key, alg)
	if err != nil {
		return nil, err
	}

	name := pkix.Name{CommonName: key.GetInfo().Name + " Certificate"}
	certTemplate := x509.Certificate{
		Issuer:       name,
		Subject:      name,
		SerialNumber: big.NewInt(0),
	}

	signer, err := piv.NewSigner(c, pubKey, key, func(_ *card.Card) error {
		return pivInteractiveLogin(ctx)
	})
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(
		rand.Reader,
		&certTemplate,
		&certTemplate,
		pubKey,
		signer)
	if err != nil {
		return nil, err

	}

	pivCert := piv.Certificate{
		Certificate: cert,
		CertInfo:    []byte{0x00},
	}

	err = piv.SetCertificate(c, key, pivCert)
	if err != nil {
		return nil, err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})), nil
}

func pivLoginCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	if len(args) == 0 {
		return nil, pivInteractiveLogin(ctx)
	}

	return nil, piv.Login(c, piv.ApplicationPIN, []byte(args[0]))
}

func pivLogoutCmd(ctx context.Context, args []string) (interface{}, error) {
	return nil, piv.Logout(getCard(ctx))
}

func pivInteractiveLogin(ctx context.Context) (err error) {
	c := getCard(ctx)
	var pin string

	err = piv.Login(c, piv.ApplicationPIN, nil)
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

		err = piv.Login(c, piv.ApplicationPIN, []byte(pin))
		if err != nil {
			continue
		}
		break
	}
	return nil
}

func pivManageCmd(ctx context.Context, args []string) (interface{}, error) {
	var key string
	var err error

	c := getCard(ctx)
	if len(args) == 0 {
		key, err = dshl.GetShell(ctx).PasswordPrompt("Key: ")
		if err != nil {
			return nil, err
		}
	} else {
		key = args[0]
	}

	keyBuf, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}
	if len(keyBuf) != 24 {
		return nil, errors.New("Management keys should be 24 bytes and specified as hex")
	}

	return nil, piv.Manage(c, keyBuf)
}

// pivStatusCmd represents the piv status command
func pivStatusCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	err := piv.Login(c, piv.ApplicationPIN, nil)
	switch {
	case card.PinAttempts(err) != -1:
		n := card.PinAttempts(err)
		if n == 0 {
			return nil, errors.New("Pin blocked")
		} else {
			return fmt.Sprintf("%d pin attempts remaining", n), nil
		}
	case err != nil:
		return nil, err
	default:
		return "Logged in", nil
	}
}

func pivYKAttestCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	data, err := piv.YubicoAttest(c, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	}), nil
}

func pivSignerCmd(ctx context.Context, args []string) (interface{}, error) {
	c := getCard(ctx)
	if len(args) < 2 {
		return nil, errors.New("Usage: cardkit piv signer <key-id> <listen-address>")
	}

	listenAddr := "localhost:8000"
	if len(args) >= 2 {
		listenAddr = args[1]
	}

	key, err := piv.GetKeyID(args[0])
	if err != nil {
		return nil, err
	}

	pivCert, err := piv.GetCertificate(c, key)
	if err != nil {
		return nil, errors.Wrap(err, "Getting certificate")
	}

	cert, err := pivCert.ParseX509Certificate()
	if err != nil {
		return nil, errors.Wrap(err, "Parsing certificate")
	}

	alg, err := piv.AlgorithmFromPublicKey(cert.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "Getting algorithm")
	}

	signer, err := piv.NewSigner(c, cert.PublicKey, key, func(_ *card.Card) error {
		return pivInteractiveLogin(ctx)
	})
	if err != nil {
		return nil, err
	}

	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  config.DefaultConfig(),
	}

	sigAlg := x509.UnknownSignatureAlgorithm
	switch alg.GetInfo().PublicKeyAlgorithm {
	case x509.RSA:
		sigAlg = x509.SHA256WithRSAPSS
	case x509.ECDSA:
		sigAlg = x509.ECDSAWithSHA256
	default:
		return nil, errors.New("Unable to get signature algorithm for key algorithm")
	}

	certSigner, err := local.NewSigner(signer, cert, sigAlg, policy)
	if err != nil {
		return nil, errors.Wrap(err, "Creating certificate signer")
	}

	signHandler, err := signhandler.NewHandlerFromSigner(certSigner)
	if err != nil {
		return nil, errors.Wrap(err, "Creating signing handler")
	}

	server := http.Server{
		Addr:      listenAddr,
		TLSConfig: nil,
		Handler:   signHandler,
	}

	return nil, server.ListenAndServe()
}

func init() {
	pivCmd = newSimpleCommand("piv", func(ctx context.Context, args []string) (interface{}, error) {
		sh := dshl.GetShell(ctx)
		sh = sh.Subshell()
		sh.PS1 = dshl.NewPS1("piv> ", "! piv> ")
		for _, c := range pivCmd.info.Subcommands {
			sh.AddCommand(c)
		}

		if len(args) == 0 {
			return nil, sh.Run(ctx)
		}
		return sh.Exec(ctx, args)
	})

	pivCmd.addSubcommands(
		newSimpleCommand("select", pivSelectCmd),

		newSimpleCommand("status", pivStatusCmd),
		newSimpleCommand("login", pivLoginCmd),
		newSimpleCommand("logout", pivLogoutCmd),
		newSimpleCommand("manage", pivManageCmd),

		newSimpleCommand("genkey", pivGenKeyCmd),
		newSimpleCommand("gencsr", pivGenCsrCmd),
		newSimpleCommand("gencert", pivGenCertCmd),

		newSimpleCommand("getcert", pivGetCertCmd),

		newSimpleCommand("putcert", pivPutCertCmd),

		newSimpleCommand("signer", pivSignerCmd),
		newSimpleCommand("yk-attest", pivYKAttestCmd),
	)
}
