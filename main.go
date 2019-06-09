// Copyright 2019 Daisuke Koide. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/diskkid/go-mitm/proxy"
)

func createCA() ([]byte, []byte, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)

	pub := &priv.PublicKey
	ca, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Public key
	certOut, err := os.Create("ca.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca})
	certOut.Close()

	// Private key
	keyOut, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	keyOut.Close()

	return ca, privBytes, nil
}

func initCA(caPath, keyPath string) ([]byte, []byte, error) {
	if caPath == "" && keyPath == "" {
		return createCA()
	}

	if caPath != "" && keyPath != "" {
		if _, err := os.Stat(caPath); err != nil {
			return nil, nil, err
		}

		if _, err := os.Stat(keyPath); err != nil {
			return nil, nil, err
		}

		caPem, err := ioutil.ReadFile(caPath)
		if err != nil {
			return nil, nil, err
		}
		caBlock, _ := pem.Decode(caPem)

		keyPem, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, nil, err
		}
		keyBlock, _ := pem.Decode(keyPem)

		return caBlock.Bytes, keyBlock.Bytes, nil
	}

	return nil, nil, fmt.Errorf("CA and key must be specified together")
}

func main() {
	ip := flag.String("ip", "0.0.0.0", "Proxy server's IP")
	port := flag.Int("port", 8080, "Proxy server's port")
	caPath := flag.String("ca", "", "CA certificate for inpersonating")
	keyPath := flag.String("key", "", "Private key of CA for signing")
	flag.Parse()

	ca, keyBytes, err := initCA(*caPath, *keyPath)
	if err != nil {
		log.Fatalf("Failed to parepare CA: %v\n", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v\n", err)
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("Failed to load system CA bundle: %v\n", err)
	}

	caCert, err := x509.ParseCertificate(ca)
	if err != nil {
		log.Fatalf("Failed to parse CA: %v\n", err)
	}

	roots.AddCert(caCert)

	bind := *ip + ":" + strconv.Itoa(*port)
	s := proxy.Server{
		Address: bind,
		Roots:   roots,
		CaCert:  caCert,
		CaKey:   key,
	}
	s.ListenAndServe()
}
