// Copyright 2019 Daisuke Koide. All rights reserved.
// Use of this source code is governed by the MIT license.

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
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

func createCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey, host string) ([]byte, *rsa.PrivateKey, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
			CommonName:    host,
		},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		DNSNames:              []string{host},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey
	cert, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
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
	listener, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("Failed to listen: %v\n", err)
	}

	log.Printf("Listening to %s\n", bind)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				log.Printf("Failed to read request: %v\n", err)
				return
			}

			if req.Method == "CONNECT" {
				res := http.Response{ProtoMajor: 1, StatusCode: 200}
				res.Write(conn)

				cert, certKey, err := createCertificate(caCert, key, req.URL.Hostname())
				if err != nil {
					log.Fatalf("Failed to create certificate: %v\n", err)
				}

				tlsConfig := tls.Config{
					RootCAs: roots,
					Certificates: []tls.Certificate{
						tls.Certificate{
							Certificate: [][]byte{cert},
							PrivateKey:  certKey,
						},
					},
				}

				tlsConn := tls.Server(conn, &tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					log.Printf("Failed to handshake: %v\n", err)
					return
				}

				req, err = http.ReadRequest(bufio.NewReader(tlsConn))
				if err != nil {
					log.Printf("Failed to read request: %v\n", err)
					return
				}

				req.URL.Scheme = "https"
				req.URL.Host = req.Host

				conn = tlsConn
			}

			c := http.Client{}
			req.RequestURI = ""
			res, err := c.Do(req)
			if err != nil {
				log.Printf("Failed to send a request to %s%s: %v\n", req.Host, req.RequestURI, err)
				return
			}

			res.Write(conn)
			conn.Close()
		}()
	}
}
