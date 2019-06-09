// Copyright 2019 Daisuke Koide. All rights reserved.
// Use of this source code is governed by the MIT license.

package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

type Server struct {
	Address string
	Roots   *x509.CertPool
	CaCert  *x509.Certificate
	CaKey   *rsa.PrivateKey
}

func (s *Server) ListenAndServe() {
	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		log.Fatalf("Failed to listen: %v\n", err)
	}

	log.Printf("Listening to %s\n", s.Address)

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

				cert, certKey, err := createCertificate(s.CaCert, s.CaKey, req.URL.Hostname())
				if err != nil {
					log.Fatalf("Failed to create certificate: %v\n", err)
				}

				tlsConfig := tls.Config{
					RootCAs: s.Roots,
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
