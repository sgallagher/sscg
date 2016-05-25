// Copyright (c) 2016, Stephen Gallagher <sgallagh@redhat.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/spacemonkeygo/openssl"
)

// GenerateSerial Create a random certificate serial number
func GenerateSerial() (*big.Int, error) {
	// Generate a random serial number
	maxSerial := new(big.Int)
	maxSerial.SetUint64(math.MaxInt32)

	serial := new(big.Int)

	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, err
	}

	DebugLogger.Printf("Serial: %v\n", serial)

	return serial, nil
}

// CreateNewCertificate Generate a new certificate and keypair
func (sc *SscgConfig) CreateNewCertificate(serial *big.Int, commonName string) (*openssl.Certificate, *openssl.CertificateInfo, openssl.PrivateKey, error) {
	certInfo := new(openssl.CertificateInfo)

	// Create a keypair for the temporary CA
	VerboseLogger.Printf("Generating a %d-bit public/private keypair", int(sc.keyStrength))
	key, err := openssl.GenerateRSAKey(int(sc.keyStrength))
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a certificate

	// Set the "Issued" time to right now
	certInfo.Issued = 0

	// Set the Expiration time
	certInfo.Expires, err = time.ParseDuration(fmt.Sprintf("%dh", sc.lifetime*24))
	if err != nil {
		return nil, nil, nil, err
	}

	DebugLogger.Printf("Expiration: %v\n", certInfo.Expires)

	// DN Naming
	certInfo.Country = sc.country
	certInfo.Organization = sc.organization
	certInfo.Serial = serial

	certInfo.CommonName = commonName

	DebugLogger.Printf("CommonName: %v\n", certInfo.CommonName)

	VerboseLogger.Printf("Generating Certificate")
	// Generate the new certificate from this keypair
	cert, err := openssl.NewCertificate(certInfo, key)
	if err != nil {
		DebugLogger.Printf("NewCertificate failed: %v\n", err)
		return nil, nil, nil, err
	}

	// All certificates created by SSCG must be x509v3 certificates
	err = cert.SetVersion(openssl.X509_V3)
	if err != nil {
		DebugLogger.Printf("Could not set certificate version to x509v3")
		return nil, nil, nil, err
	}

	return cert, certInfo, key, nil
}

// SignCertificate Sign a certificate with a provided private key
func (sc *SscgConfig) SignCertificate(cert *openssl.Certificate, key openssl.PrivateKey) error {
	var digest openssl.EVP_MD
	switch sc.hashAlgorithm {
	case HashAlgorithmSHA256:
		digest = openssl.EVP_SHA256
	case HashAlgorithmSHA384:
		digest = openssl.EVP_SHA384
	case HashAlgorithmSHA512:
		digest = openssl.EVP_SHA512
	default:
		return errors.New("Unknown hash digest")
	}

	err := cert.Sign(key, digest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Certificate signing failed: %v\n", err)
		return err
	}

	return nil
}

// CertificateDebug Display information about the certificate on
// the debug output writer.
func (sc *SscgConfig) CertificateDebug(cert *openssl.Certificate, key openssl.PrivateKey) {
	DebugLogger.Printf("Certificate Public Key:\n")
	publicData, err := cert.MarshalPEM()
	if err != nil {
		DebugLogger.Printf("Could not retrieve public key: %s\n", err)
	}
	fmt.Fprintf(debugIO, "%s\n", publicData)

	DebugLogger.Printf("Certificate Private Key:\n")
	privateData, err := sc.caCertificateKey.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		DebugLogger.Printf("Could not retrieve private key: %s\n", err)
	}
	fmt.Fprintf(debugIO, "%s\n", privateData)
}

func (sc *SscgConfig) WriteCertificatePEM(cert *openssl.Certificate, file string) error {
	var data []byte
	var err error

	if data, err = cert.MarshalPEM(); err != nil {
		fmt.Fprintf(os.Stderr, "Error getting certificate data: %v\n", err)
		return err
	}

	err = sc.WriteSecureFile(file, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing certificate file: %v\n", err)
		return err
	}
	return nil
}

func (sc *SscgConfig) WriteCertificateKeyPEM(key openssl.PrivateKey, file string, append bool) error {
	var data []byte
	var err error

	if data, err = key.MarshalPKCS1PrivateKeyPEM(); err != nil {
		fmt.Fprintf(os.Stderr, "Error getting certificate key data: %v\n", err)
		return err
	}

	if append {
		err = sc.AppendToFile(file, data)
		if err != nil {
			os.Exit(1)
		}
	} else {
		err = sc.WriteSecureFile(file, data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing private key file: %v\n", err)
			return err
		}
	}
	return nil
}
