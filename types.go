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
	"errors"
	"fmt"
	"strconv"

	"github.com/spacemonkeygo/openssl"
)

// SscgConfig Master context for the sscg
type SscgConfig struct {
	// Display information
	quiet        bool
	verbose      bool
	debug        bool
	printVersion bool

	// Output information
	lifetime      uint
	keyStrength   KeyStrengthType
	hashAlgorithm HashAlgorithmType
	packagename   string
	caFile        string
	certFile      string
	certKeyFile   string

	// Certificate information
	hostname        string
	subjectAltNames SubjectAltNamesType
	country         string
	organization    string

	// Certificates and keys
	caCertificate     *openssl.Certificate
	caCertificateKey  openssl.PrivateKey
	svcCertificate    *openssl.Certificate
	svcCertificateKey openssl.PrivateKey
}

// SscgNIDNameConstraints X.509 extension to limit
// signing validity to specific names
const SscgNIDNameConstraints = 666

// KeyStrengthType An enum containing the list of supported key lengths
type KeyStrengthType int

// Supported key strengths
const (
	KeyStrength512  KeyStrengthType = 512
	KeyStrength1024                 = 1024
	KeyStrength2048                 = 2048
	KeyStrength4096                 = 4096
)

func (keystrength *KeyStrengthType) String() string {
	return strconv.Itoa(int(*keystrength))
}

// Set This is part of the Value interface. It checks that a valid
//     option was provided.
func (keystrength *KeyStrengthType) Set(value string) error {
	intvalue, err := strconv.Atoi(value)
	if err != nil {
		return err
	}

	switch intvalue {
	case 512:
		*keystrength = KeyStrength512
	case 1024:
		*keystrength = KeyStrength1024
	case 2048:
		*keystrength = KeyStrength2048
	case 4096:
		*keystrength = KeyStrength4096

	default:
		return errors.New("Supported key lengths are 512, 1024, 2048 or 4096.")
	}

	return nil
}

// HashAlgorithmType Hashing algorithm for certificates
type HashAlgorithmType int

// Available hashing algorithms
const (
	HashAlgorithmSHA256 HashAlgorithmType = iota
	HashAlgorithmSHA384
	HashAlgorithmSHA512
)

var hashAlgorithmStrings = [...]string{
	"sha256",
	"sha384",
	"sha512",
}

func (hashType *HashAlgorithmType) String() string {
	return hashAlgorithmStrings[*hashType]
}

// Set This is part of the Value interface. It checks that a valid
//     option was provided.
func (hashType *HashAlgorithmType) Set(value string) error {
	switch value {
	case "sha256":
		*hashType = HashAlgorithmSHA256
	case "sha384":
		*hashType = HashAlgorithmSHA384
	case "sha512":
		*hashType = HashAlgorithmSHA512
	default:
		return errors.New("Unknown hash algorithm.")
	}

	return nil
}

// SubjectAltNamesType List of alternate acceptable names for this service
type SubjectAltNamesType []string

func (altNames *SubjectAltNamesType) String() string {
	return fmt.Sprint(*altNames)
}

// Set This is part of the Value interface. It checks that a valid
//     option was provided.
//     Appends each alternate name to the list
func (altNames *SubjectAltNamesType) Set(value string) error {
	*altNames = append(*altNames, value)

	return nil
}
