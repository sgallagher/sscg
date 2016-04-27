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
	"fmt"

	"github.com/spacemonkeygo/openssl"
)

// Create a temporary Certificate authority that will be used to sign a
// single service certificate. We will not save the private key for this
// signing authority, so it cannot be used to sign other certificates in the
// future.
func (sc *SscgConfig) createServiceCert() error {
	serial, err := GenerateSerial()
	if err != nil {
		return err
	}

	DebugLogger.Printf("Service CommonName: %v\n", sc.hostname)
	svcCert, _, svcKey, err := sc.CreateNewCertificate(serial, sc.hostname)
	if err != nil {
		return err
	}

	DebugLogger.Printf("Setting issuer to the private certificate authority")
	svcCert.SetIssuer(sc.caCertificate)

	// Sign this certificate by the private Certificate Authority

	VerboseLogger.Printf("Signing Certificate with private certificate authority")
	err = sc.SignCertificate(svcCert, sc.caCertificateKey)
	if err != nil {
		return err
	}

	// Add x509v3 constraint extensions

	// Basic Constraints
	err = svcCert.AddExtension(openssl.NID_basic_constraints, "CA:FALSE")
	if err != nil {
		DebugLogger.Printf("%v\n", err)
		return err
	}

	// Subject Alternate Names
	for _, altName := range sc.subjectAltNames {
		dnsAltName := fmt.Sprintf("DNS:%s", altName)
		svcCert.AddExtension(openssl.NID_subject_alt_name, dnsAltName)
	}

	sc.svcCertificate = svcCert
	sc.svcCertificateKey = svcKey
	return nil
}
