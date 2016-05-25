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
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spacemonkeygo/openssl"
)

// VersionMajor sscg major version
const VersionMajor int = 1

// VersionMinor sscg minor version
const VersionMinor int = 0

// VersionPatch sscg patch version
const VersionPatch int = 5

var debugIO = ioutil.Discard
var verboseIO = ioutil.Discard
var standardIO = ioutil.Discard

// DebugLogger Debug printouts
var DebugLogger *log.Logger

// VerboseLogger Logger for progress
var VerboseLogger *log.Logger

// StandardLogger Display basic output
var StandardLogger *log.Logger

func parseArgs(sc *SscgConfig) error {
	var err error

	// --quiet
	flag.BoolVar(&sc.quiet, "quiet", false, "Display no output unless there is an error.")

	// --verbose
	flag.BoolVar(&sc.verbose, "verbose", false, "Display progress messages.")

	// --debug
	flag.BoolVar(&sc.debug, "debug", false, "Enable logging of debug messages. Implies verbose.\n\tWarning! This will print private key information to the screen!")

	// --version
	flag.BoolVar(&sc.printVersion, "version", false, "Display the version number and exit")

	// --lifetime
	flag.UintVar(&sc.lifetime, "lifetime", 3650, "Certificate lifetime (days).\n\t")

	// --key-strength
	sc.keyStrength = KeyStrength2048
	flag.Var(&sc.keyStrength, "key-strength", "Strength of the certificate private keys in bits. {512,1024,2048,4096}\n\t")

	// --hash-alg
	sc.hashAlgorithm = HashAlgorithmSHA256
	flag.Var(&sc.hashAlgorithm, "hash-alg", "Hashing algorithm to use for signing. {sha256,sha384,sha512}\n\t")

	// --package
	flag.StringVar(&sc.packagename, "package", "Unknown", "The name of the package needing a certificate\n\t")

	// --ca-file
	flag.StringVar(&sc.caFile, "ca-file", "ca.crt", "Path where the public CA certificate will be stored.\n\t")

	// --ca-key-file
	flag.StringVar(&sc.caKeyFile, "ca-key-file", "", "Path where the CA's private key will be stored. If unspecified, the key will be destroyed rather than written to the disk.")

	// --cert-file
	flag.StringVar(&sc.certFile, "cert-file", "service.pem", "Path where the public service certificate will be stored.\n\t")

	// --cert-key-file
	flag.StringVar(&sc.certKeyFile, "cert-key-file", "service-key.pem", "Path where the service's private key will be stored.\n\t")

	// --signing-cert
	flag.StringVar(&sc.signingCertFile, "signing-cert", "", "The location of an existing signing certificate. Setting this option will skip creation of a private CA.")

	// --signing-key
	flag.StringVar(&sc.signingKeyFile, "signing-key", "", "The location of an existing signing key. Setting this option will skip creation of a private CA.")

	// --hostname
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	flag.StringVar(&sc.hostname, "hostname", hostname, "The valid hostname of the certificate. Must be an FQDN.\n\t")

	// --subject-alt-name
	flag.Var(&sc.subjectAltNames, "subject-alt-name", "An additional valid hostname for the certificate. May be specified multiple times.\n\t")

	// --country
	flag.StringVar(&sc.country, "country", "US", "Certificate DN: Country (C)\n\t")

	// --organization
	flag.StringVar(&sc.organization, "organization", "Unspecified", "Certificate DN: Organization (O)\n\t")

	flag.Parse()

	return nil
}

func main() {
	var sc = new(SscgConfig)

	err := parseArgs(sc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parsing arguments failed: %s\n", err)
		os.Exit(1)
	}

	if sc.printVersion {
		fmt.Printf("%d.%d.%d\n", VersionMajor, VersionMinor, VersionPatch)
		os.Exit(0)
	}

	if !sc.quiet {
		standardIO = os.Stdout
	}
	StandardLogger = log.New(standardIO, "[OUTPUT] ", 0)

	if sc.verbose || sc.debug {
		verboseIO = os.Stdout
	}
	VerboseLogger = log.New(verboseIO, "", log.Ldate|log.Ltime|log.Lmicroseconds)

	if sc.debug {
		debugIO = os.Stdout
	}
	DebugLogger = log.New(debugIO, "[DEBUG] ", 0)

	DebugLogger.Printf("%+#v\n", sc)

	// Compare the cert-file and cert-key-file arguments
	// We don't want to write anything out if this comparison fails

	matched_cert, err := sc.SamePath(sc.certFile, sc.certKeyFile)
	if err != nil {
		os.Exit(1)
	}

	matched_ca, err := sc.SamePath(sc.caFile, sc.caKeyFile)
	if err != nil {
		os.Exit(1)
	}

	if (len(sc.signingCertFile) == 0 && len(sc.signingKeyFile) != 0) || (len(sc.signingCertFile) != 0 && len(sc.signingKeyFile) == 0) {
		fmt.Fprintf(os.Stderr, "Both -signing-cert and -signing-key must be specified together.\n")
		os.Exit(1)
	}

	if len(sc.signingKeyFile) == 0 {
		// Create a private CA to sign the certificate
		VerboseLogger.Printf("Generating CA")
		err = sc.createPrivateCA()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Creating CA failed: %s\n", err)
			os.Exit(1)
		}
		VerboseLogger.Printf("CA generated successfully\n")

		if sc.debug {
			sc.CertificateDebug(sc.caCertificate, sc.caCertificateKey)
		}
	} else {
		// Read in the existing certificate
		signingCertData, err := ioutil.ReadFile(sc.signingCertFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open CA certificate for reading: %v\n", err)
			os.Exit(1)
		}
		sc.caCertificate, err = openssl.LoadCertificateFromPEM(signingCertData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load CA certificate data: %v\n", err)
			os.Exit(1)
		}

		// Read in the existing certificate key
		signingKeyData, err := ioutil.ReadFile(sc.signingKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open CA private key for reading: %v\n", err)
			os.Exit(1)
		}
		sc.caCertificateKey, err = openssl.LoadPrivateKeyFromPEM(signingKeyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot load CA private key data: %v\n", err)
			fmt.Fprintf(os.Stderr, "SSCG does not support loading from password-protected key files yet.")
			os.Exit(1)
		}
	}

	// Create a service certificate and sign it with the private CA
	err = sc.createServiceCert()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating service certificate failed: %s\n", err)
		os.Exit(1)
	}
	VerboseLogger.Printf("Service certificate generated successfully\n")

	if sc.debug {
		sc.CertificateDebug(sc.svcCertificate, sc.svcCertificateKey)
	}

	/* == Write the output files == */

	if len(sc.signingKeyFile) == 0 {
		// Write the CA public certificate
		if err = sc.WriteCertificatePEM(sc.caCertificate, sc.caFile); err != nil {
			fmt.Fprintf(os.Stderr, "Aborting: Error writing CA certificate file: %v\n", err)
			os.Exit(1)
		}
		StandardLogger.Printf("CA public certificate written to %s.\n", sc.caFile)

		// Write the private key of the certificate if it was requested
		if len(sc.caKeyFile) != 0 {
			if err = sc.WriteCertificateKeyPEM(sc.caCertificateKey, sc.caKeyFile, matched_ca); err != nil {
				fmt.Fprintf(os.Stderr, "Aborting: Error writing CA key file: %v\n", err)
				os.Exit(1)
			}
			StandardLogger.Printf("CA private key written to %s.\n", sc.caKeyFile)
		}
	}

	// Write the public service certificate
	if err = sc.WriteCertificatePEM(sc.svcCertificate, sc.certFile); err != nil {
		fmt.Fprintf(os.Stderr, "Aborting: Error writing service certificate file: %v\n", err)
		os.Exit(1)
	}
	StandardLogger.Printf("Service public certificate written to %s.\n", sc.certFile)

	// Write the service private key
	if err = sc.WriteCertificateKeyPEM(sc.svcCertificateKey, sc.certKeyFile, matched_cert); err != nil {
		fmt.Fprintf(os.Stderr, "Aborting: Error writing CA key file: %v\n", err)
		os.Exit(1)
	}
	StandardLogger.Printf("Service certificate private key written to %s.\n", sc.certKeyFile)
}
