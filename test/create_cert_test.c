/* SPDX-License-Identifier: GPL-3.0-or-later WITH cryptsetup-OpenSSL-exception */
/*
    This file is part of sscg.

    sscg is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sscg is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sscg.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations
    including the two.
    You must obey the GNU General Public License in all respects
    for all of the code used other than OpenSSL.  If you modify
    file(s) with this exception, you may extend this exception to your
    version of the file(s), but you are not obligated to do so.  If you
    do not wish to do so, delete this exception statement from your
    version.  If you delete this exception statement from all source
    files in the program, then also delete it here.

    Copyright 2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdio.h>
#include <talloc.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "include/sscg.h"
#include "include/cert.h"
#include "include/authority.h"
#include "include/x509.h"

static int
setup_test_options (TALLOC_CTX *mem_ctx, struct sscg_options **_options)
{
  struct sscg_options *options;

  options = talloc_zero (mem_ctx, struct sscg_options);
  if (!options)
    {
      return ENOMEM;
    }

  /* Set up basic test values manually (avoiding internal function) */
  options->lifetime = 365; /* 1 year */
  options->verbosity = SSCG_QUIET; /* Keep tests quiet */
  options->hash_fn = EVP_sha256 ();
  options->key_strength = 2048; /* Reasonable default */

  /* Set up test-specific values */
  options->country = talloc_strdup (options, "US");
  if (!options->country)
    return ENOMEM;

  options->state = talloc_strdup (options, "TestState");
  if (!options->state)
    return ENOMEM;

  options->locality = talloc_strdup (options, "TestCity");
  if (!options->locality)
    return ENOMEM;

  options->org = talloc_strdup (options, "Test Organization");
  if (!options->org)
    return ENOMEM;

  options->org_unit = talloc_strdup (options, "Test Unit");
  if (!options->org_unit)
    return ENOMEM;

  options->email = talloc_strdup (options, "test@example.com");
  if (!options->email)
    return ENOMEM;

  options->hostname = talloc_strdup (options, "test.example.com");
  if (!options->hostname)
    return ENOMEM;

  options->lifetime = 365; /* 1 year */
  options->verbosity = SSCG_QUIET; /* Keep tests quiet */
  options->hash_fn = EVP_sha256 ();

  /* Initialize streams array to avoid segfaults */
  options->streams =
    talloc_zero_array (options, struct sscg_stream *, SSCG_NUM_FILE_TYPES);
  if (!options->streams)
    return ENOMEM;

  *_options = options;
  return EOK;
}

/* Test data structures for comprehensive testing */
struct hash_test_case
{
  const char *name;
  const EVP_MD *(*hash_func) (void);
};

struct key_strength_test_case
{
  const char *name;
  int bits;
};

/* Hash functions to test - only including modern, supported algorithms */
static struct hash_test_case hash_test_cases[] = {
  { "SHA-256", EVP_sha256 }, /* Most common, widely supported */
  { "SHA-384", EVP_sha384 }, /* High security */
  { "SHA-512", EVP_sha512 }, /* Highest security */
  { NULL, NULL } /* Terminator */
};

/* Key strengths to test */
static struct key_strength_test_case key_strength_test_cases[] = {
  { "512-bit", 512 }, /* Weak, but requested for testing */
  { "1024-bit", 1024 }, /* Deprecated but still used */
  { "2048-bit", 2048 }, /* Current standard */
  { "4096-bit", 4096 }, /* High security */
  { NULL, 0 } /* Terminator */
};

static int
create_cert_with_params (TALLOC_CTX *mem_ctx,
                         const char *hash_name,
                         const EVP_MD *hash_func,
                         int key_strength,
                         struct sscg_x509_cert *ca_cert,
                         struct sscg_evp_pkey *ca_key,
                         enum sscg_cert_type cert_type,
                         struct sscg_x509_cert **_cert,
                         struct sscg_evp_pkey **_key)
{
  int ret;
  struct sscg_options *options;

  /* Set up test options for this specific test */
  ret = setup_test_options (mem_ctx, &options);
  if (ret != EOK)
    {
      return ret;
    }

  /* Override with test-specific parameters */
  options->hash_fn = hash_func;
  options->key_strength = key_strength;

  /* Allow weak keys for testing purposes */
  options->minimum_key_strength = 512;

  /* Create certificate with specified parameters */
  ret =
    create_cert (mem_ctx, options, ca_cert, ca_key, cert_type, _cert, _key);

  return ret;
}

static int
verify_certificate_basic_properties (struct sscg_x509_cert *cert,
                                     struct sscg_evp_pkey *key,
                                     struct sscg_x509_cert *ca_cert)
{
  X509 *x509 = cert->certificate;
  EVP_PKEY *pkey = key->evp_pkey;
  X509 *ca_x509 = ca_cert->certificate;

  /* Verify certificate has a serial number */
  ASN1_INTEGER *serial = X509_get_serialNumber (x509);
  if (!serial)
    {
      printf ("Certificate missing serial number.\n");
      return EINVAL;
    }

  /* Verify certificate has valid dates */
  ASN1_TIME *not_before = X509_get_notBefore (x509);
  ASN1_TIME *not_after = X509_get_notAfter (x509);
  if (!not_before || !not_after)
    {
      printf ("Certificate missing validity dates.\n");
      return EINVAL;
    }

  /* Verify the certificate was signed by the CA */
  EVP_PKEY *ca_pubkey = X509_get_pubkey (ca_x509);
  if (!ca_pubkey)
    {
      printf ("Could not extract CA public key.\n");
      return EINVAL;
    }

  int verify_result = X509_verify (x509, ca_pubkey);
  EVP_PKEY_free (ca_pubkey);

  if (verify_result != 1)
    {
      printf ("Certificate verification against CA failed.\n");
      return EINVAL;
    }

  /* Verify the private key matches the certificate */
  if (X509_check_private_key (x509, pkey) != 1)
    {
      printf ("Private key does not match certificate.\n");
      return EINVAL;
    }

  return EOK;
}

static int
verify_server_certificate_extensions (struct sscg_x509_cert *cert)
{
  X509 *x509 = cert->certificate;

  /* Check for Key Usage extension */
  int key_usage = X509_get_key_usage (x509);
  if (!(key_usage & X509v3_KU_DIGITAL_SIGNATURE) ||
      !(key_usage & X509v3_KU_KEY_ENCIPHERMENT))
    {
      printf ("Server certificate missing required key usage extensions.\n");
      return EINVAL;
    }

  return EOK;
}

int
main (int argc, char **argv)
{
  int ret;
  size_t initial_blocks, final_blocks;
  struct sscg_options *options = NULL;
  struct sscg_x509_cert *ca_cert = NULL;
  struct sscg_evp_pkey *ca_key = NULL;
  struct sscg_x509_cert *server_cert = NULL;
  struct sscg_evp_pkey *server_key = NULL;
  struct sscg_x509_cert *client_cert = NULL;
  struct sscg_evp_pkey *client_key = NULL;

  /* Enable talloc leak reporting for memory leak detection */
  talloc_enable_leak_report_full ();

  /* Record initial memory state for leak detection */
  initial_blocks = talloc_total_blocks (NULL);

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  printf ("=== SSCG Create Cert Test with Talloc Leak Detection ===\n");
  printf ("Initial talloc blocks: %zu\n", initial_blocks);

  /* Test 1: Set up test options */
  printf ("Setting up test options. ");
  ret = setup_test_options (tmp_ctx, &options);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 2: Create a private CA for testing */
  printf ("Creating private CA for testing. ");
  ret = create_private_CA (tmp_ctx, options, &ca_cert, &ca_key);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 3: Create a server certificate */
  printf ("Creating server certificate. ");
  ret = create_cert (tmp_ctx,
                     options,
                     ca_cert,
                     ca_key,
                     SSCG_CERT_TYPE_SERVER,
                     &server_cert,
                     &server_key);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 4: Verify server certificate properties */
  printf ("Verifying server certificate properties. ");
  ret = verify_certificate_basic_properties (server_cert, server_key, ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 5: Verify server certificate extensions */
  printf ("Verifying server certificate extensions. ");
  ret = verify_server_certificate_extensions (server_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 6: Create a client certificate */
  printf ("Creating client certificate. ");
  ret = create_cert (tmp_ctx,
                     options,
                     ca_cert,
                     ca_key,
                     SSCG_CERT_TYPE_CLIENT,
                     &client_cert,
                     &client_key);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 7: Verify client certificate properties */
  printf ("Verifying client certificate properties. ");
  ret = verify_certificate_basic_properties (client_cert, client_key, ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 8: Verify certificates are different */
  printf ("Verifying server and client certificates are different. ");
  if (X509_cmp (server_cert->certificate, client_cert->certificate) == 0)
    {
      printf ("FAILED. Server and client certificates are identical.\n");
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test 9: Test error handling with invalid certificate type */
  printf ("Testing error handling with invalid certificate type. ");
  struct sscg_x509_cert *invalid_cert = NULL;
  struct sscg_evp_pkey *invalid_key = NULL;

  ret = create_cert (tmp_ctx,
                     options,
                     ca_cert,
                     ca_key,
                     SSCG_CERT_TYPE_UNKNOWN,
                     &invalid_cert,
                     &invalid_key);
  if (ret == EOK)
    {
      printf ("FAILED. Expected error but got success.\n");
      ret = EINVAL;
      goto done;
    }
  printf ("SUCCESS. Correctly failed with invalid certificate type.\n");

  /* Test 10: Test memory management with isolated context */
  printf ("Testing memory management with isolated context. ");

  TALLOC_CTX *isolated_ctx = talloc_new (NULL);
  if (!isolated_ctx)
    {
      printf ("FAILED. Could not create isolated context.\n");
      ret = ENOMEM;
      goto done;
    }

  struct sscg_x509_cert *isolated_cert = NULL;
  struct sscg_evp_pkey *isolated_key = NULL;

  ret = create_cert (isolated_ctx,
                     options,
                     ca_cert,
                     ca_key,
                     SSCG_CERT_TYPE_SERVER,
                     &isolated_cert,
                     &isolated_key);
  if (ret != EOK)
    {
      printf ("FAILED. Could not create certificate in isolated context.\n");
      talloc_free (isolated_ctx);
      goto done;
    }

  /* Verify the certificate in isolated context */
  ret =
    verify_certificate_basic_properties (isolated_cert, isolated_key, ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED. Isolated certificate verification failed.\n");
      talloc_free (isolated_ctx);
      goto done;
    }

  /* Clean up isolated context */
  talloc_free (isolated_ctx);
  printf ("SUCCESS.\n");

  /* Test 11: Comprehensive hash function testing */
  printf ("\n=== Comprehensive Hash Function Testing ===\n");

  for (int h = 0; hash_test_cases[h].name != NULL; h++)
    {
      printf ("Testing %s hash function. ", hash_test_cases[h].name);

      struct sscg_x509_cert *hash_test_cert = NULL;
      struct sscg_evp_pkey *hash_test_key = NULL;

      ret = create_cert_with_params (
        tmp_ctx,
        hash_test_cases[h].name,
        hash_test_cases[h].hash_func (),
        2048, /* Use standard key size for hash tests */
        ca_cert,
        ca_key,
        SSCG_CERT_TYPE_SERVER,
        &hash_test_cert,
        &hash_test_key);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          goto done;
        }

      ret = verify_certificate_basic_properties (
        hash_test_cert, hash_test_key, ca_cert);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          goto done;
        }

      printf ("SUCCESS.\n");
    }

  /* Test 12: Comprehensive key strength testing */
  printf ("\n=== Comprehensive Key Strength Testing ===\n");

  for (int k = 0; key_strength_test_cases[k].name != NULL; k++)
    {
      printf ("Testing %s key strength. ", key_strength_test_cases[k].name);

      struct sscg_x509_cert *key_test_cert = NULL;
      struct sscg_evp_pkey *key_test_key = NULL;

      ret = create_cert_with_params (tmp_ctx,
                                     "SHA-256",
                                     EVP_sha256 (),
                                     key_strength_test_cases[k].bits,
                                     ca_cert,
                                     ca_key,
                                     SSCG_CERT_TYPE_SERVER,
                                     &key_test_cert,
                                     &key_test_key);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          goto done;
        }

      ret = verify_certificate_basic_properties (
        key_test_cert, key_test_key, ca_cert);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          goto done;
        }

      printf ("SUCCESS.\n");
    }

  /* Test 13: Matrix testing - critical combinations */
  printf ("\n=== Matrix Testing - Critical Combinations ===\n");

  /* Test a representative subset to avoid excessive test time */
  struct
  {
    const char *hash_name;
    const EVP_MD *(*hash_func) (void);
    const char *key_name;
    int key_bits;
  } matrix_tests[] = { { "SHA-256", EVP_sha256, "1024-bit", 1024 },
                       { "SHA-256", EVP_sha256, "4096-bit", 4096 },
                       { "SHA-384", EVP_sha384, "2048-bit", 2048 },
                       { "SHA-512", EVP_sha512, "2048-bit", 2048 },
                       { "SHA-512", EVP_sha512, "4096-bit", 4096 },
                       { NULL, NULL, NULL, 0 } };

  for (int m = 0; matrix_tests[m].hash_name != NULL; m++)
    {
      printf ("Testing %s with %s. ",
              matrix_tests[m].hash_name,
              matrix_tests[m].key_name);

      struct sscg_x509_cert *matrix_cert = NULL;
      struct sscg_evp_pkey *matrix_key = NULL;

      ret = create_cert_with_params (
        tmp_ctx,
        matrix_tests[m].hash_name,
        matrix_tests[m].hash_func (),
        matrix_tests[m].key_bits,
        ca_cert,
        ca_key,
        SSCG_CERT_TYPE_CLIENT, /* Use client for variety */
        &matrix_cert,
        &matrix_key);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          goto done;
        }

      ret =
        verify_certificate_basic_properties (matrix_cert, matrix_key, ca_cert);
      if (ret != EOK)
        {
          printf ("FAILED.\n");
          goto done;
        }

      printf ("SUCCESS.\n");
    }

  /* Test 14: Performance test with high-security parameters */
  printf ("\n=== High-Security Parameters Test ===\n");
  printf ("Testing SHA-512 with 4096-bit key (high-security). ");

  struct sscg_x509_cert *high_sec_cert = NULL;
  struct sscg_evp_pkey *high_sec_key = NULL;

  ret = create_cert_with_params (tmp_ctx,
                                 "SHA-512",
                                 EVP_sha512 (),
                                 4096,
                                 ca_cert,
                                 ca_key,
                                 SSCG_CERT_TYPE_SERVER,
                                 &high_sec_cert,
                                 &high_sec_key);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }

  ret =
    verify_certificate_basic_properties (high_sec_cert, high_sec_key, ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }

  printf ("SUCCESS.\n");

  printf ("\n=== Comprehensive Testing Complete ===\n");
  ret = EOK;

done:
  /* Clean up main test context */
  talloc_free (tmp_ctx);

  /* Check for memory leaks */
  final_blocks = talloc_total_blocks (NULL);
  printf ("\n=== Talloc Leak Detection Report ===\n");
  printf ("Initial talloc blocks: %zu\n", initial_blocks);
  printf ("Final talloc blocks: %zu\n", final_blocks);

  if (final_blocks > initial_blocks)
    {
      printf ("FAILED: Memory leak detected! %zu blocks leaked.\n",
              final_blocks - initial_blocks);
      printf ("Detailed leak report:\n");
      talloc_report_full (NULL, stderr);
      /* Fail the test when leaks are detected */
      ret = ENOMEM;
    }
  else
    {
      printf ("SUCCESS: No memory leaks detected.\n");
    }

  printf ("=== Test Complete ===\n");
  return ret;
}
