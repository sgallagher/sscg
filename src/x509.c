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

    Copyright 2017 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <openssl/err.h>
#include <openssl/evp.h>

#include <sys/param.h>
#include <string.h>
#include "include/sscg.h"
#include "include/key.h"
#include "include/x509.h"
#include "include/bignum.h"

int
sscg_generate_serial (TALLOC_CTX *mem_ctx, struct sscg_bignum **serial)
{
  int ret = EOK;
  int bnret;
  struct sscg_bignum *bn;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  ret = sscg_init_bignum (tmp_ctx, 0, &bn);
  CHECK_OK (ret);

  /* We'll create a random number of sizeof(unsigned long) - 1 bits
       to use as the serial. We use unsigned long to ensure that it
       could be printed by BN_get_word() later. We omit the last bit
       in order to ensure that we can't randomly get 0xffffffffL, which
       is reserved by BN_get_word() to mean "too large to represent". */
  bnret = BN_pseudo_rand (bn->bn,
                          (sizeof (unsigned long) * CHAR_BIT) - 1,
                          BN_RAND_TOP_ANY,
                          BN_RAND_BOTTOM_ANY);
  CHECK_SSL (bnret, BN_pseudo_rand);

  ret = EOK;

done:
  if (ret == EOK)
    {
      *serial = talloc_steal (mem_ctx, bn);
    }
  talloc_zfree (tmp_ctx);

  return ret;
}

static int
_sscg_certinfo_destructor (TALLOC_CTX *ctx)
{
  struct sscg_cert_info *certinfo =
    talloc_get_type_abort (ctx, struct sscg_cert_info);

  sk_X509_EXTENSION_pop_free(certinfo->extensions, X509_EXTENSION_free);

  return 0;
}

struct sscg_cert_info *
sscg_cert_info_new (TALLOC_CTX *mem_ctx, const EVP_MD *hash_fn)
{
  int ret;
  struct sscg_cert_info *certinfo;

  certinfo = talloc_zero (mem_ctx, struct sscg_cert_info);
  CHECK_MEM (certinfo);

  if (hash_fn)
    {
      certinfo->hash_fn = hash_fn;
    }
  else
    {
      certinfo->hash_fn = EVP_sha256 ();
    }

  /* Allocate space for the stack of extensions */
  certinfo->extensions = sk_X509_EXTENSION_new_null ();
  CHECK_MEM (certinfo->extensions);
  talloc_set_destructor ((TALLOC_CTX *)certinfo, _sscg_certinfo_destructor);

  ret = EOK;
done:
  if (ret != EOK)
    {
      talloc_free (certinfo);
      return NULL;
    }
  return certinfo;
}

static int
_sscg_csr_destructor (TALLOC_CTX *ctx)
{
  struct sscg_x509_req *csr =
    talloc_get_type_abort (ctx, struct sscg_x509_req);

  X509_REQ_free (csr->x509_req);

  return 0;
}

int
sscg_x509v3_csr_new (TALLOC_CTX *mem_ctx,
                     struct sscg_cert_info *certinfo,
                     struct sscg_evp_pkey *spkey,
                     struct sscg_x509_req **_csr)
{
  int ret, sslret;
  size_t i;
  X509_NAME *subject;
  char *alt_name = NULL;
  char *tmp = NULL;
  char *san = NULL;
  TALLOC_CTX *tmp_ctx;
  X509_EXTENSION *ex = NULL;
  struct sscg_x509_req *csr;

  /* Make sure we have a key available */
  if (!talloc_get_type (spkey, struct sscg_evp_pkey))
    {
      return EINVAL;
    }

  tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  csr = talloc_zero (tmp_ctx, struct sscg_x509_req);
  CHECK_MEM (csr);

  csr->x509_req = X509_REQ_new ();
  CHECK_MEM (csr->x509_req);

  talloc_set_destructor ((TALLOC_CTX *)csr, _sscg_csr_destructor);

  /* We will generate only x509v3 certificates */
  sslret = X509_REQ_set_version (csr->x509_req, 2);
  CHECK_SSL (sslret, X509_REQ_set_version);

  subject = X509_REQ_get_subject_name (csr->x509_req);

  /* Country */
  sslret =
    X509_NAME_add_entry_by_NID (subject,
                                NID_countryName,
                                MBSTRING_UTF8,
                                (const unsigned char *)certinfo->country,
                                -1,
                                -1,
                                0);
  CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (C));

  /* State or Principality */
  if (certinfo->state && certinfo->state[0])
    {
      sslret =
        X509_NAME_add_entry_by_NID (subject,
                                    NID_stateOrProvinceName,
                                    MBSTRING_UTF8,
                                    (const unsigned char *)certinfo->state,
                                    -1,
                                    -1,
                                    0);
      CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (ST));
    }

  /* Locality */
  if (certinfo->locality && certinfo->locality[0])
    {
      sslret =
        X509_NAME_add_entry_by_NID (subject,
                                    NID_localityName,
                                    MBSTRING_UTF8,
                                    (const unsigned char *)certinfo->locality,
                                    -1,
                                    -1,
                                    0);
      CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (L));
    }

  /* Organization */
  if (certinfo->org && certinfo->org[0])
    {
      sslret =
        X509_NAME_add_entry_by_NID (subject,
                                    NID_organizationName,
                                    MBSTRING_UTF8,
                                    (const unsigned char *)certinfo->org,
                                    -1,
                                    -1,
                                    0);
      CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (O));
    }

  /* Organizational Unit */
  if (certinfo->org_unit && certinfo->org_unit[0])
    {
      sslret =
        X509_NAME_add_entry_by_NID (subject,
                                    NID_organizationalUnitName,
                                    MBSTRING_UTF8,
                                    (const unsigned char *)certinfo->org_unit,
                                    -1,
                                    -1,
                                    0);
      CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (OU));
    }

  /* Common Name */
  sslret = X509_NAME_add_entry_by_NID (subject,
                                       NID_commonName,
                                       MBSTRING_UTF8,
                                       (const unsigned char *)certinfo->cn,
                                       -1,
                                       -1,
                                       0);
  CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (CN));

  /* Email Address */
  if (certinfo->email && certinfo->email[0])
    {
      sslret =
        X509_NAME_add_entry_by_NID (subject,
                                    NID_pkcs9_emailAddress,
                                    MBSTRING_UTF8,
                                    (const unsigned char *)certinfo->email,
                                    -1,
                                    -1,
                                    0);
      CHECK_SSL (sslret, X509_NAME_add_entry_by_NID (Email));
    }

  /* SubjectAltNames */
  alt_name = talloc_asprintf (tmp_ctx, "DNS:%s", certinfo->cn);
  CHECK_MEM (alt_name);

  if (certinfo->subject_alt_names)
    {
      for (i = 0; certinfo->subject_alt_names[i]; i++)
        {
          if (!strchr (certinfo->subject_alt_names[i], ':'))
            {
              san = talloc_asprintf (
                tmp_ctx, "DNS:%s", certinfo->subject_alt_names[i]);
            }
          else
            {
              san = talloc_strdup (tmp_ctx, certinfo->subject_alt_names[i]);
            }
          CHECK_MEM (san);

          if (strnlen (san, MAXHOSTNAMELEN + 5) > MAXHOSTNAMELEN + 4)
            {
              fprintf (stderr,
                       "Hostnames may not exceed %d characters in Subject "
                       "Alternative Names\n",
                       MAXHOSTNAMELEN);
              ret = EINVAL;
              goto done;
            }

          tmp = talloc_asprintf (tmp_ctx, "%s, %s", alt_name, san);
          talloc_zfree (san);
          CHECK_MEM (tmp);
          talloc_free (alt_name);
          alt_name = tmp;
        }
    }

  ex = X509V3_EXT_conf_nid (NULL, NULL, NID_subject_alt_name, alt_name);
  CHECK_MEM (ex);
  sk_X509_EXTENSION_push (certinfo->extensions, ex);

  /* Set the public key for the certificate */
  sslret = X509_REQ_set_pubkey (csr->x509_req, spkey->evp_pkey);
  CHECK_SSL (sslret, X509_REQ_set_pubkey (OU));

  *_csr = talloc_steal (mem_ctx, csr);
  ret = EOK;

done:
  talloc_free (tmp_ctx);
  return ret;
}

int
sscg_x509v3_csr_finalize (struct sscg_cert_info *certinfo,
                          struct sscg_evp_pkey *spkey,
                          struct sscg_x509_req *csr)
{
  int ret, sslret;

  /* Add extensions */
  sslret = X509_REQ_add_extensions (csr->x509_req, certinfo->extensions);
  CHECK_SSL (sslret, X509_REQ_add_extensions);

  /* Set the private key */
  sslret = X509_REQ_sign (csr->x509_req, spkey->evp_pkey, certinfo->hash_fn);
  if (sslret <= 0)
    {
      /* Get information about error from OpenSSL */
      fprintf (stderr,
               "Error occurred in X509_REQ_sign: [%s].\n",
               ERR_error_string (ERR_get_error (), NULL));
      ret = EIO;
      goto done;
    }

  ret = EOK;
done:
  return ret;
}

static int
_sscg_cert_destructor (TALLOC_CTX *ctx)
{
  struct sscg_x509_cert *cert =
    talloc_get_type_abort (ctx, struct sscg_x509_cert);

  X509_free (cert->certificate);

  return 0;
}

struct sscg_x509_cert *
sscg_x509_cert_new (TALLOC_CTX *mem_ctx)
{
  int ret, sslret;
  struct sscg_x509_cert *cert = talloc_zero (NULL, struct sscg_x509_cert);
  CHECK_MEM (cert);

  cert->certificate = X509_new ();
  CHECK_MEM (cert->certificate);
  talloc_set_destructor ((TALLOC_CTX *)cert, _sscg_cert_destructor);

  // set version to X509 v3 certificate
  sslret = X509_set_version (cert->certificate, 2);
  CHECK_SSL (sslret, X509_set_version);

  ret = EOK;
done:
  if (ret != EOK)
    {
      talloc_free (cert);
      return NULL;
    }

  return talloc_steal (mem_ctx, cert);
}

int
sscg_sign_x509_csr (TALLOC_CTX *mem_ctx,
                    struct sscg_x509_req *scsr,
                    struct sscg_bignum *serial,
                    size_t days,
                    struct sscg_x509_cert *issuer,
                    struct sscg_evp_pkey *signing_key,
                    const EVP_MD *hash_fn,
                    struct sscg_x509_cert **_cert)
{
  int ret, sslret;
  size_t i;
  struct sscg_x509_cert *scert = NULL;
  X509 *cert;
  X509_REQ *csr = NULL;
  X509_NAME *subject = NULL;
  EVP_PKEY *pktmp;
  STACK_OF (X509_EXTENSION) *extensions = NULL;
  X509_EXTENSION *ext;
  X509V3_CTX x509v3_ctx;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  CHECK_MEM (tmp_ctx);

  X509V3_set_ctx_nodb (&x509v3_ctx);

  scert = sscg_x509_cert_new (tmp_ctx);
  CHECK_MEM (scert);

  /* Easier shorthand */
  cert = scert->certificate;
  csr = scsr->x509_req;

  /* Set the serial number for the new certificate */
  BN_to_ASN1_INTEGER (serial->bn, X509_get_serialNumber (cert));

  /* set the issuer name */
  if (issuer)
    {
      X509_set_issuer_name (cert, X509_get_subject_name (issuer->certificate));
    }
  else
    {
      /* If unspecified, it's self-signing */
      X509_set_issuer_name (cert, X509_REQ_get_subject_name (csr));
    }

  /* set time */
  X509_gmtime_adj (X509_get_notBefore (cert), 0);
  X509_gmtime_adj (X509_get_notAfter (cert), days * 24 * 3650);

  /* set subject */
  subject = X509_NAME_dup (X509_REQ_get_subject_name (csr));
  sslret = X509_set_subject_name (cert, subject);
  CHECK_SSL (sslret, X509_set_subject_name);

  /* Copy the extensions from the CSR */
  extensions = X509_REQ_get_extensions (csr);
  for (i = 0; i < sk_X509_EXTENSION_num (extensions); i++)
    {
      ext = sk_X509_EXTENSION_value (extensions, i);
      sslret = X509_add_ext (cert, ext, -1);
      CHECK_SSL (sslret, X509_add_ext);
    }
  sk_X509_EXTENSION_pop_free (extensions, X509_EXTENSION_free);

  /* set pubkey from req */
  pktmp = X509_REQ_get_pubkey (csr);
  sslret = X509_set_pubkey (cert, pktmp);
  EVP_PKEY_free (pktmp);
  CHECK_SSL (sslret, X509_set_pubkey);

  if (issuer)
    {
      X509V3_set_ctx (&x509v3_ctx, issuer->certificate, cert, NULL, NULL, 0);
      /* Set the Authority Key Identifier extension */
      ext = X509V3_EXT_conf_nid (NULL,
                                 &x509v3_ctx,
                                 NID_authority_key_identifier,
                                 "keyid:always,issuer");
      if (!ext)
        {
          /* Get information about error from OpenSSL */
          fprintf (stderr,
                   "Error occurred in "
                   "X509V3_EXT_conf_nid(AuthorityKeyIdentifier): [%s].\n",
                   ERR_error_string (ERR_get_error (), NULL));
          ret = EIO;
          goto done;
        }
      sslret = X509_add_ext (cert, ext, -1);
      CHECK_SSL (sslret, X509_add_ext);

      X509_EXTENSION_free (ext);
    }

  /* Sign the new certificate */
  sslret = X509_sign (cert, signing_key->evp_pkey, hash_fn);
  if (sslret <= 0)
    {
      /* Get information about error from OpenSSL */
      fprintf (stderr,
               "Error occurred in X509_sign: [%s].\n",
               ERR_error_string (ERR_get_error (), NULL));
      ret = EIO;
      goto done;
    }

  ret = EOK;
done:
  if (ret == EOK)
    {
      *_cert = talloc_steal (mem_ctx, scert);
    }
  X509_NAME_free (subject);
  talloc_free (tmp_ctx);
  return ret;
}
