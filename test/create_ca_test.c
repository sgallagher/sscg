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

    Copyright 2017-2025 by Stephen Gallagher <sgallagh@redhat.com>
*/

#include <errno.h>
#include <stdio.h>
#include <talloc.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#include "include/sscg.h"
#include "include/x509.h"
#include "include/authority.h"

static int
verify_subject_alt_names (struct sscg_x509_cert *cert)
{
  X509 *x509 = cert->certificate;
  STACK_OF (GENERAL_NAME) *san_names = NULL;
  GENERAL_NAME *name = NULL;
  ASN1_STRING *san_str = NULL;
  int san_count = 0;
  int found_primary_cn = 0;
  int found_alt1 = 0;
  int found_alt2 = 0;
  int found_ip4_1 = 0;
  int found_ip4_2 = 0;
  int found_ip6 = 0;
  int found_ip4_netmask = 0;
  int found_ip6_netmask = 0;
  int found_email = 0;
  int found_uri = 0;
  int found_wildcard = 0;
  int found_subdomain = 0;
  int found_international = 0;
  char *name_str = NULL;

  /* Get the Subject Alternative Name extension */
  san_names = X509_get_ext_d2i (x509, NID_subject_alt_name, NULL, NULL);
  if (!san_names)
    {
      printf ("Certificate missing Subject Alternative Name extension.\n");
      return EINVAL;
    }

  san_count = sk_GENERAL_NAME_num (san_names);
  printf ("\n    Processing %d Subject Alternative Names:\n", san_count);

  /* Check each SAN entry */
  for (int i = 0; i < san_count; i++)
    {
      name = sk_GENERAL_NAME_value (san_names, i);

      switch (name->type)
        {
        case GEN_DNS:
          san_str = name->d.dNSName;
          name_str = (char *)ASN1_STRING_get0_data (san_str);
          printf ("      DNS: %s\n", name_str);

          if (strcmp (name_str, "server.example.com") == 0)
            found_primary_cn = 1;
          else if (strcmp (name_str, "alt1.example.com") == 0)
            found_alt1 = 1;
          else if (strcmp (name_str, "alt2.example.com") == 0)
            found_alt2 = 1;
          else if (strcmp (name_str, "*.wildcard.example.com") == 0)
            found_wildcard = 1;
          else if (strcmp (name_str, "subdomain.alt1.example.com") == 0)
            found_subdomain = 1;
          else if (strcmp (name_str, "xn--nxasmq6b.example.com") == 0)
            found_international = 1;
          break;

        case GEN_IPADD:
          san_str = name->d.iPAddress;
          /* IP addresses are stored as binary data */
          if (ASN1_STRING_length (san_str) == 4) /* IPv4 */
            {
              const unsigned char *ip_data = ASN1_STRING_get0_data (san_str);
              printf ("      IP (IPv4): %d.%d.%d.%d\n",
                      ip_data[0],
                      ip_data[1],
                      ip_data[2],
                      ip_data[3]);

              if (ip_data[0] == 192 && ip_data[1] == 168 && ip_data[2] == 1 &&
                  ip_data[3] == 100)
                found_ip4_1 = 1;
              else if (ip_data[0] == 10 && ip_data[1] == 0 &&
                       ip_data[2] == 0 && ip_data[3] == 1)
                found_ip4_2 = 1;
              else if (ip_data[0] == 203 && ip_data[1] == 0 &&
                       ip_data[2] == 113 && ip_data[3] == 0)
                found_ip4_netmask = 1;
            }
          else if (ASN1_STRING_length (san_str) == 16) /* IPv6 */
            {
              const unsigned char *ip_data = ASN1_STRING_get0_data (san_str);
              printf ("      IP (IPv6): ");
              for (int j = 0; j < 16; j += 2)
                {
                  printf ("%02x%02x", ip_data[j], ip_data[j + 1]);
                  if (j < 14)
                    printf (":");
                }
              printf ("\n");

              /* Check for 2001:db8::1 */
              if (ip_data[0] == 0x20 && ip_data[1] == 0x01 &&
                  ip_data[2] == 0x0d && ip_data[3] == 0xb8 &&
                  ip_data[4] == 0x00 && ip_data[5] == 0x00 &&
                  ip_data[6] == 0x00 && ip_data[7] == 0x00 &&
                  ip_data[8] == 0x00 && ip_data[9] == 0x00 &&
                  ip_data[10] == 0x00 && ip_data[11] == 0x00 &&
                  ip_data[12] == 0x00 && ip_data[13] == 0x00 &&
                  ip_data[14] == 0x00 && ip_data[15] == 0x01)
                found_ip6 = 1;
              /* Check for 2001:db8:85a3:: (netmask stripped) */
              else if (ip_data[0] == 0x20 && ip_data[1] == 0x01 &&
                       ip_data[2] == 0x0d && ip_data[3] == 0xb8 &&
                       ip_data[4] == 0x85 && ip_data[5] == 0xa3 &&
                       ip_data[6] == 0x00 && ip_data[7] == 0x00 &&
                       ip_data[8] == 0x00 && ip_data[9] == 0x00 &&
                       ip_data[10] == 0x00 && ip_data[11] == 0x00 &&
                       ip_data[12] == 0x00 && ip_data[13] == 0x00 &&
                       ip_data[14] == 0x00 && ip_data[15] == 0x00)
                found_ip6_netmask = 1;
            }
          break;

        case GEN_EMAIL:
          san_str = name->d.rfc822Name;
          name_str = (char *)ASN1_STRING_get0_data (san_str);
          printf ("      Email: %s\n", name_str);

          if (strcmp (name_str, "admin@example.com") == 0)
            found_email = 1;
          break;

        case GEN_URI:
          san_str = name->d.uniformResourceIdentifier;
          name_str = (char *)ASN1_STRING_get0_data (san_str);
          printf ("      URI: %s\n", name_str);

          if (strcmp (name_str, "https://www.example.com/service") == 0)
            found_uri = 1;
          break;

        default: printf ("      Other type: %d\n", name->type); break;
        }
    }

  GENERAL_NAMES_free (san_names);

  /* Verify all expected SANs were found */
  int missing_count = 0;

  if (!found_primary_cn)
    {
      printf (
        "    MISSING: Primary CN not found in Subject Alternative Names.\n");
      missing_count++;
    }

  if (!found_alt1)
    {
      printf (
        "    MISSING: alt1.example.com not found in Subject Alternative "
        "Names.\n");
      missing_count++;
    }

  if (!found_alt2)
    {
      printf (
        "    MISSING: alt2.example.com not found in Subject Alternative "
        "Names.\n");
      missing_count++;
    }

  if (!found_ip4_1)
    {
      printf (
        "    MISSING: IPv4 192.168.1.100 not found in Subject Alternative "
        "Names.\n");
      missing_count++;
    }

  if (!found_ip4_2)
    {
      printf (
        "    MISSING: IPv4 10.0.0.1 not found in Subject Alternative "
        "Names.\n");
      missing_count++;
    }

  if (!found_ip6)
    {
      printf (
        "    MISSING: IPv6 2001:db8::1 not found in Subject Alternative "
        "Names.\n");
      missing_count++;
    }

  if (!found_ip4_netmask)
    {
      printf (
        "    MISSING: IPv4 203.0.113.0 (from 203.0.113.0/24, netmask "
        "stripped) not found in Subject Alternative Names.\n");
      missing_count++;
    }

  if (!found_ip6_netmask)
    {
      printf (
        "    MISSING: IPv6 2001:db8:85a3:: (from 2001:db8:85a3::/64, netmask "
        "stripped) not found in Subject Alternative Names.\n");
      missing_count++;
    }

  if (!found_email)
    {
      printf (
        "    MISSING: Email admin@example.com not found in Subject "
        "Alternative Names.\n");
      missing_count++;
    }

  if (!found_uri)
    {
      printf (
        "    MISSING: URI https://www.example.com/service not found in "
        "Subject Alternative Names.\n");
      missing_count++;
    }

  if (!found_wildcard)
    {
      printf (
        "    MISSING: Wildcard *.wildcard.example.com not found in Subject "
        "Alternative Names.\n");
      missing_count++;
    }

  if (!found_subdomain)
    {
      printf (
        "    MISSING: Subdomain subdomain.alt1.example.com not found in "
        "Subject Alternative Names.\n");
      missing_count++;
    }

  if (!found_international)
    {
      printf (
        "    MISSING: International domain xn--nxasmq6b.example.com not found "
        "in Subject Alternative Names.\n");
      missing_count++;
    }

  if (missing_count > 0)
    {
      printf ("    %d expected SAN entries were missing.\n", missing_count);
      return EINVAL;
    }

  printf ("    All expected SAN entries found successfully.\n");
  return EOK;
}

static int
test_san_edge_cases (struct sscg_x509_cert *cert)
{
  X509 *x509 = cert->certificate;
  STACK_OF (GENERAL_NAME) *san_names = NULL;
  GENERAL_NAME *name = NULL;
  ASN1_STRING *san_str = NULL;
  int san_count = 0;
  int dns_count = 0;
  int ip_count = 0;
  int email_count = 0;
  int uri_count = 0;
  char *name_str = NULL;

  /* Get the Subject Alternative Name extension */
  san_names = X509_get_ext_d2i (x509, NID_subject_alt_name, NULL, NULL);
  if (!san_names)
    {
      printf ("Certificate missing Subject Alternative Name extension.\n");
      return EINVAL;
    }

  san_count = sk_GENERAL_NAME_num (san_names);

  printf ("\n    Performing comprehensive SAN validation:\n");

  /* Count and validate all SAN types */
  for (int i = 0; i < san_count; i++)
    {
      name = sk_GENERAL_NAME_value (san_names, i);

      switch (name->type)
        {
        case GEN_DNS:
          dns_count++;
          san_str = name->d.dNSName;
          name_str = (char *)ASN1_STRING_get0_data (san_str);

          /* Validate DNS name format */
          if (strlen (name_str) == 0)
            {
              printf ("      ERROR: Empty DNS name found in SANs.\n");
              GENERAL_NAMES_free (san_names);
              return EINVAL;
            }

          /* Allow wildcards and validate domain format */
          if (name_str[0] != '*' && !strchr (name_str, '.'))
            {
              printf ("      ERROR: DNS name '%s' missing domain part.\n",
                      name_str);
              GENERAL_NAMES_free (san_names);
              return EINVAL;
            }

          /* Validate wildcard format */
          if (name_str[0] == '*' && name_str[1] != '.')
            {
              printf ("      ERROR: Invalid wildcard DNS name '%s'.\n",
                      name_str);
              GENERAL_NAMES_free (san_names);
              return EINVAL;
            }
          break;

        case GEN_IPADD:
          ip_count++;
          san_str = name->d.iPAddress;

          /* Validate IP address length */
          int ip_len = ASN1_STRING_length (san_str);
          if (ip_len != 4 && ip_len != 16) /* IPv4 or IPv6 */
            {
              printf ("      ERROR: Invalid IP address length: %d bytes.\n",
                      ip_len);
              GENERAL_NAMES_free (san_names);
              return EINVAL;
            }
          break;

        case GEN_EMAIL:
          email_count++;
          san_str = name->d.rfc822Name;
          name_str = (char *)ASN1_STRING_get0_data (san_str);

          /* Validate email format */
          if (!strchr (name_str, '@'))
            {
              printf ("      ERROR: Invalid email address '%s' - missing @.\n",
                      name_str);
              GENERAL_NAMES_free (san_names);
              return EINVAL;
            }
          break;

        case GEN_URI:
          uri_count++;
          san_str = name->d.uniformResourceIdentifier;
          name_str = (char *)ASN1_STRING_get0_data (san_str);

          /* Validate URI format - must have scheme */
          if (!strstr (name_str, "://"))
            {
              printf ("      ERROR: Invalid URI '%s' - missing scheme.\n",
                      name_str);
              GENERAL_NAMES_free (san_names);
              return EINVAL;
            }
          break;

        default:
          /* Other SAN types are acceptable but not validated here */
          break;
        }
    }

  printf ("      Found %d total SANs: %d DNS, %d IP, %d Email, %d URI.\n",
          san_count,
          dns_count,
          ip_count,
          email_count,
          uri_count);

  /* Validate expected counts for comprehensive test */
  int expected_dns =
    6; /* CN + alt1 + alt2 + wildcard + subdomain + international */
  int expected_ip = 5; /* IPv4 x2 + IPv6 x1 + IPv4 netmask + IPv6 netmask */
  int expected_email = 1;
  int expected_uri = 1;

  if (dns_count < expected_dns)
    {
      printf ("      ERROR: Expected at least %d DNS names, found %d.\n",
              expected_dns,
              dns_count);
      GENERAL_NAMES_free (san_names);
      return EINVAL;
    }

  if (ip_count < expected_ip)
    {
      printf ("      ERROR: Expected at least %d IP addresses, found %d.\n",
              expected_ip,
              ip_count);
      GENERAL_NAMES_free (san_names);
      return EINVAL;
    }

  if (email_count < expected_email)
    {
      printf ("      ERROR: Expected at least %d email addresses, found %d.\n",
              expected_email,
              email_count);
      GENERAL_NAMES_free (san_names);
      return EINVAL;
    }

  if (uri_count < expected_uri)
    {
      printf ("      ERROR: Expected at least %d URIs, found %d.\n",
              expected_uri,
              uri_count);
      GENERAL_NAMES_free (san_names);
      return EINVAL;
    }

  printf ("      All SAN format validations passed successfully.\n");

  GENERAL_NAMES_free (san_names);
  return EOK;
}

static int
test_ip_netmask_handling (struct sscg_x509_cert *cert)
{
  X509 *x509 = cert->certificate;
  STACK_OF (GENERAL_NAME) *san_names = NULL;
  GENERAL_NAME *name = NULL;
  ASN1_STRING *san_str = NULL;
  int san_count = 0;
  int found_netmask_ipv4 = 0;
  int found_netmask_ipv6 = 0;

  /* Get the Subject Alternative Name extension */
  san_names = X509_get_ext_d2i (x509, NID_subject_alt_name, NULL, NULL);
  if (!san_names)
    {
      printf ("Certificate missing Subject Alternative Name extension.\n");
      return EINVAL;
    }

  san_count = sk_GENERAL_NAME_num (san_names);

  printf ("\n    Testing IP address netmask stripping:\n");

  /* Look specifically for IP addresses that had netmasks stripped */
  for (int i = 0; i < san_count; i++)
    {
      name = sk_GENERAL_NAME_value (san_names, i);

      if (name->type == GEN_IPADD)
        {
          san_str = name->d.iPAddress;

          if (ASN1_STRING_length (san_str) == 4) /* IPv4 */
            {
              const unsigned char *ip_data = ASN1_STRING_get0_data (san_str);

              /* Check for 203.0.113.0 (from original 203.0.113.0/24) */
              if (ip_data[0] == 203 && ip_data[1] == 0 && ip_data[2] == 113 &&
                  ip_data[3] == 0)
                {
                  printf (
                    "      ✓ IPv4 netmask stripped: 203.0.113.0/24 → "
                    "203.0.113.0\n");
                  found_netmask_ipv4 = 1;
                }
            }
          else if (ASN1_STRING_length (san_str) == 16) /* IPv6 */
            {
              const unsigned char *ip_data = ASN1_STRING_get0_data (san_str);

              /* Check for 2001:db8:85a3:: (from original 2001:db8:85a3::/64) */
              if (ip_data[0] == 0x20 && ip_data[1] == 0x01 &&
                  ip_data[2] == 0x0d && ip_data[3] == 0xb8 &&
                  ip_data[4] == 0x85 && ip_data[5] == 0xa3 &&
                  ip_data[6] == 0x00 && ip_data[7] == 0x00 &&
                  ip_data[8] == 0x00 && ip_data[9] == 0x00 &&
                  ip_data[10] == 0x00 && ip_data[11] == 0x00 &&
                  ip_data[12] == 0x00 && ip_data[13] == 0x00 &&
                  ip_data[14] == 0x00 && ip_data[15] == 0x00)
                {
                  printf (
                    "      ✓ IPv6 netmask stripped: 2001:db8:85a3::/64 → "
                    "2001:db8:85a3::\n");
                  found_netmask_ipv6 = 1;
                }
            }
        }
    }

  GENERAL_NAMES_free (san_names);

  /* Verify that netmask stripping worked correctly */
  if (!found_netmask_ipv4)
    {
      printf ("      ERROR: IPv4 netmask stripping test failed.\n");
      return EINVAL;
    }

  if (!found_netmask_ipv6)
    {
      printf ("      ERROR: IPv6 netmask stripping test failed.\n");
      return EINVAL;
    }

  printf ("      All IP address netmask tests passed successfully.\n");
  return EOK;
}

static int
verify_name_constraints (struct sscg_x509_cert *ca_cert,
                         char **expected_san_list)
{
  X509 *x509 = ca_cert->certificate;
  X509_EXTENSION *name_constraints_ext = NULL;
  ASN1_OCTET_STRING *ext_data = NULL;
  BIO *bio = NULL;
  char *ext_str = NULL;
  char *line = NULL;
  char *saveptr = NULL;
  size_t ext_str_len = 0;
  int found_constraints[20] = {
    0
  }; /* Track which expected constraints we found */
  int missing_count = 0;
  int j;

  printf ("\n    Verifying name constraints in CA certificate:\n");

  /* Find the name constraints extension */
  int ext_idx = X509_get_ext_by_NID (x509, NID_name_constraints, -1);
  if (ext_idx < 0)
    {
      printf (
        "      ERROR: CA certificate missing Name Constraints extension.\n");
      return EINVAL;
    }

  name_constraints_ext = X509_get_ext (x509, ext_idx);
  if (!name_constraints_ext)
    {
      printf ("      ERROR: Failed to get Name Constraints extension.\n");
      return EINVAL;
    }

  /* Get the extension data */
  ext_data = X509_EXTENSION_get_data (name_constraints_ext);
  if (!ext_data)
    {
      printf ("      ERROR: Failed to get Name Constraints extension data.\n");
      return EINVAL;
    }

  /* Convert the extension to a readable string using BIO */
  bio = BIO_new (BIO_s_mem ());
  if (!bio)
    {
      printf ("      ERROR: Failed to create BIO for extension parsing.\n");
      return EINVAL;
    }

  /* Print the extension to the BIO */
  if (!X509V3_EXT_print (bio, name_constraints_ext, 0, 0))
    {
      printf ("      ERROR: Failed to print Name Constraints extension.\n");
      BIO_free (bio);
      return EINVAL;
    }

  /* Get the string representation */
  ext_str_len = BIO_get_mem_data (bio, &ext_str);
  if (ext_str_len <= 0 || !ext_str)
    {
      printf ("      ERROR: Failed to get extension string data.\n");
      BIO_free (bio);
      return EINVAL;
    }

  /* Null-terminate the string for parsing */
  char *ext_str_copy = malloc (ext_str_len + 1);
  if (!ext_str_copy)
    {
      printf (
        "      ERROR: Failed to allocate memory for extension parsing.\n");
      BIO_free (bio);
      return ENOMEM;
    }
  memcpy (ext_str_copy, ext_str, ext_str_len);
  ext_str_copy[ext_str_len] = '\0';

  printf ("      Name Constraints content:\n%s\n", ext_str_copy);

  /* Parse the extension string to find constraints */
  line = strtok_r (ext_str_copy, "\n", &saveptr);
  while (line)
    {
      /* Look for "Permitted:" sections and DNS/IP entries */
      if (strstr (line, "DNS:"))
        {
          char *dns_start = strstr (line, "DNS:");
          if (dns_start)
            {
              dns_start += 4; /* Skip "DNS:" */
              /* Trim whitespace */
              while (*dns_start == ' ' || *dns_start == '\t')
                dns_start++;

              printf ("        Found DNS constraint: %s\n", dns_start);

              /* Check if this matches our expected CN (truncated) */
              if (strstr (dns_start, "server"))
                {
                  found_constraints[0] = 1;
                }

              /* Check against our expected SAN list */
              if (expected_san_list)
                {
                  for (j = 0; expected_san_list[j]; j++)
                    {
                      char *expected_dns = NULL;

                      if (!strchr (expected_san_list[j], ':'))
                        {
                          expected_dns = expected_san_list[j];
                        }
                      else if (strncmp (expected_san_list[j], "DNS:", 4) == 0)
                        {
                          expected_dns = expected_san_list[j] + 4;
                        }

                      if (expected_dns && strstr (dns_start, expected_dns))
                        {
                          found_constraints[j + 1] = 1;
                        }
                    }
                }
            }
        }
      else if (strstr (line, "IP:"))
        {
          char *ip_start = strstr (line, "IP:");
          if (ip_start)
            {
              ip_start += 3; /* Skip "IP:" */
              while (*ip_start == ' ' || *ip_start == '\t')
                ip_start++;

              printf ("        Found IP constraint: %s\n", ip_start);

              /* Check against expected IP SANs */
              if (expected_san_list)
                {
                  for (j = 0; expected_san_list[j]; j++)
                    {
                      if (strncmp (expected_san_list[j], "IP:", 3) == 0)
                        {
                          char *expected_ip = expected_san_list[j] + 3;
                          char *slash = strchr (expected_ip, '/');
                          char expected_constraint[128];
                          char clean_ip[64];

                          /* Extract IP and netmask parts */
                          if (slash)
                            {
                              int ip_len = slash - expected_ip;
                              strncpy (clean_ip, expected_ip, ip_len);
                              clean_ip[ip_len] = '\0';

                              /* Parse the CIDR netmask */
                              char *cidr_str = slash + 1;
                              int cidr_bits = atoi (cidr_str);

                              /* Convert to constraint format with proper netmask */
                              if (strchr (clean_ip, ':'))
                                {
                                  /* IPv6 - convert CIDR to hex netmask */
                                  const char *netmask;
                                  if (cidr_bits == 128)
                                    netmask =
                                      "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:"
                                      "FFFF";
                                  else if (cidr_bits == 64)
                                    netmask = "FFFF:FFFF:FFFF:FFFF:0:0:0:0";
                                  else
                                    netmask =
                                      "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:"
                                      "FFFF"; /* default to /128 */

                                  /* Handle compressed IPv6 forms */
                                  if (strstr (clean_ip, "2001:db8::1"))
                                    {
                                      snprintf (expected_constraint,
                                                sizeof (expected_constraint),
                                                "IP:2001:DB8:0:0:0:0:0:1/%s",
                                                netmask);
                                    }
                                  else if (strstr (clean_ip,
                                                   "2001:db8:85a3::"))
                                    {
                                      snprintf (
                                        expected_constraint,
                                        sizeof (expected_constraint),
                                        "IP:2001:DB8:85A3:0:0:0:0:0/%s",
                                        netmask);
                                    }
                                  else
                                    {
                                      snprintf (expected_constraint,
                                                sizeof (expected_constraint),
                                                "IP:%s/%s",
                                                clean_ip,
                                                netmask);
                                    }
                                }
                              else
                                {
                                  /* IPv4 - convert CIDR to dotted decimal */
                                  const char *netmask;
                                  if (cidr_bits == 32)
                                    netmask = "255.255.255.255";
                                  else if (cidr_bits == 24)
                                    netmask = "255.255.255.0";
                                  else if (cidr_bits == 16)
                                    netmask = "255.255.0.0";
                                  else if (cidr_bits == 8)
                                    netmask = "255.0.0.0";
                                  else
                                    netmask =
                                      "255.255.255.255"; /* default to /32 */

                                  snprintf (expected_constraint,
                                            sizeof (expected_constraint),
                                            "IP:%s/%s",
                                            clean_ip,
                                            netmask);
                                }
                            }
                          else
                            {
                              /* No netmask - add single host netmask */
                              strncpy (clean_ip, expected_ip, 64);
                              clean_ip[63] = '\0';

                              if (strchr (clean_ip, ':'))
                                {
                                  /* IPv6 with /128 netmask */
                                  if (strstr (clean_ip, "2001:db8::1"))
                                    {
                                      snprintf (expected_constraint,
                                                sizeof (expected_constraint),
                                                "IP:2001:DB8:0:0:0:0:0:1/"
                                                "FFFF:FFFF:FFFF:FFFF:FFFF:"
                                                "FFFF:FFFF:FFFF");
                                    }
                                  else if (strstr (clean_ip,
                                                   "2001:db8:85a3::"))
                                    {
                                      snprintf (expected_constraint,
                                                sizeof (expected_constraint),
                                                "IP:2001:DB8:85A3:0:0:0:0:0/"
                                                "FFFF:FFFF:FFFF:FFFF:FFFF:"
                                                "FFFF:FFFF:FFFF");
                                    }
                                  else
                                    {
                                      snprintf (expected_constraint,
                                                sizeof (expected_constraint),
                                                "IP:%s/"
                                                "FFFF:FFFF:FFFF:FFFF:FFFF:"
                                                "FFFF:FFFF:FFFF",
                                                clean_ip);
                                    }
                                }
                              else
                                {
                                  /* IPv4 with /32 netmask */
                                  snprintf (expected_constraint,
                                            sizeof (expected_constraint),
                                            "IP:%s/255.255.255.255",
                                            clean_ip);
                                }
                            }

                          /* Check if this expected constraint matches what we found */
                          /* Skip the "IP:" prefix for comparison since ip_start doesn't include it */
                          char *constraint_without_prefix =
                            expected_constraint + 3; /* Skip "IP:" */
                          if (strcmp (ip_start, constraint_without_prefix) ==
                              0)
                            {
                              found_constraints[j + 1] = 1;
                            }
                        }
                    }
                }
            }
        }

      line = strtok_r (NULL, "\n", &saveptr);
    }

  free (ext_str_copy);
  BIO_free (bio);

  /* Verify that we found all expected constraints */
  if (!found_constraints[0])
    {
      printf ("      MISSING: CN constraint 'server' not found.\n");
      missing_count++;
    }

  if (expected_san_list)
    {
      for (j = 0; expected_san_list[j]; j++)
        {
          if (!found_constraints[j + 1])
            {
              /* Only report missing DNS and IP constraints, skip email/URI */
              if (!strchr (expected_san_list[j], ':') ||
                  strncmp (expected_san_list[j], "DNS:", 4) == 0 ||
                  strncmp (expected_san_list[j], "IP:", 3) == 0)
                {
                  printf ("      MISSING: Constraint for '%s' not found.\n",
                          expected_san_list[j]);
                  missing_count++;
                }
            }
        }
    }

  if (missing_count > 0)
    {
      printf ("      %d expected name constraints were missing.\n",
              missing_count);
      return EINVAL;
    }

  printf ("      All expected name constraints found successfully.\n");
  return EOK;
}

int
main (int argc, char **argv)
{
  int ret, bits;
  struct sscg_cert_info *certinfo;
  struct sscg_bignum *serial;
  struct sscg_x509_req *csr = NULL;
  struct sscg_evp_pkey *pkey = NULL;
  struct sscg_x509_cert *cert = NULL;

  /* Variables for CA testing */
  struct sscg_x509_cert *ca_cert = NULL;
  struct sscg_evp_pkey *ca_key = NULL;
  struct sscg_options ca_options;

  TALLOC_CTX *tmp_ctx = talloc_new (NULL);
  if (!tmp_ctx)
    {
      return ENOMEM;
    }

  certinfo = sscg_cert_info_new (tmp_ctx, EVP_sha256 ());
  if (!certinfo)
    {
      ret = ENOMEM;
      goto done;
    }

  ret = sscg_generate_serial (tmp_ctx, &certinfo->serial);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }

  /* Create a subject matching the defaults in sscg.c
       Keep this in sync if defaults change. */
  certinfo->country = talloc_strdup (certinfo, "US");
  CHECK_MEM (certinfo->country);

  certinfo->state = talloc_strdup (certinfo, "");
  CHECK_MEM (certinfo->state);

  certinfo->locality = talloc_strdup (certinfo, "");
  CHECK_MEM (certinfo->locality);

  certinfo->org = talloc_strdup (certinfo, "Unspecified");
  CHECK_MEM (certinfo->org);

  certinfo->org_unit = talloc_strdup (certinfo, "");
  CHECK_MEM (certinfo->org_unit);

  certinfo->cn = talloc_strdup (certinfo, "server.example.com");
  CHECK_MEM (certinfo->cn);

  /* Set up comprehensive subject alternative names covering all supported formats
   *
   * SSCG SAN Format Support Summary:
   * - DNS names: Supported (both implicit and explicit "DNS:" prefix)
   * - IPv4/IPv6 addresses: Supported (with "IP:" prefix)
   * - Email addresses: Supported (with "email:" prefix)
   * - URIs: Partial support (limitation: slashes get truncated due to IP subnet mask handling)
   * - Wildcards: Supported in DNS names
   * - Internationalized domains: Limited (needs ACE encoding)
   *
   * Known limitations:
   * 1. URI paths with slashes get truncated (affects https://example.com/path)
   * 2. Only basic SAN formats supported (no otherName, directoryName, etc.)
   *
   * IP Address Netmask Handling:
   * - SSCG automatically strips netmask suffixes (e.g., /24, /64) from IP addresses
   * - This is intentional behavior to ensure clean IP address encoding in certificates
   */
  certinfo->subject_alt_names = talloc_zero_array (certinfo, char *, 13);
  CHECK_MEM (certinfo->subject_alt_names);

  /* DNS names (both implicit and explicit) */
  certinfo->subject_alt_names[0] =
    talloc_strdup (certinfo->subject_alt_names, "alt1.example.com");
  CHECK_MEM (certinfo->subject_alt_names[0]);

  certinfo->subject_alt_names[1] =
    talloc_strdup (certinfo->subject_alt_names, "DNS:alt2.example.com");
  CHECK_MEM (certinfo->subject_alt_names[1]);

  /* IPv4 addresses */
  certinfo->subject_alt_names[2] =
    talloc_strdup (certinfo->subject_alt_names, "IP:192.168.1.100");
  CHECK_MEM (certinfo->subject_alt_names[2]);

  certinfo->subject_alt_names[3] =
    talloc_strdup (certinfo->subject_alt_names, "IP:10.0.0.1");
  CHECK_MEM (certinfo->subject_alt_names[3]);

  /* IPv6 address */
  certinfo->subject_alt_names[4] =
    talloc_strdup (certinfo->subject_alt_names, "IP:2001:db8::1");
  CHECK_MEM (certinfo->subject_alt_names[4]);

  /* IPv4 address with netmask (SSCG will strip the /24 part) */
  certinfo->subject_alt_names[5] =
    talloc_strdup (certinfo->subject_alt_names, "IP:203.0.113.0/24");
  CHECK_MEM (certinfo->subject_alt_names[5]);

  /* IPv6 address with netmask (SSCG will strip the /64 part) */
  certinfo->subject_alt_names[6] =
    talloc_strdup (certinfo->subject_alt_names, "IP:2001:db8:85a3::/64");
  CHECK_MEM (certinfo->subject_alt_names[6]);

  /* Email addresses */
  certinfo->subject_alt_names[7] =
    talloc_strdup (certinfo->subject_alt_names, "email:admin@example.com");
  CHECK_MEM (certinfo->subject_alt_names[7]);

  /* URI (proper format - let's see what SSCG actually does with it) */
  certinfo->subject_alt_names[8] = talloc_strdup (
    certinfo->subject_alt_names, "URI:https://www.example.com/service");
  CHECK_MEM (certinfo->subject_alt_names[8]);

  /* Wildcard DNS name */
  certinfo->subject_alt_names[9] =
    talloc_strdup (certinfo->subject_alt_names, "*.wildcard.example.com");
  CHECK_MEM (certinfo->subject_alt_names[9]);

  /* Subdomain */
  certinfo->subject_alt_names[10] =
    talloc_strdup (certinfo->subject_alt_names, "subdomain.alt1.example.com");
  CHECK_MEM (certinfo->subject_alt_names[10]);

  /* International domain (ACE encoded) */
  certinfo->subject_alt_names[11] =
    talloc_strdup (certinfo->subject_alt_names, "xn--nxasmq6b.example.com");
  CHECK_MEM (certinfo->subject_alt_names[11]);

  /* NULL terminator */
  certinfo->subject_alt_names[12] = NULL;

  /* Test RSA key generation */
  printf ("Testing RSA key generation. ");
  bits = 4096;
  ret = sscg_generate_rsa_key (certinfo, bits, &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");

  /* Test EC key generation with different curves */
  printf ("Testing EC key generation (prime256v1). ");
  ret = sscg_generate_ec_key (certinfo, "prime256v1", &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");

  printf ("Testing EC key generation (secp384r1). ");
  ret = sscg_generate_ec_key (certinfo, "secp384r1", &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");

  printf ("Testing EC key generation (secp521r1). ");
  ret = sscg_generate_ec_key (certinfo, "secp521r1", &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");

  /* Test ML-DSA key generation (if available) */
#ifdef HAVE_ML_DSA
  printf ("Testing ML-DSA key generation (NIST level 2). ");
  ret = sscg_generate_mldsa_key (certinfo, 2, &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");

  printf ("Testing ML-DSA key generation (NIST level 3). ");
  ret = sscg_generate_mldsa_key (certinfo, 3, &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");

  printf ("Testing ML-DSA key generation (NIST level 5). ");
  ret = sscg_generate_mldsa_key (certinfo, 5, &pkey);
  CHECK_OK (ret);
  printf ("SUCCESS.\n");
#else
  printf ("ML-DSA not available, skipping test.\n");
#endif

  /* Create the CSR */
  ret = sscg_x509v3_csr_new (tmp_ctx, certinfo, pkey, &csr);
  CHECK_OK (ret);

  ret = sscg_x509v3_csr_finalize (certinfo, pkey, csr);
  CHECK_OK (ret);

  /* Sign the CSR */
  ret = sscg_generate_serial (tmp_ctx, &serial);
  CHECK_OK (ret);

  ret = sscg_sign_x509_csr (
    tmp_ctx, csr, serial, 3650, NULL, pkey, EVP_sha512 (), &cert);
  CHECK_OK (ret);

  /* ============= SERVICE CERTIFICATE TESTS ============= */

  /* Verify that subject alternative names were properly included */
  printf ("Verifying subject alternative names in service certificate. ");
  ret = verify_subject_alt_names (cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test additional SAN verification scenarios */
  printf ("Testing SAN edge cases and validation. ");
  ret = test_san_edge_cases (cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test IP address netmask handling */
  printf ("Testing IP address netmask stripping functionality. ");
  ret = test_ip_netmask_handling (cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* ============= CA CERTIFICATE TESTS ============= */

  printf ("\n=== CA CERTIFICATE TESTS ===\n");

  /* Set up options for CA creation */
  memset (&ca_options, 0, sizeof (ca_options));
  ca_options.country = "US";
  ca_options.state = "";
  ca_options.locality = "";
  ca_options.org = "Unspecified";
  ca_options.email = "";
  ca_options.hostname = "server.example.com";
  ca_options.hash_fn = EVP_sha256 ();
  ca_options.lifetime = 3650;
  ca_options.verbosity = SSCG_QUIET;

  /* Set up the same subject alternative names for the CA */
  ca_options.subject_alt_names = certinfo->subject_alt_names;

  /* Test CA creation with RSA key */
  printf ("Testing CA creation with RSA key. ");
  ret = sscg_generate_rsa_key (tmp_ctx, SSCG_RSA_CA_KEY_MIN_STRENGTH, &ca_key);
  CHECK_OK (ret);
  ret = create_private_CA (tmp_ctx, &ca_options, ca_key, &ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Verify name constraints for RSA CA */
  printf ("Verifying name constraints for RSA CA. ");
  ret = verify_name_constraints (ca_cert, certinfo->subject_alt_names);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test CA creation with EC key (secp384r1) */
  printf ("Testing CA creation with EC key (secp384r1). ");
  ret = sscg_generate_ec_key (tmp_ctx, "secp384r1", &ca_key);
  CHECK_OK (ret);
  ret = create_private_CA (tmp_ctx, &ca_options, ca_key, &ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Verify name constraints for EC CA (secp384r1) */
  printf ("Verifying name constraints for EC CA (secp384r1). ");
  ret = verify_name_constraints (ca_cert, certinfo->subject_alt_names);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test CA creation with EC key (secp521r1) */
  printf ("Testing CA creation with EC key (secp521r1). ");
  ret = sscg_generate_ec_key (tmp_ctx, "secp521r1", &ca_key);
  CHECK_OK (ret);
  ret = create_private_CA (tmp_ctx, &ca_options, ca_key, &ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Verify name constraints for EC CA (secp521r1) */
  printf ("Verifying name constraints for EC CA (secp521r1). ");
  ret = verify_name_constraints (ca_cert, certinfo->subject_alt_names);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

#ifdef HAVE_ML_DSA
  /* Test CA creation with ML-DSA key (NIST level 3) */
  printf ("Testing CA creation with ML-DSA key (NIST level 3). ");
  ret = sscg_generate_mldsa_key (tmp_ctx, 3, &ca_key);
  CHECK_OK (ret);
  ret = create_private_CA (tmp_ctx, &ca_options, ca_key, &ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Verify name constraints for ML-DSA CA (NIST level 3) */
  printf ("Verifying name constraints for ML-DSA CA (NIST level 3). ");
  ret = verify_name_constraints (ca_cert, certinfo->subject_alt_names);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Test CA creation with ML-DSA key (NIST level 5) */
  printf ("Testing CA creation with ML-DSA key (NIST level 5). ");
  ret = sscg_generate_mldsa_key (tmp_ctx, 5, &ca_key);
  CHECK_OK (ret);
  ret = create_private_CA (tmp_ctx, &ca_options, ca_key, &ca_cert);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");

  /* Verify name constraints for ML-DSA CA (NIST level 5) */
  printf ("Verifying name constraints for ML-DSA CA (NIST level 5). ");
  ret = verify_name_constraints (ca_cert, certinfo->subject_alt_names);
  if (ret != EOK)
    {
      printf ("FAILED.\n");
      goto done;
    }
  printf ("SUCCESS.\n");
#else
  printf ("ML-DSA not available for CA, skipping test.\n");
#endif

  /* Use the last generated key for the rest of the test */
  printf ("Using final CA key for remaining tests. SUCCESS.\n");
  /* If create_private_CA returns EOK, ca_cert must be non-NULL */
  if (ca_cert == NULL)
    {
      printf ("FAILED: ca_cert is NULL.\n");
      ret = EINVAL;
      goto done;
    }


done:
  if (ret != EOK)
    {
      fprintf (stderr, "FAILURE: %s\n", strerror (ret));
    }
  talloc_free (tmp_ctx);
  return ret;
}
