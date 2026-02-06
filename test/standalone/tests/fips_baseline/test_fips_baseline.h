/* test_fips_baseline.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfProvider.
 *
 * wolfProvider is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfProvider is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TEST_FIPS_BASELINE_H
#define TEST_FIPS_BASELINE_H

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "../../test_common.h"

/* Global provider handles (defined in test_fips_baseline.c) */
extern OSSL_PROVIDER *g_default_prov;
extern OSSL_PROVIDER *g_wolfprov;

/* Global library contexts - one for each provider (defined in test_fips_baseline.c) */
extern OSSL_LIB_CTX *osslLibCtx;
extern OSSL_LIB_CTX *wpLibCtx;

/* Setup and cleanup functions (implemented in test_fips_baseline.c) */
int setup_and_verify_providers(void);
void cleanup_providers(void);

/* FIPS sanity check (implemented in test_fips_baseline_digest.c) */
int test_fips_sanity(void);

/* Digest restriction tests (implemented in test_fips_baseline_digest.c) */
int test_md5_restriction(void);

/* Cipher restriction tests (implemented in test_fips_baseline_ciphers.c) */
int test_cipher_restrictions(void);

/* Edwards curve and X curve restriction tests (implemented in test_fips_baseline_ecx.c) */
int test_ecx_restrictions(void);

/* RSA restriction tests (implemented in test_fips_baseline_rsa.c) */
int test_rsa_restriction(void);

/* ECDSA key size restriction tests (implemented in test_fips_baseline_ecdsa.c) */
int test_ecdsa_key_size_restrictions(void);

/* ECDH restriction tests (implemented in test_fips_baseline_ecdh.c) */
int test_ecdh_restrictions(void);

/* DH restriction tests (implemented in test_fips_baseline_dh.c) */
int test_dh_restrictions(void);

/* HMAC key strength restriction tests (implemented in test_fips_baseline_hmac.c) */
int test_hmac_key_restrictions(void);

/* PBKDF2 password strength restriction tests (implemented in test_fips_baseline_pbkdf2.c) */
int test_pbkdf2_restrictions(void);

#endif /* TEST_FIPS_BASELINE_H */

