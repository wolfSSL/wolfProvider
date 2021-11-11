/* test_dh.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "unit.h"

#ifdef WP_HAVE_DH

/* dh1024 p */
static const unsigned char dh_p[] =
{
    0xE6, 0x96, 0x9D, 0x3D, 0x49, 0x5B, 0xE3, 0x2C, 0x7C, 0xF1, 0x80, 0xC3,
    0xBD, 0xD4, 0x79, 0x8E, 0x91, 0xB7, 0x81, 0x82, 0x51, 0xBB, 0x05, 0x5E,
    0x2A, 0x20, 0x64, 0x90, 0x4A, 0x79, 0xA7, 0x70, 0xFA, 0x15, 0xA2, 0x59,
    0xCB, 0xD5, 0x23, 0xA6, 0xA6, 0xEF, 0x09, 0xC4, 0x30, 0x48, 0xD5, 0xA2,
    0x2F, 0x97, 0x1F, 0x3C, 0x20, 0x12, 0x9B, 0x48, 0x00, 0x0E, 0x6E, 0xDD,
    0x06, 0x1C, 0xBC, 0x05, 0x3E, 0x37, 0x1D, 0x79, 0x4E, 0x53, 0x27, 0xDF,
    0x61, 0x1E, 0xBB, 0xBE, 0x1B, 0xAC, 0x9B, 0x5C, 0x60, 0x44, 0xCF, 0x02,
    0x3D, 0x76, 0xE0, 0x5E, 0xEA, 0x9B, 0xAD, 0x99, 0x1B, 0x13, 0xA6, 0x3C,
    0x97, 0x4E, 0x9E, 0xF1, 0x83, 0x9E, 0xB5, 0xDB, 0x12, 0x51, 0x36, 0xF7,
    0x26, 0x2E, 0x56, 0xA8, 0x87, 0x15, 0x38, 0xDF, 0xD8, 0x23, 0xC6, 0x50,
    0x50, 0x85, 0xE2, 0x1F, 0x0D, 0xD5, 0xC8, 0x6B,
};

/* dh1024 g */
static const unsigned char dh_g[] =
{
  0x02,
};

static int test_dh_pkey_keygen(EVP_PKEY *params)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *keyOpenSSL = NULL;
    EVP_PKEY *keyWolfProvider = NULL;
    unsigned char *secretOpenSSL = NULL;
    size_t secretLenOpenSSL = 0;
    unsigned char *secretWolfProvider = NULL;
    size_t secretLenWolfProvider = 0;

    PRINT_MSG("Generate DH key pair with OpenSSL and params from "
              "wolfProvider");
    ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, params, NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &keyWolfProvider) != 1;
    }

    if (err == 0) {
        PRINT_MSG("Generate DH key pair with OpenSSL and params from "
                  "wolfProvider");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(osslLibCtx, params, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctx, &keyOpenSSL) != 1;
    }

    if (err == 0) {
        PRINT_MSG("Compute shared secret with OpenSSL private key and "
                  "wolfProvider public key.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(osslLibCtx, keyOpenSSL, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyWolfProvider) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &secretLenOpenSSL) <= 0;
    }
    if (err == 0) {
        secretOpenSSL = (unsigned char*)OPENSSL_malloc(secretLenOpenSSL);
        err = secretOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secretOpenSSL, &secretLenOpenSSL) <= 0;
    }

    if (err == 0) {
        PRINT_BUFFER("Secret", secretOpenSSL, secretLenOpenSSL);
        PRINT_MSG("Compute shared secret with wolfProvider private key and "
                  "OpenSSL public key.");
        EVP_PKEY_CTX_free(ctx);
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, keyWolfProvider, NULL);
        err = ctx == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_init(ctx) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive_set_peer(ctx, keyOpenSSL) <= 0;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, NULL, &secretLenWolfProvider) <= 0;
    }
    if (err == 0) {
        secretWolfProvider = (unsigned char*)OPENSSL_malloc(secretLenWolfProvider);
        err = secretWolfProvider == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_derive(ctx, secretWolfProvider, &secretLenWolfProvider) <= 0;
    }

    if (err == 0) {
        PRINT_BUFFER("Secret", secretOpenSSL, secretLenOpenSSL);
        PRINT_MSG("Ensure shared secrets are the same.");
        err = secretLenOpenSSL != secretLenWolfProvider;
    }
    if (err == 0) {
        err = memcmp(secretOpenSSL, secretWolfProvider, secretLenOpenSSL) != 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(keyOpenSSL);
    EVP_PKEY_free(keyWolfProvider);

    if (secretWolfProvider != NULL)
        OPENSSL_free(secretWolfProvider);
    if (secretOpenSSL != NULL)
        OPENSSL_free(secretOpenSSL);

    return err;
}

int test_dh_pgen_pkey(void *data)
{
    int err;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params = NULL;

    (void)data;

    PRINT_MSG("Generate DH parameters and key pair with wolfProvider");
    err = (ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL)) == NULL;
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctx, &params) != 1;
    }

    if (err == 0) {
        err = test_dh_pkey_keygen(params);
    }

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);

    return err;
}

int test_dh_pkey(void *data)
{
    int err;
    DH *dh;
    EVP_PKEY *params = NULL;
    BIGNUM *p;
    BIGNUM *g;

    (void)data;

    dh = DH_new();
    err = (dh == NULL);
    if (err == 0) {
        p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
        err = p == NULL;
    }
    if (err == 0) {
        g = BN_bin2bn(dh_g, sizeof(dh_g), NULL);
        err = g == NULL;
    }
    if (err == 0) {
        err = DH_set0_pqg(dh, p, NULL, g) == 0;
    }
    if (err == 0) {
        err = (params = EVP_PKEY_new()) == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_set1_DH(params, dh) != 1;
    }

    if (err == 0) {
        err = test_dh_pkey_keygen(params);
    }

    EVP_PKEY_free(params);
    DH_free(dh);

    return err;
}

#endif /* WP_HAVE_DH */
