/* test_dh.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#include "unit.h"
#include <openssl/core_names.h>

#ifdef WP_HAVE_DH

/* dh pkcs8 private key der */
static const unsigned char dh_der[] = {
    0x30, 0x82, 0x02, 0x26, 0x02, 0x01, 0x00, 0x30, 0x82, 0x01, 0x17, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01, 0x30, 0x82,
    0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xBA, 0x58, 0x07, 0x7D, 0xB2,
    0x45, 0x41, 0x40, 0xF7, 0x72, 0xDF, 0x98, 0x98, 0x51, 0x7D, 0xBE, 0x17,
    0xE3, 0xD0, 0xB6, 0xCA, 0x38, 0xC3, 0x65, 0x7F, 0xE2, 0x13, 0xC1, 0x42,
    0x1A, 0x7A, 0x94, 0x2B, 0xB5, 0x58, 0xC0, 0x39, 0xD4, 0xB8, 0x41, 0xFD,
    0x21, 0xCF, 0xE3, 0x9C, 0x17, 0xB9, 0x8D, 0x34, 0x1A, 0x98, 0x81, 0xAF,
    0xAE, 0x19, 0xD5, 0x01, 0x9F, 0xD3, 0x29, 0xD1, 0x29, 0xEF, 0xDD, 0x73,
    0x4B, 0xF4, 0xEB, 0x87, 0xAC, 0xF3, 0xF9, 0xBD, 0x8B, 0xD5, 0xAD, 0x20,
    0xE4, 0xEB, 0x6C, 0x99, 0xDE, 0x40, 0x76, 0xF3, 0x18, 0x41, 0x85, 0xE9,
    0x1D, 0xFE, 0x8C, 0xEA, 0x5B, 0xAD, 0xB4, 0x11, 0xCA, 0x0D, 0x22, 0x0C,
    0xD7, 0x06, 0xAD, 0x06, 0x59, 0xFB, 0x1B, 0x61, 0xEB, 0xF4, 0x1B, 0xCA,
    0x6E, 0x8C, 0x0F, 0x92, 0x8D, 0xF3, 0x80, 0x1B, 0x4A, 0xAF, 0xF2, 0x9E,
    0x3F, 0x60, 0xFD, 0xB1, 0x49, 0x6D, 0xCA, 0x0B, 0xD4, 0x99, 0x3B, 0x45,
    0xA5, 0xB1, 0xED, 0xA1, 0xB7, 0x94, 0xD0, 0x33, 0xA5, 0x21, 0xEB, 0x29,
    0xC2, 0xEB, 0xFB, 0x5C, 0x1A, 0xD5, 0xAF, 0xC4, 0xC9, 0x02, 0xCD, 0x7A,
    0xEB, 0xB4, 0xC5, 0x7B, 0x34, 0xBD, 0x2F, 0x4F, 0xA0, 0xC4, 0x63, 0x6A,
    0xFE, 0x98, 0xD0, 0x83, 0xFA, 0xEF, 0x6F, 0xAF, 0xA8, 0x4B, 0x46, 0x59,
    0x77, 0xCA, 0xC5, 0x19, 0xDA, 0x8A, 0x77, 0xC6, 0x56, 0x08, 0xD6, 0x0A,
    0xAD, 0xFC, 0x04, 0x35, 0xFA, 0xDA, 0xAA, 0x08, 0x42, 0x1B, 0x48, 0xE8,
    0x42, 0x3C, 0x4F, 0x31, 0xA2, 0x22, 0xE9, 0xF3, 0x0F, 0xD7, 0x06, 0xCB,
    0x08, 0x54, 0x7C, 0x2C, 0xEA, 0x38, 0x11, 0x2B, 0x53, 0x7C, 0xE5, 0x86,
    0xC9, 0x74, 0xB9, 0x98, 0x68, 0x6D, 0xE4, 0xF0, 0x7A, 0x2B, 0xE5, 0xB9,
    0x4E, 0xAD, 0xD1, 0x34, 0xC7, 0x4C, 0xFE, 0x1A, 0x7C, 0x8A, 0x37, 0x02,
    0x01, 0x02, 0x04, 0x82, 0x01, 0x04, 0x02, 0x82, 0x01, 0x00, 0x45, 0xED,
    0x6E, 0x18, 0x44, 0x8F, 0xA0, 0x43, 0x04, 0xF7, 0xE0, 0x5E, 0x98, 0x23,
    0xFB, 0xE8, 0xDA, 0x49, 0x7E, 0x2A, 0x11, 0xEC, 0xD0, 0xCD, 0xB7, 0x13,
    0xE1, 0x11, 0xCB, 0xDA, 0x00, 0x34, 0x13, 0x16, 0x5A, 0xB5, 0xEA, 0x2D,
    0xCC, 0xAB, 0x0D, 0xE1, 0x75, 0x5D, 0xCA, 0xBC, 0x1E, 0xBD, 0x5D, 0x01,
    0xB4, 0xC3, 0xCA, 0x78, 0xDF, 0x4C, 0x4F, 0x1B, 0x21, 0x40, 0x8A, 0x64,
    0x7F, 0x4B, 0x45, 0xE3, 0x7F, 0x43, 0xD7, 0xFD, 0x4E, 0xA0, 0xA1, 0x4A,
    0x1C, 0x5A, 0x8D, 0x87, 0x7E, 0x5A, 0xB5, 0x26, 0x1A, 0xDC, 0x9B, 0xDD,
    0xD1, 0x8D, 0xD0, 0xBB, 0x45, 0x0F, 0x67, 0x41, 0xC1, 0xC0, 0xA5, 0x7B,
    0x6A, 0x35, 0x51, 0x06, 0x14, 0xC7, 0x61, 0x0D, 0xF7, 0x01, 0x30, 0x0A,
    0xB5, 0x07, 0xF6, 0x8F, 0x76, 0xCF, 0x99, 0x1F, 0xAF, 0x2C, 0x66, 0x20,
    0xB4, 0x69, 0x0A, 0xC3, 0x04, 0x76, 0x1B, 0xF4, 0x0D, 0x7C, 0x54, 0x0A,
    0xB8, 0xF6, 0xF8, 0x35, 0x17, 0x81, 0xDD, 0x6E, 0xCE, 0x17, 0xBD, 0x00,
    0x9C, 0x5D, 0x3F, 0x37, 0x37, 0xC4, 0x58, 0xBC, 0xA5, 0xB3, 0xD3, 0x0F,
    0x98, 0x0F, 0x6C, 0x0C, 0x78, 0x53, 0x92, 0x36, 0x94, 0x4D, 0xF5, 0x7D,
    0x1A, 0xD8, 0xC6, 0x54, 0x0A, 0xED, 0x79, 0xAA, 0xAC, 0x4F, 0xFF, 0x2B,
    0x41, 0xC6, 0x41, 0x7A, 0x4D, 0xBC, 0xB0, 0x43, 0xF9, 0x22, 0x33, 0xD4,
    0xAA, 0x43, 0x75, 0xAD, 0x97, 0xAB, 0xE8, 0xCC, 0x57, 0xFA, 0x0D, 0x48,
    0x08, 0x44, 0x99, 0x6A, 0x9D, 0x14, 0x14, 0x4D, 0x32, 0x00, 0x3E, 0x8A,
    0x82, 0x30, 0xB1, 0x85, 0x3E, 0xD2, 0xD3, 0x8C, 0xEF, 0x73, 0x72, 0x56,
    0x28, 0xF5, 0xBA, 0x2F, 0x85, 0x45, 0x46, 0xD1, 0xED, 0x42, 0x2E, 0x9A,
    0xAE, 0x4F, 0x41, 0x5B, 0xBD, 0x9C, 0xF9, 0x58, 0x8D, 0xFA, 0x13, 0xB4,
    0xDF, 0x31,
};

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

    PRINT_MSG("Generate DH key pair with WolfSSL and params from "
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

int test_dh_decode(void *data)
{
    int err = 0;
    const unsigned char *p = NULL;
    int len = 0;
    PKCS8_PRIV_KEY_INFO* p8inf = NULL;
    EVP_PKEY* pkey1 = NULL;
    DH *dh1 = NULL;
    const BIGNUM *p1 = NULL;
    const BIGNUM *g1 = NULL;
    const BIGNUM *priv1 = NULL;
    const BIGNUM *pub1 = NULL;
    EVP_PKEY* pkey2 = NULL;
    DH *dh2 = NULL;
    const BIGNUM *p2 = NULL;
    const BIGNUM *g2 = NULL;
    const BIGNUM *priv2 = NULL;
    const BIGNUM *pub2 = NULL;

    (void)data;

    p = &dh_der[0];
    len = sizeof(dh_der);
    p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, (const unsigned char **)&p, len);
    err = p8inf == NULL;

    if (err == 0) {
        PRINT_MSG("Decode with OpenSSL and Wolfprovider");
        pkey1 = EVP_PKCS82PKEY_ex(p8inf, osslLibCtx, NULL);
        pkey2 = EVP_PKCS82PKEY_ex(p8inf, wpLibCtx, NULL);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        err = (pkey1 == NULL || pkey2 == NULL);
    }

    if (err == 0) {
        dh1 = EVP_PKEY_get1_DH(pkey1);
        dh2 = EVP_PKEY_get1_DH(pkey2);
        err = (dh1 == NULL || dh2 == NULL);
    }

    if (err == 0) {
        DH_get0_pqg(dh1, &p1, NULL, &g1);
        err = (p1 == NULL || g1 == NULL);
    }
    if (err == 0) {
        DH_get0_pqg(dh2, &p2, NULL, &g2);
        err = (p2 == NULL || g2 == NULL);
    }

    if (err == 0) {
        DH_get0_key(dh1, &pub1, &priv1);
        err = (pub1 == NULL || priv1 == NULL);
    }
    if (err == 0) {
        DH_get0_key(dh2, &pub2, &priv2);
        err = (pub2 == NULL || priv2 == NULL);
    }

    if (err == 0) {
        err = BN_cmp(p1, p2) != 0;
    }
    if (err == 0) {
        err = BN_cmp(g1, g2) != 0;
    }
    if (err == 0) {
        err = BN_cmp(priv1, priv2) != 0;
    }
    if (err == 0) {
        err = BN_cmp(pub1, pub2) != 0;
    }

    DH_free(dh1);
    DH_free(dh2);
    EVP_PKEY_free(pkey1);
    EVP_PKEY_free(pkey2);

    return err;
}

int test_dh_get_params(void *data) 
{
    (void)data;
    int err = 0;
    EVP_PKEY_CTX *ctxOpenSSL = NULL;
    EVP_PKEY_CTX *ctxWolfProvider = NULL;
    EVP_PKEY *keyParamsOpenSSL = NULL;
    EVP_PKEY *keyParamsWolfProvider = NULL;
    EVP_PKEY *keyOpenSSL = NULL;
    EVP_PKEY *keyWolfProvider = NULL;

    if (err == 0) {
        ctxOpenSSL = EVP_PKEY_CTX_new_from_name(osslLibCtx, "DH", NULL);
        err = ctxOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctxOpenSSL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctxOpenSSL, 2048) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctxOpenSSL, &keyParamsOpenSSL) != 1;
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(ctxOpenSSL);
        ctxOpenSSL = EVP_PKEY_CTX_new_from_pkey(osslLibCtx, keyParamsOpenSSL, NULL);
        err = ctxOpenSSL == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctxOpenSSL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctxOpenSSL, &keyOpenSSL) != 1;
    }

    if (err == 0) {
        ctxWolfProvider = EVP_PKEY_CTX_new_from_name(wpLibCtx, "DH", NULL);
        err = ctxWolfProvider == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen_init(ctxWolfProvider) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctxWolfProvider, 2048) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_paramgen(ctxWolfProvider, &keyParamsWolfProvider) != 1;
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(ctxWolfProvider);
        ctxWolfProvider = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, keyParamsWolfProvider, NULL);
        err = ctxWolfProvider == NULL;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen_init(ctxWolfProvider) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_keygen(ctxWolfProvider, &keyWolfProvider) != 1;
    }

    static const OSSL_PARAM gettableParams[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        /* Note that OpenSSL treats the keys as BIGNUMs, not strings. */
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };
    // const size_t paramsSize = sizeof(gettableParams);

    if (err == 0) {
        int retWolfProvider;
        unsigned char bufWolfProvider[256];
        const char* mode;

        OSSL_PARAM paramsWolfProvider[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

        for (int i = 0; i < (int)(sizeof(gettableParams)/sizeof(gettableParams[0])) - 1; i++) {
            memset(bufWolfProvider, 0, sizeof(bufWolfProvider));
            for (int j = 0; j < 2; j++) {
                if (j == 0) {
                    mode = "Null data";
                }
                else {
                    mode = "Buffer data";
                    paramsWolfProvider[0] = gettableParams[i];
                    paramsWolfProvider[0].data = bufWolfProvider;
                    paramsWolfProvider[0].data_size = sizeof(bufWolfProvider);
                }

                retWolfProvider = EVP_PKEY_get_params(keyWolfProvider, paramsWolfProvider);
                if (retWolfProvider != 1) {
                    PRINT_MSG("EVP_PKEY_get_params failed for param %s in mode %s (WolfProvider (%d))",
                            gettableParams[i].key, mode, retWolfProvider);
                    err = 1;
                }
                if (err == 0 && paramsWolfProvider[0].data) {
                    if (paramsWolfProvider[0].return_size == 0) {
                        PRINT_MSG("EVP_PKEY_get_params did not set return_size for param %s in mode %s (WolfProvider (%d))",
                                gettableParams[i].key, mode, retWolfProvider);
                        err = 1;
                    }
                }
            }
        }
    }

    EVP_PKEY_CTX_free(ctxOpenSSL);
    EVP_PKEY_CTX_free(ctxWolfProvider);
    EVP_PKEY_free(keyOpenSSL);
    EVP_PKEY_free(keyWolfProvider);
    EVP_PKEY_free(keyParamsOpenSSL);
    EVP_PKEY_free(keyParamsWolfProvider);

    return err;
}


#endif /* WP_HAVE_DH */
