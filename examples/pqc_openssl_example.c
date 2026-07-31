/* pqc_openssl_example.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#define WOLFPROV_NAME "libwolfprov"

static EVP_PKEY* generate_key(OSSL_LIB_CTX* libCtx, const char* algorithm)
{
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* keyCtx = NULL;

    keyCtx = EVP_PKEY_CTX_new_from_name(libCtx, algorithm, NULL);
    if ((keyCtx == NULL) || (EVP_PKEY_keygen_init(keyCtx) != 1) ||
            (EVP_PKEY_keygen(keyCtx, &key) != 1)) {
        EVP_PKEY_free(key);
        key = NULL;
    }

    EVP_PKEY_CTX_free(keyCtx);
    return key;
}

#ifdef WOLFPROV_HAVE_MLKEM
static int run_mlkem(OSSL_LIB_CTX* libCtx)
{
    int rc = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* encapCtx = NULL;
    EVP_PKEY_CTX* decapCtx = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char* encapSecret = NULL;
    unsigned char* decapSecret = NULL;
    size_t ciphertextLen = 0;
    size_t encapSecretLen = 0;
    size_t decapSecretLen = 0;

    key = generate_key(libCtx, "ML-KEM-768");
    if (key == NULL) {
        rc = 1;
    }

    if (rc == 0) {
        encapCtx = EVP_PKEY_CTX_new_from_pkey(libCtx, key, NULL);
        if ((encapCtx == NULL) ||
                (EVP_PKEY_encapsulate_init(encapCtx, NULL) != 1) ||
                (EVP_PKEY_encapsulate(encapCtx, NULL, &ciphertextLen, NULL,
                    &encapSecretLen) != 1)) {
            rc = 1;
        }
    }

    if (rc == 0) {
        decapSecretLen = encapSecretLen;
        ciphertext = OPENSSL_malloc(ciphertextLen);
        encapSecret = OPENSSL_malloc(encapSecretLen);
        decapSecret = OPENSSL_malloc(decapSecretLen);
        if ((ciphertext == NULL) || (encapSecret == NULL) ||
                (decapSecret == NULL)) {
            rc = 1;
        }
    }

    if (rc == 0) {
        if (EVP_PKEY_encapsulate(encapCtx, ciphertext, &ciphertextLen,
                encapSecret, &encapSecretLen) != 1) {
            rc = 1;
        }
    }

    if (rc == 0) {
        decapCtx = EVP_PKEY_CTX_new_from_pkey(libCtx, key, NULL);
        if ((decapCtx == NULL) ||
                (EVP_PKEY_decapsulate_init(decapCtx, NULL) != 1) ||
                (EVP_PKEY_decapsulate(decapCtx, decapSecret, &decapSecretLen,
                    ciphertext, ciphertextLen) != 1)) {
            rc = 1;
        }
    }

    if (rc == 0) {
        rc = (encapSecretLen != decapSecretLen) ||
            (CRYPTO_memcmp(encapSecret, decapSecret, encapSecretLen) != 0);
    }

    OPENSSL_clear_free(decapSecret, decapSecretLen);
    OPENSSL_clear_free(encapSecret, encapSecretLen);
    OPENSSL_free(ciphertext);
    EVP_PKEY_CTX_free(decapCtx);
    EVP_PKEY_CTX_free(encapCtx);
    EVP_PKEY_free(key);
    return rc;
}
#endif

#if defined(WOLFPROV_HAVE_MLDSA) || defined(WOLFPROV_HAVE_SLHDSA)
static int run_signature(OSSL_LIB_CTX* libCtx, const char* algorithm)
{
    static const unsigned char message[] =
        "wolfProvider post-quantum example";
    int rc = 0;
    EVP_PKEY* key = NULL;
    EVP_MD_CTX* signCtx = NULL;
    EVP_MD_CTX* verifyCtx = NULL;
    unsigned char* signature = NULL;
    size_t signatureLen = 0;

    key = generate_key(libCtx, algorithm);
    signCtx = EVP_MD_CTX_new();
    if ((key == NULL) || (signCtx == NULL) ||
            (EVP_DigestSignInit_ex(signCtx, NULL, NULL, libCtx, NULL, key,
                NULL) != 1) ||
            (EVP_DigestSign(signCtx, NULL, &signatureLen, message,
                sizeof(message) - 1) != 1)) {
        rc = 1;
    }

    if (rc == 0) {
        signature = OPENSSL_malloc(signatureLen);
        if ((signature == NULL) ||
                (EVP_DigestSign(signCtx, signature, &signatureLen, message,
                    sizeof(message) - 1) != 1)) {
            rc = 1;
        }
    }

    if (rc == 0) {
        verifyCtx = EVP_MD_CTX_new();
        if ((verifyCtx == NULL) ||
                (EVP_DigestVerifyInit_ex(verifyCtx, NULL, NULL, libCtx, NULL,
                    key, NULL) != 1)) {
            rc = 1;
        }
    }
    if (rc == 0) {
        rc = EVP_DigestVerify(verifyCtx, signature, signatureLen, message,
            sizeof(message) - 1) != 1;
    }

    OPENSSL_free(signature);
    EVP_MD_CTX_free(verifyCtx);
    EVP_MD_CTX_free(signCtx);
    EVP_PKEY_free(key);
    return rc;
}
#endif

int main(void)
{
    int rc = 0;
    OSSL_LIB_CTX* libCtx = NULL;
    OSSL_PROVIDER* wolfProv = NULL;

    libCtx = OSSL_LIB_CTX_new();
    if (libCtx == NULL) {
        rc = 1;
    }

    if (rc == 0) {
        OSSL_PROVIDER_set_default_search_path(libCtx, ".libs");
        wolfProv = OSSL_PROVIDER_load(libCtx, WOLFPROV_NAME);
        if (wolfProv == NULL) {
            rc = 1;
        }
    }

#ifdef WOLFPROV_HAVE_MLKEM
    if ((rc == 0) && (run_mlkem(libCtx) != 0)) {
        fprintf(stderr, "ML-KEM-768 encapsulation failed\n");
        rc = 1;
    }
    if (rc == 0) {
        printf("ML-KEM-768 encapsulation passed\n");
    }
#endif

#ifdef WOLFPROV_HAVE_MLDSA
    if ((rc == 0) && (run_signature(libCtx, "ML-DSA-65") != 0)) {
        fprintf(stderr, "ML-DSA-65 signature failed\n");
        rc = 1;
    }
    if (rc == 0) {
        printf("ML-DSA-65 signature passed\n");
    }
#endif

#ifdef WOLFPROV_HAVE_SLHDSA
    if ((rc == 0) &&
            (run_signature(libCtx, "SLH-DSA-SHA2-128f") != 0)) {
        fprintf(stderr, "SLH-DSA-SHA2-128f signature failed\n");
        rc = 1;
    }
    if (rc == 0) {
        printf("SLH-DSA-SHA2-128f signature passed\n");
    }
#endif

    if (rc != 0) {
        ERR_print_errors_fp(stderr);
    }
    OSSL_PROVIDER_unload(wolfProv);
    OSSL_LIB_CTX_free(libCtx);
    return rc;
}
