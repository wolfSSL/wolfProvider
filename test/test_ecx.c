/* test_ecc.c
 *
 * Copyright (C) 2025 wolfSSL Inc.
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

#include <openssl/store.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#if defined(WP_HAVE_ED25519) || defined(WP_HAVE_ECD448)

#ifndef ARRAY_SIZE
    #define ARRAY_SIZE(a)   ((sizeof(a)/sizeof(a[0])))
#endif

#ifndef ED25519_SIGSIZE
    #define ED25519_SIGSIZE 64
#endif

#ifndef ED448_SIGSIZE
    #define ED448_SIGSIZE 114
#endif

#ifdef WP_HAVE_ED25519
// Generated with OpenSSL:
// openssl genpkey -algorithm ed25519 -outform der -out ed25519.der
static const unsigned char ed25519_key_der[] = {
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, 0x55, 0xba, 0xe1, 0x23, 0x18, 0x24, 0xea, 0x90,
    0x5f, 0x29, 0xe2, 0x8c, 0xe7, 0x6d, 0x99, 0x99, 0x8c, 0x15, 0x06, 0x1e,
    0x53, 0x61, 0x1a, 0x94, 0xd0, 0x4e, 0x83, 0xef, 0x04, 0xf1, 0x77, 0xdd,
};
// Isolated private key for the keypair above.
// > openssl pkey -in ed25519.der
static const unsigned char ed25519_priv_key_raw[] = {
    0x55, 0xBA, 0xE1, 0x23, 0x18, 0x24, 0xEA, 0x90, 0x5F, 0x29, 0xE2, 0x8C,
    0xE7, 0x6D, 0x99, 0x99, 0x8C, 0x15, 0x06, 0x1E, 0x53, 0x61, 0x1A, 0x94, 
    0xD0, 0x4E, 0x83, 0xEF, 0x04, 0xF1, 0x77, 0xDD
};
// Isolated public key for the keypair above.
// > openssl pkey -in ed25519.der -pubout
static const unsigned char ed25519_pub_key_raw[] = {
    0x19, 0x31, 0xC8, 0xA8, 0x5F, 0x8F, 0x5C, 0x50, 0xEF, 0xD9, 0xB4, 0x97, 
    0x4B, 0xDE, 0xBC, 0xF5, 0x0E, 0x13, 0x1B, 0xDC, 0x51, 0x91, 0x8C, 0x62, 
    0xF1, 0x9C, 0x36, 0x15, 0x5C, 0x9A, 0x5F, 0x69
};
#endif /* WP_HAVE_ED25519 */

#ifdef WP_HAVE_ED448
// Generated with OpenSSL:
// > openssl genpkey -algorithm ed448 -outform der -out ed448.der
static const unsigned char ed448_key_der[] = {
    0x30, 0x47, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71,
    0x04, 0x3b, 0x04, 0x39, 0xe9, 0x6c, 0x21, 0x55, 0x78, 0x4d, 0x3b, 0x4e,
    0x61, 0xb2, 0xd1, 0xa8, 0x8a, 0x2a, 0xcd, 0xd7, 0xa3, 0x5f, 0xb4, 0x49,
    0x9d, 0xa8, 0x4e, 0x0c, 0xdd, 0x7b, 0x24, 0xd9, 0x79, 0x89, 0x03, 0x64,
    0x93, 0x01, 0xff, 0xc9, 0x4f, 0x72, 0x57, 0x28, 0x36, 0x81, 0x06, 0x52,
    0x38, 0xa3, 0x5f, 0x45, 0xea, 0x6f, 0xdf, 0xef, 0xc4, 0x67, 0xfc, 0xb4,
    0x53,
};
// Isolated private key for the keypair above.
// > openssl pkey -in ed448.der
static const unsigned char ed448_priv_key_raw[] = {
    0xE9, 0x6C, 0x21, 0x55, 0x78, 0x4D, 0x3B, 0x4E, 0x61, 0xB2, 0xD1, 0xA8,
    0x8A, 0x2A, 0xCD, 0xD7, 0xA3, 0x5F, 0xB4, 0x49, 0x9D, 0xA8, 0x4E, 0x0C,
    0xDD, 0x7B, 0x24, 0xD9, 0x79, 0x89, 0x03, 0x64, 0x93, 0x01, 0xFF, 0xC9,
    0x4F, 0x72, 0x57, 0x28, 0x36, 0x81, 0x06, 0x52, 0x38, 0xA3, 0x5F, 0x45,
    0xEA, 0x6F, 0xDF, 0xEF, 0xC4, 0x67, 0xFC, 0xB4, 0x53
};
// Isolated public key for the keypair above.
// > openssl pkey -in ed448.der -pubout
static const unsigned char ed448_pub_key_raw[] = {
    0x3D, 0x05, 0x53, 0x9D, 0x4B, 0x89, 0xA2, 0xD1, 0xED, 0x2A, 0x2F, 0xB5, 
    0xF2, 0x90, 0x38, 0x95, 0x70, 0x0D, 0xA1, 0xBB, 0x84, 0x2B, 0x52, 0x56, 
    0x4E, 0xAB, 0x55, 0xF3, 0xB5, 0x9E, 0x05, 0x1F, 0x08, 0xB0, 0xBE, 0xB6, 
    0x29, 0xC8, 0x68, 0x21, 0xBE, 0x21, 0xE4, 0x51, 0xB2, 0x20, 0x79, 0xB1, 
    0x19, 0x6A, 0x80, 0xE7, 0x9A, 0x51, 0xF5, 0xAC, 0x00
};
#endif /* WP_HAVE_ED448 */

static int sign_verify(unsigned char* sig, size_t sigLen,
    EVP_PKEY *pkey, const char* name)
{
    int err = 0;
    static unsigned char buf[128];
    static size_t bufLen = 0;

    if (bufLen == 0) {
        err = RAND_bytes(buf, sizeof(buf)) == 0;
        bufLen = sizeof(buf);
    }

    if (err == 0) {
        PRINT_MSG("Sign with OpenSSL (%s)", name);
        err = test_digest_sign(pkey, osslLibCtx, buf, bufLen, NULL,
                                sig, &sigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with WolfProvider (%s)", name);
        err = test_digest_verify(pkey, wpLibCtx, buf, bufLen, NULL,
                                sig, sigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify bad signature with WolfProvider (%s)", name);
        sig[1] ^= 0x80;
        err = test_digest_verify(pkey, wpLibCtx, buf, bufLen, NULL,
                                sig, sigLen, 0) != 1;
    }
    if (err == 0) {
        PRINT_MSG("Sign with WolfProvider (%s)", name);
        err = test_digest_sign(pkey, wpLibCtx, buf, bufLen, NULL,
                            sig, &sigLen, 0);
    }
    if (err == 0) {
        PRINT_MSG("Verify with OpenSSL (%s)", name);
        err = test_digest_verify(pkey, osslLibCtx, buf, bufLen, NULL,
                                sig, sigLen, 0);
    }

    return err;
}

int test_ecx_sign_verify(void *data)
{
    int err = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char buf[128];
    const unsigned char *p;

    #ifdef WP_HAVE_ED25519
    unsigned char sig_ed25519[ED25519_SIGSIZE];
    #endif
    #ifdef WP_HAVE_ED448
    unsigned char sig_ed448[ED448_SIGSIZE];
    #endif

    (void)data;

    struct {
        int type;
        size_t keyLen;
        const unsigned char* key;
        size_t sigLen;
        unsigned char* sig;
        const char* name;
    } types[] = {
        #ifdef WP_HAVE_ED25519
        { EVP_PKEY_ED25519, sizeof(ed25519_key_der), ed25519_key_der, 
            sizeof(sig_ed25519), sig_ed25519, "ed25519" },
        #endif
        #ifdef WP_HAVE_ED448
        { EVP_PKEY_ED448, sizeof(ed448_key_der), ed448_key_der, 
            sizeof(sig_ed448), sig_ed448, "ed448" },
        #endif
    };

    for (unsigned i = 0; i < ARRAY_SIZE(types) && err == 0; i++) {
        PRINT_MSG("Testing %s", types[i].name);
        PRINT_MSG("Testing ECX sign/verify with DER keys (%s)", 
            types[i].name);
        err = RAND_bytes(buf, sizeof(buf)) == 0;
        p = types[i].key;

        if (err == 0) {
            pkey = d2i_PrivateKey(types[i].type, NULL, &p, types[i].keyLen);
            err = pkey == NULL;
            if (err) {
                PRINT_MSG("could not create key");
            }
        }

        if (err == 0) {
            err = sign_verify(types[i].sig, types[i].sigLen, pkey, types[i].name);
        }

        EVP_PKEY_free(pkey);
    }

    return err;
}

int test_ecx_sign_verify_raw_priv(void *data)
{
    int err = 0;
    (void)data;

    EVP_PKEY *pkey_ossl = NULL;
    EVP_PKEY *pkey_wolf = NULL;

    #ifdef WP_HAVE_ED25519
    unsigned char sig_ed25519[ED25519_SIGSIZE];
    #endif
    #ifdef WP_HAVE_ED448
    unsigned char sig_ed448[ED448_SIGSIZE];
    #endif

    struct {
        int type;
        size_t keyLen;
        const unsigned char* key;
        size_t sigLen;
        unsigned char* sig;
        const char* name;
    } types[] = {
        #ifdef WP_HAVE_ED25519
        { EVP_PKEY_ED25519, sizeof(ed25519_priv_key_raw), ed25519_priv_key_raw, 
            sizeof(sig_ed25519), sig_ed25519, "ED25519" },
        #endif
        #ifdef WP_HAVE_ED448
        { EVP_PKEY_ED448, sizeof(ed448_priv_key_raw), ed448_priv_key_raw,
            sizeof(sig_ed448), sig_ed448, "ED448" },
        #endif
    };

    for (unsigned i = 0; i < ARRAY_SIZE(types) && err == 0; i++) {
        PRINT_MSG("Testing ECX sign/verify with raw keys (%s)", 
            types[i].name);

        if (err == 0) {
            pkey_ossl = EVP_PKEY_new_raw_private_key_ex(osslLibCtx, 
                types[i].name, NULL, types[i].key, types[i].keyLen);
            err = pkey_ossl == NULL;
            if (err) {
                PRINT_MSG("could not create key (OpenSSL)");
            }
        }

        if (err == 0) {
            pkey_wolf = EVP_PKEY_new_raw_private_key_ex(wpLibCtx, types[i].name, 
                NULL, types[i].key, types[i].keyLen);
            err = pkey_wolf == NULL;
            if (err) {
                PRINT_MSG("could not create key (wolfSSL)");
            }
        }

        if (err == 0) {
            if (EVP_PKEY_cmp(pkey_wolf, pkey_ossl) != 1) {
                PRINT_MSG("EVP_PKEY_cmp failed"); 
                err = 1;
            }
            if (EVP_PKEY_cmp_parameters(pkey_wolf, pkey_ossl) != 1) {
                PRINT_MSG("EVP_PKEY_cmp_parameters failed");
                err = 1;
            }
        }

        if (err == 0) {
            err = sign_verify(types[i].sig, types[i].sigLen, pkey_ossl, 
                types[i].name);
        }

        if (err == 0) {
            err = sign_verify(types[i].sig, types[i].sigLen, pkey_wolf, 
                types[i].name);
        }

        EVP_PKEY_free(pkey_ossl);
        EVP_PKEY_free(pkey_wolf);
    }

    return err;
}

int test_ecx_sign_verify_raw_pub(void *data)
{
    int err = 0;
    (void)data;

    EVP_PKEY *pkey_der = NULL;
    EVP_PKEY *pkey_ossl = NULL;
    EVP_PKEY *pkey_wolf = NULL;
    const unsigned char *p = NULL;
    unsigned char buf[128];
    size_t bufLen = 0;

    #ifdef WP_HAVE_ED25519
    unsigned char sig_ed25519[ED25519_SIGSIZE];
    #endif
    #ifdef WP_HAVE_ED448
    unsigned char sig_ed448[ED448_SIGSIZE];
    #endif

    struct {
        int type;
        size_t keyLen;
        const unsigned char* key;
        size_t pubKeyLen;
        const unsigned char* pubKey;
        size_t sigLen;
        unsigned char* sig;
        const char* name;
    } types[] = {
        #ifdef WP_HAVE_ED25519
        { EVP_PKEY_ED25519, 
            sizeof(ed25519_key_der), ed25519_key_der,
            sizeof(ed25519_pub_key_raw), ed25519_pub_key_raw, 
            sizeof(sig_ed25519), sig_ed25519, "ED25519" },
        #endif
        #ifdef WP_HAVE_ED448
        { EVP_PKEY_ED448, 
            sizeof(ed448_key_der), ed448_key_der,
            sizeof(ed448_pub_key_raw), ed448_pub_key_raw,
            sizeof(sig_ed448), sig_ed448, "ED448" },
        #endif
    };

    if (err == 0) {
        err = RAND_bytes(buf, sizeof(buf)) == 0;
        bufLen = sizeof(buf);
    }

    for (unsigned i = 0; i < ARRAY_SIZE(types) && err == 0; i++) {
        PRINT_MSG("Testing ECX sign/verify with raw public keys (%s)", 
            types[i].name);

        /* Use OpenSSL to get the key from the DER */
        if (err == 0) {
            p = types[i].key;
            pkey_der = d2i_PrivateKey(types[i].type, NULL, &p, types[i].keyLen);
            err = pkey_der == NULL;
            if (err) {
                PRINT_MSG("could not create key");
            }
        }

        /* Use OpenSSL to sign the block of random bytes */
        if (err == 0) {
            PRINT_MSG("Sign with OpenSSL (%s)", types[i].name);
            err = test_digest_sign(pkey_der, osslLibCtx, buf, bufLen, NULL,
                                    types[i].sig, &types[i].sigLen, 0);
        }

        /* Create keys from the public byte arrays */
        if (err == 0) {
            pkey_ossl = EVP_PKEY_new_raw_public_key_ex(osslLibCtx, 
                types[i].name, NULL, types[i].pubKey, types[i].pubKeyLen);
            err = pkey_ossl == NULL;
            if (err) {
                PRINT_MSG("could not create key (OpenSSL)");
            }
        }

        if (err == 0) {
            pkey_wolf = EVP_PKEY_new_raw_public_key_ex(wpLibCtx, types[i].name, 
                NULL, types[i].pubKey, types[i].pubKeyLen);
            err = pkey_wolf == NULL;
            if (err) {
                PRINT_MSG("could not create key (wolfSSL)");
            }
        }

        /* Compare keys */
        if (err == 0) {
            if (EVP_PKEY_cmp(pkey_wolf, pkey_ossl) != 1) {
                PRINT_MSG("EVP_PKEY_cmp failed"); 
                err = 1;
            }
            if (EVP_PKEY_cmp_parameters(pkey_wolf, pkey_ossl) != 1) {
                PRINT_MSG("EVP_PKEY_cmp_parameters failed");
                err = 1;
            }
        }

        /* Verify the signature with the public keys */
        if (err == 0) {
            PRINT_MSG("Verify with OpenSSL (%s)", types[i].name);
            err = test_digest_verify(pkey_ossl, osslLibCtx, buf, bufLen, NULL,
                                    types[i].sig, types[i].sigLen, 0);
        }
        if (err == 0) {
            PRINT_MSG("Verify with WolfProvider (%s)", types[i].name);
            err = test_digest_verify(pkey_wolf, wpLibCtx, buf, bufLen, NULL,
                                    types[i].sig, types[i].sigLen, 0);
        }

        /* Verify bad signature with the public keys */
        types[i].sig[1] ^= 0x80;
        if (err == 0) {
            PRINT_MSG("Verify bad signature with OpenSSL (%s)", types[i].name);
            err = test_digest_verify(pkey_ossl, osslLibCtx, buf, bufLen, NULL,
                                    types[i].sig, types[i].sigLen, 0) != 1;
        }
        if (err == 0) {
            PRINT_MSG("Verify bad signature with WolfProvider (%s)", types[i].name);
            err = test_digest_verify(pkey_wolf, wpLibCtx, buf, bufLen, NULL,
                                    types[i].sig, types[i].sigLen, 0) != 1;
        }

        EVP_PKEY_free(pkey_der);
        EVP_PKEY_free(pkey_ossl);
        EVP_PKEY_free(pkey_wolf);
    }

    return err;
}

#endif /* defined(WP_HAVE_ED25519) || defined(WP_HAVE_ECD444) */
