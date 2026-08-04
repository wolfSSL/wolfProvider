/* test_lms.c
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
 */

#include "unit.h"

#include <openssl/decoder.h>
#include <openssl/err.h>

#ifdef WP_HAVE_LMS

/* OpenSSL LMS XDR public keys exclude the single-level HSS header. */
static const unsigned char lmsPub1[] = {
    0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x08,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x2c, 0x57, 0x14, 0x50, 0xae, 0xd9, 0x9c, 0xfb,
    0x4f, 0x4a, 0xc2, 0x85, 0xda, 0x14, 0x88, 0x27,
    0x96, 0x61, 0x83, 0x14, 0x50, 0x8b, 0x12, 0xd2
};

static const unsigned char lmsPub2[] = {
    0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0xdb, 0x54, 0xa4, 0x50, 0x99, 0x01, 0x05, 0x1c,
    0x01, 0xe2, 0x6d, 0x99, 0x90, 0xe5, 0x50, 0x34,
    0x79, 0x86, 0xda, 0x87, 0x92, 0x4f, 0xf0, 0xb1
};

static const unsigned char lmsPub3[] = {
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01,
    0xc3, 0x4b, 0xae, 0x13, 0x90, 0xdd, 0xdb, 0x18,
    0x2e, 0x0e, 0xd8, 0x97, 0x27, 0xcb, 0x17, 0xe6,
    0x50, 0xdb, 0x2d, 0xad, 0x1f, 0xd2, 0xfa, 0x75,
    0x19, 0x2b, 0x92, 0x3c, 0x5b, 0x6a, 0xf9, 0xa2,
    0x70, 0xc8, 0x46, 0xd9, 0xfa, 0xfb, 0x22, 0xb0,
    0x45, 0x1f, 0x2c, 0x28, 0xd4, 0x8a, 0x29, 0x67
};

static int lms_from_data(const unsigned char* pub, size_t pubLen,
    int selection, EVP_PKEY** pkey)
{
    int err = 0;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        (unsigned char*)pub, pubLen);
    params[1] = OSSL_PARAM_construct_end();
    ctx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "LMS", NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = EVP_PKEY_fromdata_init(ctx) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_fromdata(ctx, pkey, selection, params) != 1;
    }
    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int lms_decode_data(const unsigned char* data, size_t dataLen,
    int selection, EVP_PKEY** pkey, size_t* remaining)
{
    int err = 0;
    OSSL_DECODER_CTX* ctx = NULL;
    const unsigned char* p = data;

    ctx = OSSL_DECODER_CTX_new_for_pkey(pkey, "XDR", NULL, "LMS",
        selection, wpLibCtx, NULL);
    err = ctx == NULL;
    if (err == 0) {
        err = OSSL_DECODER_from_data(ctx, &p, &dataLen) != 1;
    }
    if (remaining != NULL) {
        *remaining = dataLen;
    }
    OSSL_DECODER_CTX_free(ctx);
    return err;
}

int test_lms_import_export(void* data)
{
    int err = 0;
    EVP_PKEY* key1 = NULL;
    EVP_PKEY* key1Copy = NULL;
    EVP_PKEY* key2 = NULL;
    EVP_PKEY* badKey = NULL;
    EVP_PKEY* rawKey = NULL;
    EVP_PKEY_CTX* checkCtx = NULL;
    OSSL_PARAM* exportedParams = NULL;
    const OSSL_PARAM* p = NULL;
    const void* exported = NULL;
    unsigned char badPub[sizeof(lmsPub1)];
    unsigned char badPubLen[sizeof(lmsPub3)] = { 0 };
    size_t exportedLen = 0;

    (void)data;
    XMEMCPY(badPub, lmsPub1, sizeof(badPub));
    badPub[3] = 0xaa;
    XMEMCPY(badPubLen, lmsPub1, sizeof(lmsPub1));

    err = lms_from_data(lmsPub1, sizeof(lmsPub1), EVP_PKEY_PUBLIC_KEY,
        &key1);
    if (err != 0) {
        PRINT_ERR_MSG("LMS public key import failed");
    }
    if (err == 0) {
        err = lms_from_data(lmsPub1, sizeof(lmsPub1), EVP_PKEY_PUBLIC_KEY,
            &key1Copy);
        if (err != 0) {
            PRINT_ERR_MSG("LMS duplicate public key import failed");
        }
    }
    if (err == 0) {
        err = lms_from_data(lmsPub2, sizeof(lmsPub2), EVP_PKEY_PUBLIC_KEY,
            &key2);
        if (err != 0) {
            PRINT_ERR_MSG("LMS alternate public key import failed");
        }
    }
    if (err == 0) {
        err = EVP_PKEY_todata(key1, EVP_PKEY_PUBLIC_KEY,
            &exportedParams) != 1;
        if (err == 0) {
            p = OSSL_PARAM_locate_const(exportedParams,
                OSSL_PKEY_PARAM_PUB_KEY);
            err = (p == NULL) || !OSSL_PARAM_get_octet_string_ptr(p,
                &exported, &exportedLen);
        }
        if (err != 0) {
            PRINT_ERR_MSG("LMS public key export failed");
        }
    }
    if (err == 0) {
        err = (exportedLen != sizeof(lmsPub1)) || (exported == NULL) ||
            (XMEMCMP(exported, lmsPub1, sizeof(lmsPub1)) != 0);
        if (err != 0) {
            PRINT_ERR_MSG("LMS public key export did not round trip");
        }
    }
    if (err == 0) {
        err = (EVP_PKEY_eq(key1, key1Copy) != 1) ||
            (EVP_PKEY_eq(key1, key2) == 1);
        if (err != 0) {
            PRINT_ERR_MSG("LMS public key equality check failed");
        }
    }
    if (err == 0) {
        err = (EVP_PKEY_parameters_eq(key1, key1Copy) != 1) ||
            (EVP_PKEY_parameters_eq(key1, key2) == 1);
        if (err != 0) {
            PRINT_ERR_MSG("LMS parameter equality check failed");
        }
    }
    if (err == 0) {
        checkCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key1, NULL);
        err = (checkCtx == NULL) || (EVP_PKEY_check(checkCtx) != 1) ||
            (EVP_PKEY_public_check(checkCtx) != 1) ||
            (EVP_PKEY_private_check(checkCtx) == 1);
        if (err != 0) {
            PRINT_ERR_MSG("LMS public/private selection check failed");
        }
    }
    if (err == 0) {
        err = lms_from_data(lmsPub1, sizeof(lmsPub1) - 1,
            EVP_PKEY_PUBLIC_KEY, &badKey) == 0;
        if (err != 0) {
            PRINT_ERR_MSG("LMS short public key was accepted");
        }
    }
    if (err == 0) {
        err = lms_from_data(NULL, sizeof(lmsPub1), EVP_PKEY_PUBLIC_KEY,
            &badKey) == 0;
        if (err != 0) {
            PRINT_ERR_MSG("LMS NULL public key was accepted");
        }
    }
    if (err == 0) {
        err = lms_from_data(badPubLen, sizeof(badPubLen),
            EVP_PKEY_PUBLIC_KEY, &badKey) == 0;
        if (err != 0) {
            PRINT_ERR_MSG("LMS public key with a mismatched length was accepted");
        }
    }
    if (err == 0) {
        err = lms_from_data(badPub, sizeof(badPub), EVP_PKEY_PUBLIC_KEY,
            &badKey) == 0;
        if (err != 0) {
            PRINT_ERR_MSG("LMS public key with an unknown type was accepted");
        }
    }
    if (err == 0) {
        rawKey = EVP_PKEY_new_raw_public_key_ex(wpLibCtx, "LMS", NULL,
            lmsPub1, sizeof(lmsPub1));
        err = rawKey == NULL;
        if (err != 0) {
            PRINT_ERR_MSG("OpenSSL raw LMS public key import failed");
        }
    }
    if (err == 0) {
        EVP_PKEY_CTX_free(checkCtx);
        checkCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, rawKey, NULL);
        err = (checkCtx == NULL) || (EVP_PKEY_private_check(checkCtx) == 1);
        if (err != 0) {
            PRINT_ERR_MSG("Raw LMS public key reported a private component");
        }
    }
    if (err != 0) {
        PRINT_ERR_MSG("LMS public key import/export validation failed");
    }
    ERR_clear_error();
    OSSL_PARAM_free(exportedParams);
    EVP_PKEY_CTX_free(checkCtx);
    EVP_PKEY_free(rawKey);
    EVP_PKEY_free(badKey);
    EVP_PKEY_free(key2);
    EVP_PKEY_free(key1Copy);
    EVP_PKEY_free(key1);
    return err;
}

int test_lms_decode(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* checkCtx = NULL;
    unsigned char bad[sizeof(lmsPub1) + 1];
    size_t remaining = 0;

    (void)data;
    XMEMCPY(bad, lmsPub1, sizeof(lmsPub1));
    bad[sizeof(lmsPub1)] = 0;

    err = lms_decode_data(lmsPub1, sizeof(lmsPub1), EVP_PKEY_PUBLIC_KEY,
        &key, NULL);
    if (err != 0) {
        PRINT_ERR_MSG("LMS XDR public key decode failed");
    }
    EVP_PKEY_free(key);
    key = NULL;
    if (err == 0) {
        err = lms_decode_data(lmsPub3, sizeof(lmsPub3),
            EVP_PKEY_PUBLIC_KEY, &key, NULL);
        if (err != 0) {
            PRINT_ERR_MSG("LMS 32-byte XDR public key decode failed");
        }
    }
    EVP_PKEY_free(key);
    key = NULL;
    if (err == 0) {
        err = lms_decode_data(lmsPub1, sizeof(lmsPub1) - 1,
            EVP_PKEY_PUBLIC_KEY, &key, NULL) == 0;
        if (err != 0) {
            PRINT_ERR_MSG("LMS short XDR public key was accepted");
        }
    }
    if (err == 0) {
        err = lms_decode_data(bad, sizeof(bad), EVP_PKEY_PUBLIC_KEY,
            &key, &remaining);
        if (err != 0) {
            PRINT_ERR_MSG("LMS XDR public key with trailing data failed");
        }
    }
    if (err == 0) {
        err = remaining != 1;
        if (err != 0) {
            PRINT_ERR_MSG("LMS XDR decoder consumed trailing data");
        }
    }
    EVP_PKEY_free(key);
    key = NULL;
    if (err == 0) {
        bad[3] = 0xaa;
        err = lms_decode_data(bad, sizeof(lmsPub1), EVP_PKEY_PUBLIC_KEY,
            &key, NULL) == 0;
        if (err != 0) {
            PRINT_ERR_MSG("LMS XDR public key with an unknown type was accepted");
        }
    }
    if (err == 0) {
        err = lms_decode_data(lmsPub1, sizeof(lmsPub1), EVP_PKEY_KEYPAIR,
            &key, NULL);
        if (err != 0) {
            PRINT_ERR_MSG("LMS XDR keypair selection failed");
        }
    }
    if (err == 0) {
        checkCtx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (checkCtx == NULL) || (EVP_PKEY_private_check(checkCtx) == 1);
        if (err != 0) {
            PRINT_ERR_MSG("Decoded LMS public key reported a private component");
        }
    }
    if (err != 0) {
        PRINT_ERR_MSG("LMS XDR decoder validation failed");
    }
    ERR_clear_error();
    EVP_PKEY_CTX_free(checkCtx);
    EVP_PKEY_free(key);
    return err;
}

int test_lms_unsupported_operations(void* data)
{
    int err = 0;
    EVP_PKEY* key = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY_CTX* genCtx = NULL;
    EVP_SIGNATURE* signature = NULL;
    EVP_MD_CTX* mdCtx = NULL;
    const unsigned char msg[] = "LMS unsupported operation test";
    const unsigned char badSig[] = { 0 };

    (void)data;
    err = lms_from_data(lmsPub1, sizeof(lmsPub1), EVP_PKEY_PUBLIC_KEY, &key);
    if (err == 0) {
        signature = EVP_SIGNATURE_fetch(wpLibCtx, "LMS", NULL);
        ctx = EVP_PKEY_CTX_new_from_pkey(wpLibCtx, key, NULL);
        err = (signature == NULL) || (ctx == NULL);
    }
    if (err == 0) {
        err = EVP_PKEY_verify_message_init(ctx, signature, NULL) != 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify(ctx, badSig, sizeof(badSig), msg,
            sizeof(msg) - 1) == 1;
    }
    if (err == 0) {
        err = EVP_PKEY_verify_init(ctx) != -2;
    }
    if (err == 0) {
        err = EVP_PKEY_sign_message_init(ctx, signature, NULL) != -2;
    }
    if (err == 0) {
        mdCtx = EVP_MD_CTX_new();
        err = (mdCtx == NULL) || (EVP_DigestVerifyInit_ex(mdCtx, NULL, NULL,
            wpLibCtx, NULL, key, NULL) != 0);
    }
    if (err == 0) {
        EVP_MD_CTX_free(mdCtx);
        mdCtx = EVP_MD_CTX_new();
        err = (mdCtx == NULL) || (EVP_DigestSignInit_ex(mdCtx, NULL, NULL,
            wpLibCtx, NULL, key, NULL) != 0);
    }
    if (err == 0) {
        genCtx = EVP_PKEY_CTX_new_from_name(wpLibCtx, "LMS", NULL);
        err = (genCtx == NULL) || (EVP_PKEY_keygen_init(genCtx) != -2) ||
            (EVP_PKEY_paramgen_init(genCtx) != -2);
    }
    if (err != 0) {
        PRINT_ERR_MSG("LMS unsupported operation validation failed");
    }
    ERR_clear_error();
    EVP_MD_CTX_free(mdCtx);
    EVP_SIGNATURE_free(signature);
    EVP_PKEY_CTX_free(genCtx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return err;
}

#endif /* WP_HAVE_LMS */
