/* test_tls1_prf.c
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

#include "unit.h"

#ifdef WP_HAVE_TLS1_PRF

static int test_tls1_prf_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    int keyLen, const EVP_MD *md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[32] = { 0, };
    unsigned char label[5] = "Label";
    unsigned char seed[32] = { 0, };
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "TLS1-PRF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set_tls1_prf_md(ctx, md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, secret,
                                              sizeof(secret)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, label, sizeof(label)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed, sizeof(seed)) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, NULL, 0) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed, 0) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if (len != (size_t)keyLen) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_tls1_prf_md(const EVP_MD *md)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    PRINT_MSG("Calc with OpenSSL");
    err = test_tls1_prf_calc(osslLibCtx, oKey, sizeof(oKey), md);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with wolfSSL");
        err = test_tls1_prf_calc(wpLibCtx, wKey, sizeof(wKey), md);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }

    return err;
}

static int test_tls1_prf_str_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    int keyLen, const char *md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    /* FIPS min key length is 14 */
    const char* secret = "0123456789abcf";
    const char* label = "Label";
    const char* seed = "A seed";
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "TLS1-PRF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "secret", secret) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "seed", label) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "seed", seed) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "seed", "") != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if (len != (size_t)keyLen) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_tls1_prf_hexstr_calc(OSSL_LIB_CTX* libCtx, unsigned char *key,
    int keyLen, const char *md)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    const char* secret = "00000000000000000000000000000000";
    const char* label = "31323334343536";
    const char* seed = "00000000000000000000000000000000";
    size_t len = keyLen;

    ctx = EVP_PKEY_CTX_new_from_name(libCtx, "TLS1-PRF", NULL);
    if (ctx == NULL) {
        err = 1;
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "md", md) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsecret", secret) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexsecret", secret) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexseed", label) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_CTX_ctrl_str(ctx, "hexseed", seed) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive(ctx, key, &len) != 1) {
            err = 1;
        }
    }

    if (len != (size_t)keyLen) {
        err = 1;
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

#if defined(WP_HAVE_SHA256) || defined(WP_HAVE_SHA384)
static int test_tls1_prf_str_md(const char *md)
{
    int err = 0;
    unsigned char oKey[128];
    unsigned char wKey[128];

    PRINT_MSG("Calc with strings OpenSSL");
    err = test_tls1_prf_str_calc(osslLibCtx, oKey, sizeof(oKey), md);
    if (err == 1) {
        PRINT_MSG("FAILED OpenSSL");
    }

    if (err == 0) {
        PRINT_MSG("Calc with strings wolfSSL");
        err = test_tls1_prf_str_calc(wpLibCtx, wKey, sizeof(wKey), md);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings OpenSSL");
        err = test_tls1_prf_hexstr_calc(osslLibCtx, oKey, sizeof(oKey), md);
        if (err == 1) {
            PRINT_MSG("FAILED OpenSSL");
        }
    }

    if (err == 0) {
        PRINT_MSG("Calc with hex strings wolfSSL");
        err = test_tls1_prf_hexstr_calc(wpLibCtx, wKey, sizeof(wKey), md);
        if (err == 1) {
            PRINT_MSG("FAILED wolfSSL");
        }
    }


    if ((err == 0) && (memcmp(oKey, wKey, sizeof(oKey)) != 0)) {
        PRINT_BUFFER("OpenSSL key", oKey, sizeof(oKey));
        PRINT_BUFFER("wolfSSL key", wKey, sizeof(wKey));
        err = 1;
    }
    return err;
}
#endif

static int test_tls1_prf_fail_calc(OSSL_LIB_CTX* libCtx)
{
    int err = 0;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char secret[1] = { 0 };
    unsigned char label[1] = { 0 };

    if (EVP_PKEY_CTX_ctrl_str(NULL, "md", "sha256") == 1) {
        err = 1;
    }
    if (err == 0) {
        ctx = EVP_PKEY_CTX_new_from_name(libCtx, "TLS1-PRF", NULL);
        if (ctx == NULL) {
            err = 1;
        }
    }
    if (err == 0) {
        if (EVP_PKEY_derive_init(ctx) != 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Invalid control value. */
        if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE,
                              EVP_PKEY_CTRL_HKDF_SALT, 0, NULL) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative secret length. */
        if (EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, secret, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Negative seed length. */
        if (EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, label, -1) == 1) {
            err = 1;
        }
    }
    if (err == 0) {
        /* Invalid control type string. */
        if (EVP_PKEY_CTX_ctrl_str(ctx, "invalid", "") == 1) {
            err = 1;
        }
    }

    EVP_PKEY_CTX_free(ctx);
    return err;
}

static int test_tls1_prf_fail(void)
{
    int err;

    PRINT_MSG("Failure cases with OpenSSL");
    err = test_tls1_prf_fail_calc(osslLibCtx);
    if (err == 0) {
        PRINT_MSG("Failure cases with wolfSSL");
        err = test_tls1_prf_fail_calc(wpLibCtx);
    }

    return err;
}

int test_tls1_prf(void *data)
{
    int err = 0;

    (void)data;

#ifdef WP_HAVE_MD5_SHA1
    err = test_tls1_prf_md(EVP_md5_sha1());
#endif
#ifdef WP_HAVE_SHA256
    if (err == 0) {
        err = test_tls1_prf_md(EVP_sha256());
    }
#endif
#ifdef WP_HAVE_SHA384
    if (err == 0) {
        err = test_tls1_prf_md(EVP_sha384());
    }
#endif
#if defined(WP_HAVE_SHA256)
    if (err == 0) {
        err = test_tls1_prf_str_md("sha256");
    }
#elif defined(WP_HAVE_SHA384)
    if (err == 0) {
        err = test_tls1_prf_str_md("sha384");
    }
#endif
    if (err == 0) {
        err = test_tls1_prf_fail();
    }

    return err;
}

#endif /* WP_HAVE_TLS1_PRF */


