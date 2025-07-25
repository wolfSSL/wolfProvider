/* wp_krb5kdf.c
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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

/** Base set of parameters settable against context for KRB5KDF. */
#define WP_KRB5KDF_BASE_SETTABLES                                          \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),           \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),               \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),                 \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_CONSTANT, NULL, 0)

/**
 * The KRB5KDF context structure.
 */
typedef struct wp_Krb5kdfCtx {
    /** wolfSSL provider context. */
    WOLFPROV_CTX* provCtx;

    /** Cipher type for KRB5KDF. */
    int cipherType;

    /** Key for KDF. */
    unsigned char* key;
    /** Size of key in bytes. */
    size_t keySz;

    /** Constant for KRB5KDF. */
    unsigned char* constant;
    /** Size of constant in bytes. */
    size_t constantSz;
} wp_Krb5kdfCtx;

#define WP_KRB5KDF_CIPHER_NONE 0
#define WP_KRB5KDF_CIPHER_AES_128_CBC 1
#define WP_KRB5KDF_CIPHER_AES_256_CBC 2

/**
 * Create a new KRB5KDF context object.
 *
 * @param [in] provCtx  wolfProvider context object.
 * @return  NULL on failure.
 * @return  KRB5KDF context object on success.
 */
static wp_Krb5kdfCtx* wp_kdf_krb5kdf_new(WOLFPROV_CTX* provCtx)
{
    wp_Krb5kdfCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
        ctx->cipherType = WP_KRB5KDF_CIPHER_NONE;
    }

    return ctx;
}

/**
 * Clear KRB5KDF context object.
 *
 * @param [in, out] ctx  KRB5KDF context object.
 */
static void wp_kdf_krb5kdf_clear(wp_Krb5kdfCtx* ctx)
{
    if (ctx != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->keySz);
        if (ctx->constant != NULL) {
            OPENSSL_free(ctx->constant);
        }
    }
}

/**
 * Free the KRB5KDF context object.
 *
 * @param [in, out] ctx  KRB5KDF context object.
 */
static void wp_kdf_krb5kdf_free(wp_Krb5kdfCtx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_krb5kdf_clear(ctx);
        OPENSSL_free(ctx);
    }
}

/**
 * Reset KRB5KDF context object.
 *
 * Disposes of allocated data.
 *
 * @param [in, out] ctx  KRB5KDF context object.
 */
static void wp_kdf_krb5kdf_reset(wp_Krb5kdfCtx* ctx)
{
    if (ctx != NULL) {
        WOLFPROV_CTX* provCtx = ctx->provCtx;
        wp_kdf_krb5kdf_clear(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

#define WP_MAX_CIPHER_NAME_LEN 12

/**
 * Set the KRB5KDF context parameters.
 *
 * @param [in, out] ctx     KRB5KDF context object.
 * @param [in]      params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_krb5kdf_set_ctx_params(wp_Krb5kdfCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    if (params != NULL) {
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_CIPHER);
            if ((p != NULL) && (p->data != NULL)) {
                char cipher[WP_MAX_CIPHER_NAME_LEN];
                char* pCipher = cipher;
                XMEMSET(cipher, 0, sizeof(cipher));

                if (!OSSL_PARAM_get_utf8_string(p, &pCipher, sizeof(cipher))) {
                    ok = 0;
                }
                if (ok) {
                    /* Only allow AES-128-CBC or AES-256-CBC. */
                    if (XSTRCMP(cipher, "AES-128-CBC") == 0) {
                        ctx->cipherType = WP_KRB5KDF_CIPHER_AES_128_CBC;
                    }
                    else if (XSTRCMP(cipher, "AES-256-CBC") == 0) {
                        ctx->cipherType = WP_KRB5KDF_CIPHER_AES_256_CBC;
                    }
                    else {
                        ok = 0;
                    }
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_KEY);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_clear_free(ctx->key, ctx->keySz);
                ctx->key = NULL;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->key, 0,
                        &ctx->keySz)) {
                    ok = 0;
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_CONSTANT);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_free(ctx->constant);
                ctx->constant = NULL;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->constant, 0,
                        &ctx->constantSz)) {
                    ok = 0;
                }
            }
        }
    }

    return ok;
}

/**
 * Get the KRB5KDF context parameters.
 *
 * @param [in]      ctx     KRB5KDF context object.
 * @param [in, out] params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_krb5kdf_get_ctx_params(wp_Krb5kdfCtx* ctx,
    OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->keySz)) {
            ok = 0;
        }
    }

    return ok;
}

/**
 * Returns the parameters that can be set in the KRB5KDF context.
 *
 * @param [in] ctx      KRB5KDF context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_krb5kdf_settable_ctx_params(wp_Krb5kdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_krb5kdf_supported_settable_ctx_params[] = {
        WP_KRB5KDF_BASE_SETTABLES,
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_krb5kdf_supported_settable_ctx_params;
}

/**
 * Returns the parameters that can be retrieved from the KRB5KDF context.
 *
 * @param [in] ctx      KRB5KDF context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_krb5kdf_gettable_ctx_params(wp_Krb5kdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_krb5kdf_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_krb5kdf_supported_gettable_ctx_params;
}

static int wp_kdf_krb5kdf_expected_key_size(wp_Krb5kdfCtx* ctx)
{
    switch (ctx->cipherType) {
        case WP_KRB5KDF_CIPHER_AES_128_CBC:
            return 16;
        case WP_KRB5KDF_CIPHER_AES_256_CBC:
            return 32;
        default:
            return 0;
    }
}

/* N-fold(K) where blocksize is N, and constant_len is K
 * Note: Here |= denotes concatenation
 *
 * L = lcm(N,K)
 * R = L/K
 *
 * for r: 1 -> R
 *   s |= constant rot 13*(r-1))
 *
 * block = 0
 * for k: 1 -> K
 *   block += s[N(k-1)..(N-1)k] (ones'-complement addition)
 *
 * Optimizing for space we compute:
 * for each l in L-1 -> 0:
 *   s[l] = (constant rot 13*(l/K))[l%k]
 *   block[l % N] += s[l] (with carry)
 * finally add carry if any
 */
static void n_fold(unsigned char *block, unsigned int blocksize,
                   const unsigned char *constant, size_t constant_len)
{
    unsigned int cnt;
    unsigned int i;
    unsigned int a;
    unsigned int b;
    unsigned int carry;
    unsigned int rot;
    unsigned int bi;
    unsigned int const_len = (unsigned int)constant_len;

    /* If equal size then only one unrotated copy of constant needed. */
    if (blocksize == const_len) {
        XMEMCPY(block, constant, constant_len);
        return;
    }

    /* Compute GCD of constant_len and blocksize. */
    a = blocksize;
    b = const_len;
    while (b != 0) {
        unsigned int t = b;
        b = a % b;
        a = t;
    }
    /* Calculate LCM of constant_len and blocksize. */
    cnt = (const_len * blocksize) / a;

    /* Start with constant un-rotated and then add to zero for the rest. */
    XMEMCPY(block, constant, constant_len);
    XMEMSET(block + constant_len, 0, blocksize - constant_len);

    /* No initial carry. */
    carry = 0;
    /* First rotation is 13 bits. */
    rot = 13;
    /* Starting block index - constant_len <= blocksize. */
    bi = const_len;
    /* Do one constant at a time - cnt is a multiple of constant_len. */
    for (i = const_len; i < cnt; i += const_len) {
         unsigned int j;
         /* Calculate first index into constant to rotate. */
         unsigned int ci = ((const_len - (rot >> 3)) - 1) % const_len;
         /* Calculate amount to rotate right and left. */
         unsigned char rr = rot & 0x7;
         unsigned char rl = 8 - rr;

         /* Add in constant buffer to block. */
         for (j = 0; j < const_len; j++) {
             /* Rotated constant value. */
             unsigned char rcv;

             /* Get rotated constant buffer value. */
             rcv  = (unsigned char)(constant[ci] << rl);
             ci = (ci + 1) % const_len;
             rcv |= (unsigned char)(constant[ci] >> rr);

             /* Add block value and rotated constant value to previous carry. */
             carry += block[bi] + rcv;
             /* Store new block value. */
             block[bi] = (unsigned char)(carry & 0xff);
             /* Get carry. */
             carry >>= 8;

             /* Next block index. */
             bi = (bi + 1) % blocksize;
         }
         rot += 13;
    }

    /* Final carry pass. */
    for (i = 0; (i < blocksize) && (carry > 0); i++) {
        carry += block[i];
        block[i] = (unsigned char)(carry & 0xff);
        carry >>= 8;
    }
}

/**
 * Derive a key using KRB5KDF.
 *
 * @param [in, out] ctx     KRB5KDF context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_krb5kdf_derive(wp_Krb5kdfCtx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;
    size_t osize = 0;
    size_t cipherLen = 0;
    int rc;
    Aes aes;
    byte block[AES_BLOCK_SIZE];
    byte cipherBlock[AES_BLOCK_SIZE];
    byte *plain = NULL;
    byte *cipher = NULL;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_kdf_krb5kdf_set_ctx_params(ctx, params))) {
        ok = 0;
    }
    if (ok && (ctx->key == NULL)) {
        ok = 0;
    }
    if (ok && (ctx->keySz != keyLen)) {
        ok = 0;
    }
    if (ok && (wp_kdf_krb5kdf_expected_key_size(ctx) != (int)ctx->keySz)) {
        ok = 0;
    }
    if (ok) {
        XMEMSET(key, 0, keyLen);

        rc = wc_AesSetKey(&aes, ctx->key, (word32)ctx->keySz, NULL,
            AES_ENCRYPTION);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        n_fold(block, AES_BLOCK_SIZE, ctx->constant, ctx->constantSz);
        plain = block;
        cipher = cipherBlock;
        for (osize = 0; ok && osize < keyLen; osize += cipherLen) {
            rc = wc_AesCbcEncrypt(&aes, cipher, plain, AES_BLOCK_SIZE);
            if (rc != 0) {
                ok = 0;
            }

            cipherLen = AES_BLOCK_SIZE;
            if (cipherLen > (keyLen - osize))
                cipherLen = (keyLen - osize);

            XMEMCPY(key + osize, cipher, cipherLen);
            if (keyLen > (osize + cipherLen)) {
                rc = wc_AesSetKey(&aes, ctx->key, (word32)ctx->keySz, NULL,
                    AES_ENCRYPTION);
                if (rc != 0) {
                    ok = 0;
                }

                if (ok) {
                    /* swap blocks */
                    plain = cipher;
                    if (cipher == block) {
                        cipher = cipherBlock;
                    } else {
                        cipher = block;
                    }
                }
            }
        }
    }

    wc_AesFree(&aes);

    return ok;
}

/** Dispatch table for KRB5KDF functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_krb5kdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (DFUNC)wp_kdf_krb5kdf_new },
    { OSSL_FUNC_KDF_FREECTX, (DFUNC)wp_kdf_krb5kdf_free },
    { OSSL_FUNC_KDF_RESET, (DFUNC)wp_kdf_krb5kdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (DFUNC)wp_kdf_krb5kdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (DFUNC)wp_kdf_krb5kdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (DFUNC)wp_kdf_krb5kdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (DFUNC)wp_kdf_krb5kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (DFUNC)wp_kdf_krb5kdf_get_ctx_params },
    { 0, NULL }
};
