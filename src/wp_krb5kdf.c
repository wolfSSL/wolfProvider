/* wp_krb5kdf.c
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

/* Calculate the greatest common divisor using Euclidean algorithm */
static unsigned int gcd(unsigned int a, unsigned int b)
{
    while (b != 0) {
        unsigned int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

/* Calculate the least common multiple */
static unsigned int lcm(unsigned int a, unsigned int b)
{
    unsigned int g = gcd(a, b);
    if (g == 0) {
        return 0;
    }
    /* Check for potential overflow before multiplication */
    if (a > 0xFFFFFFFFU / (b / g)) {
        return 0;
    }
    return (a / g) * b;
}

/* Add two byte arrays using 1's complement addition (end-around carry) */
static void ones_complement_add(unsigned char *result, const unsigned char *a,
    const unsigned char *b, unsigned int len)
{
    unsigned int carry = 0;
    int i;

    /* Add from right to left (MSB at index 0) */
    for (i = (int)len - 1; i >= 0; i--) {
        unsigned int sum = (unsigned int)a[i] + (unsigned int)b[i] + carry;
        result[i] = (unsigned char)(sum & 0xFF);
        carry = (sum >> 8) & 1;
    }

    /* Handle end-around carry for 1's complement */
    while (carry) {
        unsigned int new_carry = 0;
        for (i = (int)len - 1; i >= 0; i--) {
            unsigned int sum = (unsigned int)result[i] + carry;
            result[i] = (unsigned char)(sum & 0xFF);
            new_carry = (sum >> 8) & 1;
            carry = 0;
        }
        carry = new_carry;
    }
}

/* Rotate a byte array to the right by specified number of bits */
static void rotate_right(unsigned char *data, unsigned int data_len,
    unsigned int bits)
{
    unsigned int total_bits = data_len * 8;
    unsigned char *temp;
    unsigned int i;

    if (data_len == 0 || bits == 0) {
        return;
    }

    bits = bits % total_bits;
    if (bits == 0) {
        return;
    }

    temp = (unsigned char*)OPENSSL_malloc(data_len);
    if (temp == NULL) {
        return;
    }

    XMEMSET(temp, 0, data_len);

    /* Perform bit-level rotation */
    for (i = 0; i < total_bits; i++) {
        unsigned int src_byte = i / 8;
        unsigned int src_bit = i % 8;
        unsigned int dst_pos = (i + bits) % total_bits;
        unsigned int dst_byte = dst_pos / 8;
        unsigned int dst_bit = dst_pos % 8;

        /* Extract source bit (MSB = bit 0) */
        unsigned char bit = (data[src_byte] >> (7 - src_bit)) & 1;

        /* Set destination bit (MSB = bit 0) */
        if (bit) {
            temp[dst_byte] |= (1U << (7 - dst_bit));
        }
    }

    XMEMCPY(data, temp, data_len);
    OPENSSL_clear_free(temp, data_len);
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
    unsigned int input_bits = (unsigned int)(constant_len * 8);
    unsigned int output_bits = blocksize * 8;
    unsigned int expanded_bits;
    unsigned int expanded_bytes;
    unsigned int replications;
    unsigned int i;
    unsigned char *expanded = NULL;
    unsigned char *temp = NULL;

    /* Clear output block */
    XMEMSET(block, 0, blocksize);

    /* Handle edge cases */
    if (blocksize == 0 || constant_len == 0) {
        return;
    }

    /* Calculate LCM of input and output bit lengths */
    expanded_bits = lcm(input_bits, output_bits);
    if (expanded_bits == 0) {
        return;
    }

    expanded_bytes = (expanded_bits + 7) / 8;
    expanded = (unsigned char*)OPENSSL_zalloc(expanded_bytes);
    temp = (unsigned char*)OPENSSL_malloc(constant_len);
    if (expanded == NULL || temp == NULL) {
        goto cleanup;
    }

    /* Calculate number of replications */
    replications = expanded_bits / input_bits;

    /* Initialize temp with constant */
    XMEMCPY(temp, constant, constant_len);

    /* Replicate input data with rotation */
    for (i = 0; i < replications; i++) {
        unsigned int bit_offset = i * input_bits;
        unsigned int bit;

        /* Copy current input to expanded buffer at bit offset */
        for (bit = 0; bit < input_bits; bit++) {
            unsigned int src_byte = bit / 8;
            unsigned int src_bit = bit % 8;
            unsigned int dst_pos = bit_offset + bit;
            unsigned int dst_byte = dst_pos / 8;
            unsigned int dst_bit = dst_pos % 8;

            if (dst_byte >= expanded_bytes) {
                break;
            }

            /* Extract bit from source (MSB = bit 0) */
            unsigned char bit_val = (temp[src_byte] >> (7 - src_bit)) & 1;

            /* Set bit in destination (MSB = bit 0) */
            if (bit_val) {
                expanded[dst_byte] |= (1U << (7 - dst_bit));
            }
        }

        /* Rotate input for next iteration */
        if (i + 1 < replications) {
            rotate_right(temp, (unsigned int)constant_len, 13);
        }
    }

    /* Fold the expanded buffer into the output block */
    for (i = 0; i < expanded_bytes; i += blocksize) {
        ones_complement_add(block, block, expanded + i,
            (i + blocksize <= expanded_bytes) ? blocksize :
            (expanded_bytes - i));
    }

cleanup:
    if (expanded != NULL) {
        OPENSSL_clear_free(expanded, expanded_bytes);
    }
    if (temp != NULL) {
        OPENSSL_clear_free(temp, constant_len);
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
