/* wp_aes_xts.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_AESXTS

/* IEEE 1619-2018 / SP 800-38E: max 2^20 blocks per data unit, as OpenSSL. */
#define WP_AES_XTS_MAX_BYTES    (((size_t)1 << 20) * AES_BLOCK_SIZE)

/**
 * Data structure for AES-XTS.
 */
typedef struct wp_AesXtsCtx {
    /** wolfSSL XTS object: data key (direction specific) and tweak key. */
    XtsAes xts;

    /** Length of both keys combined in bytes: 32 or 64. */
    size_t keyLen;

    /** Direction the key schedule was built for. */
    unsigned int enc:1;
    /** Key schedule is set. */
    unsigned int keySet:1;
    /** Tweak has been set. */
    unsigned int ivSet:1;

    /** Tweak for each data unit. wolfCrypt never advances it, so
     * IV == UPDATED_IV. */
    unsigned char iv[AES_BLOCK_SIZE];
} wp_AesXtsCtx;


/**
 * Free the AES-XTS context object.
 *
 * @param [in, out] ctx  AES-XTS context object.
 */
static void wp_aes_xts_freectx(wp_AesXtsCtx *ctx)
{
    wc_AesXtsFree(&ctx->xts);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/**
 * Duplicate the AES-XTS context object.
 *
 * @param [in] src  AES-XTS context object to copy.
 * @return  NULL on failure, and always when WC_AESFREE_IS_MANDATORY.
 * @return  AES-XTS context object.
 */
static void *wp_aes_xts_dupctx(wp_AesXtsCtx *src)
{
    wp_AesXtsCtx *dst = NULL;

#ifndef WC_AESFREE_IS_MANDATORY
    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_malloc(sizeof(*dst));
    }
    if (dst != NULL) {
        XMEMCPY(dst, src, sizeof(*src));
    }
#else
    /* Aes owns fds/handles/heap here: a shallow copy would share them. */
    (void)src;
#endif

    return dst;
}


/**
 * Parameters able to be retrieved for an AES-XTS cipher.
 */
static const OSSL_PARAM wp_aes_xts_supported_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};

/**
 * Returns the parameters that can be retrieved.
 *
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_aes_xts_gettable_params(WOLFPROV_CTX *provCtx)
{
    (void)provCtx;
    return wp_aes_xts_supported_gettable_params;
}

/**
 * Get the values of the AES-XTS cipher for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      keyLen  Length of both keys combined in bytes.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_aes_xts_get_params(OSSL_PARAM params[], size_t keyLen)
{
    int ok = 1;
    OSSL_PARAM *p;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_get_params");

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, EVP_CIPH_XTS_MODE))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, keyLen))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, 1))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, 1))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, 0))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of an AES-XTS context that can be retrieved.
 *
 * @param [in] ctx      AES-XTS context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_aes_xts_gettable_ctx_params(wp_AesXtsCtx *ctx,
    WOLFPROV_CTX *provCtx)
{
    /**
     * Parameters able to be retrieved for an AES-XTS context.
     */
    static const OSSL_PARAM wp_aes_xts_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_xts_supported_gettable_ctx_params;
}

/**
 * Put values from the AES-XTS context object into parameters objects.
 *
 * @param [in]      ctx     AES-XTS context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_get_ctx_params(wp_AesXtsCtx *ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM *p;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_get_ctx_params");

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, AES_BLOCK_SIZE))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->keyLen))) {
            ok = 0;
        }
    }
    if (ok) {
        /* OpenSSL reports its generic pad flag, which XTS never clears. */
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        if ((p != NULL) && (!OSSL_PARAM_set_uint(p, 1))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
        if ((p != NULL) && (!OSSL_PARAM_set_uint(p, 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, AES_BLOCK_SIZE)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->iv, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, AES_BLOCK_SIZE)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->iv, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of an AES-XTS context that can be set.
 *
 * @param [in] ctx      AES-XTS context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_aes_xts_settable_ctx_params(wp_AesXtsCtx *ctx,
    WOLFPROV_CTX *provCtx)
{
    /**
     * Parameters able to be set into an AES-XTS context.
     */
    static const OSSL_PARAM wp_aes_xts_supported_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_xts_supported_settable_ctx_params;
}

/**
 * Sets the parameters to use into AES-XTS context object.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_set_ctx_params(wp_AesXtsCtx *ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_set_ctx_params");

    if (params != NULL) {
        size_t keyLen = ctx->keyLen;

        if (!wp_params_get_size_t(params, OSSL_CIPHER_PARAM_KEYLEN, &keyLen)) {
            ok = 0;
        }
        if (ok && (keyLen != ctx->keyLen)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of AES-XTS.
 *
 * Internal. Handles both encrypt and decrypt.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      key     Data key followed by tweak key. May be NULL.
 * @param [in]      keyLen  Length of both keys combined in bytes.
 * @param [in]      iv      Tweak. May be NULL.
 * @param [in]      ivLen   Length of tweak in bytes.
 * @param [in]      params  Parameters to set against AES-XTS context object.
 * @param [in]      enc     Initializing for encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_init(wp_AesXtsCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int enc)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_init");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (iv != NULL)) {
        if (ivLen != AES_BLOCK_SIZE) {
            ok = 0;
        }
        else {
            XMEMCPY(ctx->iv, iv, AES_BLOCK_SIZE);
            ctx->ivSet = 1;
        }
    }

    if (ok && (key != NULL)) {
        int rc;

        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        /* Encrypt only, as OpenSSL. Decrypt is left to wolfCrypt, which also
         * refuses under FIPS and, by default, from wolfSSL 5.9.2. */
        if (ok && enc &&
                (CRYPTO_memcmp(key, key + keyLen / 2, keyLen / 2) == 0)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_AesXtsSetKeyNoInit(&ctx->xts, key, (word32)keyLen,
                enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_AES,
                    "wc_AesXtsSetKeyNoInit", rc);
                /* May fail after replacing the data key: no key now. */
                ctx->keySet = 0;
                ok = 0;
            }
            else {
                /* Direction is baked into the schedule: change it only with a
                 * key. */
                ctx->keySet = 1;
                ctx->enc = enc;
            }
        }
    }

    if (ok) {
        ok = wp_aes_xts_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of AES-XTS for encryption.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      key     Data key followed by tweak key. May be NULL.
 * @param [in]      keyLen  Length of both keys combined in bytes.
 * @param [in]      iv      Tweak. May be NULL.
 * @param [in]      ivLen   Length of tweak in bytes.
 * @param [in]      params  Parameters to set against AES-XTS context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_einit(wp_AesXtsCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_xts_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialization of AES-XTS for decryption.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      key     Data key followed by tweak key. May be NULL.
 * @param [in]      keyLen  Length of both keys combined in bytes.
 * @param [in]      iv      Tweak. May be NULL.
 * @param [in]      ivLen   Length of tweak in bytes.
 * @param [in]      params  Parameters to set against AES-XTS context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_dinit(wp_AesXtsCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_xts_init(ctx, key, keyLen, iv, ivLen, params, 0);
}

/**
 * Encrypt/decrypt one data unit with AES-XTS.
 *
 * Used for both update and one-shot cipher.
 *
 * @param [in]  ctx      AES-XTS context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data unit to encrypt/decrypt.
 * @param [in]  inLen    Length of data unit in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_update(wp_AesXtsCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_update");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < inLen)) {
        ok = 0;
    }
    if (ok && ((!ctx->keySet) || (!ctx->ivSet))) {
        ok = 0;
    }
    if (ok && ((in == NULL) || (out == NULL))) {
        ok = 0;
    }
    if (ok && ((inLen < AES_BLOCK_SIZE) || (inLen > WP_AES_XTS_MAX_BYTES))) {
        ok = 0;
    }
    if (ok) {
        if (ctx->enc) {
            rc = wc_AesXtsEncrypt(&ctx->xts, out, in, (word32)inLen, ctx->iv,
                AES_BLOCK_SIZE);
        }
        else {
            rc = wc_AesXtsDecrypt(&ctx->xts, out, in, (word32)inLen, ctx->iv,
                AES_BLOCK_SIZE);
        }
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_AES,
                ctx->enc ? "wc_AesXtsEncrypt" : "wc_AesXtsDecrypt", rc);
            ok = 0;
        }
    }
    if (ok) {
        *outLen = inLen;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES-XTS encryption/decryption.
 *
 * @param [in]  ctx      AES-XTS context object. Unused.
 * @param [out] out      Buffer to hold encrypted/decrypted data. Unused.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer. Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_final(wp_AesXtsCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_final");

    (void)ctx;
    (void)out;
    (void)outSize;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok) {
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}


/** Implements get params, new context and dispatch table for AES-XTS. */
#define IMPLEMENT_AES_XTS(kBits)                                               \
/**                                                                            \
 * Get the values of the AES-XTS cipher for the parameters.                    \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_aes_##kBits##_xts_get_params(OSSL_PARAM params[])                \
{                                                                              \
    return wp_aes_xts_get_params(params, 2 * (kBits) / 8);                     \
}                                                                              \
/**                                                                            \
 * Create a new AES-XTS context object.                                        \
 *                                                                             \
 * @param [in] provCtx  Provider context object. Unused.                       \
 * @return  NULL on failure.                                                   \
 * @return  AES-XTS context object on success.                                 \
 */                                                                            \
static wp_AesXtsCtx* wp_aes_##kBits##_xts_newctx(WOLFPROV_CTX *provCtx)        \
{                                                                              \
    wp_AesXtsCtx *ctx = NULL;                                                  \
    int rc;                                                                    \
                                                                               \
    /* Warm AES CAST before the first wc_AesXts* call (FIPS wrappers gate on   \
     * it). */                                                                 \
    WP_CHECK_FIPS_ALGO_PTR(WP_CAST_ALGO_AES);                                  \
                                                                               \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        rc = wc_AesXtsInit(&ctx->xts, NULL, INVALID_DEVID);                    \
        if (rc != 0) {                                                         \
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_AES, "wc_AesXtsInit", rc);  \
            OPENSSL_free(ctx);                                                 \
            ctx = NULL;                                                        \
        }                                                                      \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        ctx->keyLen = 2 * (kBits) / 8;                                         \
    }                                                                          \
    return ctx;                                                                \
}                                                                              \
const OSSL_DISPATCH wp_aes##kBits##xts_functions[] = {                         \
    { OSSL_FUNC_CIPHER_NEWCTX,          (DFUNC)wp_aes_##kBits##_xts_newctx  }, \
    { OSSL_FUNC_CIPHER_FREECTX,         (DFUNC)wp_aes_xts_freectx           }, \
    { OSSL_FUNC_CIPHER_DUPCTX,          (DFUNC)wp_aes_xts_dupctx            }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,    (DFUNC)wp_aes_xts_einit             }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,    (DFUNC)wp_aes_xts_dinit             }, \
    { OSSL_FUNC_CIPHER_UPDATE,          (DFUNC)wp_aes_xts_update            }, \
    { OSSL_FUNC_CIPHER_FINAL,           (DFUNC)wp_aes_xts_final             }, \
    { OSSL_FUNC_CIPHER_CIPHER,          (DFUNC)wp_aes_xts_update            }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                                     (DFUNC)wp_aes_##kBits##_xts_get_params }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,  (DFUNC)wp_aes_xts_get_ctx_params    }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,  (DFUNC)wp_aes_xts_set_ctx_params    }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_aes_xts_gettable_params   }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                                     (DFUNC)wp_aes_xts_gettable_ctx_params  }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                                     (DFUNC)wp_aes_xts_settable_ctx_params  }, \
    { 0, NULL }                                                                \
};

/** wp_aes256xts_functions */
IMPLEMENT_AES_XTS(256)
/** wp_aes128xts_functions */
IMPLEMENT_AES_XTS(128)

#endif /* WP_HAVE_AESXTS */
