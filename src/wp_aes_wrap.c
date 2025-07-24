/* wp_aes_wrap.c
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

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/prov_ssl.h>

#include <wolfprovider/alg_funcs.h>

#ifdef HAVE_AES_KEYWRAP

/**
 * Data structure for AES ciphers that wrap.
 */
typedef struct wp_AesWrapCtx {
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    Aes aes;
#endif

    unsigned int wrap:1;
    unsigned int ivSet:1;

    size_t keyLen;
    size_t ivLen;
    unsigned char iv[AES_IV_SIZE];
#if LIBWOLFSSL_VERSION_HEX < 0x05000000
    unsigned char key[AES_256_KEY_SIZE];
#endif
} wp_AesWrapCtx;


/* Prototype for initialization to call. */
static int wp_aes_wrap_set_ctx_params(wp_AesWrapCtx *ctx,
    const OSSL_PARAM params[]);


/**
 * Free the AES wrap context object.
 *
 * @param [in, out] ctx  AES wrap context object.
 */
static void wp_aes_wrap_freectx(wp_AesWrapCtx *ctx)
{
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    wc_AesFree(&ctx->aes);
#else
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
#endif
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/**
 * Duplicate the AES wrap context object.
 *
 * @param [in] src  AES wrap context object to copy.
 * @return  NULL on failure.
 * @return  AES wrap context object.
 */
static void *wp_aes_wrap_dupctx(wp_AesWrapCtx *src)
{
    wp_AesWrapCtx *dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_malloc(sizeof(*dst));
    }
    if (dst != NULL) {
        /* TODO: copying Aes may not work if it has pointers in it. */
        XMEMCPY(dst, src, sizeof(*src));
    }

    return dst;
}

/**
 * Returns the parameters that can be retrieved.
 *
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_aes_wrap_gettable_params(
    WOLFPROV_CTX *provCtx)
{
    /**
     * Parameters able to be retrieved for an AES wrap operation.
     */
    static const OSSL_PARAM wp_aes_wrap_supported_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_aes_wrap_supported_gettable_params;
}

/**
 * Get the values from the AES wrap context for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      mode    AES cipher mode.
 * @param [in]      kBits   Number of bits in key.
 * @param [in]      ivBits  Number of bits in IV.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_aes_wrap_get_params(OSSL_PARAM params[], unsigned int mode,
    size_t kBits, size_t ivBits)
{
    int ok = 1;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, mode))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, kBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ivBits / 8))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of a cipher context that can be retrieved.
 *
 * @param [in] ctx      AES wrap context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_aes_wrap_gettable_ctx_params(wp_AesWrapCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters able to be retrieved for a cipher context.
     */
    static const OSSL_PARAM wp_aes_wrap_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_wrap_supported_gettable_ctx_params;
}

/**
 * Returns the parameters of a cipher context that can be set.
 *
 * @param [in] ctx      AES wrap context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_aes_wrap_settable_ctx_params(wp_AesWrapCtx* ctx,
    WOLFPROV_CTX *provCtx)
{
    /*
     * Parameters able to be set into a cipher context.
     */
    static const OSSL_PARAM wp_aes_wrap_supported_settable_ctx_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_wrap_supported_settable_ctx_params;
}

/**
 * Initialization of an AES wrap.
 *
 * Internal. Handles both wrap and unwrap.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES wrap context object.
 * @param [in]      wrap    Initializing for wrap.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_init(wp_AesWrapCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int wrap)
{
    int ok = 1;

    ctx->wrap = wrap;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (iv != NULL)) {
        if (ivLen != ctx->ivLen) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, iv, ivLen);
        }
    }

    if (ok && (key != NULL)) {
        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        if (ok) {
        #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
            int rc = wc_AesSetKey(&ctx->aes, key, (word32)ctx->keyLen, iv,
                wrap ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                ok = 0;
            }
        #else
            XMEMCPY(ctx->key, key, keyLen);
        #endif
        }
    }

    if (ok) {
        ok = wp_aes_wrap_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an AES wrapping.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES wrap context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_einit(wp_AesWrapCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_wrap_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialization of an AES unwrapping.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES wrap context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_dinit(wp_AesWrapCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_wrap_init(ctx, key, keyLen, iv, ivLen, params, 0);
}

/**
 * One-shot wrap/unwrap.
 *
 * @param [in]  ctx      AES wrap context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_update(wp_AesWrapCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (inLen == 0)) {
        *outLen = 0;
    }
    else if (ok) {
        int rc;
        word32 outSz = (word32)outSize;
        unsigned char* iv;

        if (ctx->ivSet) {
            iv = ctx->iv;
        }
        else {
            iv = NULL;
        }

    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        if (ctx->wrap) {
            rc = wc_AesKeyWrap_ex(&ctx->aes, in, (word32)inLen, out, outSz, iv);
            if (rc <= 0) {
                ok = 0;
            }
        }
        else {
            rc = wc_AesKeyUnWrap_ex(&ctx->aes, in, (word32)inLen, out, outSz,
                iv);
            if (rc <= 0) {
                ok = 0;
            }
        }
    #else
        if (ctx->wrap) {
            rc = wc_AesKeyWrap(ctx->key, ctx->keyLen, in, inLen, out, outSz,
                iv);
            if (rc <= 0) {
                ok = 0;
            }
        }
        else {
            rc = wc_AesKeyUnWrap(ctx->key, ctx->keyLen, in, inLen, out, outSz,
                iv);
            if (rc <= 0) {
                ok = 0;
            }
    #endif

        if (ok) {
            *outLen = rc;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES wrap/unwrap. Nothing to do.
 *
 * @param [in]  ctx      AES wrap context object.
 * @param [out] out      Buffer to hold encrypted/decrypted data.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_final(wp_AesWrapCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    (void)ctx;
    (void)out;
    (void)outSize;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok) {
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put values from the AES wrap context object into parameters objects.
 *
 * @param [in]      ctx     AES wrap context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_get_ctx_params(wp_AesWrapCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->ivLen))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        /* No padding implementation available in wolfSSL. */
        if ((p != NULL) && (!OSSL_PARAM_set_uint(p, 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivLen)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivLen))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->keyLen))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into AES wrap context object.
 *
 * @param [in, out] ctx     AES wrap context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_wrap_set_ctx_params(wp_AesWrapCtx *ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        size_t keyLen = ctx->keyLen;
        unsigned int pad = 0;

        if (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_PADDING, &pad,
                NULL)) {
            ok = 0;
        }
        if (ok && (pad != 0)) {
            ok = 0;
        }

        if (ok && (!wp_params_get_size_t(params, OSSL_CIPHER_PARAM_KEYLEN,
                &keyLen))) {
            ok = 0;
        }
        if (ok && (keyLen != ctx->keyLen)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize the AES wrap context object.
 *
 * @param [in, out] ctx      AES wrap context object.
 * @param [in]      kBits    Number of bits in a valid key.
 * @param [in]      ivBits   Number of bits in a valid IV.
 * @return  1 on success.
 * @return  0 on failure.
 */
static void wp_aes_wrap_init_ctx(wp_AesWrapCtx* ctx, size_t kBits,
    size_t ivBits)
{
    ctx->keyLen = ((kBits) / 8);
    ctx->ivLen = ((ivBits) / 8);
}

/** Implement the get params API for a block cipher. */
#define IMPLEMENT_AES_WRAP_GET_PARAMS(lcmode, UCMODE, kBits, ivBits)           \
/**                                                                            \
 * Get the values from the AES wrap context for the parameters.                \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_aes_##kBits##_##lcmode##_get_params(OSSL_PARAM params[])         \
{                                                                              \
    return wp_aes_wrap_get_params(params, EVP_CIPH_##UCMODE##_MODE, kBits,     \
        ivBits);                                                               \
}

/** Implement the new context API for a block cipher. */
#define IMPLEMENT_AES_WRAP_NEWCTX(lcmode, UCMODE, kBits, ivBits)               \
/**                                                                            \
 * Create a new block cipher context object.                                   \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AEAD context object on success.                                    \
 */                                                                            \
static wp_AesWrapCtx* wp_aes_wrap_##kBits##_##lcmode##_newctx(                 \
    WOLFPROV_CTX *provCtx)                                                     \
{                                                                              \
    wp_AesWrapCtx *ctx = NULL;                                                 \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        wp_aes_wrap_init_ctx(ctx, kBits, ivBits);                              \
    }                                                                          \
    return ctx;                                                                \
}

/** Implement the dispatch table for a block cipher. */
#define IMPLEMENT_AES_WRAP_DISPATCH(fname, kBits, ivBits)                      \
const OSSL_DISPATCH wp_aes##kBits##fname##_functions[] = {                     \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
                              (DFUNC)wp_aes_wrap_##kBits##_##fname##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX,           (DFUNC)wp_aes_wrap_freectx        }, \
    { OSSL_FUNC_CIPHER_DUPCTX,            (DFUNC)wp_aes_wrap_dupctx         }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,      (DFUNC)wp_aes_wrap_einit          }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,      (DFUNC)wp_aes_wrap_dinit          }, \
    { OSSL_FUNC_CIPHER_UPDATE,            (DFUNC)wp_aes_wrap_update         }, \
    { OSSL_FUNC_CIPHER_FINAL,             (DFUNC)wp_aes_wrap_final          }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                               (DFUNC)wp_aes_##kBits##_##fname##_get_params }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,    (DFUNC)wp_aes_wrap_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,    (DFUNC)wp_aes_wrap_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
                               (DFUNC)wp_aes_wrap_gettable_params           }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                               (DFUNC)wp_aes_wrap_gettable_ctx_params       }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                               (DFUNC)wp_aes_wrap_settable_ctx_params       }, \
    { 0, NULL }                                                                \
};

/** Implements the functions calling base functions for a block cipher. */
#define IMPLEMENT_AES_WRAP(lcmode, fname, UCMODE, kBits, ivBits)               \
IMPLEMENT_AES_WRAP_GET_PARAMS(fname, UCMODE, kBits, ivBits)                    \
IMPLEMENT_AES_WRAP_NEWCTX(fname, UCMODE, kBits, ivBits)                        \
IMPLEMENT_AES_WRAP_DISPATCH(fname, kBits, ivBits)

/*
 * AES Key Wrap unpadded
 */

/** wp_aes256wrap_functions */
IMPLEMENT_AES_WRAP(wrap, wrap, WRAP, 256, 128)
/** wp_aes192wrap_functions */
IMPLEMENT_AES_WRAP(wrap, wrap, WRAP, 192, 128)
/** wp_aes128wrap_functions */
IMPLEMENT_AES_WRAP(wrap, wrap, WRAP, 128, 128)

#endif
