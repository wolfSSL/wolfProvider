/* wp_aes_xts.c
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

#include <openssl/err.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/evp.h>

#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_AESXTS

/**
 * Maximum data unit size: 2^20 blocks (IEEE Std 1619-2018, NIST SP 800-38E).
 */
#define WP_AES_XTS_MAX_BYTES    ((size_t)AES_BLOCK_SIZE << 20)

/**
 * Data structure for AES-XTS ciphers.
 *
 * Matches OpenSSL's AES-XTS: the IV is the 16-byte tweak, and each update is
 * one complete data unit processed with that tweak.
 */
typedef struct wp_AesXtsCtx {
    /** wolfSSL AES-XTS object: data key and tweak key. */
    XtsAes xts;

    /** Length of key in bytes: both halves. */
    size_t keyLen;

    /** Operation being performed is encryption. */
    unsigned int enc:1;
    /** Key has been set. */
    unsigned int keySet:1;
    /** Key schedule was set up for encryption. */
    unsigned int keyEnc:1;
    /** Tweak has been set. */
    unsigned int ivSet:1;

    /** Tweak. Not changed by an update. */
    unsigned char iv[AES_BLOCK_SIZE];
} wp_AesXtsCtx;


/* Prototype for initialization to call. */
static int wp_aes_xts_set_ctx_params(wp_AesXtsCtx *ctx,
    const OSSL_PARAM params[]);


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
 * @return  NULL on failure.
 * @return  AES-XTS context object.
 */
static void *wp_aes_xts_dupctx(wp_AesXtsCtx *src)
{
    wp_AesXtsCtx *dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_malloc(sizeof(*dst));
    }
    if (dst != NULL) {
        /* XtsAes is copied by value, as Aes is for the other AES ciphers. */
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
static const OSSL_PARAM *wp_aes_xts_gettable_params(WOLFPROV_CTX *provCtx)
{
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
    (void)provCtx;
    return wp_aes_xts_supported_gettable_params;
}

/**
 * Get the values of an AES-XTS cipher for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      kBits   Number of bits in the key: both halves.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_aes_xts_get_params(OSSL_PARAM params[], size_t kBits)
{
    int ok = 1;
    OSSL_PARAM *p;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_get_params");

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, EVP_CIPH_XTS_MODE))) {
        ok = 0;
    }
    if (ok) {
        /* The IV is the tweak, as in OpenSSL. */
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
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, kBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        /* Any length of at least one block is processed in one update. */
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, 1))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of a cipher context that can be retrieved.
 *
 * @param [in] ctx      AES-XTS context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_aes_xts_gettable_ctx_params(wp_AesXtsCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters able to be retrieved for a cipher context.
     */
    static const OSSL_PARAM wp_aes_xts_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aes_xts_supported_gettable_ctx_params;
}

/**
 * Returns the parameters of a cipher context that can be set.
 *
 * @param [in] ctx      AES-XTS context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_aes_xts_settable_ctx_params(wp_AesXtsCtx* ctx,
    WOLFPROV_CTX *provCtx)
{
    /*
     * Parameters able to be set into a cipher context.
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
 * Initialization of an AES-XTS cipher.
 *
 * Internal. Handles both encryption and decryption.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      key     Data key followed by tweak key. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
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
    if (ok) {
        ctx->enc = enc;
    }

    if (ok && (iv != NULL)) {
        if (ivLen != AES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, iv, ivLen);
            ctx->ivSet = 1;
        }
    }

    if (ok && (key != NULL)) {
        int rc;

        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        /* The two halves must differ (IEEE Std 1619-2018, SP 800-38E).
         * OpenSSL's FIPS provider rejects equal halves; so do we, in both
         * directions and whatever the wolfSSL build. */
        if (ok && (CRYPTO_memcmp(key, key + keyLen / 2, keyLen / 2) == 0)) {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_AES,
                "AES-XTS data and tweak keys are equal");
            ok = 0;
        }
        if (ok) {
            WP_CHECK_FIPS_ALGO(WP_CAST_ALGO_AES);
            rc = wc_AesXtsSetKeyNoInit(&ctx->xts, key, (word32)keyLen,
                enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
                    "wc_AesXtsSetKeyNoInit", rc);
                ok = 0;
            }
        }
        if (ok) {
            ctx->keySet = 1;
            ctx->keyEnc = enc;
        }
        else {
            /* A failed key setup leaves no usable key. */
            ctx->keySet = 0;
        }
    }
    else if (ok && ctx->keySet && (ctx->keyEnc != (unsigned int)enc)) {
        /* The key schedule is for one direction only: changing direction
         * needs the key again. */
        ok = 0;
    }

    if (ok) {
        ok = wp_aes_xts_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an AES-XTS encryption.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      key     Data key followed by tweak key. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
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
 * Initialization of an AES-XTS decryption.
 *
 * @param [in, out] ctx     AES-XTS context object.
 * @param [in]      key     Data key followed by tweak key. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
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
 * Encrypt/decrypt one data unit.
 *
 * The whole input is one data unit: at least one block, a partial last block
 * handled with ciphertext stealing, and at most 2^20 blocks. Every call uses
 * the tweak set at initialization.
 *
 * @param [in]  ctx      AES-XTS context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_cipher(wp_AesXtsCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_xts_cipher");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    /* The key schedule must be for the direction in use: a failed re-init
     * may have changed the direction. */
    if (ok && ((!ctx->keySet) || (!ctx->ivSet) ||
               (ctx->keyEnc != ctx->enc))) {
        ok = 0;
    }
    if (ok && ((in == NULL) || (out == NULL))) {
        ok = 0;
    }
    if (ok && ((inLen < AES_BLOCK_SIZE) || (inLen > WP_AES_XTS_MAX_BYTES))) {
        ok = 0;
    }
    if (ok && (outSize < inLen)) {
        ok = 0;
    }

    if (ok) {
        int rc;

        if (ctx->enc) {
            rc = wc_AesXtsEncrypt(&ctx->xts, out, in, (word32)inLen, ctx->iv,
                AES_BLOCK_SIZE);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
                    "wc_AesXtsEncrypt", rc);
                ok = 0;
            }
        }
        else {
            rc = wc_AesXtsDecrypt(&ctx->xts, out, in, (word32)inLen, ctx->iv,
                AES_BLOCK_SIZE);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG,
                    "wc_AesXtsDecrypt", rc);
                ok = 0;
            }
        }
    }

    if (ok) {
        *outLen = inLen;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES-XTS encryption/decryption. Nothing to do: each update is a
 * complete data unit.
 *
 * @param [in]  ctx      AES-XTS context object.
 * @param [out] out      Buffer to hold encrypted/decrypted data.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_final(wp_AesXtsCtx* ctx, unsigned char *out,
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

/**
 * Put values from the AES-XTS context object into parameters objects.
 *
 * @param [in]      ctx     AES-XTS context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_xts_get_ctx_params(wp_AesXtsCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

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
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, AES_BLOCK_SIZE)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->iv, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }
    if (ok) {
        /* The tweak is not advanced by an update. */
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
        /* The key length is fixed by the algorithm. */
        if (ok && (keyLen != ctx->keyLen)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Implement the get params API for an AES-XTS cipher. */
#define IMPLEMENT_AES_XTS_GET_PARAMS(kBits)                                    \
/**                                                                            \
 * Get the values of the AES-XTS cipher for the parameters.                    \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_aes_##kBits##_xts_get_params(OSSL_PARAM params[])                \
{                                                                              \
    return wp_aes_xts_get_params(params, 2 * (kBits));                         \
}

/** Implement the new context API for an AES-XTS cipher. */
#define IMPLEMENT_AES_XTS_NEWCTX(kBits)                                        \
/**                                                                            \
 * Create a new AES-XTS context object.                                        \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AES-XTS context object on success.                                 \
 */                                                                            \
static wp_AesXtsCtx* wp_aes_xts_##kBits##_newctx(WOLFPROV_CTX *provCtx)        \
{                                                                              \
    wp_AesXtsCtx *ctx = NULL;                                                  \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if ((ctx != NULL) &&                                                       \
            (wc_AesXtsInit(&ctx->xts, NULL, INVALID_DEVID) != 0)) {            \
        OPENSSL_free(ctx);                                                     \
        ctx = NULL;                                                            \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        ctx->keyLen = 2 * (kBits) / 8;                                         \
    }                                                                          \
    return ctx;                                                                \
}

/** Implement the dispatch table for an AES-XTS cipher. */
#define IMPLEMENT_AES_XTS_DISPATCH(kBits)                                      \
const OSSL_DISPATCH wp_aes##kBits##xts_functions[] = {                         \
    { OSSL_FUNC_CIPHER_NEWCTX,          (DFUNC)wp_aes_xts_##kBits##_newctx  }, \
    { OSSL_FUNC_CIPHER_FREECTX,         (DFUNC)wp_aes_xts_freectx           }, \
    { OSSL_FUNC_CIPHER_DUPCTX,          (DFUNC)wp_aes_xts_dupctx            }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,    (DFUNC)wp_aes_xts_einit             }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,    (DFUNC)wp_aes_xts_dinit             }, \
    { OSSL_FUNC_CIPHER_UPDATE,          (DFUNC)wp_aes_xts_cipher            }, \
    { OSSL_FUNC_CIPHER_FINAL,           (DFUNC)wp_aes_xts_final             }, \
    { OSSL_FUNC_CIPHER_CIPHER,          (DFUNC)wp_aes_xts_cipher            }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                                  (DFUNC)wp_aes_##kBits##_xts_get_params    }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,  (DFUNC)wp_aes_xts_get_ctx_params    }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,  (DFUNC)wp_aes_xts_set_ctx_params    }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_aes_xts_gettable_params   }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                                  (DFUNC)wp_aes_xts_gettable_ctx_params     }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                                  (DFUNC)wp_aes_xts_settable_ctx_params     }, \
    { 0, NULL }                                                                \
};

/** Implements the functions calling base functions for an AES-XTS cipher. */
#define IMPLEMENT_AES_XTS(kBits)                                               \
IMPLEMENT_AES_XTS_GET_PARAMS(kBits)                                            \
IMPLEMENT_AES_XTS_NEWCTX(kBits)                                                \
IMPLEMENT_AES_XTS_DISPATCH(kBits)

/*
 * AES-XTS. kBits is the size of each of the two AES keys, as in the name.
 */

/** wp_aes256xts_functions */
IMPLEMENT_AES_XTS(256)
/** wp_aes128xts_functions */
IMPLEMENT_AES_XTS(128)

#endif /* WP_HAVE_AESXTS */
