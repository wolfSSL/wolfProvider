/* wp_aes_aead.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#include <wolfssl/wolfcrypt/error-crypt.h>

#if defined(WP_HAVE_AESGCM) || defined(WP_HAVE_AESCCM)

/* For non-streaming AES-GCM, we have to spool all previous updates.
 * This is the number of extra bytes we add when allocating the internal
 * buffer used to spool the stream input. This way we if there is space
 * we can use the existing buffer, reducing the number of full realloc + copy
 * operations we need to do. Increase this number for better performance and
 * more memory usage, decrease for worse performance but less overhead */
#ifndef WP_AES_GCM_EXTRA_BUF_LEN
#define WP_AES_GCM_EXTRA_BUF_LEN 128
#endif

/**
 * Authenticated Encryption with Associated Data structure.
 */
typedef struct wp_AeadCtx {
    /** wolfSSL AES encryption/decryption object. */
    Aes aes;
    /** wolfSSL HMAC object. */
    Hmac hmac;
    /** HMAC digest type. */
    int hashType;

    /** Provider context that we are constructed from. */
    WOLFPROV_CTX* provCtx;

    /** Cipher mode: GCM or CCM */
    int mode;

    /** Length of key. */
    size_t keyLen;
    /** Length of iv/nonce. */
    size_t ivLen;
    /** Authentication tag length.  */
    size_t tagLen;
    /** TLS pad size. */
    size_t tlsAadPadSz;
    /** TLS additional authentication data size. */
    size_t tlsAadLen;
    /** Number of TLS records encrypted - GCM check for too many. */
    uint64_t tlsEncRecords;
    /** TLS version - CBC-HMAC-SHA does different things based on version. */
    unsigned int tlsVersion;

    /** Current state of IV/nonce.  */
    int ivState;

    /** Initialized for encryption or decryption. */
    unsigned int enc:1;
    /** IV/nonce has been generated. */
    unsigned int ivGen:1;
    /** CCM needs to set IV specially. */
    unsigned int ivSet:1;
    /** GCM needs to know if key has been set. */
    unsigned int keySet:1;
    /** Cache of authentication status. */
    unsigned int authErr:1;
    /** AAD set with call to update. */
    unsigned int aadSet:1;
    /** CCM tag available and must be retrieved. */
    unsigned int tagAvail:1;

    /** Buffer to hold TLS AAD or tag. */
    unsigned char buf[AES_BLOCK_SIZE];
    /** IV/nonce data. */
    unsigned char iv[AES_BLOCK_SIZE];
    /** Original IV/nonce data. */
    unsigned char oiv[AES_BLOCK_SIZE];

    /** Length of AAD data cached.  */
    size_t aadLen;
    /** CCM is not streaming and needs to cache AAD data. */
    unsigned char* aad;
#if defined(WP_HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)
    /** Length of data cached.  */
    size_t inLen;
    /** CCM is not streaming and needs to cache AAD data. */
    unsigned char* in;
    /* Total buffer size */
    size_t bufSize;
    /* Original IV */
    unsigned char origIv[AES_BLOCK_SIZE];
#endif
} wp_AeadCtx;


/* Both GCM and CCM have the same explicit IV length. */
#define EVP_AEAD_TLS_EXPLICIT_IV_LEN    8


/** IV has not be set. */
#define IV_STATE_UNINITIALISED 0  /* initial state is not initialized */
/** IV has been copied from a source. */
#define IV_STATE_COPIED        1
/** Fixed part of IV has been buffered. */
#define IV_STATE_BUFFERED      2
/** IV has been used and can't be reuse. */
#define IV_STATE_FINISHED      3

/** Uninitialized value for a field of type size_t. */
#define UNINITIALISED_SIZET      ((size_t)-1)


/** AEAD cipher flags. */
#define AEAD_FLAGS (WP_CIPHER_FLAG_AEAD | WP_CIPHER_FLAG_CUSTOM_IV)

/** Implements the get_params function for an AEAD cipher. */
#define IMPLEMENT_AES_AEAD_GET_PARAMS(lc, UCMODE, flags, kbits, blkbits,       \
    ivbits)                                                                    \
/**                                                                            \
 * Get the AEAD cipher parameters.                                             \
 *                                                                             \
 * @param [in, out] params   Array of parameters and values.                   \
 * @return  1 on success.                                                      \
 * @return  0 on failure.                                                      \
 */                                                                            \
static int wp_aes_##kbits##_##lc##_get_params(OSSL_PARAM params[])             \
{                                                                              \
    return wp_aead_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags, kbits,  \
        blkbits, ivbits);                                                      \
}
/** Implements the newctx function for an AEAD cipher. */
#define IMPLEMENT_AES_AEAD_NEWCTX(lc, kbits)                                   \
/**                                                                            \
 * Create a new AEAD context object.                                           \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AEAD context object on success.                                    \
 */                                                                            \
static void * wp_aes_##lc##_##kbits##lc##_newctx(WOLFPROV_CTX* provCtx)        \
{                                                                              \
    return wp_aes_##lc##_newctx(provCtx, kbits);                               \
}

/** Implements the dispatch table for AES AEAD ciphers. */
#define IMPLEMENT_AES_AEAD_DISPATCH(lc, kbits)                                 \
const OSSL_DISPATCH wp_aes##kbits##lc##_functions[] = {                        \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
                                  (DFUNC)wp_aes_##lc##_##kbits##lc##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX,         (DFUNC)wp_aes_##lc##_freectx        }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,    (DFUNC)wp_aes##lc##_einit           }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,    (DFUNC)wp_aes##lc##_dinit           }, \
    { OSSL_FUNC_CIPHER_UPDATE,          (DFUNC)wp_aes##lc##_stream_update   }, \
    { OSSL_FUNC_CIPHER_FINAL,           (DFUNC)wp_aes##lc##_stream_final    }, \
    { OSSL_FUNC_CIPHER_CIPHER,          (DFUNC)wp_aes##lc##_cipher          }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                                  (DFUNC)wp_aes_##kbits##_##lc##_get_params }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,  (DFUNC)wp_aead_get_ctx_params       }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,  (DFUNC)wp_aead_set_ctx_params       }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_aead_gettable_params      }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                                        (DFUNC)wp_aead_gettable_ctx_params  }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                                        (DFUNC)wp_aead_settable_ctx_params  }, \
    { 0, NULL }                                                                \
}

/** Implements the functions calling base functions and the disapatch table. */
#define IMPLEMENT_AES_AEAD(lc, UCMODE, flags, kbits, blkbits, ivbits)          \
IMPLEMENT_AES_AEAD_GET_PARAMS(lc, UCMODE, flags, kbits, blkbits, ivbits)       \
IMPLEMENT_AES_AEAD_NEWCTX(lc, kbits)                                           \
IMPLEMENT_AES_AEAD_DISPATCH(lc, kbits)


#ifdef WP_HAVE_AESGCM
/* Prototypes for get/set params API. */
static int wp_aesgcm_get_rand_iv(wp_AeadCtx* ctx, unsigned char* out,
    size_t olen, int inc);
static int wp_aesgcm_set_rand_iv(wp_AeadCtx *ctx, unsigned char *in,
    size_t inLen);
static int wp_aesgcm_tls_iv_set_fixed(wp_AeadCtx* ctx, unsigned char* iv,
    size_t len);
#endif
#ifdef WP_HAVE_AESCCM
static int wp_aesccm_tls_iv_set_fixed(wp_AeadCtx* ctx, unsigned char* iv,
    size_t len);
#endif


/**
 * Initialize AEAD cipher for use with TLS. Return extra padding (tag length).
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      aad     Additional authentication data.
 * @param [in]      aadLen  Length of AAD in bytes.
 * @return  Length of extra padding in bytes on success.
 * @return  0 on failure.
 */
static int wp_aead_tls_init(wp_AeadCtx* ctx, unsigned char* aad, size_t aadLen)
{
    int ok = 1;
    unsigned char *buf = ctx->buf;
    size_t len;
    /* CCM will have a tag length set. */
    size_t tagLen = (ctx->tagLen != UNINITIALISED_SIZET) ? ctx->tagLen :
        EVP_GCM_TLS_TAG_LEN;

    if (!wolfssl_prov_is_running()) {
       ok = 0;
    }
    if (aadLen != EVP_AEAD_TLS1_AAD_LEN) {
       ok = 0;
    }

    if (ok) {
        /* Cache AAD. */
        XMEMCPY(buf, aad, aadLen);
        ctx->tlsAadLen = aadLen;
        ctx->tlsEncRecords = 0;

        len = (buf[aadLen - 2] << 8) | buf[aadLen - 1];
        if (len >= EVP_AEAD_TLS_EXPLICIT_IV_LEN) {
            len -= EVP_AEAD_TLS_EXPLICIT_IV_LEN;
        }
        else {
            ok = 0;
        }
    }
    /* If decrypting, correct for tag too. */
    if (ok && (!ctx->enc)) {
        if (len < tagLen) {
            ok = 0;
        }
        if (ok) {
            len -= tagLen;
        }
    }
    if (ok) {
        buf[aadLen - 2] = (unsigned char)(len >> 8);
        buf[aadLen - 1] = (unsigned char)(len & 0xff);
    }

    if (!ok) {
        tagLen = 0;
    }
    /* Extra padding: tag appended to record. */
    return (int)tagLen;
}

#if defined(WP_HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM) || \
    defined(WP_HAVE_AESCCM)
/**
 * Cache more Additional Authentication Data in AEAD context object.
 *
 * @param [in, out] ctx    AEAD context object.
 * @param [in]      in     More AAD data.
 * @param [in]      inLen  Length of new AAD data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_cache_aad(wp_AeadCtx *ctx, const unsigned char *in,
    size_t inLen)
{
    int ok = 1;
    unsigned char *p;

    if (inLen > 0) {
        p = (unsigned char*)OPENSSL_realloc(ctx->aad, ctx->aadLen + inLen);
        if (p == NULL) {
            ok = 0;
        }
        if (ok) {
            ctx->aad = p;
            XMEMCPY(ctx->aad + ctx->aadLen, in, inLen);
            ctx->aadLen += inLen;
        }
    }
    if (ok) {
        ctx->aadSet = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

#if defined(WP_HAVE_AESGCM) && !defined(WOLFSSL_AESGCM_STREAM)
/**
 * Cache more input data in AEAD context object.
 *
 * @param [in, out] ctx    AEAD context object.
 * @param [in]      in     More AAD data.
 * @param [in]      inLen  Length of new AAD data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_cache_in(wp_AeadCtx *ctx, const unsigned char *in,
    size_t inLen)
{
    int ok = 1;
    unsigned char *p;

    if (inLen > 0) {
        if (inLen < (ctx->bufSize - ctx->inLen)) {
            /* We can fit this new data into the extra space, dont realloc */
            XMEMCPY(ctx->in + ctx->inLen, in, inLen);
            ctx->inLen += inLen;
        }
        else {
            p = (unsigned char*)OPENSSL_realloc(ctx->in,
                                ctx->inLen + inLen + WP_AES_GCM_EXTRA_BUF_LEN);
            if (p == NULL) {
                ok = 0;
            }
            if (ok) {
                ctx->bufSize = ctx->inLen + inLen + WP_AES_GCM_EXTRA_BUF_LEN;
                ctx->in = p;
                XMEMCPY(ctx->in + ctx->inLen, in, inLen);
                ctx->inLen += inLen;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Get the AEAD context parameters.
 *
 * @param [in]      ctx     AEAD context object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_get_ctx_params(wp_AeadCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivLen)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keyLen)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL) {
            size_t tagLen = (ctx->tagLen != UNINITIALISED_SIZET) ? ctx->tagLen :
                             EVP_GCM_TLS_TAG_LEN;

            if (!OSSL_PARAM_set_size_t(p, tagLen)) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if (p != NULL) {
            if (ctx->ivState == IV_STATE_UNINITIALISED) {
                ok = 0;
            }
            if (ok && (ctx->ivLen > p->data_size)) {
                ok = 0;
            }
            if (ok &&
                (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivLen)) &&
                (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivLen))) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if (p != NULL) {
            if (ctx->ivState == IV_STATE_UNINITIALISED) {
                ok = 0;
            }
            if (ok && (ctx->ivLen > p->data_size)) {
                ok = 0;
            }
            if (ok &&
                (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivLen)) &&
                (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivLen))) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tlsAadPadSz)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL) {
            size_t sz = p->data_size;
            if ((!ctx->enc) || (ctx->tagLen == UNINITIALISED_SIZET) ||
                (sz == 0) || (sz > ctx->tagLen)) {
                ok = 0;
            }
            if (ok && (!OSSL_PARAM_set_octet_string(p, ctx->buf, sz))) {
                ok = 0;
            }
            ctx->tagAvail = 0;
        }
    }
#ifdef WP_HAVE_AESGCM
    if (ok && (ctx->mode == EVP_CIPH_GCM_MODE)) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
        if (p != NULL) {
            if ((p->data == NULL) ||
                (p->data_type != OSSL_PARAM_OCTET_STRING) ||
                (!wp_aesgcm_get_rand_iv(ctx, p->data, p->data_size, 1))) {
                ok = 0;
            }
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the AEAD tag from the parameters.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_set_param_tag(wp_AeadCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p = params;
    size_t sz;
    void* vp = ctx->buf;

    if (p->data != NULL) {
        if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
            ok = 0;
        }
    }
    else {
        sz = p->data_size;
    }
    if (ok && ((sz == 0) || ((p->data != NULL) && ctx->enc))) {
        ok = 0;
    }
    ctx->tagLen = sz;

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the IV length from the parameters.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_set_param_iv_len(wp_AeadCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p = params;
    size_t sz;

    if (!OSSL_PARAM_get_size_t(p, &sz)) {
        ok = 0;
    }
    if (ok & ((sz == 0) || (sz > sizeof(ctx->aes.reg)))) {
        ok = 0;
    }
    if (ok) {
        ctx->ivLen = sz;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the TLS1 AAD from the parameters.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_set_param_tls1_aad(wp_AeadCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p = params;
    size_t sz;

    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        ok = 0;
    }
    else {
        sz = wp_aead_tls_init(ctx, p->data, p->data_size);
        if (sz == 0) {
            ok = 0;
        }
        ctx->tlsAadPadSz = sz;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the TLS1 fixed IV from the parameters.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_set_param_tls1_iv_fixed(wp_AeadCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p = params;

    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        ok = 0;
    }
#ifdef WP_HAVE_AESGCM
    else if (ctx->mode == EVP_CIPH_GCM_MODE) {
        if (wp_aesgcm_tls_iv_set_fixed(ctx, p->data, p->data_size) == 0) {
            ok = 0;
        }
    }
#endif
#ifdef WP_HAVE_AESCCM
    else {
        if (wp_aesccm_tls_iv_set_fixed(ctx, p->data, p->data_size) == 0) {
            ok = 0;
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set a random IV with fixed part from the parameters.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_set_param_tls1_iv_rand(wp_AeadCtx* ctx,
    const OSSL_PARAM params[])
{
#ifdef WP_HAVE_AESGCM
    int ok = 1;
    const OSSL_PARAM* p = params;

    if (p->data == NULL) {
        ok = 0;
    }
    if (ok && (p->data_type != OSSL_PARAM_OCTET_STRING)) {
        ok = 0;
    }
    if (ok && (!wp_aesgcm_set_rand_iv(ctx, p->data, p->data_size))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    (void)ctx;
    (void)params;
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Set the AEAD context parameters.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_set_ctx_params(wp_AeadCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;

    while ((params != NULL) && (params->key != NULL)) {
        if (XMEMCMP(params->key, OSSL_CIPHER_PARAM_AEAD_TAG,
                 sizeof(OSSL_CIPHER_PARAM_AEAD_TAG)) == 0) {
            ok = wp_aead_set_param_tag(ctx, params);
        }
        else if (XMEMCMP(params->key, OSSL_CIPHER_PARAM_AEAD_IVLEN,
                 sizeof(OSSL_CIPHER_PARAM_AEAD_IVLEN)) == 0) {
            ok = wp_aead_set_param_iv_len(ctx, params);
        }
        else if (XMEMCMP(params->key, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
                 sizeof(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD)) == 0) {
            ok = wp_aead_set_param_tls1_aad(ctx, params);
        }
        else if (XMEMCMP(params->key, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
                 sizeof(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED)) == 0) {
            ok = wp_aead_set_param_tls1_iv_fixed(ctx, params);
        }
        else if (ok && (ctx->mode == EVP_CIPH_GCM_MODE) &&
                 (XMEMCMP(params->key, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED,
                  sizeof(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED)) == 0)) {
            ok = wp_aead_set_param_tls1_iv_rand(ctx, params);
        }

        params++;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported gettable parameters for the AEAD cipher.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_aead_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for AEAD cipher.
     */
    static const OSSL_PARAM wp_aead_supported_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_aead_supported_gettable_params;
}

/**
 * Get the AEAD cipher parameters.
 *
 * @param [in, out] params   Array of parameters and values.
 * @param [in]      md       Message digest id.
 * @param [in]      flags    Flags of cipher.
 * @param [in]      keyBits  Size of key in bits.
 * @param [in]      blkBits  Size of block in bits.
 * @param [in]      ivBits   Size of IV/nonce in bits.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aead_get_params(OSSL_PARAM params[], unsigned int md,
     uint64_t flags, size_t keyBits, size_t blkBits, size_t ivBits)
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, md))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, (flags & WP_CIPHER_FLAG_AEAD) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, (flags & WP_CIPHER_FLAG_CUSTOM_IV) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, (flags & WP_CIPHER_FLAG_RAND_KEY) != 0))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, keyBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, blkBits / 8))) {
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
 * Return an array of supported gettable parameters for the AEAD context.
 *
 * @param [in] ctx      AEAD context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_aead_gettable_ctx_params(wp_AeadCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for AEAD context.
     */
    static const OSSL_PARAM wp_aead_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
#ifdef WP_HAVE_AESGCM
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL,
            0),
#endif
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aead_supported_gettable_ctx_params;
}

/**
 * Return an array of supported settable parameters for the AEAD context.
 *
 * @param [in] ctx      AEAD context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_aead_settable_ctx_params(wp_AeadCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for AEAD context.
     */
    static const OSSL_PARAM wp_aead_supported_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
#ifdef WP_HAVE_AESGCM
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL,
            0),
#endif
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_aead_supported_settable_ctx_params;
}


#ifdef WP_HAVE_AESGCM

/*
 * AES-GCM
 */

/**
 * Get the random part of the IV/nonce.
 *
 * FIPS 140 requires the encryptor to generate a random part for the IV.
 * This has to be sent to the other side.
 *
 * @param [in, out] ctx   AEAD context object.
 * @param [out]     out   Buffer to hold random part of IV.
 * @param [in]      olen  Length of random in bytes.
 * @param [in]      inc   Whether to increment IV after copy.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_get_rand_iv(wp_AeadCtx* ctx, unsigned char* out,
    size_t olen, int inc)
{
    int ok = 1;

    /* Ensure that an IV/nonce has not been generated or a key set. */
    if ((!ctx->ivGen) || (!ctx->keySet)) {
        ok = 0;
    }
    if (ok) {
    #ifdef WOLFSSL_AESGCM_STREAM
        int rc;

        rc = wc_AesGcmInit(&ctx->aes, NULL, 0, ctx->iv, (word32)ctx->ivLen);
        if (rc != 0) {
            ok = 0;
        }
    #endif
    }
    if (ok) {
        /* Use all the IV/nonce length if none specified or too much. */
        if ((olen == 0) || (olen > ctx->ivLen)) {
            olen = ctx->ivLen;
        }
        XMEMCPY(out, ctx->iv + ctx->ivLen - olen, olen);
#ifndef WOLFSSL_AESGCM_STREAM
        XMEMCPY(ctx->origIv, ctx->iv, ctx->ivLen);
#endif
        if (inc) {
            int i;
            unsigned char* p = ctx->iv + ctx->ivLen - 8;

            for (i = 7; i >= 0 && (++p[i]) == 0; i--) {
                /* Nothing to do. */
            }
        }
        ctx->ivState = IV_STATE_COPIED;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the random part of the IV/nonce.
 *
 * FIPS 140 requires the encryptor to generate a random part for the IV.
 *
 * @param [in, out] ctx    AEAD context object.
 * @param [in]      in     Random part of the IV/nonce to set.
 * @param [in]      inLen  Length of random.
 */
static int wp_aesgcm_set_rand_iv(wp_AeadCtx *ctx, unsigned char *in,
    size_t inLen)
{
    int ok = 1;

    /* Ensure that an IV/nonce has not been generated or a key set and this
     * is the decrypt side.
     */
    if ((!ctx->ivGen) || (!ctx->keySet) || (ctx->enc)) {
        ok = 0;
    }
    else {
#ifndef WOLFSSL_AESGCM_STREAM
        XMEMCPY(ctx->origIv, ctx->iv, ctx->ivLen);
#endif
        XMEMCPY(ctx->iv + ctx->ivLen - inLen, in, inLen);
        ctx->ivState = IV_STATE_COPIED;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the fixed part of the nonce for GCM cipher and generate random for rest.
 *
 * @param [in, out] ctx  AEAD context object.
 * @param [in]      iv   Fixed part of IV/nonce.
 * @param [in]      len  Length of fixed part or -1 to restore IV/nonce.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_tls_iv_set_fixed(wp_AeadCtx* ctx, unsigned char* iv,
    size_t len)
{
    int ok = 1;

    /* Special case: -1 length restores whole IV */
    if (len == (size_t)-1) {
        XMEMCPY(ctx->iv, iv, ctx->ivLen);
        ctx->ivGen = 1;
        ctx->ivState = IV_STATE_BUFFERED;
    }
    else {
        /* Fixed field must be at least 4 bytes and invocation field at least 8
         */
        if ((len < EVP_GCM_TLS_FIXED_IV_LEN) ||
            (ctx->ivLen - (int)len) < EVP_GCM_TLS_EXPLICIT_IV_LEN) {
                return 0;
        }
        if (ctx->enc) {
            int rc;

        #ifndef WP_SINGLE_THREADED
            if (!wp_provctx_lock_rng(ctx->provCtx)) {
                ok = 0;
            }
        #endif
            if (ok) {
                rc = wc_AesGcmSetIV(&ctx->aes, (word32)ctx->ivLen, iv,
                    (word32)len, wp_provctx_get_rng(ctx->provCtx));
                if (rc != 0) {
                    ok = 0;
                }
            }
        #ifndef WP_SINGLE_THREADED
            wp_provctx_unlock_rng(ctx->provCtx);
        #endif
            if (ok && len > 0) {
                XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
                ctx->ivSet = 1;
            }
        }
        else {
            XMEMCPY(ctx->iv, iv, len);
        }
        ctx->ivGen = 1;
        ctx->ivState = IV_STATE_BUFFERED;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize AES GCM cipher for encryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_einit(wp_AeadCtx* ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    Aes *aes = &ctx->aes;
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
#ifdef WOLFSSL_AESGCM_STREAM
    if (ok) {
        int rc;

        if (iv != NULL) {
            if (ivLen == 0) {
                ok = 0;
            }
            if (ok) {
                XMEMCPY(ctx->iv, iv, ivLen);
                ctx->ivState = IV_STATE_BUFFERED;
                ctx->ivSet = 0;
                ctx->ivLen = ivLen;
            }
        }
        if ((ivLen == 0) && (key != NULL)) {
            rc = wc_AesGcmSetKey(aes, key, (word32)keyLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        else if (key != NULL) {
            rc = wc_AesGcmEncryptInit(aes, key, (word32)keyLen, iv, (word32)ivLen);
            if (rc != 0) {
                ok = 0;
            }
        }
    }
#else
    if (ok && (key != NULL)) {
        int rc = wc_AesGcmSetKey(aes, key, (word32)keyLen);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok && (iv != NULL)) {
        if (ivLen != ctx->ivLen) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, iv, ivLen);
            ctx->ivState = IV_STATE_BUFFERED;
            ctx->ivSet = 0;
        }
    }
#endif
    if (ok) {
        ctx->enc = 1;
        ctx->keySet |= (key != NULL);
        ctx->tlsAadLen = UNINITIALISED_SIZET;
        ok = wp_aead_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize AES GCM cipher for decryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_dinit(wp_AeadCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    Aes *aes = &ctx->aes;
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
#ifdef WOLFSSL_AESGCM_STREAM
    if (ok && key != NULL) {
        if (wc_AesGcmDecryptInit(aes, key, (word32)keyLen, iv, (word32)ivLen) != 0) {
            ok = 0;
        }
    }
    if (ok) {
        XMEMCPY(ctx->iv, iv, ivLen);
        ctx->ivState = IV_STATE_BUFFERED;
        ctx->ivSet = 0;
    }
#else
    if (ok && (key != NULL)) {
        int rc = wc_AesGcmSetKey(aes, key, (word32)keyLen);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok && (iv != NULL)) {
        if (ivLen != ctx->ivLen) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, iv, ivLen);
            ctx->ivState = IV_STATE_BUFFERED;
            ctx->ivSet = 0;
        }
    }
#endif
    if (ok) {
        ctx->enc = 0;
        ctx->keySet |= (key != NULL);
        ctx->tlsAadLen = UNINITIALISED_SIZET;
        ok = wp_aead_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encrypt or decrypt with AES GCM for TLS 1.2 and below.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [out]     out     Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen  Length of data in output buffer.
 * @param [in]      in      Data to be encrypted/decrypted.
 * @param [in]      len     Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_tls_cipher(wp_AeadCtx* ctx, unsigned char* out,
    size_t* outLen, const unsigned char* in, size_t len)
{
    int ok = 1;
    size_t oLen = 0;

    if (!wolfssl_prov_is_running() || !ctx->keySet) {
        ok = 0;
    }

    if (ok && ((out != in) ||
               (len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN)))) {
        ok = 0;
    }

    if (ok && ctx->enc && (++ctx->tlsEncRecords == 0)) {
        ok = 0;
    }

    if (ok) {
        if (ctx->enc) {
            if (!wp_aesgcm_get_rand_iv(ctx, out, EVP_GCM_TLS_EXPLICIT_IV_LEN,
                    0)) {
                ok = 0;
            }
        }
        else {
            if (!wp_aesgcm_set_rand_iv(ctx, out, EVP_GCM_TLS_EXPLICIT_IV_LEN)) {
                ok = 0;
            }
        }
    }

    if (ok) {
        int rc;

        in  += EVP_GCM_TLS_EXPLICIT_IV_LEN;
        out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
        len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;

        if (ctx->enc) {
            rc = wc_AesGcmEncrypt(&ctx->aes, out, in, (word32)len, ctx->iv,
                    (word32)ctx->ivLen, out + len, EVP_GCM_TLS_TAG_LEN,
                    ctx->buf, EVP_AEAD_TLS1_AAD_LEN);
            if (rc != 0) {
                ok = 0;
            }
        }
        else {
            rc = wc_AesGcmDecrypt(&ctx->aes, out, in, (word32)len, ctx->iv,
                    (word32)ctx->ivLen, in + len, EVP_GCM_TLS_TAG_LEN, ctx->buf,
                    EVP_AEAD_TLS1_AAD_LEN);
            if (rc != 0) {
                OPENSSL_cleanse(out, len);
                ok = 0;
            }
        }
    }
    if (ok) {
        oLen = len;
        if (ctx->enc) {
            oLen += EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
        }
    }

    ctx->ivState = IV_STATE_FINISHED;
    ctx->tlsAadLen = UNINITIALISED_SIZET;
    *outLen = oLen;
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WOLFSSL_AESGCM_STREAM

/**
 * Streaming update of AES GCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_stream_update(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int done = 0;
    size_t oLen = 0;
    int rc;

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        ok = wp_aesgcm_tls_cipher(ctx, out, outLen, in, inLen);
        done = 1;
    }

    if ((!done) && (outSize < inLen)) {
        ok = 0;
    }

    if ((!done) && ok) {
        if (ctx->ivState == IV_STATE_BUFFERED) {
            rc = wc_AesGcmInit(&ctx->aes, NULL, 0, ctx->iv, (word32)ctx->ivLen);
            if (rc != 0) {
                ok = 0;
            }

            ctx->ivState = IV_STATE_COPIED;
        }
    }

    if ((!done) && ok) {
        const unsigned char* aad = NULL;
        size_t aadLen = 0;

        if (out == NULL) {
            aad = in;
            aadLen = inLen;
            in = NULL;
            inLen = 0;
        }

        if (ctx->enc) {
            rc = wc_AesGcmEncryptUpdate(&ctx->aes, out, in, (word32)inLen, aad, (word32)aadLen);
        }
        else {
            rc = wc_AesGcmDecryptUpdate(&ctx->aes, out, in, (word32)inLen, aad, (word32)aadLen);
        }
        if (rc == 0) {
            if (out != NULL) {
                oLen = inLen;
            }
            else {
                oLen = aadLen;
            }
        }
        else {
            ok = 0;
        }

        *outLen = oLen;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Streaming final of AES GCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_stream_final(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    Aes *aes = &ctx->aes;
    int ok = 1;
    int done = 0;
    int rc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (ctx->tlsAadLen != UNINITIALISED_SIZET)) {
        ok = wp_aesgcm_tls_cipher(ctx, out, outLen, NULL, 0);
        done = 1;
    }

    if ((!done) && ok && (!ctx->enc) && (ctx->tagLen == UNINITIALISED_SIZET)) {
        ok = 0;
    }

    if ((!done) && ok) {
        if (outSize == 0) {
            outSize = (ctx->tagLen != UNINITIALISED_SIZET) ? ctx->tagLen :
                EVP_GCM_TLS_TAG_LEN;
        }
        ctx->tagLen = outSize;

        if (ctx->enc) {
            rc = wc_AesGcmEncryptFinal(aes, ctx->buf, sizeof(ctx->buf));
        }
        else {
            rc = wc_AesGcmDecryptFinal(aes, ctx->buf, (word32)ctx->tagLen);
        }
        if (rc != 0) {
            ok = 0;
        }
    }

    if (!done) {
        ctx->ivState = IV_STATE_FINISHED;
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#else

/**
 * Encrypt/decrypt the data using AES-GCM.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold decrypted/encrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      offset   Offset into the spooled data buffer.
 * @param [in]      done     This is a final operation.
 *
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_encdec(wp_AeadCtx *ctx, unsigned char *out, size_t* outLen,
                            size_t offset, int done)
{
    int ok = 1;
    int rc;
    unsigned char *tmp = NULL;
    byte *iv = NULL;

    if (ctx->tagLen == UNINITIALISED_SIZET) {
        ctx->tagLen = EVP_GCM_TLS_TAG_LEN;
    }

    if (ctx->inLen > offset || (ctx->tagAvail == 0 && done)) {
        /* Prepare a temp buffer to store all the output */
        if (ctx->inLen > 0) {
            tmp = OPENSSL_zalloc(ctx->inLen);
            if (tmp == NULL) {
                ok = 0;
            }
        }
        /* Once loaded, always use original IV */
        iv = ctx->iv;
        if (ctx->ivState == IV_STATE_COPIED) {
            iv = ctx->origIv;
        }
        if (ok) {
            rc = wc_AesGcmSetExtIV(&ctx->aes, iv, (word32)ctx->ivLen);
            if (rc != 0) {
                ok = 0;
            }

            if (ok && ctx->ivState == IV_STATE_BUFFERED) {
                ctx->ivState = IV_STATE_COPIED;
                XMEMCPY(ctx->origIv, ctx->iv, ctx->ivLen);
            }
        }
        if (ctx->enc) {
            if (ok) {
                ctx->ivSet = 1;
                /* IV coming out in this call. */
                rc = wc_AesGcmEncrypt_ex(&ctx->aes, tmp, ctx->in,
                    (word32)ctx->inLen, iv, (word32)ctx->ivLen, ctx->buf,
                    (word32)ctx->tagLen, ctx->aad, (word32)ctx->aadLen);
                if (rc != 0) {
                    ok = 0;
                }
                if (ok) {
                    ctx->tagAvail = 1;
                }
            }
        }
        else {
            if (done) {
                /* Only the most recent auth err matters */
                ctx->authErr = 0;
                rc = wc_AesGcmDecrypt(&ctx->aes, tmp, ctx->in, (word32)ctx->inLen,
                    iv, (word32)ctx->ivLen, ctx->buf, (word32)ctx->tagLen,
                    ctx->aad, (word32)ctx->aadLen);
                if (rc == AES_GCM_AUTH_E) {
                    ctx->authErr = 1;
                }
                if (rc != 0) {
                    ok = 0;
                }
            }
            else {
                byte tmpTag[16];

                /* wc_AesGcmDecrypt does not yield plaintext on auth tag error.
                 * For all calls except final we use encrypt instead to yield
                 * the proper plaintext */
                rc = wc_AesGcmEncrypt_ex(&ctx->aes, tmp, ctx->in,
                    (word32)ctx->inLen, iv, (word32)ctx->ivLen, (byte*)tmpTag,
                    (word32)ctx->tagLen, ctx->aad, (word32)ctx->aadLen);
                if (rc != 0) {
                    ok = 0;
                }
            }
        }
        /* Copy out relevant portion of output */
        if (ok) {
            XMEMCPY(out, tmp + offset, (ctx->inLen - offset));
            *outLen = (ctx->inLen - offset);
        }
        OPENSSL_free(tmp);
    }
    else {
        *outLen = 0;
    }
    if (done) {
        OPENSSL_free(ctx->aad);
        ctx->aad = NULL;
        ctx->aadLen = 0;
        ctx->aadSet = 0;
        OPENSSL_free(ctx->in);
        ctx->bufSize = 0;
        ctx->in = NULL;
        ctx->inLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Streaming update of AES GCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_stream_update(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int process = 0;
    size_t curLen = 0;

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        ok = wp_aesgcm_tls_cipher(ctx, out, outLen, in, inLen);
    }
    else {
        int oLen = 0;

        if ((out == NULL) && (in == NULL)) {
            /* Nothing to do. */
            oLen = (word32)inLen;
        }
        else if ((out == NULL) && (in != NULL)) {
            /* AAD only. */
            ok = wp_aead_cache_aad(ctx, in, inLen);
            if (ok) {
                oLen = (word32)inLen;
            }
        }
        else if (outSize < inLen) {
            ok = 0;
        }
        else if (inLen > 0) {
            curLen = ctx->inLen;
            if (!wp_aead_cache_in(ctx, in, inLen)) {
                ok = 0;
            }
            else {
                process = 1;
            }
        }

        /* If there is data to process, do it now */
        if (process) {
            ok = wp_aesgcm_encdec(ctx, out, outLen, curLen, 0);
        }
        else {
            *outLen = oLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Streaming final of AES GCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_stream_final(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;
    (void)outSize;

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        ok = wp_aesgcm_tls_cipher(ctx, out, outLen, NULL, 0);
    }
    else if (ctx->authErr) {
        ok = 0;
    }
    else {
        ok = wp_aesgcm_encdec(ctx, out, outLen, ctx->inLen, 1);
        ctx->ivSet = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#endif

/**
 * One-shot of AES GCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesgcm_cipher(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    size_t finalLen = 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok) {
        *outLen = 0;
        if (in != NULL) {
            ok = wp_aesgcm_stream_update(ctx, out, outLen, outSize, in, inLen);
        }
        else {
            ok = wp_aesgcm_stream_final(ctx, out + *outLen, &finalLen,
                outSize - *outLen);
        }
    }
    if (ok) {
        *outLen += finalLen;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a new AEAD context object for performing AES GCM.
 *
 * @param [in] provCtx  Provider context object. RNG retrieved from this object.
 * @param [in] keyBits  Number of bits in key to be supported.
 * @return  NULL on failure.
 * @return  AEAD context object on success.
 */
static void *wp_aes_gcm_newctx(WOLFPROV_CTX* provCtx, size_t keyBits)
{
    wp_AeadCtx *ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
        ctx->keyLen = keyBits / 8;
        ctx->ivLen = (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
        ctx->tagLen = UNINITIALISED_SIZET;
        ctx->mode = EVP_CIPH_GCM_MODE;

        if (wc_AesInit(&ctx->aes, NULL, INVALID_DEVID) != 0) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }
    return ctx;
}

/**
 * Dispose of an AEAD context object used for AES GCM.
 *
 * @param [in] ctx  AEAD context object.
 */
static void wp_aes_gcm_freectx(wp_AeadCtx* ctx)
{
    wc_AesFree(&ctx->aes);
    OPENSSL_free(ctx);
}


/* Implement AES GCM for key sizes: 128, 192 and 256 bits. */
IMPLEMENT_AES_AEAD(gcm, GCM, AEAD_FLAGS, 128, 8, 96);
IMPLEMENT_AES_AEAD(gcm, GCM, AEAD_FLAGS, 192, 8, 96);
IMPLEMENT_AES_AEAD(gcm, GCM, AEAD_FLAGS, 256, 8, 96);

#endif /* WP_HAVE_AESGCM */

#ifdef WP_HAVE_AESCCM

/*
 * AES-CCM
 */

/**
 * Set the fixed part of the nonce for CCM cipher.
 *
 * @param [in, out] ctx  AEAD context object.
 * @param [in]      iv   Fixed part of IV/nonce.
 * @param [in]      len  Length of fixed part or -1 to restore IV/nonce.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_tls_iv_set_fixed(wp_AeadCtx* ctx, unsigned char* iv,
    size_t len)
{
    int ok = 1;

    if (len != EVP_CCM_TLS_FIXED_IV_LEN) {
        ok = 0;
    }
    else {
        /* Copy to first part of the iv. */
        memcpy(ctx->iv, iv, len);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize AES CCM cipher for encryption/decryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_init(wp_AeadCtx* ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int enc)
{
    int ok = 1;
    int rc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (key != NULL)) {
        rc = wc_AesCcmSetKey(&ctx->aes, key, (word32)keyLen);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok && (iv != NULL)) {
        if (ivLen != ctx->ivLen) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, iv, ivLen);
            ctx->ivState = IV_STATE_BUFFERED;
            ctx->ivSet = 0;
        }
    }
    if (ok) {
        ctx->enc = enc;
        ok = wp_aead_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize AES CCM cipher for encryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_einit(wp_AeadCtx* ctx, const unsigned char* key,
    size_t keyLen, const unsigned char* iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aesccm_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialize AES CCM cipher for decryption.
 *
 * Sets the parameters as well as key and IV/nonce.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [in]      key     Private key to initialize with. May be NULL.
 * @param [in]      keyLen  Length of key in bytes.
 * @param [in]      iv      IV/nonce to initialize with. May be NULL.
 * @param [in]      ivLen   Length of IV/nonce in bytes.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_dinit(wp_AeadCtx* ctx, const unsigned char* key,
    size_t keyLen, const unsigned char* iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aesccm_init(ctx, key, keyLen, iv, ivLen, params, 0);
}


/**
 * Encrypt or decrypt with AES CCM for TLS 1.2 and below.
 *
 * @param [in, out] ctx     AEAD context object.
 * @param [out]     out     Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen  Length of data in output buffer.
 * @param [in]      in      Data to be encrypted/decrypted.
 * @param [in]      len     Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_tls_cipher(wp_AeadCtx* ctx, unsigned char* out,
    size_t* outLen, const unsigned char* in, size_t len)
{
    int ok = 1;
    size_t olen = 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && ((in == NULL) || (out != in) ||
               (len < EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->tagLen))) {
        ok = 0;
    }

    if (ok) {
        int rc;

        if (ctx->enc) {
            XMEMCPY(out, ctx->buf, EVP_CCM_TLS_EXPLICIT_IV_LEN);
        }
        XMEMCPY(ctx->iv + EVP_CCM_TLS_FIXED_IV_LEN, in,
            EVP_CCM_TLS_EXPLICIT_IV_LEN);

        len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->tagLen;
        in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
        out += EVP_CCM_TLS_EXPLICIT_IV_LEN;

        if (ctx->enc) {
            rc = wc_AesCcmSetNonce(&ctx->aes, ctx->iv, (word32)ctx->ivLen);
            if (rc != 0) {
                ok = 0;
            }
            else {
                rc = wc_AesCcmEncrypt_ex(&ctx->aes, out, in, (word32)len,
                    ctx->iv, (word32)ctx->ivLen, out + len, (word32)ctx->tagLen,
                    ctx->buf, (word32)ctx->tlsAadLen);
                if (rc != 0) {
                    ok = 0;
                }
            }
        }
        else {
            rc = wc_AesCcmDecrypt(&ctx->aes, out, in, (word32)len, ctx->iv,
                (word32)ctx->ivLen, in + len, (word32)ctx->tagLen, ctx->buf,
                (word32)ctx->tlsAadLen);
            if (rc != 0) {
                ok = 0;
            }
        }
    }
    if (ok) {
        olen = len;
        if (ctx->enc) {
            olen += EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->tagLen;
        }
    }

    *outLen = olen;
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encrypt/decrypt the data using AES-CCM.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold decrypted/encrypted data.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_encdec(wp_AeadCtx *ctx, unsigned char *out,
    const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int rc;

    if (ctx->tagLen == UNINITIALISED_SIZET) {
        ctx->tagLen = EVP_CCM_TLS_TAG_LEN;
    }

    if (ctx->enc) {
        if (!ctx->ivSet) {
            rc = wc_AesCcmSetNonce(&ctx->aes, ctx->iv, (word32)ctx->ivLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            ctx->ivSet = 1;
            /* IV coming out in this call. */
            rc = wc_AesCcmEncrypt_ex(&ctx->aes, out, in, (word32)inLen,
                ctx->iv, (word32)ctx->ivLen, ctx->buf, (word32)ctx->tagLen,
                ctx->aad, (word32)ctx->aadLen);
            if (rc != 0) {
                ok = 0;
            }
        }
    }
    else {
        rc = wc_AesCcmDecrypt(&ctx->aes, out, in, (word32)inLen,
            ctx->iv, (word32)ctx->ivLen, ctx->buf, (word32)ctx->tagLen,
            ctx->aad, (word32)ctx->aadLen);
        if (rc == AES_CCM_AUTH_E) {
            ctx->authErr = 1;
        }
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
        }
    }

    OPENSSL_free(ctx->aad);
    ctx->aad = NULL;
    ctx->aadLen = 0;
    ctx->aadSet = 0;

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
/**
 * Streaming update of AES CCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_stream_update(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        ok = wp_aesccm_tls_cipher(ctx, out, outLen, in, inLen);
    }
    else if (ctx->tagAvail) {
        ok = 0;
    }
    else {
        int oLen = 0;

        if ((out == NULL) && (in == NULL)) {
            /* Nothing to do. */
            oLen = (int)inLen;
        }
        else if ((out == NULL) && (in != NULL)) {
            /* AAD only. */
            ok = wp_aead_cache_aad(ctx, in, inLen);
            if (ok) {
                oLen = (int)inLen;
            }
        }
        else if (outSize < inLen) {
            ok = 0;
        }
        else if ((!ctx->enc) || (inLen > 0)) {
            if (!wp_aesccm_encdec(ctx, out, in, inLen)) {
                ok = 0;
            }
            if (ok) {
                ctx->tagAvail = ctx->enc;
                oLen = (int)inLen;
            }
        }

        *outLen = (size_t)oLen;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Streaming final of AES CCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_stream_final(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;
    (void)outSize;

    if (ctx->tlsAadLen != UNINITIALISED_SIZET) {
        ok = wp_aesccm_tls_cipher(ctx, out, outLen, NULL, 0);
    }
    else if (ctx->authErr) {
        ok = 0;
    }
    else {
        if (ctx->aadSet && (!wp_aesccm_encdec(ctx, out, NULL, 0))) {
            ok = 0;
        }
        if (ok) {
            ctx->ivSet = 0;
            *outLen = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * One-shot of AES CCM cipher.
 *
 * @param [in, out] ctx      AEAD context object.
 * @param [out]     out      Buffer to hold encrypted/decrypted data.
 * @param [out]     outLen   Length of data in output buffer.
 * @param [in]      outSize  Size of output buffer in bytes.
 * @param [in]      in       Data to be encrypted/decrypted.
 * @param [in]      inLen    Length of data to be encrypted/decrypted.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aesccm_cipher(wp_AeadCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    size_t finalLen;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok) {
        ok = wp_aesccm_stream_update(ctx, out, outLen, outSize, in, inLen);
    }
    if (ok) {
        ok = wp_aesccm_stream_final(ctx, out + *outLen, &finalLen,
            outSize - *outLen);
    }
    if (ok) {
        *outLen += finalLen;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a new AEAD context object for performing AES CCM.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @param [in] keyBits  Number of bits in key to be supported.
 * @return  NULL on failure.
 * @return  AEAD context object on success.
 */
static void *wp_aes_ccm_newctx(WOLFPROV_CTX* provCtx, size_t keyBits)
{
    wp_AeadCtx *ctx = NULL;

    (void)provCtx;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
        ctx->keyLen = keyBits / 8;
        ctx->ivLen = 15 - 8;
        ctx->tagLen = UNINITIALISED_SIZET;
        ctx->ivSet = 0;
        ctx->mode = EVP_CIPH_CCM_MODE;
        ctx->tlsAadLen = UNINITIALISED_SIZET;

        if (wc_AesInit(&ctx->aes, NULL, INVALID_DEVID) != 0) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }
    return ctx;
}

/**
 * Dispose of an AEAD context object used for AES CCM.
 *
 * @param [in] ctx  AEAD context object.
 */
static void wp_aes_ccm_freectx(wp_AeadCtx* ctx)
{
    OPENSSL_free(ctx->aad);
    wc_AesFree(&ctx->aes);
    OPENSSL_free(ctx);
}

/* Implement AES CCM for key sizes: 128, 192 and 256 bits. */
IMPLEMENT_AES_AEAD(ccm, CCM, AEAD_FLAGS, 128, 8, 96);
IMPLEMENT_AES_AEAD(ccm, CCM, AEAD_FLAGS, 192, 8, 96);
IMPLEMENT_AES_AEAD(ccm, CCM, AEAD_FLAGS, 256, 8, 96);

#endif /* WP_HAVE_AESCCM */

#endif /* WP_HAVE_AESGCM || WP_HAVE_AESCCM */
