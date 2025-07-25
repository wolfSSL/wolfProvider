/* wp_aes_stream.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#if defined(WP_HAVE_AESCTR) || defined(WP_HAVE_AESCFB) || defined(WP_HAVE_AESCTS)

/**
 * Data structure for AES ciphers that are streaming.
 */
typedef struct wp_AesStreamCtx {
    /** wolfSSL AES object.  */
    Aes aes;

    /** Cipher mode - CTR, CFB or CTS. */
    int mode;

    /** Length of key in bytes. */
    size_t keyLen;
    /** Length of IV in bytes */
    size_t ivLen;

    /** Operation being performed is encryption. */
    unsigned int enc:1;

    /** Current IV. */
    unsigned char iv[AES_BLOCK_SIZE];
    /** Original IV. */
    unsigned char oiv[AES_BLOCK_SIZE];

#if defined(WP_HAVE_AESCTS)
    /* Only single shot allowed */
    unsigned int updated:1;
#endif
} wp_AesStreamCtx;


/* Prototype for initialization to call. */
static int wp_aes_stream_set_ctx_params(wp_AesStreamCtx *ctx,
    const OSSL_PARAM params[]);


/**
 * Free the AES stream context object.
 *
 * @param [in, out] ctx  AES stream context object.
 */
static void wp_aes_stream_freectx(wp_AesStreamCtx *ctx)
{
    wc_AesFree(&ctx->aes);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/**
 * Duplicate the AES stream context object.
 *
 * @param [in] src  AES stream context object to copy.
 * @return  NULL on failure.
 * @return  AES stream context object.
 */
static void *wp_aes_stream_dupctx(wp_AesStreamCtx *src)
{
    wp_AesStreamCtx *dst = NULL;

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
 * Parameters able to be retrieved for a cipher.
 */
static const OSSL_PARAM cipher_supported_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_END
};
/**
 * Returns the parameters that can be retrieved.
 *
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_cipher_gettable_params(
    WOLFPROV_CTX *provCtx)
{
    (void)provCtx;
    return cipher_supported_gettable_params;
}

/**
 * Get the values from the AES stream context for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      mode    AES cipher mode.
 * @param [in]      kBits   Number of bits in key.
 * @param [in]      ivBits  Number of bits in IV.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_aes_stream_get_params(OSSL_PARAM params[], unsigned int mode,
    unsigned int flags, size_t kBits, size_t ivBits)
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
#ifdef WP_HAVE_AESCTS
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, flags & EVP_CIPH_FLAG_CTS))) {
            ok = 0;
        }
    }
#endif /* WP_HAVE_AESCTS */

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of a cipher context that can be retrieved.
 *
 * @param [in] ctx      AES stream context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cipher_gettable_ctx_params(wp_AesStreamCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters able to be retrieved for a cipher context.
     */
    static const OSSL_PARAM wp_cipher_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
#ifdef WP_HAVE_AESCTS
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
#endif
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cipher_supported_gettable_ctx_params;
}

/**
 * Returns the parameters of a cipher context that can be set.
 *
 * @param [in] ctx      AES stream context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cipher_settable_ctx_params(wp_AesStreamCtx* ctx,
    WOLFPROV_CTX *provCtx)
{
    /**
     * Parameters able to be set into a cipher context.
     */
    static const OSSL_PARAM wp_cipher_supported_settable_ctx_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, NULL),
#ifdef WP_HAVE_AESCTS
        OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
#endif
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cipher_supported_settable_ctx_params;
}

/**
 * Set the IV against the AES stream context object.
 *
 * @param [in, out] ctx    AES stream context object.
 * @param [in]      iv     IV data.
 * @param [in]      ivlen  Length of IV data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_init_iv(wp_AesStreamCtx *ctx, const unsigned char *iv,
    size_t ivLen)
{
    int ok = 1;

    if (ivLen != ctx->ivLen) {
        ok = 0;
    }
    if (ok) {
        XMEMCPY(ctx->iv, iv, ivLen);
        XMEMCPY(ctx->oiv, iv, ivLen);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an AES stream cipher.
 *
 * Internal. Handles both encrypt and ddecrypt.
 *
 * @param [in, out] ctx     AES stream context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES stream context object.
 * @param [in]      enc     Initializing for encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_init(wp_AesStreamCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int enc)
{
    int ok = 1;
    /* Decryption is the same as encryption with CTR mode. */
    int dir = AES_ENCRYPTION;

    ctx->enc = enc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (iv != NULL) && (!wp_aes_init_iv(ctx, iv, ivLen))) {
        ok = 0;
    }

    if (ok && (key != NULL)) {
        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        if (ok) {
#if defined(WP_HAVE_AESCTS)
            if (ctx->mode == EVP_CIPH_CBC_MODE && !enc) {
                dir = AES_DECRYPTION;
            }
#endif
            int rc = wc_AesSetKey(&ctx->aes, key, (word32)ctx->keyLen, iv,
                dir);
            if (rc != 0) {
                ok = 0;
            }
        }
    }
    else if (ok) {
        /* TODO: don't reach in under the covers.
         * Setting the key will reset this.
         */
        ctx->aes.left = 0;
    }

    if (ok) {
#if defined(WP_HAVE_AESCTS)
        /* We only allow one shot, always reset on init */
        ctx->updated = 0;
#endif
        ok = wp_aes_stream_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an AES stream cipher for encryption.
 *
 * @param [in, out] ctx     AES stream context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES stream context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_einit(wp_AesStreamCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_stream_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialization of an AES stream cipher for decryption.
 *
 * @param [in, out] ctx     AES stream context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES stream context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_dinit(wp_AesStreamCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_stream_init(ctx, key, keyLen, iv, ivLen, params, 0);
}

#ifdef WP_HAVE_AESCTS

static int wp_aes_cts_encrypt(wp_AesStreamCtx *ctx, unsigned char *out,
    const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int rc;
    int blocks;
    byte ctsBlock[AES_BLOCK_SIZE * 2];

    /* Since AES-CTS is not a FIPS approved algo, we will never be able to call
     * the existing wolfSSL AES_CTS APIs with FIPS, so the implementation is
     * effectively copied here from wolfSSL internals. */

    blocks = (int)((inLen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE);
    blocks -= 2;
    XMEMSET(ctsBlock, 0, AES_BLOCK_SIZE * 2);
    if (ok && blocks > 0) {
        XMEMCPY(&ctx->aes.reg, ctx->iv, ctx->ivLen);
        rc = wc_AesCbcEncrypt(&ctx->aes, out, in, blocks * AES_BLOCK_SIZE);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
            in += blocks * AES_BLOCK_SIZE;
            out += blocks * AES_BLOCK_SIZE;
            inLen -= blocks * AES_BLOCK_SIZE;
        }
    }
    if (ok) {
        XMEMCPY(ctsBlock, in, inLen);
        rc = wc_AesCbcEncrypt(&ctx->aes, ctsBlock, ctsBlock,
            AES_BLOCK_SIZE * 2);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
        }
    }
    if (ok) {
        XMEMCPY(out, ctsBlock + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        XMEMCPY(out + AES_BLOCK_SIZE, ctsBlock, inLen - AES_BLOCK_SIZE);
    }

    return ok;
}

static int wp_aes_cts_decrypt(wp_AesStreamCtx *ctx, unsigned char *out,
    const unsigned char *in, size_t inLen)
{
    int ok = 1;
    int rc;
    int blocks;
    byte ctsBlock[AES_BLOCK_SIZE * 2];
    byte tmp[AES_BLOCK_SIZE];
    word32 partialSz;
    word32 padSz;

    /* Since AES-CTS is not a FIPS approved algo, we will never be able to call
     * the existing wolfSSL AES_CTS APIs with FIPS, so the implementation is
     * effectively copied here from wolfSSL internals. */

    partialSz = inLen % AES_BLOCK_SIZE;
    if (partialSz == 0) {
        partialSz = AES_BLOCK_SIZE;
    }
    padSz = AES_BLOCK_SIZE - partialSz;

    blocks = (int)((inLen + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE);
    blocks -= 2;
    XMEMSET(ctsBlock, 0, AES_BLOCK_SIZE * 2);
    if (ok && blocks > 0) {
        XMEMCPY(&ctx->aes.reg, ctx->iv, ctx->ivLen);
        rc = wc_AesCbcDecrypt(&ctx->aes, out, in, blocks * AES_BLOCK_SIZE);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
            in += blocks * AES_BLOCK_SIZE;
            out += blocks * AES_BLOCK_SIZE;
            inLen -= blocks * AES_BLOCK_SIZE;
        }
    }
    if (ok) {
        XMEMCPY(ctsBlock, in, inLen);
        XMEMCPY(&ctx->aes.reg, ctsBlock + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        rc = wc_AesCbcDecrypt(&ctx->aes, tmp, ctsBlock, AES_BLOCK_SIZE);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        XMEMCPY(out + AES_BLOCK_SIZE, tmp, partialSz);
        XMEMCPY(ctsBlock + inLen, tmp + partialSz, padSz);
        XMEMCPY(tmp, &ctx->aes.reg, AES_BLOCK_SIZE);
        XMEMCPY(&ctx->aes.reg, ctx->iv, AES_BLOCK_SIZE);
        rc = wc_AesCbcDecrypt(&ctx->aes, out, ctsBlock + AES_BLOCK_SIZE,
            AES_BLOCK_SIZE);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            /* Restore the proper IV */
            XMEMCPY(ctx->iv, tmp, ctx->ivLen);
        }
    }

    return ok;
}

#endif /* ifdef WP_HAVE_AESCTS */

/**
 * Encrypt/decrypt using AES-CTR, AES-CFB or AES-CTS with wolfSSL.
 *
 * Assumes out has inLen bytes available.
 * Assumes whole blocks only.
 *
 * @param [in]  ctx    AES stream context object.
 * @param [out] out    Buffer to hold encrypted/decrypted result.
 * @param [in]  in     Data to encrypt/decrypt.
 * @param [in]  inLen  Length of data to encrypt/decrypt in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_doit(wp_AesStreamCtx *ctx, unsigned char *out,
    const unsigned char *in, size_t inLen)
{
    int ok = 1;

#ifdef WP_HAVE_AESCTR
    if (ctx->mode == EVP_CIPH_CTR_MODE) {
        int rc;

        XMEMCPY(&ctx->aes.reg, ctx->iv, ctx->ivLen);
        rc = wc_AesCtrEncrypt(&ctx->aes, out, in, (word32)inLen);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
        }
    }
    else
#endif
#ifdef WP_HAVE_AESCFB
    if (ctx->mode == EVP_CIPH_CFB_MODE) {
        int rc;

        XMEMCPY(&ctx->aes.reg, ctx->iv, ctx->ivLen);
        if (ctx->enc) {
            rc = wc_AesCfbEncrypt(&ctx->aes, out, in, (word32)inLen);
        }else {
            rc = wc_AesCfbDecrypt(&ctx->aes, out, in, (word32)inLen);
        }
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
        }
    }
    else
#endif
#ifdef WP_HAVE_AESCTS
    if (ctx->mode == EVP_CIPH_CBC_MODE) {
        if (ctx->updated) {
            ok = 0;
        }
        if (inLen < AES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok) {
            if (ctx->enc) {
                ok = wp_aes_cts_encrypt(ctx, out, in, inLen);
            }
            else {
                ok = wp_aes_cts_decrypt(ctx, out, in, inLen);
            }
        }
        if (ok) {
            ctx->updated = 1;
        }
    }
    else
#endif
    {}

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Update encryption/decryption with more data.
 *
 * @param [in]  ctx      AES stream context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_update(wp_AesStreamCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;

    if (outSize < inLen) {
        ok = 0;
    }
    if (ok) {
        ok = wp_aes_stream_doit(ctx, out, in, inLen);
    }
    if (ok) {
        *outLen = inLen;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES stream encryption/decryption.
 *
 * @param [in]  ctx      AES stream context object.
 * @param [out] out      Buffer to hold encrypted/decrypted data.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_final(wp_AesStreamCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    /* Nothing to do as all the data has been processed in update. */
    (void)ctx;
    (void)out;
    (void)outSize;
    *outLen = 0;
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * One-shot encryption/decryption operation.
 *
 * @param [in]  ctx      AES stream context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_cipher(wp_AesStreamCtx* ctx, unsigned char* out,
    size_t* outLen, size_t outSize, const unsigned char* in, size_t inLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < inLen)) {
        ok = 0;
    }
    /* NULL in, NULL out, 0 len is OK */
    if (ok && (in != NULL && out != NULL && inLen != 0) &&
              (!wp_aes_stream_doit(ctx, out, in, inLen))) {
        ok = 0;
    }

    *outLen = inLen;
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put values from the AES stream context object into parameters objects.
 *
 * @param [in]      ctx     AES stream context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_get_ctx_params(wp_AesStreamCtx* ctx,
    OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->ivLen))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivLen)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivLen))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivLen)) &&
            (!OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivLen))) {
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
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->keyLen))) {
            ok = 0;
        }
    }
#ifdef WP_HAVE_AESCTS
    if (ok && ctx->mode == EVP_CIPH_CBC_MODE) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "CS3"))) {
            ok = 0;
        }
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into AES stream context object.
 *
 * @param [in, out] ctx     AES stream context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_stream_set_ctx_params(wp_AesStreamCtx *ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    (void)ctx;

    if (params != NULL) {
        unsigned int val;

        /* TODO: can these be left out? */
        if (ok && (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_USE_BITS,
                &val, NULL))) {
            ok = 0;
        }
        (void)val;
        if (ok && (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_NUM,
                &val, NULL))) {
            ok = 0;
        }
        (void)val;
#ifdef WP_HAVE_AESCTS
        if (ok && ctx->mode == EVP_CIPH_CBC_MODE) {
            char cts_mode[4];
            char *pcts = cts_mode;
            const OSSL_PARAM* p = NULL;
            XMEMSET(cts_mode, 0, sizeof(cts_mode));

            p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
            if (p != NULL) {
                if (!OSSL_PARAM_get_utf8_string(p, &pcts,
                        sizeof(cts_mode))) {
                    ok = 0;
                }
                if (ok && (XSTRCMP(cts_mode, "CS3") != 0)) {
                    ok = 0; /* Only CS3 supported */
                }
            }
        }
#endif
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize the AES stream context object.
 *
 * @param [in, out] ctx      AES stream context object.
 * @param [in]      kBits    Number of bits in a valid key.
 * @param [in]      ivBits   Number of bits in a valid IV. 0 indicates no IV.
 * @param [in]      mode     AES stream mode: CTR, CFB or CTS.
 * @return  1 on success.
 * @return  0 on failure.
 */
static void wp_aes_stream_init_ctx(wp_AesStreamCtx* ctx, size_t kBits,
    size_t ivBits, unsigned int mode)
{
    ctx->keyLen = ((kBits) / 8);
    ctx->ivLen = ((ivBits) / 8);
    ctx->mode = mode;
}


/** Implements the get parameters API for a stream cipher. */
#define IMPLEMENT_AES_STREAM_GET_PARAMS(lcmode, UCMODE, flags, kBits, ivBits)  \
/**                                                                            \
 * Get the values from the AES stream context for the parameters.              \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_aes_##kBits##_##lcmode##_get_params(OSSL_PARAM params[])         \
{                                                                              \
    return wp_aes_stream_get_params(params, EVP_CIPH_##UCMODE##_MODE, flags,   \
        kBits, ivBits);                                                        \
}

/** Implements the new context API for a stream cipher. */
#define IMPLEMENT_AES_STREAM_NEWCTX(lcmode, UCMODE, kBits, ivBits)             \
/**                                                                            \
 * Create a new stream cipher context object.                                  \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AEAD context object on success.                                    \
 */                                                                            \
static wp_AesStreamCtx* wp_aes_stream_##kBits##_##lcmode##_newctx(             \
    WOLFPROV_CTX *provCtx)                                                     \
{                                                                              \
    wp_AesStreamCtx *ctx = NULL;                                               \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        wp_aes_stream_init_ctx(ctx, kBits, ivBits, EVP_CIPH_##UCMODE##_MODE);  \
    }                                                                          \
    return ctx;                                                                \
}

/** Implements dispatch table for a stream cipher. */
#define IMPLEMENT_AES_STREAM_DISPATCH(mode, kBits, ivBits)                     \
const OSSL_DISPATCH wp_aes##kBits##mode##_functions[] = {                      \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
                             (DFUNC)wp_aes_stream_##kBits##_##mode##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX,         (DFUNC)wp_aes_stream_freectx        }, \
    { OSSL_FUNC_CIPHER_DUPCTX,          (DFUNC)wp_aes_stream_dupctx         }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,    (DFUNC)wp_aes_stream_einit          }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,    (DFUNC)wp_aes_stream_dinit          }, \
    { OSSL_FUNC_CIPHER_UPDATE,          (DFUNC)wp_aes_stream_update         }, \
    { OSSL_FUNC_CIPHER_FINAL,           (DFUNC)wp_aes_stream_final          }, \
    { OSSL_FUNC_CIPHER_CIPHER,          (DFUNC)wp_aes_stream_cipher         }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                             (DFUNC)wp_aes_##kBits##_##mode##_get_params    }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,  (DFUNC)wp_aes_stream_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,  (DFUNC)wp_aes_stream_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_cipher_gettable_params    }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                             (DFUNC)wp_cipher_gettable_ctx_params           }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                             (DFUNC)wp_cipher_settable_ctx_params           }, \
    { 0, NULL }                                                                \
};

/** Implements the functions calling base functions for a stream cipher. */
#define IMPLEMENT_AES_STREAM(lcmode, UCMODE, flags, kBits, ivBits)             \
IMPLEMENT_AES_STREAM_GET_PARAMS(lcmode, UCMODE, flags, kBits, ivBits)          \
IMPLEMENT_AES_STREAM_NEWCTX(lcmode, UCMODE, kBits, ivBits)                     \
IMPLEMENT_AES_STREAM_DISPATCH(lcmode, kBits, ivBits)

/*
 * AES CTR
 */
#ifdef WP_HAVE_AESCTR
/** wp_aes256ctr_functions */
IMPLEMENT_AES_STREAM(ctr, CTR, 0, 256, 128)
/** wp_aes192ctr_functions */
IMPLEMENT_AES_STREAM(ctr, CTR, 0, 192, 128)
/** wp_aes128ctr_functions */
IMPLEMENT_AES_STREAM(ctr, CTR, 0, 128, 128)
#endif /* WP_HAVE_AESCTR */

/*
 * AES CFB
 */
#ifdef WP_HAVE_AESCFB
/** wp_aes256cfb_functions */
IMPLEMENT_AES_STREAM(cfb, CFB, 0, 256, 128)
/** wp_aes192cfb_functions */
IMPLEMENT_AES_STREAM(cfb, CFB, 0, 192, 128)
/** wp_aes128cfb_functions */
IMPLEMENT_AES_STREAM(cfb, CFB, 0, 128, 128)
#endif /* WP_HAVE_AESCFB */

/*
 * AES CTS
 *
 * Even though AES-CTS is a block cipher, since we will only be supporting a
 * single-shot mode it actually behaves more like a stream cipher.
 */
#ifdef WP_HAVE_AESCTS
/** wp_aes256cts_functions */
IMPLEMENT_AES_STREAM(cts, CBC, EVP_CIPH_FLAG_CTS, 256, 128)
/** wp_aes192cts_functions */
IMPLEMENT_AES_STREAM(cts, CBC, EVP_CIPH_FLAG_CTS, 192, 128)
/** wp_aes128cts_functions */
IMPLEMENT_AES_STREAM(cts, CBC, EVP_CIPH_FLAG_CTS, 128, 128)
#endif /* WP_HAVE_AESCTS */

#endif /* WP_HAVE_AESCTR || WP_HAVE_AESCFB || WP_HAVE_AESCTS */

