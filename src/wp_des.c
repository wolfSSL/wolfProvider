/* wp_des.c
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


#if defined(WP_HAVE_DES3CBC)

/**
 * Data structure for DES3 ciphers that are block based.
 */
typedef struct wp_Des3BlockCtx {
    /** wolfSSL DES object.  */
    Des3 des3;

    /** Cipher mode - CBC or ECB. */
    int mode;

    unsigned int tls_version;

    /** Length of key in bytes. */
    size_t keyLen;
    /** Length of IV in bytes */
    size_t ivLen;

    /** Operation being performed is encryption. */
    unsigned int enc:1;
    /** Pad data to complete the last block. */
    unsigned int pad:1;
    /** IV has been set. */
    unsigned int ivSet:1;

    /** Number of cached bytes. */
    size_t bufSz;
    /** Cached bytes that didn't fill a block. */
    unsigned char buf[DES_BLOCK_SIZE];
    /** Current IV. */
    unsigned char iv[DES_BLOCK_SIZE];
    /** Original IV. */
    unsigned char oiv[DES_BLOCK_SIZE];
} wp_Des3BlockCtx;


/* Prototype for initialization to call. */
static int wp_des3_block_set_ctx_params(wp_Des3BlockCtx *ctx,
    const OSSL_PARAM params[]);


/**
 * Free the DES3 block context object.
 *
 * @param [in, out] ctx  DES3 block context object.
 */
static void wp_des3_block_freectx(wp_Des3BlockCtx *ctx)
{
    wc_Des3Free(&ctx->des3);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/**
 * Duplicate the DES3 block context object.
 *
 * @param [in] src  DES3 block context object to copy.
 * @return  NULL on failure.
 * @return  DES3 block context object.
 */
static void *wp_des3_block_dupctx(wp_Des3BlockCtx *src)
{
    wp_Des3BlockCtx *dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_malloc(sizeof(*dst));
    }
    if (dst != NULL) {
        /* TODO: copying des3 may not work if it has pointers in it. */
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
static const OSSL_PARAM *wp_cipher_gettable_params(
    WOLFPROV_CTX *provCtx)
{
    /**
     * Parameters able to be retrieved for a cipher.
     */
    static const OSSL_PARAM cipher_supported_gettable_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return cipher_supported_gettable_params;
}

/**
 * Get the values from the DES3 block context for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      mode    DES3 cipher mode.
 * @param [in]      kBits   Number of bits in key.
 * @param [in]      ivBits  Number of bits in IV.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_des3_block_get_params(OSSL_PARAM params[], unsigned int mode,
    size_t kBits, size_t ivBits)
{
    int ok = 1;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if ((p != NULL) && (!OSSL_PARAM_set_uint(p, mode))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, kBits / 8))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, DES_BLOCK_SIZE))) {
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
 * @param [in] ctx      DES3 block context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cipher_gettable_ctx_params(wp_Des3BlockCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters able to be retrieved for a cipher context.
     */
    static const OSSL_PARAM wp_cipher_supported_gettable_ctx_params[] = {
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
    return wp_cipher_supported_gettable_ctx_params;
}

/**
 * Returns the parameters of a cipher context that can be set.
 *
 * @param [in] ctx      DES3 block context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cipher_settable_ctx_params(wp_Des3BlockCtx* ctx,
    WOLFPROV_CTX *provCtx)
{
    /*
     * Parameters able to be set into a cipher context.
     */
    static const OSSL_PARAM wp_cipher_supported_settable_ctx_params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cipher_supported_settable_ctx_params;
}

/**
 * Set the IV against the DES3 block context object.
 *
 * @param [in, out] ctx    DES3 block context object.
 * @param [in]      iv     IV data.
 * @param [in]      ivlen  Length of IV data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_init_iv(wp_Des3BlockCtx *ctx, const unsigned char *iv,
    size_t ivLen)
{
    int ok = 1;

    if (ivLen != ctx->ivLen) {
        ok = 0;
    }
    if (ok) {
        int rc;

        ctx->ivSet = 1;
        XMEMCPY(ctx->iv, iv, ivLen);
        XMEMCPY(ctx->oiv, iv, ivLen);
        rc = wc_Des3_SetIV(&ctx->des3, iv);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an DES3 block cipher.
 *
 * Internal. Handles both encrypt and decrypt.
 *
 * @param [in, out] ctx     DES3 block context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against DES3 block context object.
 * @param [in]      enc     Initializing for encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_init(wp_Des3BlockCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int enc)
{
    int ok = 1;

    ctx->bufSz = 0;
    ctx->enc = enc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (iv != NULL) && (ctx->mode != EVP_CIPH_ECB_MODE) &&
            (!wp_des3_init_iv(ctx, iv, ivLen))) {
        ok = 0;
    }
    if (ok && (iv == NULL) && ctx->ivSet && (ctx->mode == EVP_CIPH_CBC_MODE)) {
        XMEMCPY(ctx->iv, ctx->oiv, ctx->ivLen);
    }

    if (ok && (key != NULL)) {
        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        if (ok) {
            int rc = wc_Des3_SetKey(&ctx->des3, key, iv,
                enc ? DES_ENCRYPTION : DES_DECRYPTION);
            if (rc != 0) {
                ok = 0;
            }
        }
    }

    if (ok) {
        ok = wp_des3_block_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an DES3 block cipher for encryption.
 *
 * @param [in, out] ctx     DES3 block context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against DES3 block context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_einit(wp_Des3BlockCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_des3_block_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialization of an DES3 block cipher for decryption.
 *
 * @param [in, out] ctx     DES3 block context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against DES3 block context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_dinit(wp_Des3BlockCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_des3_block_init(ctx, key, keyLen, iv, ivLen, params, 0);
}

/**
 * Encrypt/decrypt using DES3-CBC with wolfSSL.
 *
 * Assumes out has inLen bytes available.
 * Assumes whole blocks only.
 *
 * @param [in]  ctx    DES3 block context object.
 * @param [out] out    Buffer to hold encrypted/decrypted result.
 * @param [in]  in     Data to encrypt/decrypt.
 * @param [in]  inLen  Length of data to encrypt/decrypt in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_doit(wp_Des3BlockCtx *ctx, unsigned char *out,
    const unsigned char *in, size_t inLen)
{
    int rc;

    if (ctx->mode == EVP_CIPH_CBC_MODE) {
        if (ctx->enc) {
            rc = wc_Des3_CbcEncrypt(&ctx->des3, out, in, (word32)inLen);
        }
        else {
            rc = wc_Des3_CbcDecrypt(&ctx->des3, out, in, (word32)inLen);
        }
        XMEMCPY(ctx->iv, ctx->des3.reg, ctx->ivLen);
    }
    else
    {
        rc = -1;
    }

    return rc == 0;
}

/**
 * Update encryption/decryption with more data.
 *
 * @param [in]  ctx      DES3 block context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_update(wp_Des3BlockCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    size_t oLen = 0;
    size_t nextBlocks;

    if ((ctx->tls_version > 0) && (ctx->enc)) {
        int i;
        unsigned char off = inLen % DES_BLOCK_SIZE;
        unsigned char pad = DES_BLOCK_SIZE - off - 1;
        for (i = off; i < DES_BLOCK_SIZE; i++) {
            out[inLen - off + i] = pad;
        }
        inLen += pad + 1;
    }
    if (ctx->bufSz != 0) {
        size_t len = DES_BLOCK_SIZE - ctx->bufSz;

        if (inLen < len) {
            len = inLen;
        }
        XMEMCPY(ctx->buf + ctx->bufSz, in, len);
        in += len;
        inLen -= len;
        ctx->bufSz += len;
    }
    nextBlocks = inLen & (~(DES_BLOCK_SIZE - 1));

    if ((!ctx->enc) && inLen == 0 && ctx->pad) {
        /* Keep last block for final call. */
    }
    else if (ctx->bufSz == DES_BLOCK_SIZE) {
        if (outSize < DES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok && (!wp_des3_block_doit(ctx, out, ctx->buf, DES_BLOCK_SIZE))) {
            ok = 0;
        }
        if (ok) {
            ctx->bufSz = 0;
            oLen = DES_BLOCK_SIZE;
            out += DES_BLOCK_SIZE;
        }
    }
    if (ok && (nextBlocks > 0)) {
        if ((!ctx->enc) && ctx->pad && (nextBlocks == inLen) &&
            (ctx->tls_version == 0)) {
            nextBlocks -= DES_BLOCK_SIZE;
        }
        if (outSize < oLen) {
            ok = 0;
        }
    }
    if (ok && (nextBlocks > 0)) {
        if (!wp_des3_block_doit(ctx, out, in, nextBlocks)) {
            ok = 0;
        }
        if (ok) {
            in += nextBlocks;
            inLen -= nextBlocks;
            oLen += nextBlocks;
        }
    }
    if (ok) {
        if (inLen != 0) {
            XMEMCPY(ctx->buf, in, inLen);
            ctx->bufSz = inLen;
        }
        *outLen = oLen;
    }
    if (ok && (ctx->tls_version > 0) && (!ctx->enc)) {
        unsigned char pad = out[oLen-1];
        int padStart = DES_BLOCK_SIZE - pad - 1;
        unsigned char invalid = (pad < DES_BLOCK_SIZE) - 1;
        int i;

        for (i = DES_BLOCK_SIZE - 1; i >= 0; i--) {
            byte check = wp_ct_int_mask_gte(i, padStart);
            check &= wp_ct_byte_mask_ne(out[oLen - DES_BLOCK_SIZE + i], pad);
            invalid |= check;
        }
        *outLen = oLen - pad - 1 - DES_BLOCK_SIZE;
        ok = invalid == 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize DES3 block encryption.
 *
 * @param [in]  ctx      DES3 block context object.
 * @param [out] out      Buffer to hold encrypted data.
 * @param [out] outLen   Length of data encrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_final_enc(wp_Des3BlockCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;
    size_t oLen = 0;

    if (ctx->pad) {
        size_t i;
        unsigned char pad = (unsigned char)(DES_BLOCK_SIZE - ctx->bufSz);

        for (i = ctx->bufSz; i < DES_BLOCK_SIZE; i++) {
            ctx->buf[i] = pad;
        }
        ctx->bufSz = DES_BLOCK_SIZE;
    }
    else if (ctx->bufSz != 0) {
        ok = 0;
    }

    if (ok && (ctx->bufSz == DES_BLOCK_SIZE)) {
        if (outSize < DES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok && !wp_des3_block_doit(ctx, out, ctx->buf, DES_BLOCK_SIZE)) {
            ok = 0;
        }
        if (ok) {
            oLen = DES_BLOCK_SIZE;
        }
    }

    if (ok) {
        ctx->bufSz = 0;
        *outLen = oLen;
    }
    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize DES3 block decryption.
 *
 * @param [in]  ctx      DES3 block context object.
 * @param [out] out      Buffer to hold decrypted data.
 * @param [out] outLen   Length of data decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_final_dec(wp_Des3BlockCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    if (ctx->pad) {
        if (ctx->bufSz != DES_BLOCK_SIZE) {
            ok = 0;
        }
    }
    else if (ctx->bufSz != 0) {
        ok = 0;
    }

    if (ok && (ctx->bufSz > 0) &&
        (!wp_des3_block_doit(ctx, ctx->buf, ctx->buf, DES_BLOCK_SIZE))) {
        ok = 0;
    }

    if (ok && ctx->pad) {
        unsigned char pad;

        pad = ctx->buf[DES_BLOCK_SIZE - 1];
        if ((pad == 0) || (pad > DES_BLOCK_SIZE)) {
            ok = 0;
        }
        if (ok) {
            unsigned char len = DES_BLOCK_SIZE;
            unsigned char i;

            for (i = 0; i < pad; i++) {
                if (ctx->buf[--len] != pad) {
                    return 0;
                }
            }
            ctx->bufSz = len;
        }
    }

    if (ok && (outSize < ctx->bufSz)) {
        ok = 0;
    }
    if (ok && (ctx->bufSz > 0)) {
        XMEMCPY(out, ctx->buf, ctx->bufSz);
        XMEMSET(ctx->buf, 0, DES_BLOCK_SIZE);
        *outLen = ctx->bufSz;
        ctx->bufSz = 0;
    }
    else {
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize DES3 block encryption/decryption.
 *
 * @param [in]  ctx      DES3 block context object.
 * @param [out] out      Buffer to hold encrypted/decrypted data.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_final(wp_Des3BlockCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok) {
        if (ctx->enc) {
            ok = wp_des3_block_final_enc(ctx, out, outLen, outSize);
        }
        else {
            ok = wp_des3_block_final_dec(ctx, out, outLen, outSize);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * One-shot encryption/decryption operation.
 *
 * @param [in]  ctx      DES3 block context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_cipher(wp_Des3BlockCtx* ctx, unsigned char* out,
    size_t* outLen, size_t outSize, const unsigned char* in, size_t inLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < inLen)) {
        ok = 0;
    }
    if (ok && !wp_des3_block_doit(ctx, out, in, inLen)) {
        ok = 0;
    }
    if (ok) {
        *outLen = inLen;
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put values from the DES3 block context object into parameters objects.
 *
 * @param [in]      ctx     DES3 block context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_get_ctx_params(wp_Des3BlockCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->ivLen))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
        if ((p != NULL) && (!OSSL_PARAM_set_uint(p, ctx->pad))) {
            ok = 0;
        }
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

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into DES3 block context object.
 *
 * @param [in, out] ctx     DES3 block context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_set_ctx_params(wp_Des3BlockCtx *ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        unsigned int val;
        int set;

        if (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_PADDING, &val,
                &set)) {
            ok = 0;
        }
        if (set) {
            ctx->pad = val != 0;
        }
        /* TODO: can these be left out? */
        if (ok && (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_USE_BITS,
                &val, &set))) {
            ok = 0;
        }
        (void)val;
        (void)set;
        if (ok && (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_NUM,
                &val, &set))) {
            ok = 0;
        }
        (void)val;
        (void)set;
        if (ok && (!wp_params_get_uint(params, OSSL_CIPHER_PARAM_TLS_VERSION,
                &ctx->tls_version, NULL))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_CIPHER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize the DES3 block context object.
 *
 * @param [in, out] ctx      DES3 block context object.
 * @param [in]      kBits    Number of bits in a valid key.
 * @param [in]      ivBits   Number of bits in a valid IV. 0 indicates no IV.
 * @param [in]      mode     DES3 block mode: ECB or CBC.
 * @return  1 on success.
 * @return  0 on failure.
 */
static void wp_des3_block_init_ctx(wp_Des3BlockCtx* ctx, size_t kBits,
    size_t ivBits, unsigned int mode)
{
    ctx->pad = 1;
    ctx->keyLen = ((kBits) / 8);
    ctx->ivLen = ((ivBits) / 8);
    ctx->mode = mode;
}

/** Implement the get params API for a block cipher. */
#define IMPLEMENT_DES3_BLOCK_GET_PARAMS(lcmode, UCMODE, kBits, ivBits)         \
/**                                                                            \
 * Get the values from the DES3 block context for the parameters.              \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_des3_##lcmode##_get_params(OSSL_PARAM params[])                  \
{                                                                              \
    return wp_des3_block_get_params(params, EVP_CIPH_##UCMODE##_MODE, kBits,   \
        ivBits);                                                               \
}

/** Implement the new context API for a block cipher. */
#define IMPLEMENT_DES3_BLOCK_NEWCTX(lcmode, UCMODE, kBits, ivBits)             \
/**                                                                            \
 * Create a new block cipher context object.                                   \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AEAD context object on success.                                    \
 */                                                                            \
static wp_Des3BlockCtx* wp_des3_block_##lcmode##_newctx(                       \
    WOLFPROV_CTX *provCtx)                                                     \
{                                                                              \
    wp_Des3BlockCtx *ctx = NULL;                                               \
    (void)provCtx;                                                             \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        wp_des3_block_init_ctx(ctx, kBits, ivBits, EVP_CIPH_##UCMODE##_MODE);  \
    }                                                                          \
    return ctx;                                                                \
}

/** Implement the dispatch table for a block cipher. */
#define IMPLEMENT_DES3_BLOCK_DISPATCH(mode, kBits, ivBits)                     \
const OSSL_DISPATCH wp_des3##mode##_functions[] = {                            \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
                              (DFUNC)wp_des3_block_##mode##_newctx },          \
    { OSSL_FUNC_CIPHER_FREECTX,         (DFUNC)wp_des3_block_freectx        }, \
    { OSSL_FUNC_CIPHER_DUPCTX,          (DFUNC)wp_des3_block_dupctx         }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,    (DFUNC)wp_des3_block_einit          }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,    (DFUNC)wp_des3_block_dinit          }, \
    { OSSL_FUNC_CIPHER_UPDATE,          (DFUNC)wp_des3_block_update         }, \
    { OSSL_FUNC_CIPHER_FINAL,           (DFUNC)wp_des3_block_final          }, \
    { OSSL_FUNC_CIPHER_CIPHER,          (DFUNC)wp_des3_block_cipher         }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                              (DFUNC)wp_des3_##mode##_get_params   },          \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,  (DFUNC)wp_des3_block_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,  (DFUNC)wp_des3_block_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_cipher_gettable_params   },  \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                              (DFUNC)wp_cipher_gettable_ctx_params          }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                              (DFUNC)wp_cipher_settable_ctx_params          }, \
    { 0, NULL }                                                                \
};

/** Implements the functions calling base functions for a block cipher. */
#define IMPLEMENT_DES3_BLOCK(lcmode, UCMODE, kBits, ivBits)                    \
IMPLEMENT_DES3_BLOCK_GET_PARAMS(lcmode, UCMODE, kBits, ivBits)                 \
IMPLEMENT_DES3_BLOCK_NEWCTX(lcmode, UCMODE, kBits, ivBits)                     \
IMPLEMENT_DES3_BLOCK_DISPATCH(lcmode, kBits, ivBits)

/*
 * DES3 CBC
 */

/** wp_des3cbc_functions_functions */
IMPLEMENT_DES3_BLOCK(cbc, CBC, 192, 64)


#endif /* WP_HAVE_AESCBC || WP_HAVE_AESECB */

