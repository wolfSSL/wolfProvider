/* wp_aes_block.c
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


#if defined(WP_HAVE_AESCBC) || defined(WP_HAVE_AESECB)

/**
 * Data structure for AES ciphers that are block based.
 */
typedef struct wp_AesBlockCtx {
    /** wolfSSL AES object.  */
    Aes aes;

    /** Provider context - needed for wolfCrypt RNG access. */
    WOLFPROV_CTX *provCtx;

    /** Cipher mode - CBC or ECB. */
    int mode;

    unsigned int tls_version;

    /** Pointer to the MAC extracted from a decrypted TLS record. */
    unsigned char *tlsmac;
    /** Size of the MAC expected in TLS records. */
    size_t tlsmacsize;
    /** Whether tlsmac was separately allocated. */
    int tlsmacAlloced;

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
    unsigned char buf[AES_BLOCK_SIZE];
    /** Current IV. */
    unsigned char iv[AES_BLOCK_SIZE];
    /** Original IV. */
    unsigned char oiv[AES_BLOCK_SIZE];
} wp_AesBlockCtx;


/* Prototype for initialization to call. */
static int wp_aes_block_set_ctx_params(wp_AesBlockCtx *ctx,
    const OSSL_PARAM params[]);


/**
 * Free the AES block context object.
 *
 * @param [in, out] ctx  AES block context object.
 */
static void wp_aes_block_freectx(wp_AesBlockCtx *ctx)
{
    if (ctx->tlsmacAlloced) {
        OPENSSL_free(ctx->tlsmac);
    }
    wc_AesFree(&ctx->aes);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/**
 * Duplicate the AES block context object.
 *
 * @param [in] src  AES block context object to copy.
 * @return  NULL on failure.
 * @return  AES block context object.
 */
static void *wp_aes_block_dupctx(wp_AesBlockCtx *src)
{
    wp_AesBlockCtx *dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = OPENSSL_malloc(sizeof(*dst));
    }
    if (dst != NULL) {
        /* TODO: copying Aes may not work if it has pointers in it. */
        XMEMCPY(dst, src, sizeof(*src));
        /* Deep-copy tlsmac to avoid double-free between src and dst. */
        if (src->tlsmacAlloced && src->tlsmac != NULL) {
            dst->tlsmac = OPENSSL_malloc(src->tlsmacsize);
            if (dst->tlsmac == NULL) {
                OPENSSL_free(dst);
                return NULL;
            }
            XMEMCPY(dst->tlsmac, src->tlsmac, src->tlsmacsize);
        }
        else {
            dst->tlsmac = NULL;
            dst->tlsmacAlloced = 0;
        }
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
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return cipher_supported_gettable_params;
}

/**
 * Get the values from the AES block context for the parameters.
 *
 * @param [in, out] params  Array of parameters to retrieve.
 * @param [in]      mode    AES cipher mode.
 * @param [in]      kBits   Number of bits in key.
 * @param [in]      ivBits  Number of bits in IV.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_aes_block_get_params(OSSL_PARAM params[], unsigned int mode,
    size_t kBits, size_t ivBits)
{
    int ok = 1;
    OSSL_PARAM *p;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_get_params");

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

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters of a cipher context that can be retrieved.
 *
 * @param [in] ctx      AES block context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cipher_gettable_ctx_params(wp_AesBlockCtx* ctx,
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
        { OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, NULL, 0,
          OSSL_PARAM_UNMODIFIED },
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cipher_supported_gettable_ctx_params;
}

/**
 * Returns the parameters of a cipher context that can be set.
 *
 * @param [in] ctx      AES block context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cipher_settable_ctx_params(wp_AesBlockCtx* ctx,
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
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cipher_supported_settable_ctx_params;
}

#ifdef WP_HAVE_AESCBC
/**
 * Set the IV against the AES block context object.
 *
 * @param [in, out] ctx    AES block context object.
 * @param [in]      iv     IV data.
 * @param [in]      ivlen  Length of IV data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_init_iv(wp_AesBlockCtx *ctx, const unsigned char *iv,
    size_t ivLen)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_init_iv");

    if (ivLen != ctx->ivLen) {
        ok = 0;
    }
    if (ok) {
        int rc;

        ctx->ivSet = 1;
        XMEMCPY(ctx->iv, iv, ivLen);
        XMEMCPY(ctx->oiv, iv, ivLen);
        rc = wc_AesSetIV(&ctx->aes, iv);
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_AesSetIV", rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Initialization of an AES block cipher.
 *
 * Internal. Handles both encrypt and decrypt.
 *
 * @param [in, out] ctx     AES block context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES block context object.
 * @param [in]      enc     Initializing for encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_init(wp_AesBlockCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[], int enc)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_init");

    ctx->bufSz = 0;
    ctx->enc = enc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

#ifdef WP_HAVE_AESCBC
    if (ok && (iv != NULL) && (ctx->mode != EVP_CIPH_ECB_MODE) &&
            (!wp_aes_init_iv(ctx, iv, ivLen))) {
        ok = 0;
    }
#endif
#ifdef WP_HAVE_AESCBC
    if (ok && (iv == NULL) && ctx->ivSet && (ctx->mode == EVP_CIPH_CBC_MODE)) {
        if (!wp_aes_init_iv(ctx, ctx->oiv, ctx->ivLen)) {
            ok = 0;
        }
    }
#else
    (void)ivLen;
#endif

    if (ok && (key != NULL)) {
        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        if (ok) {
            int rc;
            WP_CHECK_FIPS_ALGO(WP_CAST_ALGO_AES);
            rc = wc_AesSetKey(&ctx->aes, key, (word32)ctx->keyLen, ctx->iv,
                enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_AesSetKey", rc);
                ok = 0;
            }
        }
    }

    if (ok) {
        ok = wp_aes_block_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialization of an AES block cipher for encryption.
 *
 * @param [in, out] ctx     AES block context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES block context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_einit(wp_AesBlockCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_block_init(ctx, key, keyLen, iv, ivLen, params, 1);
}

/**
 * Initialization of an AES block cipher for decryption.
 *
 * @param [in, out] ctx     AES block context object.
 * @param [in]      key     Private key data. May be NULL.
 * @param [in]      keyLen  Length of private key in bytes.
 * @param [in]      iv      IV data. May be NULL.
 * @param [in]      ivLen   Length of IV in bytes.
 * @param [in]      params  Parameters to set against AES block context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_dinit(wp_AesBlockCtx *ctx, const unsigned char *key,
    size_t keyLen, const unsigned char *iv, size_t ivLen,
    const OSSL_PARAM params[])
{
    return wp_aes_block_init(ctx, key, keyLen, iv, ivLen, params, 0);
}

/**
 * Encrypt/decrypt using AES-ECB or AES-CBC with wolfSSL.
 *
 * Assumes out has inLen bytes available.
 * Assumes whole blocks only.
 *
 * @param [in]  ctx    AES block context object.
 * @param [out] out    Buffer to hold encrypted/decrypted result.
 * @param [in]  in     Data to encrypt/decrypt.
 * @param [in]  inLen  Length of data to encrypt/decrypt in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_doit(wp_AesBlockCtx *ctx, unsigned char *out,
    const unsigned char *in, size_t inLen)
{
    int rc;

#ifdef WP_HAVE_AESCBC
    if (ctx->mode == EVP_CIPH_CBC_MODE) {
        if (ctx->enc) {
            rc = wc_AesCbcEncrypt(&ctx->aes, out, in, (word32)inLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_AesCbcEncrypt", rc);
            }
        }
        else {
            rc = wc_AesCbcDecrypt(&ctx->aes, out, in, (word32)inLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_AesCbcDecrypt", rc);
            }
        }
        XMEMCPY(ctx->iv, ctx->aes.reg, ctx->ivLen);
    }
    else
#endif
#ifdef WP_HAVE_AESECB
    if (ctx->mode == EVP_CIPH_ECB_MODE) {
        if (ctx->enc) {
            rc = wc_AesEcbEncrypt(&ctx->aes, out, in, (word32)inLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_AesEcbEncrypt", rc);
            }
        }
        else {
            rc = wc_AesEcbDecrypt(&ctx->aes, out, in, (word32)inLen);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_AesEcbDecrypt", rc);
            }
        }
    }
    else
#endif
    {
        rc = -1;
    }

    return rc == 0;
}

/**
 * Update encryption/decryption with more data.
 *
 * @param [in]  ctx      AES block context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_update(wp_AesBlockCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize, const unsigned char *in, size_t inLen)
{
    int ok = 1;
    size_t oLen = 0;
    size_t nextBlocks;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_update");

    if ((ctx->tls_version > 0) && (ctx->enc)) {
        int i;
        unsigned char off = inLen % AES_BLOCK_SIZE;
        unsigned char pad = AES_BLOCK_SIZE - off - 1;
        for (i = off; i < AES_BLOCK_SIZE; i++) {
            out[inLen - off + i] = pad;
        }
        inLen += pad + 1;
    }
    if (ctx->bufSz != 0) {
        size_t len = AES_BLOCK_SIZE - ctx->bufSz;

        if (inLen < len) {
            len = inLen;
        }
        XMEMCPY(ctx->buf + ctx->bufSz, in, len);
        in += len;
        inLen -= len;
        ctx->bufSz += len;
    }
    nextBlocks = inLen & (~(AES_BLOCK_SIZE - 1));

    if ((!ctx->enc) && inLen == 0 && ctx->pad) {
        /* Keep last block for final call. */
    }
    else if (ctx->bufSz == AES_BLOCK_SIZE) {
        if (outSize < AES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok && (!wp_aes_block_doit(ctx, out, ctx->buf, AES_BLOCK_SIZE))) {
            ok = 0;
        }
        if (ok) {
            ctx->bufSz = 0;
            oLen = AES_BLOCK_SIZE;
            out += AES_BLOCK_SIZE;
        }
    }
    if (ok && (nextBlocks > 0)) {
        if ((!ctx->enc) && ctx->pad && (nextBlocks == inLen) &&
            (ctx->tls_version == 0)) {
            nextBlocks -= AES_BLOCK_SIZE;
        }
    }
    if (ok && (nextBlocks > 0)) {
        if (!wp_aes_block_doit(ctx, out, in, nextBlocks)) {
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
        /*
         * TLS 1.2 CBC padding removal and MAC extraction.
         * Buffer: [explicit_IV(BS)][payload][MAC(macsize)][padding(pad+1)]
         *
         * Constant-time padding validation based on OpenSSL's
         * tls1_cbc_remove_padding_and_mac() (ssl/record/methods/tls_pad.c)
         *
         * Constant-time MAC extraction based on OpenSSL's
         * ssl3_cbc_copy_mac() rotation pattern. On bad padding the MAC
         * is replaced with random bytes via ct select.
         */
        unsigned char *rec;
        size_t recLen;
        size_t origRecLen;
        unsigned char padVal;
        size_t overhead;
        size_t toCheck;
        size_t good;
        size_t i, j;
        size_t macSize = ctx->tlsmacsize;

        /* Free any previously allocated MAC */
        if (ctx->tlsmacAlloced) {
            OPENSSL_free(ctx->tlsmac);
            ctx->tlsmacAlloced = 0;
            ctx->tlsmac = NULL;
        }

        if (macSize == 0 || macSize > EVP_MAX_MD_SIZE ||
            oLen < AES_BLOCK_SIZE + macSize + 1) {
            ok = 0;
        }

        if (ok) {
            /* 64-byte aligned buffer for cache-line-aware MAC rotation */
            unsigned char rotatedMacBuf[64 + EVP_MAX_MD_SIZE];
            unsigned char *rotatedMac;
            unsigned char randMac[EVP_MAX_MD_SIZE];
            size_t macEnd;
            size_t macStart;
            size_t scanStart = 0;
            byte inMac;
            size_t rotateOff;

            /* Align rotatedMac to 64-byte boundary so the entire MAC
             * buffer (up to EVP_MAX_MD_SIZE=64) sits within one or two
             * 32-byte cache lines at known positions. */
            rotatedMac = rotatedMacBuf +
                ((0 - (size_t)rotatedMacBuf) & 63);

            /* For TLS 1.1+/DTLS: skip explicit IV */
            rec = out + AES_BLOCK_SIZE;
            recLen = oLen - AES_BLOCK_SIZE;
            origRecLen = recLen;

            padVal = rec[recLen - 1];
            overhead = macSize + (size_t)padVal + 1;

            /* CT overhead check: recLen >= overhead.
             * No branch on padVal — fold into good mask instead. */
            good = (size_t)0 -
                ((size_t)(wp_ct_int_mask_gte((int)recLen, (int)overhead) & 1));

            /* Validate padding bytes in constant time.
             * Check up to 256 bytes (max TLS padding). */
            toCheck = 256;
            if (toCheck > recLen)
                toCheck = recLen;

            for (i = 0; i < toCheck; i++) {
                byte mask = wp_ct_int_mask_gte((int)padVal, (int)i);
                unsigned char b = rec[recLen - 1 - i];
                good &= ~((size_t)(mask & (padVal ^ b)));
            }
            {
                /* Collapse lower 8 bits to full-width size_t mask.
                 * Same technique as OpenSSL constant_time_eq_s. */
                size_t diff = (good & 0xff) ^ 0xff;
                diff |= (0 - diff);
                diff >>= (sizeof(size_t) * 8 - 1);
                good = diff - 1;
            }

            /* Remove padding (only if valid) */
            recLen -= good & ((size_t)padVal + 1);

            macEnd = recLen;
            macStart = macEnd - macSize;

            recLen -= macSize;
            *outLen = recLen;

            /* Generate random MAC to use if padding was bad */
        #ifndef WP_SINGLE_THREADED
            wp_provctx_lock_rng(ctx->provCtx);
        #endif
            if (wc_RNG_GenerateBlock(wp_provctx_get_rng(ctx->provCtx),
                                     randMac, (word32)macSize) != 0) {
                ok = 0;
            }
        #ifndef WP_SINGLE_THREADED
            wp_provctx_unlock_rng(ctx->provCtx);
        #endif

            ctx->tlsmac = OPENSSL_malloc(macSize);
            if (ctx->tlsmac == NULL) {
                ok = 0;
            }
            else {
                ctx->tlsmacAlloced = 1;

                /* Constant-time MAC extraction: scan all bytes that
                 * could contain the MAC (position varies by up to 255). */
                if (origRecLen > macSize + 255 + 1)
                    scanStart = origRecLen - (macSize + 255 + 1);

                XMEMSET(rotatedMac, 0, EVP_MAX_MD_SIZE);
                inMac = 0;
                rotateOff = 0;
                for (i = scanStart, j = 0; i < origRecLen; i++) {
                    byte started = wp_ct_int_mask_eq((int)i, (int)macStart);
                    byte ended   = wp_ct_int_mask_lt((int)i, (int)macEnd);
                    unsigned char b = rec[i];

                    inMac |= started;
                    inMac &= ended;
                    rotateOff |= j & (size_t)started;
                    rotatedMac[j++] |= b & inMac;
                    j &= (size_t)wp_ct_int_mask_lt((int)j, (int)macSize);
                }

                /* Cache-line-aware un-rotation: always load from both
                 * 32-byte halves and ct-select to avoid leaking
                 * rotateOff through cache access patterns. Same
                 * technique as OpenSSL's CBC_MAC_ROTATE_IN_PLACE. */
                for (i = 0; i < macSize; i++) {
                    char aux1 = rotatedMac[rotateOff & ~32];
                    char aux2 = rotatedMac[rotateOff | 32];
                    byte eqMask = wp_ct_int_mask_eq(
                        (int)(rotateOff & ~32), (int)rotateOff);
                    unsigned char real = wp_ct_byte_mask_sel(
                        eqMask, (byte)aux1, (byte)aux2);
                    byte goodMask = (byte)(good & 0xff);

                    ctx->tlsmac[i] = wp_ct_byte_mask_sel(goodMask, real,
                                                        randMac[i]);
                    rotateOff++;
                    rotateOff &= (size_t)wp_ct_int_mask_lt(
                        (int)rotateOff, (int)macSize);
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES block encryption.
 *
 * @param [in]  ctx      AES block context object.
 * @param [out] out      Buffer to hold encrypted data.
 * @param [out] outLen   Length of data encrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_final_enc(wp_AesBlockCtx *ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;
    size_t oLen = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_final_enc");

    if (ctx->pad) {
        size_t i;
        unsigned char pad = (unsigned char)(AES_BLOCK_SIZE - ctx->bufSz);

        for (i = ctx->bufSz; i < AES_BLOCK_SIZE; i++) {
            ctx->buf[i] = pad;
        }
        ctx->bufSz = AES_BLOCK_SIZE;
    }
    else if (ctx->bufSz != 0) {
        ok = 0;
    }

    if (ok && (ctx->bufSz == AES_BLOCK_SIZE)) {
        if (outSize < AES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok && !wp_aes_block_doit(ctx, out, ctx->buf, AES_BLOCK_SIZE)) {
            ok = 0;
        }
        if (ok) {
            oLen = AES_BLOCK_SIZE;
        }
    }

    if (ok) {
        ctx->bufSz = 0;
        *outLen = oLen;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES block decryption.
 *
 * @param [in]  ctx      AES block context object.
 * @param [out] out      Buffer to hold decrypted data.
 * @param [out] outLen   Length of data decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_final_dec(wp_AesBlockCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_final_dec");

    if (ctx->pad) {
        if (ctx->bufSz != AES_BLOCK_SIZE) {
            ok = 0;
        }
    }
    else if (ctx->bufSz != 0) {
        ok = 0;
    }

    if (ok && (ctx->bufSz > 0) &&
        (!wp_aes_block_doit(ctx, ctx->buf, ctx->buf, AES_BLOCK_SIZE))) {
        ok = 0;
    }

    if (ok && ctx->pad) {
        unsigned char pad;

        pad = ctx->buf[AES_BLOCK_SIZE - 1];
        if ((pad == 0) || (pad > AES_BLOCK_SIZE)) {
            ok = 0;
        }
        if (ok) {
            unsigned char len = AES_BLOCK_SIZE;
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
        XMEMSET(ctx->buf, 0, AES_BLOCK_SIZE);
        *outLen = ctx->bufSz;
        ctx->bufSz = 0;
    }
    else {
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize AES block encryption/decryption.
 *
 * @param [in]  ctx      AES block context object.
 * @param [out] out      Buffer to hold encrypted/decrypted data.
 * @param [out] outLen   Length of data encrypted/decrypted in bytes.
 * @param [in]  outSize  Size of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_final(wp_AesBlockCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_final");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok) {
        if (ctx->enc) {
            ok = wp_aes_block_final_enc(ctx, out, outLen, outSize);
        }
        else {
            ok = wp_aes_block_final_dec(ctx, out, outLen, outSize);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * One-shot encryption/decryption operation.
 *
 * @param [in]  ctx      AES block context object.
 * @param [out] out      Buffer to hold encrypted/decrypted result.
 * @param [out] outLen   Length of encrypted/decrypted data in bytes.
 * @param [in]  outSize  Size of output buffer in bytes.
 * @param [in]  in       Data to encrypt/decrypt.
 * @param [in]  inLen    Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_cipher(wp_AesBlockCtx* ctx, unsigned char* out,
    size_t* outLen, size_t outSize, const unsigned char* in, size_t inLen)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_cipher");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < inLen)) {
        ok = 0;
    }
    /* NULL in, NULL out, 0 len is OK */
    if (ok && (out != NULL && in != NULL && inLen != 0) &&
            !wp_aes_block_doit(ctx, out, in, inLen)) {
        ok = 0;
    }
    if (ok) {
        *outLen = inLen;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put values from the AES block context object into parameters objects.
 *
 * @param [in]      ctx     AES block context object.
 * @param [in, out] params  Array of parameters objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_get_ctx_params(wp_AesBlockCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_get_ctx_params");

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
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into AES block context object.
 *
 * @param [in, out] ctx     AES block context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_aes_block_set_ctx_params(wp_AesBlockCtx *ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_AES, "wp_aes_block_set_ctx_params");

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
        if (ok) {
            const OSSL_PARAM *pmac = OSSL_PARAM_locate_const(params,
                                         OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
            if (pmac != NULL) {
                if (!OSSL_PARAM_get_size_t(pmac, &ctx->tlsmacsize)) {
                    ok = 0;
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_AES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize the AES block context object.
 *
 * @param [in, out] ctx      AES block context object.
 * @param [in]      kBits    Number of bits in a valid key.
 * @param [in]      ivBits   Number of bits in a valid IV. 0 indicates no IV.
 * @param [in]      mode     AES block mode: ECB or CBC.
 * @return  1 on success.
 * @return  0 on failure.
 */
static void wp_aes_block_init_ctx(wp_AesBlockCtx* ctx, size_t kBits,
    size_t ivBits, unsigned int mode)
{
    ctx->pad = 1;
    ctx->keyLen = ((kBits) / 8);
    ctx->ivLen = ((ivBits) / 8);
    ctx->mode = mode;
}

/** Implement the get params API for a block cipher. */
#define IMPLEMENT_AES_BLOCK_GET_PARAMS(lcmode, UCMODE, kBits, ivBits)          \
/**                                                                            \
 * Get the values from the AES block context for the parameters.               \
 *                                                                             \
 * @param [in, out] params  Array of parameters to retrieve.                   \
 * @return 1 on success.                                                       \
 * @return 0 on failure.                                                       \
 */                                                                            \
static int wp_aes_##kBits##_##lcmode##_get_params(OSSL_PARAM params[])         \
{                                                                              \
    return wp_aes_block_get_params(params, EVP_CIPH_##UCMODE##_MODE, kBits,    \
        ivBits);                                                               \
}

/** Implement the new context API for a block cipher. */
#define IMPLEMENT_AES_BLOCK_NEWCTX(lcmode, UCMODE, kBits, ivBits)              \
/**                                                                            \
 * Create a new block cipher context object.                                   \
 *                                                                             \
 * @param [in] provCtx  Provider context object.                               \
 * @return  NULL on failure.                                                   \
 * @return  AEAD context object on success.                                    \
 */                                                                            \
static wp_AesBlockCtx* wp_aes_block_##kBits##_##lcmode##_newctx(               \
    WOLFPROV_CTX *provCtx)                                                     \
{                                                                              \
    wp_AesBlockCtx *ctx = NULL;                                                \
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        ctx->provCtx = provCtx;                                               \
        wp_aes_block_init_ctx(ctx, kBits, ivBits, EVP_CIPH_##UCMODE##_MODE);   \
    }                                                                          \
    return ctx;                                                                \
}

/** Implement the dispatch table for a block cipher. */
#define IMPLEMENT_AES_BLOCK_DISPATCH(mode, kBits, ivBits)                      \
const OSSL_DISPATCH wp_aes##kBits##mode##_functions[] = {                      \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
                              (DFUNC)wp_aes_block_##kBits##_##mode##_newctx }, \
    { OSSL_FUNC_CIPHER_FREECTX,          (DFUNC)wp_aes_block_freectx        }, \
    { OSSL_FUNC_CIPHER_DUPCTX,           (DFUNC)wp_aes_block_dupctx         }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,     (DFUNC)wp_aes_block_einit          }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,     (DFUNC)wp_aes_block_dinit          }, \
    { OSSL_FUNC_CIPHER_UPDATE,           (DFUNC)wp_aes_block_update         }, \
    { OSSL_FUNC_CIPHER_FINAL,            (DFUNC)wp_aes_block_final          }, \
    { OSSL_FUNC_CIPHER_CIPHER,           (DFUNC)wp_aes_block_cipher         }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
                              (DFUNC)wp_aes_##kBits##_##mode##_get_params   }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,   (DFUNC)wp_aes_block_get_ctx_params }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,   (DFUNC)wp_aes_block_set_ctx_params }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,  (DFUNC)wp_cipher_gettable_params   }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                              (DFUNC)wp_cipher_gettable_ctx_params          }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                              (DFUNC)wp_cipher_settable_ctx_params          }, \
    { 0, NULL }                                                                \
};

/** Implements the functions calling base functions for a block cipher. */
#define IMPLEMENT_AES_BLOCK(lcmode, UCMODE, kBits, ivBits)                     \
IMPLEMENT_AES_BLOCK_GET_PARAMS(lcmode, UCMODE, kBits, ivBits)                  \
IMPLEMENT_AES_BLOCK_NEWCTX(lcmode, UCMODE, kBits, ivBits)                      \
IMPLEMENT_AES_BLOCK_DISPATCH(lcmode, kBits, ivBits)

#ifdef WP_HAVE_AESCBC

/*
 * AES CBC
 */

/** wp_aes256cbc_functions */
IMPLEMENT_AES_BLOCK(cbc, CBC, 256, 128)
/** wp_aes192cbc_functions */
IMPLEMENT_AES_BLOCK(cbc, CBC, 192, 128)
/** wp_aes128cbc_functions */
IMPLEMENT_AES_BLOCK(cbc, CBC, 128, 128)

#endif /* WP_HAVE_AESCBC */

#ifdef WP_HAVE_AESECB

/*
 * AES ECB
 */

/** wp_aes256ecb_functions */
IMPLEMENT_AES_BLOCK(ecb, ECB, 256, 0)
/** wp_aes192ecb_functions */
IMPLEMENT_AES_BLOCK(ecb, ECB, 192, 0)
/** wp_aes128ecb_functions */
IMPLEMENT_AES_BLOCK(ecb, ECB, 128, 0)

#endif /* WP_HAVE_AESECB */

#endif /* WP_HAVE_AESCBC || WP_HAVE_AESECB */

