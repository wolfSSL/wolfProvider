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
#if !defined(HAVE_FIPS) || defined(WP_ALLOW_NON_FIPS)
/**
 * Data structure for DES3 ciphers that are block based.
 */
typedef struct wp_Des3BlockCtx {
    /** wolfSSL DES object.  */
    Des3 des3;

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
    if (ctx->tlsmacAlloced) {
        OPENSSL_free(ctx->tlsmac);
    }
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
        /* Safe byte-copy: Des3 owns no heap as used here (sync, no async
         * devId); async offload would need a deep copy. */
        XMEMCPY(dst, src, sizeof(*src));
        dst->tlsmac = NULL;
        dst->tlsmacAlloced = 0;
        /* Deep-copy tlsmac to avoid double-free between src and dst. */
        if (src->tlsmacAlloced && src->tlsmac != NULL) {
            dst->tlsmac = OPENSSL_malloc(src->tlsmacsize);
            if (dst->tlsmac == NULL) {
                /* dst->des3 aliases src's - must not wc_Des3Free it here. */
                OPENSSL_clear_free(dst, sizeof(*dst));
                dst = NULL;
            }
            else {
                XMEMCPY(dst->tlsmac, src->tlsmac, src->tlsmacsize);
                dst->tlsmacAlloced = 1;
            }
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_get_params");

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

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
        OSSL_PARAM_octet_ptr(OSSL_CIPHER_PARAM_TLS_MAC, NULL, 0),
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
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_init_iv");

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
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_Des3_SetIV", rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_init");

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
        if (wc_Des3_SetIV(&ctx->des3, ctx->iv) != 0) {
            ok = 0;
        }
    }

    if (ok && (key != NULL)) {
        if (keyLen != ctx->keyLen) {
            ok = 0;
        }
        if (ok) {
            int rc = wc_Des3_SetKey(&ctx->des3, key, iv,
                enc ? DES_ENCRYPTION : DES_DECRYPTION);
            if (rc != 0) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_Des3_SetKey", rc);
                ok = 0;
            }
        }
    }

    if (ok) {
        ok = wp_des3_block_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    int rc = 0;

    if (ctx->mode == EVP_CIPH_CBC_MODE) {
        while ((rc == 0) && (inLen > 0)) {
            /* Chunk must be block-aligned (DES3 block size = 8). */
            word32 chunk = (inLen > 0xFFFFFFF8U) ? 0xFFFFFFF8U : (word32)inLen;
            if (ctx->enc) {
                rc = wc_Des3_CbcEncrypt(&ctx->des3, out, in, chunk);
            }
            else {
                rc = wc_Des3_CbcDecrypt(&ctx->des3, out, in, chunk);
            }
            in += chunk;
            out += chunk;
            inLen -= chunk;
        }
        if (rc == 0) {
            XMEMCPY(ctx->iv, ctx->des3.reg, ctx->ivLen);
        }
    }
    else
    {
        rc = -1;
    }

    return rc == 0;
}

/**
 * Constant-time TLS CBC padding removal and MAC extraction after decryption.
 *
 * For ETM/no-MAC modes, strips the explicit IV and validates/removes padding.
 * For MtE, also extracts the MAC using a constant-time rotation pattern and
 * substitutes a random MAC on bad padding so no padding oracle is exposed.
 *
 * @param [in, out] ctx     DES3 block context object.
 * @param [in]      out     Decrypted output buffer.
 * @param [in]      oLen    Length of decrypted data in bytes.
 * @param [out]     outLen  Updated with length after padding/MAC removal.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_des3_block_tls_dec_record(wp_Des3BlockCtx *ctx,
    unsigned char *out, size_t oLen, size_t *outLen)
{
    int ok = 1;

    /* Buffer: [explicit_IV(BS)][payload][MAC(macsize)][padding(pad+1)].
     * Padding validation follows OpenSSL tls1_cbc_remove_padding_and_mac;
     * MAC extraction follows the ssl3_cbc_copy_mac rotation pattern. */
    unsigned char *rec;
    size_t recLen;
    size_t origRecLen;
    unsigned char padVal;
    size_t overhead;
    size_t toCheck;
    size_t good;
    size_t i, j;
    size_t macSize = ctx->tlsmacsize;

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_tls_dec_record");

    /* Free any previously allocated MAC */
    if (ctx->tlsmacAlloced) {
        OPENSSL_free(ctx->tlsmac);
        ctx->tlsmacAlloced = 0;
        ctx->tlsmac = NULL;
    }

    /* Below TLS 1.1 there is no explicit per-record IV, so stripping one
     * would discard payload. Reject rather than corrupt the record. */
    if (ctx->tls_version == SSL3_VERSION ||
        ctx->tls_version == TLS1_VERSION) {
        ok = 0;
    }

    if (ok && (macSize > EVP_MAX_MD_SIZE ||
        oLen < DES_BLOCK_SIZE + macSize + 1)) {
        ok = 0;
    }

    if (ok && macSize == 0) {
        /* ETM/no-MAC: record layer handled the MAC, so only strip the
         * explicit IV and validate+remove padding. */
        unsigned char *ivRec = out + DES_BLOCK_SIZE;
        size_t ivRecLen = oLen - DES_BLOCK_SIZE;
        unsigned char padV = ivRec[ivRecLen - 1];
        size_t gd = (size_t)0 - ((size_t)(
            wp_ct_int_mask_gte((int)ivRecLen, (int)padV + 1) & 1));
        size_t tc = 256;
        size_t d;
        if (tc > ivRecLen) {
            tc = ivRecLen;
        }

        for (i = 0; i < tc; i++) {
            byte m = wp_ct_int_mask_gte((int)padV, (int)i);
            unsigned char bv = ivRec[ivRecLen - 1 - i];
            gd &= ~((size_t)(m & (padV ^ bv)));
        }
        /* Collapse lower 8 bits to a full-width size_t mask. */
        d = (gd & 0xff) ^ 0xff;
        d |= (0 - d);
        d >>= (sizeof(size_t) * 8 - 1);
        gd = d - 1;
        ivRecLen -= gd & ((size_t)padV + 1);
        /* ETM/no-MAC: bad padding is a real error (no oracle concern). */
        if (gd == 0) {
            ok = 0;
            *outLen = 0;
        }
        else {
            *outLen = ivRecLen;
        }
    }
    else if (ok) {
        /* 64-byte aligned buffer for cache-line-aware MAC rotation */
        unsigned char rotatedMacBuf[64 + EVP_MAX_MD_SIZE];
        unsigned char *rotatedMac;
        unsigned char randMac[EVP_MAX_MD_SIZE];
        size_t macEnd;
        size_t macStart;
        size_t scanStart = 0;
        size_t diff;
        byte inMac;
        size_t rotateOff;

        /* Align rotatedMac to a 64-byte boundary so the whole MAC buffer
         * sits at known positions within one or two cache lines. */
        rotatedMac = rotatedMacBuf +
            ((0 - (size_t)rotatedMacBuf) & 63);

        /* For TLS 1.1+/DTLS: skip explicit IV */
        rec = out + DES_BLOCK_SIZE;
        recLen = oLen - DES_BLOCK_SIZE;
        origRecLen = recLen;

        padVal = rec[recLen - 1];
        overhead = macSize + (size_t)padVal + 1;

        /* CT overhead check: recLen >= overhead, folded into good mask. */
        good = (size_t)0 -
            ((size_t)(wp_ct_int_mask_gte((int)recLen, (int)overhead) & 1));

        /* Validate up to 256 padding bytes in constant time. */
        toCheck = 256;
        if (toCheck > recLen) {
            toCheck = recLen;
        }

        for (i = 0; i < toCheck; i++) {
            byte mask = wp_ct_int_mask_gte((int)padVal, (int)i);
            unsigned char b = rec[recLen - 1 - i];
            good &= ~((size_t)(mask & (padVal ^ b)));
        }
        /* Collapse lower 8 bits to a full-width size_t mask. */
        diff = (good & 0xff) ^ 0xff;
        diff |= (0 - diff);
        diff >>= (sizeof(size_t) * 8 - 1);
        good = diff - 1;

        recLen -= good & ((size_t)padVal + 1);

        macEnd = recLen;
        macStart = macEnd - macSize;

        recLen -= macSize;
        *outLen = recLen;

    #ifndef WP_SINGLE_THREADED
        if (wp_provctx_lock_rng(ctx->provCtx)) {
            if (wc_RNG_GenerateBlock(wp_provctx_get_rng(ctx->provCtx),
                                     randMac, (word32)macSize) != 0) {
                ok = 0;
            }
            wp_provctx_unlock_rng(ctx->provCtx);
        }
        else {
            /* Cannot safely use the RNG without the lock. */
            ok = 0;
        }
    #else
        if (wc_RNG_GenerateBlock(wp_provctx_get_rng(ctx->provCtx),
                                 randMac, (word32)macSize) != 0) {
            ok = 0;
        }
    #endif

        /* Only build the substitute MAC if RNG succeeded; otherwise randMac
         * is unset and must not be read. */
        if (ok) {
            ctx->tlsmac = OPENSSL_malloc(macSize);
            if (ctx->tlsmac == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            ctx->tlsmacAlloced = 1;

            /* Scan all bytes that could hold the MAC (position varies). */
            if (origRecLen > macSize + 255 + 1) {
                scanStart = origRecLen - (macSize + 255 + 1);
            }

            XMEMSET(rotatedMac, 0, EVP_MAX_MD_SIZE);
            inMac = 0;
            rotateOff = 0;
            for (i = scanStart, j = 0; i < origRecLen; i++) {
                byte started  = wp_ct_int_mask_eq((int)i, (int)macStart);
                byte notEnded = wp_ct_int_mask_lt((int)i, (int)macEnd);
                unsigned char b = rec[i];

                inMac |= started;
                inMac &= notEnded;
                rotateOff |= j & (size_t)started;
                rotatedMac[j++] |= b & inMac;
                j &= (size_t)wp_ct_int_mask_lt((int)j, (int)macSize);
            }

            /* Cache-line-aware un-rotation: load from both halves and
             * ct-select so rotateOff does not leak via cache access. */
            for (i = 0; i < macSize; i++) {
                byte aux1 = rotatedMac[rotateOff & ~32];
                byte aux2 = rotatedMac[rotateOff | 32];
                byte eqMask = wp_ct_int_mask_eq(
                    (int)(rotateOff & ~32), (int)rotateOff);
                unsigned char real = wp_ct_byte_mask_sel(
                    eqMask, aux1, aux2);
                byte goodMask = (byte)(good & 0xff);

                ctx->tlsmac[i] = wp_ct_byte_mask_sel(goodMask, real,
                                                    randMac[i]);
                rotateOff++;
                rotateOff &= (size_t)wp_ct_int_mask_lt(
                    (int)rotateOff, (int)macSize);
            }
        }
    }

    /* Report no output on any failure path, never a partial length. */
    if (!ok) {
        *outLen = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);

    return ok;
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
    unsigned char *outStart = out;

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_update");

    if ((ctx->tls_version > 0) && (ctx->enc)) {
        int i;
        unsigned char off = inLen % DES_BLOCK_SIZE;
        unsigned char pad = DES_BLOCK_SIZE - off - 1;
        if (outSize < inLen + pad + 1) {
            ok = 0;
        }
        if (ok) {
            for (i = off; i < DES_BLOCK_SIZE; i++) {
                out[inLen - off + i] = pad;
            }
            inLen += pad + 1;
        }
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
        ok = wp_des3_block_tls_dec_record(ctx, outStart, oLen, outLen);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_final_enc");

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
    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_final_dec");

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
        unsigned char invalid;
        unsigned char i;

        pad = ctx->buf[DES_BLOCK_SIZE - 1];
        invalid = wp_ct_byte_mask_eq(pad, 0) |
                  ~wp_ct_int_mask_gte(DES_BLOCK_SIZE, (int)pad);
        for (i = 0; i < DES_BLOCK_SIZE; i++) {
            unsigned char mask = wp_ct_int_mask_gte((int)i,
                DES_BLOCK_SIZE - (int)pad);
            invalid |= mask & wp_ct_byte_mask_ne(ctx->buf[i], pad);
        }
        if (invalid) {
            ok = 0;
        }
        else {
            ctx->bufSz = DES_BLOCK_SIZE - pad;
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

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_final");

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

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_cipher");

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

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_get_ctx_params");

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

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_DES, "wp_des3_block_set_ctx_params");

    if (params != NULL) {
        unsigned int val;
        int set;
        size_t macSz = ctx->tlsmacsize;

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
        if (ok && (!wp_params_get_size_t(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
                &macSz))) {
            ok = 0;
        }
        if (ok && (macSz != ctx->tlsmacsize)) {
            /* Any stored MAC was sized for the old value - drop it so tlsmac
             * is never shorter than tlsmacsize. */
            if (ctx->tlsmacAlloced) {
                OPENSSL_free(ctx->tlsmac);
                ctx->tlsmacAlloced = 0;
            }
            ctx->tlsmac = NULL;
            ctx->tlsmacsize = macSz;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_DES, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    if (wolfssl_prov_is_running()) {                                           \
        ctx = OPENSSL_zalloc(sizeof(*ctx));                                    \
    }                                                                          \
    if (ctx != NULL) {                                                         \
        wp_des3_block_init_ctx(ctx, kBits, ivBits, EVP_CIPH_##UCMODE##_MODE);  \
        ctx->provCtx = provCtx;                                                \
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

#else /* defined(HAVE_FIPS) && !defined(WP_ALLOW_NON_FIPS */

#define IMPLEMENT_DES3_BLOCK_NULL(mode)                                        \
const OSSL_DISPATCH wp_des3##mode##_functions[] = {                            \
    { OSSL_FUNC_CIPHER_NEWCTX,          (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_FREECTX,         (DFUNC)wp_des3_void                 }, \
    { OSSL_FUNC_CIPHER_DUPCTX,          (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,    (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,    (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_UPDATE,          (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_FINAL,           (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_CIPHER,          (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_GET_PARAMS,      (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,  (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,  (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (DFUNC)wp_des3_null                 }, \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
                              (DFUNC)wp_des3_null                           }, \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
                              (DFUNC)wp_des3_null                           }, \
    { 0, NULL }                                                                \
};
static int wp_des3_null(void) { return 0; }
static void wp_des3_void(void) {}

IMPLEMENT_DES3_BLOCK_NULL(cbc)

#endif
#endif /* WP_HAVE_DES3CBC */

