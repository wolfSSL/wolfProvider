/* wp_kbkdf.c
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

/* KDF modes */
#define WP_KDF_MODE_COUNTER  0
#define WP_KDF_MODE_FEEDBACK 1
#define WP_KDF_MODE_PIPELINE 2

#define WP_MAX_MAC_SIZE     64

/** Base set of parameters settable against context for KBKDF. */
#define WP_KBKDF_BASE_SETTABLES                                          \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),         \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),             \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),               \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),              \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),                \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),             \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0)

/**
 * The KBKDF context structure.
 */
typedef struct wp_KbkdfCtx {
    /** wolfSSL provider context. */
    WOLFPROV_CTX* provCtx;

#ifdef WP_HAVE_HMAC
    Hmac hmacCtx;
    enum wc_HashType hashType;
#endif
#ifdef WP_HAVE_CMAC
    Cmac cmacCtx;
#endif

    /** Key for KDF. */
    unsigned char* key;
    /** Size of key in bytes. */
    size_t keySz;

    /** Mode and parameters */
    int mode;
    int mac;
    /** Cipher name */
    char cipher[16];
    /** Digest name */
    char digest[16];

    /** Label for KBKDF. */
    unsigned char* label;
    /** Size of label in bytes. */
    size_t labelLen;
    /** Context for KBKDF. */
    unsigned char* context;
    /** Size of context in bytes. */
    size_t contextLen;
    /** IV for KBKDF. */
    unsigned char* iv;
    /** Size of IV in bytes. */
    size_t ivLen;
} wp_KbkdfCtx;

/**
 * Create a new KBKDF context object.
 *
 * @param [in] provCtx  wolfProvider context object.
 * @return  NULL on failure.
 * @return  KBKDF context object on success.
 */
static wp_KbkdfCtx* wp_kdf_kbkdf_new(WOLFPROV_CTX* provCtx)
{
    wp_KbkdfCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Clear KBKDF context object.
 *
 * @param [in, out] ctx  KBKDF context object.
 */
static void wp_kdf_kbkdf_clear(wp_KbkdfCtx* ctx)
{
    if (ctx != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->keySz);
        OPENSSL_free(ctx->label);
        OPENSSL_free(ctx->context);
        OPENSSL_free(ctx->iv);
    }
}

/**
 * Free the KBKDF context object.
 *
 * @param [in, out] ctx  KBKDF context object.
 */
static void wp_kdf_kbkdf_free(wp_KbkdfCtx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_kbkdf_clear(ctx);
        OPENSSL_free(ctx);
    }
}

/**
 * Reset KBKDF context object.
 *
 * Disposes of allocated data.
 *
 * @param [in, out] ctx  KBKDF context object.
 */
static void wp_kdf_kbkdf_reset(wp_KbkdfCtx* ctx)
{
    if (ctx != NULL) {
        WOLFPROV_CTX* provCtx = ctx->provCtx;
        wp_kdf_kbkdf_clear(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

/**
 * Set the KBKDF context parameters.
 *
 * @param [in, out] ctx     KBKDF context object.
 * @param [in]      params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_kbkdf_set_ctx_params(wp_KbkdfCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kdf_kbkdf_set_ctx_params");

    if (params != NULL) {
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_MODE);
            if ((p != NULL) && (p->data != NULL)) {
                const char* mode = NULL;
                if (!OSSL_PARAM_get_utf8_string_ptr(p, &mode)) {
                    ok = 0;
                }
                if (ok) {
                    if (XSTRCMP(mode, "FEEDBACK") == 0) {
                        ctx->mode = WP_KDF_MODE_FEEDBACK;
                    }
                    else {
                        ok = 0;
                    }
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_DIGEST);
            if ((p != NULL) && (p->data != NULL)) {
                const char* digest = NULL;
                if (!OSSL_PARAM_get_utf8_string_ptr(p, &digest)) {
                    ok = 0;
                }
                if (ok) {
                    XMEMSET(ctx->digest, 0, sizeof(ctx->digest));
                    XSTRNCPY(ctx->digest, digest, sizeof(ctx->digest)-1);
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_CIPHER);
            if ((p != NULL) && (p->data != NULL)) {
                const char* cipher = NULL;
                if (!OSSL_PARAM_get_utf8_string_ptr(p, &cipher)) {
                    ok = 0;
                }
                if (ok) {
                    XMEMSET(ctx->cipher, 0, sizeof(ctx->cipher));
                    XSTRNCPY(ctx->cipher, cipher, sizeof(ctx->cipher)-1);
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
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_SEED);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_clear_free(ctx->iv, ctx->ivLen);
                ctx->iv = NULL;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->iv, 0,
                        &ctx->ivLen)) {
                    ok = 0;
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_SALT);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_free(ctx->label);
                ctx->label = NULL;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->label, 0,
                        &ctx->labelLen)) {
                    ok = 0;
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_INFO);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_free(ctx->context);
                ctx->context = NULL;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->context, 0,
                        &ctx->contextLen)) {
                    ok = 0;
                }
            }
        }

        if (ok) {
            const char* macName = NULL;
            if (!wp_params_get_utf8_string_ptr(params, OSSL_KDF_PARAM_MAC,
                    &macName)) {
                ok = 0;
            }
            if (ok && (macName != NULL)) {
                if (XSTRCMP(macName, "HMAC") == 0) {
                    ctx->mac = WP_MAC_TYPE_HMAC;
                }
                else if (XSTRCMP(macName, "CMAC") == 0) {
                    ctx->mac = WP_MAC_TYPE_CMAC;
                }
                else {
                    ok = 0;
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the KBKDF context parameters.
 *
 * @param [in]      ctx     KBKDF context object.
 * @param [in, out] params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_kbkdf_get_ctx_params(wp_KbkdfCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kdf_kbkdf_get_ctx_params");

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, ctx->keySz)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters that can be set in the KBKDF context.
 *
 * @param [in] ctx      KBKDF context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_kbkdf_settable_ctx_params(wp_KbkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_kbkdf_supported_settable_ctx_params[] = {
        WP_KBKDF_BASE_SETTABLES,
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kbkdf_supported_settable_ctx_params;
}

/**
 * Returns the parameters that can be retrieved from the KBKDF context.
 *
 * @param [in] ctx      KBKDF context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_kbkdf_gettable_ctx_params(wp_KbkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_kbkdf_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kbkdf_supported_gettable_ctx_params;
}

/* We are not guaranteed to have these available from wolfssl, so implement
 * them here */
static void wp_c32toa(word32 wc_u32, byte* c) {
#ifdef WOLFSSL_USE_ALIGN
    c[0] = (byte)((wc_u32 >> 24) & 0xff);
    c[1] = (byte)((wc_u32 >> 16) & 0xff);
    c[2] = (byte)((wc_u32 >>  8) & 0xff);
    c[3] = (byte) (wc_u32 &        0xff);
#elif defined(LITTLE_ENDIAN_ORDER)
    *(word32*)c = ByteReverseWord32(wc_u32);
#else
    *(word32*)c = wc_u32;
#endif
}

#ifdef WP_HAVE_HMAC
#define WP_MAX_HASH_BLOCK_SIZE 128

static int wp_kbkdf_init_hmac(wp_KbkdfCtx* ctx, unsigned char* key,
    size_t keyLen)
{
    int ok = 1;
    int rc = 0;
    unsigned char localKey[WP_MAX_HASH_BLOCK_SIZE];
    word32 localKeyLen = 0;
    word32 blockSize = wc_HashGetBlockSize(ctx->hashType);

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kbkdf_init_hmac");

    if (keyLen < blockSize) {
        /* wolfSSL FIPS needs a key that is at least block size in length with
         * the unused parts zeroed out.
         */
        XMEMSET(localKey + keyLen, 0, blockSize - keyLen);
        localKeyLen = blockSize;
    }
    else {
        localKeyLen = (word32)keyLen;
    }

    if (ok) {
        XMEMCPY(localKey, key, keyLen);
        rc = wc_HmacSetKey(&ctx->hmacCtx, ctx->hashType, localKey,
            localKeyLen);
        if (rc != 0) {
            WOLFPROV_MSG(WP_LOG_KDF, "wc_HmacSetKey failed with rc=%d", rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    /* Use rc style return */
    return (ok == 1) ? 0 : -1;
}
#endif /* ifdef WP_HAVE_HMAC */

static int wp_kbkdf_init_mac(wp_KbkdfCtx* ctx, unsigned char* key,
    size_t keyLen)
{
    int ok = 1;
    int rc = 0;

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kbkdf_init_mac");

    switch(ctx->mac) {
#ifdef WP_HAVE_HMAC
        case WP_MAC_TYPE_HMAC:
            rc = wp_kbkdf_init_hmac(ctx, key, keyLen);
            break;
#endif
#ifdef WP_HAVE_CMAC
        case WP_MAC_TYPE_CMAC:
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
            rc = wc_InitCmac_ex(&ctx->cmacCtx, key, (word32)keyLen, WC_CMAC_AES, NULL,
                NULL, INVALID_DEVID);
    #else
            rc = wc_InitCmac_ex(&ctx->cmacCtx, key, (word32)keyLen, WC_CMAC_AES, NULL);
    #endif
            if (rc != 0) {
                WOLFPROV_MSG(WP_LOG_KDF, "wc_InitCmac_ex failed with rc=%d", rc);
            }
            break;
#endif
        default:
            rc = -1;
            (void)key;
            (void)keyLen;
    }

    if (rc != 0) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_kbkdf_get_mac_size(wp_KbkdfCtx* ctx)
{
    switch(ctx->mac) {
#ifdef WP_HAVE_HMAC
        case WP_MAC_TYPE_HMAC:
            ctx->hashType =
                    wp_name_to_wc_hash_type(ctx->provCtx->libCtx,
                        ctx->digest, NULL);
            return wc_HmacSizeByType(ctx->hashType);
#endif
#ifdef WP_HAVE_CMAC
        case WP_MAC_TYPE_CMAC:
            return AES_BLOCK_SIZE;
#endif
        default:
            return -1;
    }
}

static int wp_kbkdf_mac_update(wp_KbkdfCtx* ctx, const unsigned char *data,
    size_t dataLen)
{
    int ok = 1;
    int rc = 0;

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kbkdf_mac_update");

    switch(ctx->mac) {
#ifdef WP_HAVE_HMAC
        case WP_MAC_TYPE_HMAC:
            rc = wc_HmacUpdate(&ctx->hmacCtx, data, (word32)dataLen);
            break;
#endif
#ifdef WP_HAVE_CMAC
        case WP_MAC_TYPE_CMAC:
            rc = wc_CmacUpdate(&ctx->cmacCtx, data, (word32)dataLen);
            break;
#endif
        default:
            rc = -1;
    }

    if (rc != 0) {
        WOLFPROV_MSG(WP_LOG_KDF, "wc_HmacUpdate/wc_CmacUpdate failed with rc=%d", rc);
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static void wp_kbkdf_mac_free(wp_KbkdfCtx* ctx)
{
    int ret = 0;
    switch(ctx->mac) {
#ifdef WP_HAVE_HMAC
        case WP_MAC_TYPE_HMAC:
            wc_HmacFree(&ctx->hmacCtx);
            break;
#endif
#ifdef WP_HAVE_CMAC
        case WP_MAC_TYPE_CMAC:
    #ifndef HAVE_FIPS
            ret = wc_CmacFree(&ctx->cmacCtx);
    #endif
            break;
#endif
    }

    (void)ret;
}

static int wp_kbkdf_mac_final(wp_KbkdfCtx* ctx, unsigned char *out,
    size_t *outLen, size_t outSize)
{
    int ok = 1;
    int rc = 0;
    word32 outSz;

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kbkdf_mac_final");

    (void)outSz;

    switch(ctx->mac) {
#ifdef WP_HAVE_HMAC
        case WP_MAC_TYPE_HMAC:
            rc = wc_HmacFinal(&ctx->hmacCtx, out);
            if (rc != 0) {
                WOLFPROV_MSG(WP_LOG_KDF, "wc_HmacFinal failed with rc=%d", rc);
                ok = 0;
            }
            if (ok) {
                *outLen = wc_HmacSizeByType(ctx->hashType);
            }
            break;
#endif
#ifdef WP_HAVE_CMAC
        case WP_MAC_TYPE_CMAC:
            outSz = (word32)outSize;
            rc = wc_CmacFinal(&ctx->cmacCtx, out, &outSz);
            if (rc != 0) {
                WOLFPROV_MSG(WP_LOG_KDF, "wc_CmacFinal failed with rc=%d", rc);
                ok = 0;
            }
            if (ok) {
                *outLen = outSz;
            }
            break;
#endif
        default:
            ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Derive a key using KBKDF.
 *
 * @param [in, out] ctx     KBKDF context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_kbkdf_derive(wp_KbkdfCtx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;
    int i = 0;
    int h = 0;
    int toWrite = 0;
    word32 bei = 0;
    word32 beL = 0;
    size_t k_i_len = 0;
    size_t written = 0;
    unsigned char k_i[WP_MAX_MAC_SIZE];
    unsigned char zero = 0;

    WOLFPROV_ENTER(WP_LOG_KDF, "wp_kdf_kbkdf_derive");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_kdf_kbkdf_set_ctx_params(ctx, params))) {
        ok = 0;
    }
    if (ok && (ctx->key == NULL)) {
        ok = 0;
    }
    if (ok && (keyLen == 0)) {
        ok = 0;
    }
    /* KDF as defined in SP 800-108 */
    if (ok) {
        h = (int)wp_kbkdf_get_mac_size(ctx);
        if (h <= 0 || h > WP_MAX_MAC_SIZE) {
            ok = 0;
        }
    }
    if (ok) {
        /* 3. K(0) := IV */
        if (ctx->ivLen > sizeof(k_i)) {
            ok = 0;
        }
        else {
            XMEMCPY(k_i, ctx->iv, ctx->ivLen);
            k_i_len = ctx->ivLen;
            /* Prep [L]2 */
            wp_c32toa((word32)(keyLen * 8), (byte *)&beL);
        }
    }
    /* For KDF Counter, Compute:
     * K(i) := PRF (KI, [i]2 || Label || 0x00 || Context || [L]2)
     * For KDF Feedback, Compute:
     * K(i) :=
     *   PRF (KI, K(i-1) {|| [i]2 } || Label || 0x00 || Context || [L]2) */
    for (i = 1; ok && written < keyLen; i++) {
        /* Prep [i]2 */
        wp_c32toa((word32)i, (byte *)&bei);
        ok = wp_kbkdf_init_mac(ctx, ctx->key, ctx->keySz);
        if (!ok) {
            break;
        }
        if (ctx->mode == WP_KDF_MODE_FEEDBACK) {
            /* Process K(i-1) */
            ok = wp_kbkdf_mac_update(ctx, k_i, k_i_len);
            if (!ok) {
                break;
            }
        }
        /* Process [i]2 */
        ok = wp_kbkdf_mac_update(ctx, (const unsigned char *)&bei, sizeof(bei));
        if (!ok) {
            break;
        }
        /* Process Label */
        ok = wp_kbkdf_mac_update(ctx, ctx->label, ctx->labelLen);
        if (!ok) {
            break;
        }
        /* Process 0x00 */
        ok = wp_kbkdf_mac_update(ctx, (const unsigned char *)&zero, 1);
        if (!ok) {
            break;
        }
        /* Process Context */
        ok = wp_kbkdf_mac_update(ctx, ctx->context, ctx->contextLen);
        if (!ok) {
            break;
        }
        /* Process [L]2 */
        ok = wp_kbkdf_mac_update(ctx, (const unsigned char *)&beL, sizeof(beL));
        if (!ok) {
            break;
        }
        /* Finalize MAC to yield Ki */
        k_i_len = (size_t)h;
        ok = wp_kbkdf_mac_final(ctx, k_i, &k_i_len, k_i_len);
        if (!ok) {
            break;
        }
        /* result(i) := result(i-1) || K(i)
         * KO := the leftmost L bits of result(n) */
        toWrite = MIN((int)(keyLen - written), (int)k_i_len);
        XMEMCPY(key + written, k_i, toWrite);
        written += toWrite;
        wp_kbkdf_mac_free(ctx);
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Dispatch table for KBKDF functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_kbkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (DFUNC)wp_kdf_kbkdf_new },
    { OSSL_FUNC_KDF_FREECTX, (DFUNC)wp_kdf_kbkdf_free },
    { OSSL_FUNC_KDF_RESET, (DFUNC)wp_kdf_kbkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (DFUNC)wp_kdf_kbkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (DFUNC)wp_kdf_kbkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (DFUNC)wp_kdf_kbkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (DFUNC)wp_kdf_kbkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (DFUNC)wp_kdf_kbkdf_get_ctx_params },
    { 0, NULL }
};
