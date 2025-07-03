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

    if (params != NULL) {
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_MODE);
            if ((p != NULL) && (p->data != NULL)) {
                const char* mode = NULL;
                if (!OSSL_PARAM_get_utf8_string_ptr(p, &mode)) {
                    ok = 0;
                }
                if (ok && (mode != NULL)) {
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
                if (ok && digest != NULL) {
                    XMEMSET(ctx->digest, 0, sizeof(ctx->digest));
                    XSTRNCPY(ctx->digest, digest, sizeof(ctx->digest)-1);
                }
                else {
                    ok = 0;
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
                if (ok && cipher != NULL) {
                    XMEMSET(ctx->cipher, 0, sizeof(ctx->cipher));
                    XSTRNCPY(ctx->cipher, cipher, sizeof(ctx->cipher)-1);
                }
                else {
                    ok = 0;
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
    c[3] =  (byte)(wc_u32        & 0xff);
#elif defined(LITTLE_ENDIAN_ORDER)
    *(word32*)c = ByteReverseWord32(wc_u32);
#else
    *(word32*)c = wc_u32;
#endif
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
    word32 bei = 0;
    word32 beL = 0;
    size_t k_i_len = 0;
    size_t written = 0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *macCtx = NULL;
    EVP_MAC_CTX *macCtxOrig = NULL;
    unsigned char k_i[WP_MAX_MAC_SIZE];
    unsigned char zero = 0;
    OSSL_PARAM macParams[2];

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

    /* KDF feedback mode as defined in SP 800-108 5.2 */
    if (ok) {
        if (ctx->mac == WP_MAC_TYPE_CMAC) {
            mac = EVP_MAC_fetch(ctx->provCtx->libCtx, "CMAC", NULL);
        }
        else if (ctx->mac == WP_MAC_TYPE_HMAC) {
            mac = EVP_MAC_fetch(ctx->provCtx->libCtx, "HMAC", NULL);
        }
        else {
            ok = 0;
        }
        if (mac == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        macCtxOrig = EVP_MAC_CTX_new(mac);
        if (macCtxOrig == NULL) {
            ok = 0;
        }
    }
    /* Load keying material Ki */
    if (ok) {
        if (ctx->mac == WP_MAC_TYPE_CMAC) {
            macParams[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                ctx->cipher, XSTRLEN(ctx->cipher));
            macParams[1] = OSSL_PARAM_construct_end();
        }
        else if (ctx->mac == WP_MAC_TYPE_HMAC) {
            macParams[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                ctx->digest, XSTRLEN(ctx->digest));
            macParams[1] = OSSL_PARAM_construct_end();
        }
        if (ok && EVP_MAC_CTX_set_params(macCtxOrig, macParams) <= 0) {
            ok = 0;
        }
        if (ok && EVP_MAC_init(macCtxOrig, ctx->key, ctx->keySz, NULL) <= 0) {
            ok = 0;
        }
    }
    if (ok) {
        h = EVP_MAC_CTX_get_mac_size(macCtxOrig);
        if (h <= 0 || h > WP_MAX_MAC_SIZE) {
            ok = 0;
        }
    }
    if (ok) {
        /* 3. K(0) := IV */
        if (ctx->ivLen > WP_MAX_MAC_SIZE) {
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
        macCtx = EVP_MAC_CTX_dup(macCtxOrig);
        if (macCtx == NULL) {
            ok = 0;
            break;
        }
        if (ctx->mode == WP_KDF_MODE_FEEDBACK) {
            /* Process K(i-1) */
            if (EVP_MAC_update(macCtx, k_i, k_i_len) <= 0) {
                ok = 0;
                break;
            }
        }
        /* Process [i]2 */
        if (EVP_MAC_update(macCtx, (const unsigned char *)&bei, sizeof(bei)) <= 0) {
            ok = 0;
            break;
        }
        /* Process Label */
        if (EVP_MAC_update(macCtx, ctx->label, ctx->labelLen) <= 0) {
            ok = 0;
            break;
        }
        /* Process 0x00 */
        if (EVP_MAC_update(macCtx, (const unsigned char *)&zero, 1) <= 0) {
            ok = 0;
            break;
        }
        /* Process Context */
        if (EVP_MAC_update(macCtx, ctx->context, ctx->contextLen) <= 0) {
            ok = 0;
            break;
        }
        /* Process [L]2 */
        if (EVP_MAC_update(macCtx, (const unsigned char *)&beL, sizeof(beL)) <= 0) {
            ok = 0;
            break;
        }
        /* Finalize MAC to yield Ki */
        k_i_len = (size_t)h;
        if (EVP_MAC_final(macCtx, k_i, &k_i_len, k_i_len) <= 0) {
            ok = 0;
            break;
        }
        /* result(i) := result(i-1) || K(i)
         * KO := the leftmost L bits of result(n) */
        if ((keyLen - written) < k_i_len) {
            XMEMCPY(key + written, k_i, (keyLen - written));
            written += (keyLen - written);
        }
        else {
            XMEMCPY(key + written, k_i, k_i_len);
            written += k_i_len;
        }
        EVP_MAC_CTX_free(macCtx);
        macCtx = NULL;
    }

    if (macCtxOrig != NULL) {
        EVP_MAC_CTX_free(macCtxOrig);
    }
    if (macCtx != NULL) {
        EVP_MAC_CTX_free(macCtx);
    }
    if (mac != NULL) {
        EVP_MAC_free(mac);
    }
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
