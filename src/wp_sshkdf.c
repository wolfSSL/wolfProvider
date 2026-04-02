/* wp_sshkdf.c
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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_SSHKDF

/**
 * The SSHKDF context structure.
 */
typedef struct wp_SshkdfCtx {
    /** wolfSSL provider context. */
    WOLFPROV_CTX* provCtx;

    /** Hash type for SSHKDF. */
    enum wc_HashType mdType;
    /** Length of digest output in bytes. */
    size_t mdLen;

    /** Shared secret K. */
    unsigned char* key;
    /** Size of shared secret in bytes. */
    size_t keySz;

    /** Exchange hash H. */
    unsigned char* xcghash;
    /** Size of exchange hash in bytes. */
    size_t xcghashSz;

    /** Session ID. */
    unsigned char* sessionId;
    /** Size of session ID in bytes. */
    size_t sessionIdSz;

    /** Key type character ('A'-'F'). */
    char type;
} wp_SshkdfCtx;

/**
 * Create a new SSHKDF context object.
 *
 * @param [in] provCtx  wolfProvider context object.
 * @return  NULL on failure.
 * @return  SSHKDF context object on success.
 */
static wp_SshkdfCtx* wp_kdf_sshkdf_new(WOLFPROV_CTX* provCtx)
{
    wp_SshkdfCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Clear SSHKDF context object.
 *
 * @param [in, out] ctx  SSHKDF context object.
 */
static void wp_kdf_sshkdf_clear(wp_SshkdfCtx* ctx)
{
    if (ctx != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->keySz);
        OPENSSL_clear_free(ctx->xcghash, ctx->xcghashSz);
        OPENSSL_clear_free(ctx->sessionId, ctx->sessionIdSz);
    }
}

/**
 * Free the SSHKDF context object.
 *
 * @param [in, out] ctx  SSHKDF context object.
 */
static void wp_kdf_sshkdf_free(wp_SshkdfCtx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_sshkdf_clear(ctx);
        OPENSSL_free(ctx);
    }
}

/**
 * Reset SSHKDF context object.
 *
 * Disposes of allocated data.
 *
 * @param [in, out] ctx  SSHKDF context object.
 */
static void wp_kdf_sshkdf_reset(wp_SshkdfCtx* ctx)
{
    if (ctx != NULL) {
        WOLFPROV_CTX* provCtx = ctx->provCtx;
        wp_kdf_sshkdf_clear(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

/**
 * Set the SSHKDF context parameters.
 *
 * @param [in, out] ctx     SSHKDF context object.
 * @param [in]      params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_sshkdf_set_ctx_params(wp_SshkdfCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_SSHKDF, "wp_kdf_sshkdf_set_ctx_params");

    if (params != NULL) {
        /* Get digest/hash type. */
        if (ok && !wp_params_get_digest(params, NULL,
                ctx->provCtx->libCtx, &ctx->mdType, &ctx->mdLen)) {
            ok = 0;
        }

        /* Get shared secret K. */
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params, OSSL_KDF_PARAM_KEY);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_clear_free(ctx->key, ctx->keySz);
                ctx->key = NULL;
                ctx->keySz = 0;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->key, 0,
                        &ctx->keySz)) {
                    ok = 0;
                }
            }
        }

        /* Get exchange hash H. */
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params,
                OSSL_KDF_PARAM_SSHKDF_XCGHASH);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_clear_free(ctx->xcghash, ctx->xcghashSz);
                ctx->xcghash = NULL;
                ctx->xcghashSz = 0;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->xcghash, 0,
                        &ctx->xcghashSz)) {
                    ok = 0;
                }
            }
        }

        /* Get session ID. */
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params,
                OSSL_KDF_PARAM_SSHKDF_SESSION_ID);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_clear_free(ctx->sessionId, ctx->sessionIdSz);
                ctx->sessionId = NULL;
                ctx->sessionIdSz = 0;
                if (!OSSL_PARAM_get_octet_string(p, (void**)&ctx->sessionId, 0,
                        &ctx->sessionIdSz)) {
                    ok = 0;
                }
            }
        }

        /* Get key type character ('A'-'F'). */
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM*)params,
                OSSL_KDF_PARAM_SSHKDF_TYPE);
            if (p != NULL) {
                const char* kdftype = NULL;

                if (!OSSL_PARAM_get_utf8_string_ptr(p, &kdftype)) {
                    ok = 0;
                }
                else if (kdftype == NULL || p->data_size != 1) {
                    ok = 0;
                }
                else if (kdftype[0] < 'A' || kdftype[0] > 'F') {
                    ok = 0;
                }
                else {
                    ctx->type = kdftype[0];
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_SSHKDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the SSHKDF context parameters.
 *
 * @param [in]      ctx     SSHKDF context object.
 * @param [in, out] params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_sshkdf_get_ctx_params(wp_SshkdfCtx* ctx,
    OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_SSHKDF, "wp_kdf_sshkdf_get_ctx_params");

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, SIZE_MAX)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_SSHKDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters that can be set in the SSHKDF context.
 *
 * @param [in] ctx      SSHKDF context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_sshkdf_settable_ctx_params(wp_SshkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_sshkdf_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_sshkdf_supported_settable_ctx_params;
}

/**
 * Returns the parameters that can be retrieved from the SSHKDF context.
 *
 * @param [in] ctx      SSHKDF context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_sshkdf_gettable_ctx_params(wp_SshkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_sshkdf_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_sshkdf_supported_gettable_ctx_params;
}

/**
 * Derive a key using SSHKDF (RFC 4253, Section 7.2).
 *
 * @param [in, out] ctx     SSHKDF context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_sshkdf_derive(wp_SshkdfCtx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    const unsigned char* rawKey;
    word32 rawKeySz;

    WOLFPROV_ENTER(WP_LOG_COMP_SSHKDF, "wp_kdf_sshkdf_derive");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_kdf_sshkdf_set_ctx_params(ctx, params))) {
        ok = 0;
    }
    if (ok && (ctx->mdType == WC_HASH_TYPE_NONE)) {
        ok = 0;
    }
    if (ok && (ctx->key == NULL)) {
        ok = 0;
    }
    if (ok && (ctx->xcghash == NULL)) {
        ok = 0;
    }
    if (ok && (ctx->sessionId == NULL)) {
        ok = 0;
    }
    if (ok && (ctx->type == 0)) {
        ok = 0;
    }
    if (ok && (keyLen > UINT32_MAX || ctx->keySz > UINT32_MAX ||
            ctx->xcghashSz > UINT32_MAX || ctx->sessionIdSz > UINT32_MAX)) {
        ok = 0;
    }

    if (ok) {
        rawKey = ctx->key;
        rawKeySz = (word32)ctx->keySz;

        /* The caller passes K in SSH mpint encoding (4-byte big-endian length
         * prefix, optional 0x00 padding byte, then value). wc_SSH_KDF() adds
         * its own mpint encoding internally, so strip the caller's encoding
         * to avoid double-encoding. */
        if (rawKeySz >= 4) {
            word32 mpintLen = ((word32)rawKey[0] << 24) |
                              ((word32)rawKey[1] << 16) |
                              ((word32)rawKey[2] << 8)  |
                              (word32)rawKey[3];
            if (mpintLen + 4 == rawKeySz && mpintLen > 0) {
                rawKey += 4;
                rawKeySz -= 4;
                /* Skip leading 0x00 padding if present (next byte has MSB
                 * set, indicating the padding was added for sign extension). */
                if (rawKeySz > 1 && rawKey[0] == 0x00 &&
                        (rawKey[1] & 0x80)) {
                    rawKey += 1;
                    rawKeySz -= 1;
                }
            }
        }

        PRIVATE_KEY_UNLOCK();
        rc = wc_SSH_KDF((byte)ctx->mdType, (byte)ctx->type,
            key, (word32)keyLen,
            rawKey, rawKeySz,
            ctx->xcghash, (word32)ctx->xcghashSz,
            ctx->sessionId, (word32)ctx->sessionIdSz);
        PRIVATE_KEY_LOCK();
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_COMP_SSHKDF, "wc_SSH_KDF", rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_SSHKDF, "wp_kdf_sshkdf_derive", ok);
    return ok;
}

/** Dispatch table for SSHKDF functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_sshkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (DFUNC)wp_kdf_sshkdf_new },
    { OSSL_FUNC_KDF_FREECTX, (DFUNC)wp_kdf_sshkdf_free },
    { OSSL_FUNC_KDF_RESET, (DFUNC)wp_kdf_sshkdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (DFUNC)wp_kdf_sshkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (DFUNC)wp_kdf_sshkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (DFUNC)wp_kdf_sshkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (DFUNC)wp_kdf_sshkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (DFUNC)wp_kdf_sshkdf_get_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_SSHKDF */
