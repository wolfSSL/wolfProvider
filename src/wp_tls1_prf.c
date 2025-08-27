/* wp_tls1_prf.c
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

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>


#ifdef WP_HAVE_TLS1_PRF

/** Maximum supported seed size. */
#define WP_MAX_SEED_SIZE        256


/**
 * TLS v1.1 and v1.2 PRF context structure.
 */
typedef struct wp_Tls1Prf_Ctx {
    /** wolfSSL provider context. */
    WOLFPROV_CTX* provCtx;

    /** Digest to use with HKDF. */
    enum wc_HashType mdType;

    /** Secret for PRF. */
    unsigned char* secret;
    /** Size of secret in bytes. */
    size_t secretSz;
    /** Label and seed for PRF. */
    unsigned char seed[WP_MAX_SEED_SIZE];
    /** Size of label and seed in bytes. */
    size_t seedSz;
} wp_Tls1Prf_Ctx;


/* Prototyped for the derive function. */
static int wp_kdf_tls1_prf_set_ctx_params(wp_Tls1Prf_Ctx* ctx,
    const OSSL_PARAM params[]);


/**
 * Create a new TLS1 PRF context object.
 *
 * @param [in] provCtx  wolfProvider context.
 * @return  NULL on failure.
 * @return  TLS1 PRF context object.
 */
static wp_Tls1Prf_Ctx* wp_kdf_tls1_prf_new(WOLFPROV_CTX* provCtx)
{
    wp_Tls1Prf_Ctx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Clear TLS1 PRF context object.
 *
 * @param [in, out] ctx  TLS1 PRF context object.
 */
static void wp_kdf_tls1_prf_clear(wp_Tls1Prf_Ctx* ctx)
{
    /* Clear and free secret. */
    if (ctx->secret != NULL) {
        OPENSSL_clear_free(ctx->secret, ctx->secretSz);
    }
    /* Clear seed - sensitive data. */
    OPENSSL_cleanse(ctx->seed, ctx->seedSz);
}

/**
 * Dispose of TLS1 PRF context object.
 *
 * @param [in, out] ctx  TLS1 PRF context object.
 */
static void wp_kdf_tls1_prf_free(wp_Tls1Prf_Ctx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_tls1_prf_clear(ctx);
        OPENSSL_free(ctx);
    }
}

/**
 * Reset TLS1 PRF context object.
 *
 * Disposes of allocated data.
 *
 * @param [in, out] ctx  TLS1 PRF context object.
 */
static void wp_kdf_tls1_prf_reset(wp_Tls1Prf_Ctx* ctx)
{
    if (ctx != NULL) {
        WOLFPROV_CTX* provCtx = ctx->provCtx;

        wp_kdf_tls1_prf_clear(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

/**
 * Derive key using TLS1 PRF algorithm.
 *
 * @param [in, out] ctx     TLS1 PRF context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Length of key to derive in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_tls1_prf_derive(wp_Tls1Prf_Ctx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_TLS1_PRF, "wp_kdf_tls1_prf_derive");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (!wp_kdf_tls1_prf_set_ctx_params(ctx, params)) {
        ok = 0;
    }
    if (ok && (ctx->mdType == WC_HASH_TYPE_NONE)) {
        ok = 0;
    }
    if (ok && (ctx->secret == NULL)) {
        ok = 0;
    }
    if (ok && (ctx->seedSz == 0)) {
        ok = 0;
    }
    if (ok && (keyLen == 0)) {
        ok = 0;
    }

    if (ok) {
        int rc;
        if (ctx->mdType == WC_HASH_TYPE_MD5_SHA) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_PRF_TLSv1(key, (word32)keyLen, ctx->secret,
                (word32)(ctx->secretSz), (byte*)"", 0, ctx->seed,
                (word32)(ctx->seedSz), NULL, INVALID_DEVID);
            PRIVATE_KEY_LOCK();
            if (rc != 0) {
                WOLFPROV_MSG(WP_LOG_KDF, "wc_PRF_TLSv1 failed with rc=%d", rc);
                ok = 0;
            }
        }
        else {
            PRIVATE_KEY_UNLOCK();
            rc = wc_PRF_TLS(key, (word32)keyLen, ctx->secret,
                (word32)(ctx->secretSz), (byte*)"", 0, ctx->seed,
                (word32)(ctx->seedSz), 1,
                ((ctx->mdType == WC_HASH_TYPE_SHA256) ? sha256_mac :
                                                        sha384_mac), NULL,
                INVALID_DEVID);
            PRIVATE_KEY_LOCK();
            if (rc != 0) {
                WOLFPROV_MSG(WP_LOG_KDF, "wc_PRF_TLS failed with rc=%d", rc);
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Find and set the combined seed parameters into the context.
 *
 * Purely additive.
 *
 * @param [in, out] ctx     TLS1 PRF context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_tls1_prf_get_seed(wp_Tls1Prf_Ctx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM *p;
    unsigned char* q = ctx->seed + ctx->seedSz;

    WOLFPROV_ENTER(WP_LOG_TLS1_PRF, "wp_kdf_tls1_prf_get_seed");

    /* Combine all the data in the seed parameters. */
    while (ok && ((p = OSSL_PARAM_locate_const(params,
            OSSL_KDF_PARAM_SEED)) != NULL)) {
        size_t sz = 0;

        if (p->data_size != 0 && p->data != NULL &&
            !OSSL_PARAM_get_octet_string(p, (void**)&q,
                WP_MAX_SEED_SIZE - ctx->seedSz, &sz)) {
            ok = 0;
        }
        else {
            ctx->seedSz += sz;
            q += sz;
        }
        params = p + 1;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
/**
 * Set the parameters into the TLS1 PRF context object.
 *
 * @param [in, out] ctx     TLS1 PRF context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_tls1_prf_set_ctx_params(wp_Tls1Prf_Ctx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_TLS1_PRF, "wp_kdf_tls1_prf_set_ctx_params");

    if (params != NULL) {
        if (!wp_params_get_digest(params, NULL, ctx->provCtx->libCtx,
                &ctx->mdType, NULL)) {
            ok = 0;
        }
        if (ok && (!wp_params_get_octet_string(params, OSSL_KDF_PARAM_SECRET,
                &ctx->secret, &ctx->secretSz, 1))) {
            ok = 0;
        }
        if (ok && (!wp_kdf_tls1_prf_get_seed(ctx, params))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}


/**
 * Returns the parameters to set against a TLS1 PRF context.
 *
 * @param [in] ctx      TLS1 PRF context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_tls1_prf_settable_ctx_params(
    wp_Tls1Prf_Ctx* ctx, WOLFPROV_CTX* provCtx)
{
    /** Parameters to set against a TLS1 PRF context. */
    static const OSSL_PARAM wp_kdf_tls1_prf_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kdf_tls1_prf_supported_settable_ctx_params;
}

/**
 * Retrieve the values of the parameters from the TLS1 PRF context object.
 *
 * @param [in]      ctx     TLS1 PRF context object.
 * @param [in, out] params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_tls1_prf_get_ctx_params(wp_Tls1Prf_Ctx* ctx,
    OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM *p;

    WOLFPROV_ENTER(WP_LOG_TLS1_PRF, "wp_kdf_tls1_prf_get_ctx_params");

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_size_t(p, MAX_SIZE_T)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters that can be retrieved from a TLS1 PRF context.
 *
 * @param [in] ctx      TLS1 PRF context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_tls1_prf_gettable_ctx_params(
    wp_Tls1Prf_Ctx* ctx, WOLFPROV_CTX* provCtx)
{
    /** Parameters that can be retrieved from a TLS1 PRF context. */
    static const OSSL_PARAM wp_kdf_tls1_prf_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kdf_tls1_prf_supported_gettable_ctx_params;
}

/** Dispatch table for TLS1 PRF functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_tls1_prf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,         (DFUNC)wp_kdf_tls1_prf_new                },
    { OSSL_FUNC_KDF_FREECTX,        (DFUNC)wp_kdf_tls1_prf_free               },
    { OSSL_FUNC_KDF_RESET,          (DFUNC)wp_kdf_tls1_prf_reset              },
    { OSSL_FUNC_KDF_DERIVE,         (DFUNC)wp_kdf_tls1_prf_derive             },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                                   (DFUNC)wp_kdf_tls1_prf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (DFUNC)wp_kdf_tls1_prf_set_ctx_params     },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                                   (DFUNC)wp_kdf_tls1_prf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (DFUNC)wp_kdf_tls1_prf_get_ctx_params     },
    { 0, NULL }
};

#endif /* WOLFSSL_HAVE_PRF */
