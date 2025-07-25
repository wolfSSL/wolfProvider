/* wp_pbkdf2.c
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

#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#ifndef NO_PWDBASED

/** Base set of parameters settable against context  */
#define WP_PBKDF2_BASE_SETTABLES                                 \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),  \
    OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),      \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD, NULL, 0),   \
    OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),       \
    OSSL_PARAM_uint64(OSSL_KDF_PARAM_ITER, NULL)


/**
 * The PBKDF2 context structure.
 * Includes everything for PBKDF2.
 */
typedef struct wp_Pbkdf2Ctx {
    /** wolfSSL provider context. */
    WOLFPROV_CTX* provCtx;

    /** Digest to use with PBKDF2. */
    enum wc_HashType mdType;
    /** Digest to use with PBKDF2. */
    size_t mdLen;

    /** Password to derive from. */
    unsigned char *password;
    /** Size of password in bytes. */
    size_t passwordSz;
    /** Salt for KDF. */
    unsigned char *salt;
    /** Size of salt in bytes. */
    size_t saltSz;
    /** Number of iterations. */
    uint64_t iterations;
    /** Used for PKCS#5. */
    int pkcs5;
    /** PKCS12 key usage byte used in derivation. */
    int keyUse;
} wp_Pbkdf2Ctx;

/**
 * Create a new PBKDF2 context object.
 *
 * @param [in] provCtx  wolfProvider context object.
 * @return  NULL on failure.
 * @return  PBKDF2 context object.
 */
static wp_Pbkdf2Ctx* wp_kdf_pbkdf2_new(WOLFPROV_CTX* provCtx)
{
    wp_Pbkdf2Ctx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Clear PBKDF2 context object.
 *
 * @param [in, out] ctx  PBKDF2 context object.
 */
static void wp_kdf_pbkdf2_clear(wp_Pbkdf2Ctx* ctx)
{
    if (ctx->password != NULL) {
        OPENSSL_clear_free(ctx->password, ctx->passwordSz);
    }
    OPENSSL_free(ctx->salt);
}
/**
 * Dispose of an PBKDF2 context object.
 *
 * @param [in, out] ctx  PBKDF2 context object.
 */
static void wp_kdf_pbkdf2_free(wp_Pbkdf2Ctx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_pbkdf2_clear(ctx);
        OPENSSL_free(ctx);
    }
}

/**
 * Reset PBKDF2 context object.
 *
 * Disposes of allocated data.
 *
 * @param [in, out] ctx  PBKDF2 context object.
 */
static void wp_kdf_pbkdf2_reset(wp_Pbkdf2Ctx* ctx)
{
    if (ctx != NULL) {
        WOLFPROV_CTX* provCtx = ctx->provCtx;

        wp_kdf_pbkdf2_clear(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

/**
 * Set the base PBKDF2 context parameters.
 *
 * @param [in, out] ctx     PBKDF2 context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_pbkdf2_base_set_ctx_params(wp_Pbkdf2Ctx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        if (!wp_params_get_digest(params, NULL, ctx->provCtx->libCtx,
                &ctx->mdType, &ctx->mdLen)) {
            ok = 0;
        }

        if (ok && !wp_params_get_uint64(params, OSSL_KDF_PARAM_ITER,
                &ctx->iterations)) {
            ok = 0;
        }

        if (ok && (!wp_params_get_octet_string(params, OSSL_KDF_PARAM_PASSWORD,
                &ctx->password, &ctx->passwordSz, 1))) {
            ok = 0;
        }
        if (ok && (!wp_params_get_octet_string(params, OSSL_KDF_PARAM_SALT,
                &ctx->salt, &ctx->saltSz, 0))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Retrieve parameter values from the PBKDF2 context object.
 *
 * @param [in]      ctx     PBKDF2 context object.
 * @param [in, out] params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_pbkdf2_get_ctx_params(wp_Pbkdf2Ctx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    (void)ctx;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        if (ok && !OSSL_PARAM_set_size_t(p, MAX_SIZE_T)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return parameters that can be retrieved from the PBKDF2 context.
 *
 * @param [in] ctx      PBKDF2 context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_pbkdf2_gettable_ctx_params(wp_Pbkdf2Ctx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters that can be retrieved from the PBKDF2 context.
     */
    static const OSSL_PARAM wp_kdf_pbkdf2_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kdf_pbkdf2_supported_gettable_ctx_params;
}


/*
 * PBKDF-2
 */

/* Prototyped for the derive function.  */
static int wp_kdf_pbkdf2_set_ctx_params(wp_Pbkdf2Ctx* ctx,
    const OSSL_PARAM params[]);

/**
 * Derive a key using PBKDF2.
 *
 * @param [in, out] ctx     PBKDF2 context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
*/
static int wp_kdf_pbkdf2_derive(wp_Pbkdf2Ctx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_kdf_pbkdf2_set_ctx_params(ctx, params))) {
        ok = 0;
    }
    if (ok && (ctx->password == NULL)) {
        ok = 0;
    }
    if (ok && (keyLen == 0)) {
        ok = 0;
    }

    if (ok) {
        int rc;

        PRIVATE_KEY_UNLOCK();
        rc = wc_PBKDF2_ex(key, ctx->password, (int)ctx->passwordSz, ctx->salt,
            (int)ctx->saltSz, (int)ctx->iterations, (int)keyLen, ctx->mdType,
            NULL, INVALID_DEVID);
        PRIVATE_KEY_LOCK();
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set all the PBKDF2 context parameters.
 *
 * @param [in, out] ctx     PBKDF2 context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_pbkdf2_set_ctx_params(wp_Pbkdf2Ctx* ctx,
    const OSSL_PARAM params[])
{
    int ok;

    ok = wp_pbkdf2_base_set_ctx_params(ctx, params);
    if (ok && !wp_params_get_int(params, OSSL_KDF_PARAM_PKCS5, &ctx->pkcs5)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters to set against an PBKDF2 context for PBKDF2 ops.
 *
 * @param [in] ctx      PBKDF2 context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_pbkdf2_settable_ctx_params(wp_Pbkdf2Ctx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /** Parameters to set against an PBKDF2 context for PBKDF2 ops. */
    static const OSSL_PARAM wp_pbkdf2_supported_settable_ctx_params[] = {
        WP_PBKDF2_BASE_SETTABLES,
        OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS5, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_pbkdf2_supported_settable_ctx_params;
}

/** Dispatch table for PBKDF2 functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_pbkdf2_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,              (DFUNC)wp_kdf_pbkdf2_new             },
    { OSSL_FUNC_KDF_FREECTX,             (DFUNC)wp_kdf_pbkdf2_free            },
    { OSSL_FUNC_KDF_RESET,               (DFUNC)wp_kdf_pbkdf2_reset           },
    { OSSL_FUNC_KDF_DERIVE,              (DFUNC)wp_kdf_pbkdf2_derive          },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_kdf_pbkdf2_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (DFUNC)wp_kdf_pbkdf2_set_ctx_params  },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_kdf_pbkdf2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (DFUNC)wp_kdf_pbkdf2_get_ctx_params  },
    { 0, NULL }
};


/*
 * PKCS12 PBKDF-2
 */

/* Prototyped for the derive function.  */
static int wp_kdf_pkcs12_set_ctx_params(wp_Pbkdf2Ctx* ctx,
    const OSSL_PARAM params[]);

/**
 * Derive a key using PBKDF2 for PKCS#12.
 *
 * @param [in, out] ctx     PBKDF2 context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
*/
static int wp_kdf_pkcs12_derive(wp_Pbkdf2Ctx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_kdf_pkcs12_set_ctx_params(ctx, params))) {
        ok = 0;
    }
    if (ok && (ctx->password == NULL)) {
        ok = 0;
    }
    if (ok && (keyLen == 0)) {
        ok = 0;
    }

    if (ok) {
        int rc;

        PRIVATE_KEY_UNLOCK();
        rc = wc_PKCS12_PBKDF_ex(key, ctx->password, (int)ctx->passwordSz,
            ctx->salt, (int)ctx->saltSz, (int)ctx->iterations, (int)keyLen,
            ctx->mdType, ctx->keyUse, NULL);
        PRIVATE_KEY_LOCK();
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set all the PBKDF2 context parameters for PKCS#12.
 *
 * @param [in, out] ctx     PBKDF2 context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_pkcs12_set_ctx_params(wp_Pbkdf2Ctx* ctx,
    const OSSL_PARAM params[])
{
    int ok;

    ok = wp_pbkdf2_base_set_ctx_params(ctx, params);
    if (ok && !wp_params_get_int(params, OSSL_KDF_PARAM_PKCS12_ID,
            &ctx->keyUse)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters to set against an PBKDF2 context for PBKDF2 ops.
 *
 * @param [in] ctx      PBKDF2 context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_pkcs12_settable_ctx_params(wp_Pbkdf2Ctx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /** Parameters to set against an PBKDF2 context for PBKDF2 ops. */
    static const OSSL_PARAM wp_pkcs12_supported_settable_ctx_params[] = {
        WP_PBKDF2_BASE_SETTABLES,
        OSSL_PARAM_int(OSSL_KDF_PARAM_PKCS12_ID, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_pkcs12_supported_settable_ctx_params;
}

/** Dispatch table for PBKDF2 functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_pkcs12_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,              (DFUNC)wp_kdf_pbkdf2_new             },
    { OSSL_FUNC_KDF_FREECTX,             (DFUNC)wp_kdf_pbkdf2_free            },
    { OSSL_FUNC_KDF_RESET,               (DFUNC)wp_kdf_pbkdf2_reset           },
    { OSSL_FUNC_KDF_DERIVE,              (DFUNC)wp_kdf_pkcs12_derive          },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_kdf_pkcs12_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (DFUNC)wp_kdf_pkcs12_set_ctx_params  },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_kdf_pbkdf2_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (DFUNC)wp_kdf_pbkdf2_get_ctx_params  },
    { 0, NULL }
};

#endif

