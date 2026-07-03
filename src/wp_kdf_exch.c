/* wp_kdf_exch.c
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

#include <wolfprovider/alg_funcs.h>


/**
 * Key Derivation Function (KDF) context.
 *
 * Drives the wolfProvider KDF implementation directly through its dispatch
 * table so the derivation cannot be satisfied by another provider.
 */
typedef struct wp_KdfCtx {
    /** Provider context - useful for duplication. */
    WOLFPROV_CTX* provCtx;

    /** wolfProvider KDF dispatch table - useful for duplication. */
    const OSSL_DISPATCH* kdfDisp;
    /** wolfProvider KDF implementation context object. */
    void* kctx;
    /** Duplicate the wolfProvider KDF context. */
    OSSL_FUNC_kdf_dupctx_fn* dupCtx;
    /** Free the wolfProvider KDF context. */
    OSSL_FUNC_kdf_freectx_fn* freeCtx;
    /** Derive a key with the wolfProvider KDF. */
    OSSL_FUNC_kdf_derive_fn* derive;
    /** Set parameters into the wolfProvider KDF context. */
    OSSL_FUNC_kdf_set_ctx_params_fn* setParams;
    /** Get parameters from the wolfProvider KDF context. */
    OSSL_FUNC_kdf_get_ctx_params_fn* getParams;
    /** Get the list of gettable parameters from the wolfProvider KDF. */
    OSSL_FUNC_kdf_gettable_ctx_params_fn* gettableParams;

    /** Dummy KDF key. */
    wp_Kdf* key;
    /** Name of KDF. */
    const char* name;
} wp_KdfCtx;


/* Prototype for init to call. */
static int wp_kdf_set_ctx_params(wp_KdfCtx* ctx, const OSSL_PARAM params[]);


/**
 * Resolve the wolfProvider KDF implementation from its dispatch table.
 *
 * Creates the backing KDF context so the derivation is always performed by
 * wolfProvider, never delegated to another provider via an EVP fetch.
 *
 * @param [in, out] ctx      KDF key exchange context object.
 * @param [in]      kdfDisp  wolfProvider KDF dispatch table.
 * @return  1 on success.
 * @return  0 when a required function is missing or context creation fails.
 */
static int wp_kdf_ctx_load(wp_KdfCtx* ctx, const OSSL_DISPATCH* kdfDisp)
{
    int ok = 1;
    OSSL_FUNC_kdf_newctx_fn* newCtx = NULL;
    const OSSL_DISPATCH* d;

    for (d = kdfDisp; d->function_id != 0; d++) {
        switch (d->function_id) {
            case OSSL_FUNC_KDF_NEWCTX:
                newCtx = OSSL_FUNC_kdf_newctx(d);
                break;
            case OSSL_FUNC_KDF_DUPCTX:
                ctx->dupCtx = OSSL_FUNC_kdf_dupctx(d);
                break;
            case OSSL_FUNC_KDF_FREECTX:
                ctx->freeCtx = OSSL_FUNC_kdf_freectx(d);
                break;
            case OSSL_FUNC_KDF_DERIVE:
                ctx->derive = OSSL_FUNC_kdf_derive(d);
                break;
            case OSSL_FUNC_KDF_SET_CTX_PARAMS:
                ctx->setParams = OSSL_FUNC_kdf_set_ctx_params(d);
                break;
            case OSSL_FUNC_KDF_GET_CTX_PARAMS:
                ctx->getParams = OSSL_FUNC_kdf_get_ctx_params(d);
                break;
            case OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS:
                ctx->gettableParams = OSSL_FUNC_kdf_gettable_ctx_params(d);
                break;
            default:
                break;
        }
    }

    if ((newCtx == NULL) || (ctx->dupCtx == NULL) || (ctx->freeCtx == NULL) ||
            (ctx->derive == NULL) || (ctx->setParams == NULL) ||
            (ctx->getParams == NULL)) {
        WOLFPROV_MSG_DEBUG(WP_LOG_COMP_KDF,
            "wolfProvider KDF dispatch is missing a required function");
        ok = 0;
    }
    if (ok) {
        ctx->kdfDisp = kdfDisp;
        ctx->kctx = newCtx(ctx->provCtx);
        if (ctx->kctx == NULL) {
            WOLFPROV_MSG_DEBUG(WP_LOG_COMP_KDF,
                "Failed to create wolfProvider KDF context");
            ok = 0;
        }
    }

    return ok;
}

/**
 * Create a new KDF key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] name     Name of KDF.
 * @param [in] kdfDisp  wolfProvider KDF dispatch table for name.
 * @return  KDF key exchange object on success.
 * @return  NULL on failure.
 */
static wp_KdfCtx* wp_kdf_ctx_new(WOLFPROV_CTX* provCtx, const char* name,
    const OSSL_DISPATCH* kdfDisp)
{
    wp_KdfCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
        ctx->name = name;
        /* On load failure kctx is always NULL, so there is nothing to free. */
        if (!wp_kdf_ctx_load(ctx, kdfDisp)) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Free the KDF key exchange context object.
 *
 * @param [in, out] ctx  KDF key exchange context object.
 */
static void wp_kdf_ctx_free(wp_KdfCtx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_free(ctx->key);
        if ((ctx->freeCtx != NULL) && (ctx->kctx != NULL)) {
            ctx->freeCtx(ctx->kctx);
        }
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate an KDF key exchange context object.
 *
 * @param [in] src  KDF key exchange context object.
 * @return  KDF key exchange context object on success.
 * @return  NULL on failure.
 */
static wp_KdfCtx* wp_kdf_ctx_dup(wp_KdfCtx* src)
{
    wp_KdfCtx* dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = wp_kdf_ctx_new(src->provCtx, src->name, src->kdfDisp);
    }
    if (dst != NULL) {
        int ok = 1;

        /* Replace the fresh KDF context with a deep copy of the source's so
         * the configured derivation state is preserved. dupCtx is required by
         * wp_kdf_ctx_load, so it is always available here. */
        dst->freeCtx(dst->kctx);
        dst->kctx = src->dupCtx(src->kctx);
        if (dst->kctx == NULL) {
            ok = 0;
        }
        if (ok && (src->key != NULL) && (!wp_kdf_up_ref(src->key))) {
            ok = 0;
        }
        if (ok) {
            dst->key = src->key;
        }

        if (!ok) {
            wp_kdf_ctx_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Initialize the KDF key exchange object with private key and parameters.
 *
 * @param [in, out] ctx     KDF key exchange context object.
 * @param [in, out] kdf     KDF key object. (Up referenced.)
 * @param [in]      params  Parameters - EVP_KDF parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_init(wp_KdfCtx* ctx, wp_Kdf* kdf, const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_KDF, "wp_kdf_init");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (ctx->key != kdf)) {
        wp_kdf_free(ctx->key);
        ctx->key = NULL;
        if (!wp_kdf_up_ref(kdf)) {
            ok = 0;
        }
    }
    if (ok) {
        ctx->key = kdf;
        ok = wp_kdf_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Derive a secret/key using ECDH key exchange.
 *
 * Can put the ECDH secret through a KDF.
 *
 * @param [in]  ctx      ECDH key exchange context object.
 * @param [out] secret   Buffer to hold secret/key.
 * @param [out] secLen   Length of secret/key data in bytes.
 * @param [in]  secSize  Size of buffer in bytes.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_kdf_derive(wp_KdfCtx* ctx, unsigned char* secret, size_t* secLen,
    size_t secSize)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_KDF, "wp_kdf_derive");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (secret == NULL)) {
        OSSL_PARAM params[2];
        size_t sz = 0;

        params[0] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &sz);
        params[1] = OSSL_PARAM_construct_end();
        if (!ctx->getParams(ctx->kctx, params)) {
            ok = 0;
        }
        else {
            *secLen = sz;
        }
    }
    else if (ok && !ctx->derive(ctx->kctx, secret, secSize, NULL)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the KDF key exchange parameters.
 *
 * @param [in, out] ctx     KDF key exchange context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_set_ctx_params(wp_KdfCtx* ctx, const OSSL_PARAM params[])
{
    return ctx->setParams(ctx->kctx, params);
}

/**
 * Get the KDF key exchange parameters.
 *
 * @param [in]      ctx     KDF key exchange context object.
 * @param [in, out] params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_get_ctx_params(wp_KdfCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_KDF, "wp_kdf_get_ctx_params");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && !ctx->getParams(ctx->kctx, params)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the list of gettable parameters for a KDF context.
 *
 * @param [in] ctx      KDF key exchange context object. Unused.
 * @param [in] provCtx  Provider context object.
 * @param [in] kdfName  Name of the KDF.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_kdf_gettable_ctx_params(wp_KdfCtx* ctx,
    WOLFPROV_CTX* provCtx, const char* kdfName)
{
    const OSSL_PARAM* params = NULL;

    (void)kdfName;

    if (wolfssl_prov_is_running() && (ctx != NULL) && (ctx->kctx != NULL) &&
            (ctx->gettableParams != NULL)) {
        params = ctx->gettableParams(ctx->kctx, provCtx);
    }

    return params;
}

/**
 * Return an array of supported settable parameters for the HKDF ke context.
 *
 * @param [in] ctx      ECDH key exchange context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_hkdf_settable_ctx_params(wp_KdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    (void)ctx;
    (void)provCtx;
    static const OSSL_PARAM settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END
    };
    return settable_ctx_params;
}

/**
 * Return an array of supported gettable parameters for the HKDF ke context.
 *
 * @param [in] ctx      KDF key exchange context object. Unused.
 * @param [in] provCtx  Provider context object.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_hkdf_gettable_ctx_params(wp_KdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    return wp_kdf_gettable_ctx_params(ctx, provCtx, "HKDF");
}

/*
 * HKDF
 */

/**
 * Create a new HKDF key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  KDF key exchange object on success.
 * @return  NULL on failure.
 */
static wp_KdfCtx* wp_hkdf_ctx_new(WOLFPROV_CTX* provCtx)
{
    return wp_kdf_ctx_new(provCtx, "HKDF", wp_kdf_hkdf_functions);
}

/** Dispatch table for HKDF key exchange. */
const OSSL_DISPATCH wp_hkdf_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,              (DFUNC)wp_hkdf_ctx_new           },
    { OSSL_FUNC_KEYEXCH_FREECTX,             (DFUNC)wp_kdf_ctx_free           },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              (DFUNC)wp_kdf_ctx_dup            },
    { OSSL_FUNC_KEYEXCH_INIT,                (DFUNC)wp_kdf_init               },
    { OSSL_FUNC_KEYEXCH_DERIVE,              (DFUNC)wp_kdf_derive             },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      (DFUNC)wp_kdf_set_ctx_params     },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,      (DFUNC)wp_kdf_get_ctx_params     },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_hkdf_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_hkdf_gettable_ctx_params },
    { 0, NULL }
};

/*
 * TLS1 PRF
 */

#ifdef WP_HAVE_TLS1_PRF

/**
 * Return an array of supported settable parameters for the TLS1-PRF ke context.
 *
 * @param [in] ctx      ECDH key exchange context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_tls1_prf_settable_ctx_params(wp_KdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    (void)ctx;
    (void)provCtx;
    static const OSSL_PARAM settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    return settable_ctx_params;
}

/**
 * Return an array of supported gettable parameters for the TLS1-PRF ke context.
 *
 * @param [in] ctx      KDF key exchange context object. Unused.
 * @param [in] provCtx  Provider context object.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_tls1_prf_gettable_ctx_params(wp_KdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    return wp_kdf_gettable_ctx_params(ctx, provCtx, "TLS1-PRF");
}

/**
 * Create a new TLS1 PRF key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  KDF key exchange object on success.
 * @return  NULL on failure.
 */
static wp_KdfCtx* wp_tls1_prf_ctx_new(WOLFPROV_CTX* provCtx)
{
    return wp_kdf_ctx_new(provCtx, "TLS1-PRF", wp_kdf_tls1_prf_functions);
}

/** Dispatch table for TLS1 PRF key exchange. */
const OSSL_DISPATCH wp_tls1_prf_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,              (DFUNC)wp_tls1_prf_ctx_new       },
    { OSSL_FUNC_KEYEXCH_FREECTX,             (DFUNC)wp_kdf_ctx_free           },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              (DFUNC)wp_kdf_ctx_dup            },
    { OSSL_FUNC_KEYEXCH_INIT,                (DFUNC)wp_kdf_init               },
    { OSSL_FUNC_KEYEXCH_DERIVE,              (DFUNC)wp_kdf_derive             },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      (DFUNC)wp_kdf_set_ctx_params     },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,      (DFUNC)wp_kdf_get_ctx_params     },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_tls1_prf_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_tls1_prf_gettable_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_TLS1_PRF */

