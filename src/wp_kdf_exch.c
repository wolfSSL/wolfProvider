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
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <wolfprovider/alg_funcs.h>


/**
 * Key Derivation Function (KDF) context.
 *
 * Calls through to EVP API.
 */
typedef struct wp_KdfCtx {
    /** Provider context - useful for duplication. */
    WOLFPROV_CTX* provCtx;

    /** EVP KDF context object. */
    EVP_KDF_CTX* kdfCtx;
    /** Dummy KDF key. */
    wp_Kdf* key;
    /** Name of KDF. */
    const char* name;
} wp_KdfCtx;


/* Prototype for init to call. */
static int wp_kdf_set_ctx_params(wp_KdfCtx* ctx, const OSSL_PARAM params[]);


/**
 * Create a new KDF key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] name     Name of KDF.
 * @return  KDF key exchange object on success.
 * @return  NULL on failure.
 */
static wp_KdfCtx* wp_kdf_ctx_new(WOLFPROV_CTX* provCtx, const char* name)
{
    wp_KdfCtx* ctx = NULL;
    EVP_KDF* kdf = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
     }
     if (ctx != NULL) {
        int ok = 1;

        kdf = EVP_KDF_fetch(provCtx->libCtx, name, NULL);
        if (kdf == NULL) {
            ok = 0;
        }
        if (ok) {
            ctx->kdfCtx = EVP_KDF_CTX_new(kdf);
            if (ctx->kdfCtx == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            ctx->provCtx = provCtx;
            ctx->name = name;
        }

        if (!ok) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    EVP_KDF_free(kdf);
    return ctx;
}

/**
 * Free the KDF key exchange context object.
 *
 * @param [in, out] ctx  KDF key exchange context object.
 */
static void wp_kdf_ctx_free(wp_KdfCtx* ctx)
{
    wp_kdf_free(ctx->key);
    EVP_KDF_CTX_free(ctx->kdfCtx);
    OPENSSL_free(ctx);
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
        dst = wp_kdf_ctx_new(src->provCtx, src->name);
    }
    if (dst != NULL) {
        int ok = 1;

        if ((src->key != NULL) && (!wp_kdf_up_ref(src->key))) {
            ok = 0;
        }
        if (ok) {
            dst->key = src->key;
        }

        if (!ok) {
            OPENSSL_free(dst);
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

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (secret == NULL)) {
        *secLen = EVP_KDF_CTX_get_kdf_size(ctx->kdfCtx);
    }
    else if (ok && !EVP_KDF_derive(ctx->kdfCtx, secret, secSize, NULL)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    return EVP_KDF_CTX_set_params(ctx->kdfCtx, params);
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
 * Return an array of supported settable parameters for the HKDF ke context.
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
    return wp_kdf_ctx_new(provCtx, "HKDF");
}

/** Dispatch table for HKDF key exchange. */
const OSSL_DISPATCH wp_hkdf_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,              (DFUNC)wp_hkdf_ctx_new           },
    { OSSL_FUNC_KEYEXCH_FREECTX,             (DFUNC)wp_kdf_ctx_free           },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              (DFUNC)wp_kdf_ctx_dup            },
    { OSSL_FUNC_KEYEXCH_INIT,                (DFUNC)wp_kdf_init               },
    { OSSL_FUNC_KEYEXCH_DERIVE,              (DFUNC)wp_kdf_derive             },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      (DFUNC)wp_kdf_set_ctx_params     },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_hkdf_settable_ctx_params },
    { 0, NULL }
};

/*
 * TLS1 PRF
 */

/**
 * Create a new TLS1 PRF key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  KDF key exchange object on success.
 * @return  NULL on failure.
 */
static wp_KdfCtx* wp_tls1_prf_ctx_new(WOLFPROV_CTX* provCtx)
{
    return wp_kdf_ctx_new(provCtx, "TLS1-PRF");
}

/** Dispatch table for TLS1 PRF key exchange. */
const OSSL_DISPATCH wp_tls1_prf_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,              (DFUNC)wp_tls1_prf_ctx_new       },
    { OSSL_FUNC_KEYEXCH_FREECTX,             (DFUNC)wp_kdf_ctx_free           },
    { OSSL_FUNC_KEYEXCH_DUPCTX,              (DFUNC)wp_kdf_ctx_dup            },
    { OSSL_FUNC_KEYEXCH_INIT,                (DFUNC)wp_kdf_init               },
    { OSSL_FUNC_KEYEXCH_DERIVE,              (DFUNC)wp_kdf_derive             },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,      (DFUNC)wp_kdf_set_ctx_params     },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_tls1_prf_settable_ctx_params },
    { 0, NULL }
};

