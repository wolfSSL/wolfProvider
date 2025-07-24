/* wp_hkdf.c
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

/** Base set of parameters settable against context. */
#define WP_HKDF_BASE_SETTABLES                                          \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),           \
        OSSL_PARAM_int(OSSL_KDF_PARAM_MODE, NULL),                      \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),     \
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),         \
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),           \
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0)

/** Max size of the info data to HKDF. */
#define WP_MAX_INFO_SIZE    1024

/**
 * The HKDF context structure.
 * Includes everything for TLS 1.3 HKDF.
 */
typedef struct wp_HkdfCtx {
    /** wolfSSL provider context. */
    WOLFPROV_CTX* provCtx;

    /** Mode to use with HKDF. */
    int mode;
    /** Digest to use with HKDF. */
    enum wc_HashType mdType;
    /** Digest to use with HKDF. */
    size_t mdLen;
    /** Key for KDF. */
    unsigned char *key;
    /** Size of key in bytes. */
    size_t keySz;
    /** Salt for KDF. */
    unsigned char *salt;
    /** Size of salt in bytes. */
    size_t saltSz;
    /** Info for KDF. */
    unsigned char info[WP_MAX_INFO_SIZE];
    /** Size of info in bytes. */
    size_t infoSz;

    /** Prefix for TLS 1.3 HKDF. */
    unsigned char* prefix;
    /** Size of prefix in bytes. */
    size_t prefixLen;
    /** Label for TLS 1.3 HKDF. */
    unsigned char* label;
    /** Size of label in bytes. */
    size_t labelLen;
    /** Data for TLS 1.3 HKDF. */
    unsigned char* data;
    /** Size of data in bytes. */
    size_t dataLen;
} wp_HkdfCtx;


/** Prototyped for the derive function.  */
static int wp_kdf_hkdf_set_ctx_params(wp_HkdfCtx* ctx,
    const OSSL_PARAM params[]);


/**
 * Create a new HKDF context object.
 *
 * @param [in] provCtx  wolfProvider context object.
 * @return  NULL on failure.
 * @return  HKDF context object.
 */
static wp_HkdfCtx* wp_kdf_hkdf_new(WOLFPROV_CTX* provCtx)
{
    wp_HkdfCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Dispose of data in HKDF context object.
 *
 * @param [in, out] ctx  HKDF context object.
 */
static void wp_kdf_hkdf_clear(wp_HkdfCtx* ctx)
{
    if (ctx->key != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->keySz);
    }
    if (ctx->data != NULL) {
        OPENSSL_clear_free(ctx->data, ctx->dataLen);
    }
    OPENSSL_free(ctx->label);
    OPENSSL_free(ctx->prefix);
    OPENSSL_free(ctx->salt);
    OPENSSL_cleanse(ctx->info, ctx->infoSz);
}

/**
 * Dispose of an HKDF context object.
 *
 * @param [in, out] ctx  HKDF context object.
 */
static void wp_kdf_hkdf_free(wp_HkdfCtx* ctx)
{
    if (ctx != NULL) {
        wp_kdf_hkdf_clear(ctx);
        OPENSSL_free(ctx);
    }
}

/**
 * Reset HKDF context object.
 *
 * Disposes of allocated data.
 *
 * @param [in, out] ctx  HKDF context object.
 */
static void wp_kdf_hkdf_reset(wp_HkdfCtx* ctx)
{
    if (ctx != NULL) {
        WOLFPROV_CTX* provCtx = ctx->provCtx;

        wp_kdf_hkdf_clear(ctx);
        XMEMSET(ctx, 0, sizeof(*ctx));
        ctx->provCtx = provCtx;
    }
}

/**
 * Derive a key using HKDF.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
*/
static int wp_kdf_hkdf_derive(wp_HkdfCtx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_kdf_hkdf_set_ctx_params(ctx, params))) {
        ok = 0;
    }
    if (ok && (ctx->key == NULL)) {
        ok = 0;
    }
    if (ok && (keyLen == 0)) {
        ok = 0;
    }

    if (ok) {
        int rc;

        switch (ctx->mode) {
        case EVP_KDF_HKDF_MODE_EXTRACT_ONLY:
            if (keyLen != ctx->mdLen) {
                ok = 0;
            }
            if (ok) {
                PRIVATE_KEY_UNLOCK();
                rc = wc_HKDF_Extract(ctx->mdType, ctx->salt,
                    (word32)ctx->saltSz, ctx->key, (word32)ctx->keySz, key);
                PRIVATE_KEY_LOCK();
                if (rc != 0) {
                    ok = 0;
                }
            }
            break;

        case EVP_KDF_HKDF_MODE_EXPAND_ONLY:
            PRIVATE_KEY_UNLOCK();
            rc = wc_HKDF_Expand(ctx->mdType, ctx->key, (word32)ctx->keySz,
                ctx->info, (word32)ctx->infoSz, key, (word32)keyLen);
            PRIVATE_KEY_LOCK();
            if (rc != 0) {
                ok = 0;
            }
            break;

        case EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND:
        default:
            PRIVATE_KEY_UNLOCK();
            rc = wc_HKDF(ctx->mdType, ctx->key, (word32)ctx->keySz, ctx->salt,
                (word32)ctx->saltSz, ctx->info, (word32)ctx->infoSz, key,
                (word32)keyLen);
            PRIVATE_KEY_LOCK();
            if (rc != 0) {
                ok = 0;
            }
            break;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Find and set the HKDF mode into the context.
 *
 * @param [in]      params  Array of parameters.
 * @param [in, out] ctx     HKDF context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hkdf_base_get_mode(const OSSL_PARAM params[], int* mode)
{
    int ok = 1;
    const OSSL_PARAM* p;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p != NULL) {
        int n;

        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            if (strcasecmp(p->data, "EXTRACT_AND_EXPAND") == 0) {
                *mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
            }
            else if (strcasecmp(p->data, "EXTRACT_ONLY") == 0) {
                *mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
            }
            else if (strcasecmp(p->data, "EXPAND_ONLY") == 0) {
                *mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
            }
            else {
                ok = 0;
            }
        }
        else if (OSSL_PARAM_get_int(p, &n)) {
            *mode = n;
            if ((n != EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND) &&
                (n != EVP_KDF_HKDF_MODE_EXTRACT_ONLY) &&
                (n != EVP_KDF_HKDF_MODE_EXPAND_ONLY)) {
                ok = 0;
            }
        }
        else {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the base HKDF context parameters.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hkdf_base_set_ctx_params(wp_HkdfCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM *p;

    if (params != NULL) {
        if (!wp_params_get_digest(params, NULL, ctx->provCtx->libCtx,
                &ctx->mdType, &ctx->mdLen)) {
            ok = 0;
        }
        if (ok && (!wp_hkdf_base_get_mode(params, &ctx->mode))) {
            ok = 0;
        }
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM *)params, OSSL_KDF_PARAM_KEY);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_clear_free(ctx->key, ctx->keySz);
                ctx->key = NULL;
                if (!OSSL_PARAM_get_octet_string(
                        p, (void**)&ctx->key, 0, &ctx->keySz)) {
                    ok = 0;
                }
            }
        }
        if (ok) {
            p = OSSL_PARAM_locate((OSSL_PARAM *)params, OSSL_KDF_PARAM_SALT);
            if ((p != NULL) && (p->data != NULL)) {
                OPENSSL_free(ctx->salt);
                ctx->salt = NULL;
                if (!OSSL_PARAM_get_octet_string(
                        p, (void**)&ctx->salt, 0, &ctx->saltSz)) {
                    ok = 0;
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Retrieve parameter values from the HKDF context object.
 *
 * @param [in]      ctx     HKDF context object.
 * @param [in, out] params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_hkdf_get_ctx_params(wp_HkdfCtx* ctx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p != NULL) {
        size_t sz;

        if (ctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
            sz = ctx->mdLen;
        }
        else {
            sz = MAX_SIZE_T;
        }
        if (ok && !OSSL_PARAM_set_size_t(p, sz)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Find and set the combined info parameters into the context.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hkdf_base_set_info(wp_HkdfCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;
    unsigned char* q = ctx->info;

    ctx->infoSz = 0;
    /* Combine all the data in the info parameters. */
    while (ok && ((p = OSSL_PARAM_locate_const(params,
            OSSL_KDF_PARAM_INFO)) != NULL)) {
        size_t sz = 0;

        if ((p->data_size != 0) && (p->data != NULL) &&
            (!OSSL_PARAM_get_octet_string(p, (void**)&q,
                WP_MAX_INFO_SIZE - ctx->infoSz, &sz))) {
            ok = 0;
        }
        if (ok) {
            ctx->infoSz += sz;
            q += sz;
        }
        params = p + 1;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set parameters into HKDF context object.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [in]      params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_hkdf_set_ctx_params(wp_HkdfCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        if (!wp_hkdf_base_set_ctx_params(ctx, params)) {
            ok = 0;
        }
        if (ok && (!wp_hkdf_base_set_info(ctx, params))) {
            ok = 0;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters to set against an HKDF context for HKDF ops.
 *
 * @param [in] ctx      HKDF context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_hkdf_settable_ctx_params(wp_HkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /** Parameters to set against an HKDF context for HKDF ops. */
    static const OSSL_PARAM wp_hkdf_supported_settable_ctx_params[] = {
        WP_HKDF_BASE_SETTABLES,
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_hkdf_supported_settable_ctx_params;
}

/**
 * Return parameters that can be retrieved from the HKDF context.
 *
 * @param [in] ctx      HKDF context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_hkdf_gettable_ctx_params(wp_HkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters that can be retrieved from the HKDF context.
     */
    static const OSSL_PARAM wp_kdf_hkdf_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kdf_hkdf_supported_gettable_ctx_params;
}


/** Dispatch table for HKDF functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_hkdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,              (DFUNC)wp_kdf_hkdf_new               },
    { OSSL_FUNC_KDF_FREECTX,             (DFUNC)wp_kdf_hkdf_free              },
    { OSSL_FUNC_KDF_RESET,               (DFUNC)wp_kdf_hkdf_reset             },
    { OSSL_FUNC_KDF_DERIVE,              (DFUNC)wp_kdf_hkdf_derive            },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                                       (DFUNC)wp_kdf_hkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (DFUNC)wp_kdf_hkdf_set_ctx_params    },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                                       (DFUNC)wp_kdf_hkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (DFUNC)wp_kdf_hkdf_get_ctx_params    },
    { 0, NULL }
};


/*
 * TLS 1.3 KDF
 */

/* Protyped for derivation function. */
static int wp_kdf_tls1_3_set_ctx_params(wp_HkdfCtx* ctx,
    const OSSL_PARAM params[]);

/**
 * TLS 1.3 HKDF expansion.
 *
 * This function is called by wp_tls13_hkdf_extract().
 *
 * Label and prefix from the context are used in calculation.
 * info field updated with data to expand.
 *
 * @param [in, out] ctx       HKDF context object.
 * @param [in]      inKey     Input key.
 * @param [in]      inKeyLen  Length of input key in bytes.
 * @param [in]      data      Data to be expanded.
 * @param [in]      inKeyLen  Length of data in bytes.
 * @param [out]     key       Buffer to hold output key
 * @param [in]      keyLen    Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_tls13_hkdf_expand(wp_HkdfCtx* ctx, unsigned char* inKey,
    size_t inKeyLen, unsigned char* data, size_t dataLen, unsigned char* key,
    size_t keyLen)
{
    int ok = 1;
    size_t idx = 0;
    int rc;

    /* Construct info to expand from:
     *  - output key length
     *  - label
     *  - prefix/protocol
     *  - data
     */
    ctx->info[idx++] = (byte)(keyLen >> 8);
    ctx->info[idx++] = (byte)keyLen;
    ctx->info[idx++] = (byte)(ctx->prefixLen + ctx->labelLen);
    XMEMCPY(ctx->info + idx, ctx->prefix, ctx->prefixLen);
    idx += ctx->prefixLen;
    XMEMCPY(ctx->info + idx, ctx->label, ctx->labelLen);
    idx += ctx->labelLen;
    ctx->info[idx++] = (byte)(dataLen);
    if (dataLen > 0) {
        XMEMCPY(ctx->info + idx, data, dataLen);
        idx += dataLen;
    }
    ctx->infoSz = idx;

    PRIVATE_KEY_UNLOCK();
    rc = wc_HKDF_Expand(ctx->mdType, inKey, (word32)inKeyLen, ctx->info,
        (word32)ctx->infoSz, key, (word32)keyLen);
    PRIVATE_KEY_LOCK();
    if (rc != 0) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * TLS 1.3 HKDF extract operation.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [out]     key     Buffer to hold output key
 * @param [in]      keyLen  Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_tls13_hkdf_extract(wp_HkdfCtx* ctx, unsigned char* key,
    size_t keyLen)
{
    int ok = 1;
    int rc;
    unsigned char secret[WC_MAX_DIGEST_SIZE];
    unsigned char zeros[WC_MAX_DIGEST_SIZE];
    unsigned char* inKey;
    size_t inKeyLen;
    unsigned char* salt;
    size_t saltLen;

    if (ctx->key == NULL) {
        inKey = zeros;
        inKeyLen = ctx->mdLen;
        XMEMSET(zeros, 0, inKeyLen);
    }
    else {
        inKey = ctx->key;
        inKeyLen = ctx->keySz;
    }
    if (ctx->salt == NULL) {
        salt = zeros;
        saltLen = 0;
    }
    else {
        salt = secret;
        saltLen = ctx->mdLen;
        /* Calculate the digest of an empty string. */
        rc = wc_Hash(ctx->mdType, zeros, 0, secret, (word32)ctx->mdLen);
        if (rc != 0) {
            ok = 0;
        }
        else if (!wp_tls13_hkdf_expand(ctx, ctx->salt, ctx->saltSz, secret,
                ctx->mdLen, salt, saltLen)) {
            ok = 0;
        }
    }

    if (ok) {
        (void)keyLen;
        PRIVATE_KEY_UNLOCK();
        if (saltLen == 0) {
            rc = wc_HKDF_Extract(ctx->mdType, NULL, 0, inKey,
                (word32)inKeyLen, key);
        }
        else {
            rc = wc_HKDF_Extract(ctx->mdType, salt, (word32)saltLen, inKey,
                (word32)inKeyLen, key);
        }
        PRIVATE_KEY_LOCK();
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Derive a key using TLS 1.3 HKDF.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [out]     key     Buffer to hold derived key.
 * @param [in]      keyLen  Size of buffer in bytes.
 * @param [in]      params  Array of parameters to set before deriving.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_tls1_3_derive(wp_HkdfCtx* ctx, unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && !wp_kdf_tls1_3_set_ctx_params(ctx, params)) {
        ok = 0;
    }

    if (ok) {
        if (ctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_ONLY) {
            if (!wp_tls13_hkdf_extract(ctx, key, keyLen)) {
                ok = 0;
            }
        }
        else if (ctx->mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY) {
            if (!wp_tls13_hkdf_expand(ctx, ctx->key, ctx->keySz, ctx->data,
                    ctx->dataLen, key, keyLen)) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set parameters into HKDF context object for TLS 1.3 HKDF.
 *
 * @param [in, out] ctx     HKDF context object.
 * @param [in]      params  Array of parameters with values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_kdf_tls1_3_set_ctx_params(wp_HkdfCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        if (!wp_hkdf_base_set_ctx_params(ctx, params)) {
            ok = 0;
        }
        if (ok && (ctx->mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND)) {
            ok = 0;
        }
        if (ok && (!wp_params_get_octet_string(params, OSSL_KDF_PARAM_PREFIX,
                &ctx->prefix, &ctx->prefixLen, 0))) {
            ok = 0;
        }
        if (ok && (!wp_params_get_octet_string(params, OSSL_KDF_PARAM_LABEL,
                &ctx->label, &ctx->labelLen, 0))) {
            ok = 0;
        }
        if (ok && (!wp_params_get_octet_string(params, OSSL_KDF_PARAM_DATA,
                &ctx->data, &ctx->dataLen, 0))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns the parameters to set against an HKDF context for TLS 1.3 HKDF ops.
 *
 * @param [in] ctx      HKDF context object. Unused.
 * @param [in] provCtx  wolfProvider context. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_kdf_tls1_3_settable_ctx_params(wp_HkdfCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /** Parameters to set against an HKDF context for TLS 1.3 HKDF ops. */
    static const OSSL_PARAM wp_kdf_tls1_3_supported_settable_ctx_params[] = {
        WP_HKDF_BASE_SETTABLES,
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PREFIX, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_LABEL, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_DATA, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_kdf_tls1_3_supported_settable_ctx_params;
}

/** Dispatch table for TLS 1.3 HKDF functions implemented using wolfSSL. */
const OSSL_DISPATCH wp_kdf_tls1_3_kdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX,          (DFUNC)wp_kdf_hkdf_new                   },
    { OSSL_FUNC_KDF_FREECTX,         (DFUNC)wp_kdf_hkdf_free                  },
    { OSSL_FUNC_KDF_RESET,           (DFUNC)wp_kdf_hkdf_reset                 },
    { OSSL_FUNC_KDF_DERIVE,          (DFUNC)wp_kdf_tls1_3_derive              },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_kdf_tls1_3_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS , (DFUNC)wp_kdf_tls1_3_set_ctx_params      },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_kdf_hkdf_gettable_ctx_params   },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS , (DFUNC)wp_kdf_hkdf_get_ctx_params        },
    { 0, NULL }
};


