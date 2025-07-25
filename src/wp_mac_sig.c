/* wp_mac_sig.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#if defined(WP_HAVE_HMAC) || defined(WP_HAVE_CMAC)

/**
 * MAC signature context.
 *
 * Used to store context and state of signing/verification operations.
 */
typedef struct wp_MacSigCtx {
    /* wolfProvider context object. */
    WOLFPROV_CTX *provCtx;
    /* Library context object. */
    OSSL_LIB_CTX *libCtx;

    /* MAC key. */
    wp_Mac* mac;
    /* wolfProvider MAC object. */
    EVP_MAC_CTX* macCtx;
    /* MAC name */
    char name[WP_MAX_MAC_NAME_SIZE];
    /* MAC type */
    int type;

    /* Property query string. */
    char* propQuery;
} wp_MacSigCtx;


/* Prototype for wp_mac_signverify_init() to use.  */
static int wp_mac_set_ctx_params(wp_MacSigCtx *ctx, const OSSL_PARAM params[]);

/**
 * Create a new MAC signature context object.
 *
 * @param [in] provCtx    wolfProvider context object.
 * @param [in] propQuery  Property query.
 * @return  NULL on failure.
 * @return  MAC signature context object on success.
 */
static wp_MacSigCtx* wp_mac_ctx_new(WOLFPROV_CTX* provCtx,
    const char* propQuery, const char* macName, int type)
{
    wp_MacSigCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int ok = 1;
        char* p = NULL;
        EVP_MAC* mac = NULL;

        if (propQuery != NULL) {
            p = OPENSSL_strdup(propQuery);
            if (p == NULL) {
                ctx = NULL;
                ok = 0;
            }
        }
        if (ok) {
            mac = EVP_MAC_fetch(provCtx->libCtx, macName, propQuery);
            if (mac == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            ctx->macCtx = EVP_MAC_CTX_new(mac);
            if (ctx->macCtx == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            ctx->propQuery = p;
            ctx->provCtx = provCtx;
            ctx->libCtx = provCtx->libCtx;
            XSTRNCPY(ctx->name, macName, WP_MAX_MAC_NAME_SIZE);
            ctx->name[WP_MAX_MAC_NAME_SIZE - 1] = '\0';
            ctx->type = type;
        }

        if (!ok) {
            OPENSSL_free(p);
            OPENSSL_free(ctx);
            ctx = NULL;
        }
        EVP_MAC_free(mac);
    }

    return ctx;
}

/**
 * Free an MAC signature context object.
 *
 * @param [in, out] ctx  MAC signature context object. May be NULL.
 */
static void wp_mac_ctx_free(wp_MacSigCtx* ctx)
{
    if (ctx != NULL) {
        EVP_MAC_CTX_free(ctx->macCtx);
        OPENSSL_free(ctx->propQuery);
        OPENSSL_free(ctx);
    }
}


/**
 * Duplicate the MAC signature context object.
 *
 * @param [in] srcCtx  MAC signature context object.
 * @retturn  NULL on failure.
 * @return   MAC signature context object on success.
 */
static wp_MacSigCtx* wp_mac_ctx_dup(wp_MacSigCtx* srcCtx)
{
    wp_MacSigCtx* dstCtx = NULL;

    if (wolfssl_prov_is_running()) {
        int ok = 1;

        dstCtx = wp_mac_ctx_new(srcCtx->provCtx, srcCtx->propQuery,
             srcCtx->name, srcCtx->type);
        if (dstCtx == NULL) {
            ok = 0;
        }
        if (ok) {
            EVP_MAC_CTX_free(dstCtx->macCtx);
            dstCtx->macCtx = EVP_MAC_CTX_dup(srcCtx->macCtx);
            if (dstCtx->macCtx == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            dstCtx->mac = srcCtx->mac;
        }

        if (!ok) {
            wp_mac_ctx_free(dstCtx);
            dstCtx = NULL;
        }
    }

    return dstCtx;
}

/**
 * Initialize MAC signature context object for signing/verifying digested data.
 *
 * @param [in, out] ctx     MAC signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      mac     MAC key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_digest_sign_init(wp_MacSigCtx *ctx, const char *mdName,
    wp_Mac *mac, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* priv;
    size_t privLen;
    const char* cipherName;
    const char* properties;
    OSSL_PARAM lParams[4];
    int lParamSz = 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok) {
        ctx->mac = mac;

        if (!wp_mac_get_private_key(ctx->mac, &priv, &privLen)) {
            ok = 0;
        }
    }
    if (ok) {
        EVP_MAC_CTX_set_params(ctx->macCtx, params);
    }
    if (ok && (ctx->type == WP_MAC_TYPE_CMAC)) {
        cipherName = wp_mac_get_ciphername(ctx->mac);
        if (!wp_params_get_utf8_string_ptr(params, OSSL_ALG_PARAM_CIPHER,
                &cipherName)) {
            ok = 0;
        }
        if (ok) {
            lParams[lParamSz++] = OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_CIPHER, (char*)cipherName, 0);
        }
    }
    if (ok && (ctx->type == WP_MAC_TYPE_HMAC)) {
        if (!wp_params_get_utf8_string_ptr(params, OSSL_ALG_PARAM_DIGEST,
                &mdName)) {
            ok = 0;
        }
        if (ok) {
            lParams[lParamSz++] =  OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST, (char*)mdName, 0);
        }
    }
    if (ok) {
        properties = wp_mac_get_properties(ctx->mac);
        if (!wp_params_get_utf8_string_ptr(params, OSSL_ALG_PARAM_PROPERTIES,
                &properties)) {
            ok = 0;
        }
    }
    if (ok && (properties != NULL)) {
        lParams[lParamSz++] =  OSSL_PARAM_construct_utf8_string(
             OSSL_MAC_PARAM_PROPERTIES, (char*)properties, 0);
    }
    if (ok) {
        lParams[lParamSz++] = OSSL_PARAM_construct_end();
        if (!EVP_MAC_init(ctx->macCtx, priv, privLen, lParams)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Digest data for signing/verification.
 *
 * @param [in, out] ctx       MAC signature context object.
 * @param [in]      data      Data to sign/verify.
 * @param [in]      dataLen   Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_digest_sign_update(wp_MacSigCtx *ctx,
    const unsigned char *data, size_t dataLen)
{
    int ok = 1;

    if (!EVP_MAC_update(ctx->macCtx, data, dataLen)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the signing operation on data that is digested.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      MAC signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature in bytes.
 * @param [in]      sigSize  Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_digest_sign_final(wp_MacSigCtx *ctx, unsigned char *sig,
    size_t *sigLen, size_t sigSize)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok & (sigSize == MAX_SIZE_T) && (ctx->type == WP_MAC_TYPE_CMAC)) {
        sigSize = AES_BLOCK_SIZE;
    }
    if (ok && (!EVP_MAC_final(ctx->macCtx, sig, sigLen, sigSize))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into MAC signature context object.
 *
 * @param [in, out] ctx     MAC signature context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_set_ctx_params(wp_MacSigCtx *ctx, const OSSL_PARAM params[])
{
     return EVP_MAC_CTX_set_params(ctx->macCtx, params);
}

/**
 * Returns an array of MAC signature context parameters that can be set.
 *
 * @param [in] ctx      MAC signature context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_mac_settable_ctx_params(wp_MacSigCtx *ctx,
    WOLFPROV_CTX* provCtx)
{
    (void)ctx;
    (void)provCtx;
    static const OSSL_PARAM settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_NOINIT, NULL),
        OSSL_PARAM_int(OSSL_MAC_PARAM_DIGEST_ONESHOT, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
        OSSL_PARAM_END
    };    
    return settable_ctx_params;
}

/*
 * HMAC
 */

#ifdef WP_HAVE_HMAC

static wp_MacSigCtx* wp_hmac_ctx_new(WOLFPROV_CTX* provCtx,
    const char* propQuery)
{
    return wp_mac_ctx_new(provCtx, propQuery, WP_NAMES_HMAC, WP_MAC_TYPE_HMAC);
}

/** Dspatch table for HMAC signing. */
const OSSL_DISPATCH wp_hmac_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,             (DFUNC)wp_hmac_ctx_new          },
    { OSSL_FUNC_SIGNATURE_FREECTX,            (DFUNC)wp_mac_ctx_free          },
    { OSSL_FUNC_SIGNATURE_DUPCTX,             (DFUNC)wp_mac_ctx_dup           },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,   (DFUNC)wp_mac_digest_sign_init  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
                                            (DFUNC)wp_mac_digest_sign_update  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,  (DFUNC)wp_mac_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,     (DFUNC)wp_mac_set_ctx_params    },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_mac_settable_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_HMAC */

/*
 * CMAC
 */

#ifdef WP_HAVE_CMAC

static wp_MacSigCtx* wp_cmac_ctx_new(WOLFPROV_CTX* provCtx,
    const char* propQuery)
{
    return wp_mac_ctx_new(provCtx, propQuery, WP_NAMES_CMAC, WP_MAC_TYPE_CMAC);
}

/** Dspatch table for HMAC signing. */
const OSSL_DISPATCH wp_cmac_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,             (DFUNC)wp_cmac_ctx_new          },
    { OSSL_FUNC_SIGNATURE_FREECTX,            (DFUNC)wp_mac_ctx_free          },
    { OSSL_FUNC_SIGNATURE_DUPCTX,             (DFUNC)wp_mac_ctx_dup           },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,   (DFUNC)wp_mac_digest_sign_init  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
                                            (DFUNC)wp_mac_digest_sign_update  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,  (DFUNC)wp_mac_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,     (DFUNC)wp_mac_set_ctx_params    },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_mac_settable_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_CMAC */

#endif /* WP_HAVE_HMAC || WP_HAVE_CMAC */
