/* wp_ecdh_exch.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>


#ifdef WP_HAVE_ECDH

/** No KDF applied to derived secret. */
#define WP_KDF_NONE       0
/** X9.63 KDF applied to derived secret. */
#define WP_KDF_X963       1


/**
 * ECDH key exchange context.
 */
typedef struct wp_EcdhCtx {
    /** Provider context - useful for getting library context. */
    WOLFPROV_CTX* provCtx;

    /** Reference to our key. */
    wp_Ecc* key;
    /** Reference to peer's public key. */
    wp_Ecc* peer;

    /** Whether to use cofactor - irrelevant with curves we use. */
    int cofactor;

    /** KDF type to apply to calculated secret. */
    int kdfType;
    /** Digest to use with KDF. */
    enum wc_HashType kdfMd;
    /** Name of digest to use with KDF.  */
    char kdfMdName[WP_MAX_MD_NAME_SIZE];
    /** User Keying Material. */
    unsigned char* ukm;
    /** Length of User Keying Material. */
    size_t ukmLen;
    /** Length of key to derive. */
    size_t keyLen;
} wp_EcdhCtx;


/* Prototype for init to call. */
static int wp_ecdh_set_ctx_params(wp_EcdhCtx* ctx, const OSSL_PARAM params[]);


/**
 * Create a new ECDH key exchange context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  ECDH key exchange object on success.
 * @return  NULL on failure.
 */
static wp_EcdhCtx* wp_ecdh_new(WOLFPROV_CTX* provCtx)
{
    wp_EcdhCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
    }

    return ctx;
}

/**
 * Free the ECDH key exchange context object.
 *
 * @param [in, out] ctx  ECDH key exchange context object.
 */
static void wp_ecdh_free(wp_EcdhCtx* ctx)
{
    if (ctx != NULL) {
        wp_ecc_free(ctx->peer);
        wp_ecc_free(ctx->key);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate an ECDH key exchange context object.
 *
 * @param [in] src  ECDH key exchange context object.
 * @return  ECDH key exchange context object on success.
 * @return  NULL on failure.
 */
static wp_EcdhCtx* wp_ecdh_dup(wp_EcdhCtx* src)
{
    wp_EcdhCtx* dst = NULL;

    if (wolfssl_prov_is_running()) {
        /* Create a new object. */
        dst = wp_ecdh_new(src->provCtx);
    }
    if (dst != NULL) {
        int ok = 1;

        /* Copy key by up referencing and copying pointer. */
        if ((src->key != NULL) && (!wp_ecc_up_ref(src->key))) {
            ok = 0;
        }
        else {
            dst->key = src->key;
        }
        /* Copy peer's key by up referencing and copying pointer. */
        if (ok && (src->peer != NULL) && (!wp_ecc_up_ref(src->peer))) {
            ok = 0;
        }
        else {
            dst->peer = src->peer;
        }
        /* Copy User Keying Material. */
        if (ok && (src->ukm != NULL) && (src->ukmLen > 0)) {
            dst->ukm = OPENSSL_memdup(src->ukm, src->ukmLen);
            if (dst->ukm == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            /* Copy remaining fields across. */
            dst->cofactor = src->cofactor;
            dst->kdfType  = src->kdfType;
            dst->kdfMd    = src->kdfMd;
            dst->ukmLen   = src->ukmLen;
            dst->keyLen   = src->keyLen;
        }
        if (!ok) {
            /* Free allocated memory and up referenced objects. */
            wp_ecc_free(src->peer);
            wp_ecc_free(src->key);
            OPENSSL_free(dst);
        }
    }

    return dst;
}

/**
 * Initialize the ECDH key exchange object with private key and parameters.
 *
 * @param [in, out] ctx     ECDH key exchange context object.
 * @param [in, out] ecc     ECC key object. (Up referenced.)
 * @param [in]      params  Parameters like KDF info.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdh_init(wp_EcdhCtx* ctx, wp_Ecc* ecc, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (ctx->key != ecc)) {
        /* Free old key and up reference new key. */
        wp_ecc_free(ctx->key);
        ctx->key = NULL;
        if (!wp_ecc_up_ref(ecc)) {
            ok = 0;
        }
    }
    if (ok) {
        /* Set key, default without cofactor and set parameters. */
        ctx->key = ecc;
        ctx->cofactor = 0;
        ok = wp_ecdh_set_ctx_params(ctx, params);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Derive key from secret KDF to produce output.
 *
 * @param [in]  ctx      ECDH key exchange context object.
 * @param [in]  key      Buffer to hold key derived from secret.
 * @param [out] keyLen   Length of derived key in bytes.
 * @param [in]  keySize  Length of buffer in bytes.
 * @param [in]  secret   Secret data.
 * @param [in]  secLen   Length of secret data in bytes.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_ecdh_kdf_derive(wp_EcdhCtx* ctx, unsigned char* key,
    size_t* keyLen, size_t keySize, unsigned char* secret, size_t secLen)
{
    int ok = 1;

    if (keySize < ctx->keyLen) {
        ok = 0;
    }
    if (ok) {
#ifdef HAVE_X963_KDF
        int rc;
        rc = wc_X963_KDF(ctx->kdfMd, secret, (word32)secLen, ctx->ukm,
            (word32)ctx->ukmLen, key, (word32)ctx->keyLen);
        if (rc != 0) {
            ok = 0;
        }
        else {
            *keyLen = ctx->keyLen;
        }
#else
        (void)key;
        (void)keyLen;
        (void)secret;
        (void)secLen;
        ok = 0;
#endif
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Derive secret from ECC keys.
 *
 * @param [in]      ctx     ECDH key exchange context object.
 * @param [in]      secret  Buffer to hold secret.
 * @param [in, out] secLen  On in, size of buffer in bytes.
 *                          On out, length of secret data in bytes.
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_ecdh_derive_secret(wp_EcdhCtx* ctx, unsigned char* secret,
    size_t* secLen)
{
    int ok = 1;
    int rc;
    word32 len = (word32)*secLen;

#ifdef HAVE_ECC_CDH
    if (ctx->cofactor) {
        wc_ecc_set_flags(wp_ecc_get_key(ctx->key), WC_ECC_FLAG_COFACTOR);
    }
#endif
    if ((ok = wp_ecc_check_usage(ctx->key))) {
        /* Calculate secret. */
        PRIVATE_KEY_UNLOCK();
        rc = wc_ecc_shared_secret(wp_ecc_get_key(ctx->key),
            wp_ecc_get_key(ctx->peer), secret, &len);
        PRIVATE_KEY_LOCK();
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *secLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
static int wp_ecdh_derive(wp_EcdhCtx* ctx, unsigned char* secret,
    size_t* secLen, size_t secSize)
{
    int ok = 1;
    int done = 0;
    unsigned char* out;
    size_t outLen;
    unsigned char tmp[72];

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    /* No output buffer, return maximum size only. */
    if (ok && (secret == NULL)) {
        if (ctx->kdfType == WP_KDF_NONE) {
            *secLen = wp_ecc_get_size(ctx->key);
        }
        else {
            *secLen = ctx->keyLen;;
        }
        done = 1;
    }

    if ((!done) && ok) {
        if (ctx->kdfType == WP_KDF_NONE) {
            /* Output of ECDH key exchange directly into secret. */
            out = secret;
            outLen = secSize;
        }
        else if (ctx->kdfType == WP_KDF_X963) {
            /* Output of ECDH key exchange goes into temporary buffer. */
            out = tmp;
            outLen = sizeof(tmp);
        }
        else {
            ok = 0;
        }
    }

    if ((!done) && ok) {
        /* ECDH key exchange derivation using wolfSSL. */
        ok = wp_ecdh_derive_secret(ctx, out, &outLen);
    }

    if ((!done) && ok) {
        if (ctx->kdfType == WP_KDF_X963) {
             /* Put output through KDF using wolfSSL. */
            ok = wp_ecdh_kdf_derive(ctx, secret, secLen, secSize, out, outLen);
        }
        else {
            *secLen = outLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the peer's public key into the ECDH key exchange context object.
 *
 * @param [in, out] ctx   ECDH key exchange context object.
 * @param [in, out] peer  Peer's public key in ECDH key object. (Up referenced.)
 * @return 1 on success.
 * @return 0 on failure.
 */
static int wp_ecdh_set_peer(wp_EcdhCtx* ctx, wp_Ecc* peer)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (ctx->peer != peer)) {
        /* Dispose of the old peer and up reference ECC key. */
        wp_ecc_free(ctx->peer);
        ctx->peer = NULL;
        if (!wp_ecc_up_ref(peer)) {
            ok = 0;
        }
    }
    if (ok) {
        ctx->peer = peer;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the KDF algorithm from the parameters.
 *
 * @param [in, out] ctx     ECDH key exchange context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdh_set_param_kdf(wp_EcdhCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const char* kdf = NULL;

    if (!wp_params_get_utf8_string_ptr(params, OSSL_EXCHANGE_PARAM_KDF_TYPE,
            &kdf)) {
        ok = 0;
    }
    if (ok && (kdf != NULL)) {
        if (kdf[0] == '\0') {
            ctx->kdfType = WP_KDF_NONE;
        }
        else if (XSTRNCMP(kdf, OSSL_KDF_NAME_X942KDF_ASN1, XSTRLEN(kdf)) == 0) {
            /* Only support the non ASN1 variant. */
            ctx->kdfType = WP_KDF_X963;
        }
        else {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the KDF digest from the parameters.
 *
 * @param [in, out] ctx     ECDH key exchange context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdh_set_param_kdf_digest(wp_EcdhCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;
    const char* mdName = NULL;

    if (!wp_params_get_utf8_string_ptr(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST,
            &mdName)) {
        ok = 0;
    }
    if (ok && (mdName != NULL)) {
        const char* mdProps = NULL;

        XMEMCPY(ctx->kdfMdName, mdName, XSTRLEN(mdName) + 1);
        if (!wp_params_get_utf8_string_ptr(params,
                    OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, &mdProps)) {
            ok = 0;
        }
        if (ok) {
            ctx->kdfMd = wp_name_to_wc_hash_type(ctx->provCtx->libCtx, mdName,
                mdProps);
            if (ctx->kdfMd == WC_HASH_TYPE_NONE) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the ECDH key exchange parameters.
 *
 * @param [in, out] ctx     ECDH key exchange context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdh_set_ctx_params(wp_EcdhCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    if (params != NULL) {
        if (!wp_params_get_int(params,
                OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, &ctx->cofactor)) {
            ok = 0;
        }
        if (ok && (!wp_ecdh_set_param_kdf(ctx, params))) {
            ok = 0;
        }
        if (ok && (!wp_ecdh_set_param_kdf_digest(ctx, params))) {
            ok = 0;
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
            if ((p != NULL) && !OSSL_PARAM_get_size_t(p, &ctx->keyLen)) {
                ok = 0;
            }
        }
        if (ok && (!wp_params_get_octet_string(params,
                OSSL_EXCHANGE_PARAM_KDF_UKM, &ctx->ukm, &ctx->ukmLen, 0))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported settable parameters for the ECDH ke context.
 *
 * @param [in] ctx      ECDH key exchange context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecdh_settable_ctx_params(wp_EcdhCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for ECDH key exchange context.
     */
    static const OSSL_PARAM wp_ecdh_supported_settable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_ecdh_supported_settable_ctx_params;
}

/**
 * Get the KDF algorithm from the context and put into parameters.
 *
 * @param [in]      ctx     ECDH key exchange context object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdh_get_params_kdf(wp_EcdhCtx* ctx, OSSL_PARAM params[])
{
     int ok = 1;
     OSSL_PARAM* p;

     p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
     if (p != NULL) {
         const char* type = "";
         if (ctx->kdfType == WP_KDF_X963) {
             type = OSSL_KDF_NAME_X942KDF_ASN1;
         }
         if (ok && (!OSSL_PARAM_set_utf8_string(p, type))) {
             ok = 0;
         }
     }

     WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
     return ok;
}

/**
 * Get the ECDH key exchange context parameters.
 *
 * @param [in]      ctx     ECDH key exchange context object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdh_get_ctx_params(wp_EcdhCtx* ctx, OSSL_PARAM params[])
{
     int ok = 1;
     OSSL_PARAM* p;

     p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
     if ((p != NULL) && (!OSSL_PARAM_set_int(p, ctx->cofactor))) {
         ok = 0;
     }
     if (ok && (!wp_ecdh_get_params_kdf(ctx, params))) {
         ok = 0;
     }
     if (ok) {
         p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
         if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, ctx->kdfMdName))) {
             ok = 0;
         }
     }
     if (ok) {
         p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
         if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, ctx->keyLen))) {
             ok = 0;
         }
     }
     if (ok) {
         p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
         if ((p != NULL) && (!OSSL_PARAM_set_octet_ptr(p, ctx->ukm,
                 ctx->ukmLen))) {
             ok = 0;
         }
     }

     WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
     return ok;
}

/**
 * Return an array of supported gettable parameters for the ECDH ke context.
 *
 * @param [in] ctx      ECDH key exchange context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecdh_gettable_ctx_params(wp_EcdhCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for ECDH key exchange context.
     */
    static const OSSL_PARAM wp_ecdh_supported_gettable_ctx_params[] = {
        OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
        OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR,
                        NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_ecdh_supported_gettable_ctx_params;
}

/** Dispatch table for ECDH key exchange. */
const OSSL_DISPATCH wp_ecdh_keyexch_functions[] = {
    { OSSL_FUNC_KEYEXCH_NEWCTX,            (DFUNC)wp_ecdh_new                 },
    { OSSL_FUNC_KEYEXCH_FREECTX,           (DFUNC)wp_ecdh_free                },
    { OSSL_FUNC_KEYEXCH_DUPCTX,            (DFUNC)wp_ecdh_dup                 },
    { OSSL_FUNC_KEYEXCH_INIT,              (DFUNC)wp_ecdh_init                },
    { OSSL_FUNC_KEYEXCH_DERIVE,            (DFUNC)wp_ecdh_derive              },
    { OSSL_FUNC_KEYEXCH_SET_PEER,          (DFUNC)wp_ecdh_set_peer            },
    { OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,    (DFUNC)wp_ecdh_set_ctx_params      },
    { OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
                                           (DFUNC)wp_ecdh_settable_ctx_params },
    { OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,    (DFUNC)wp_ecdh_get_ctx_params      },
    { OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
                                           (DFUNC)wp_ecdh_gettable_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_ECDH */

