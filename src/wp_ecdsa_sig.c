/* wp_ecdsa_sig.c
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


#ifdef WP_HAVE_ECDSA

/**
 * ECDSA signature context.
 *
 * Used to store context and state of signing/verification operations.
 */
typedef struct wp_EcdsaSigCtx {
    /** wolfProvider context object. */
    WOLFPROV_CTX *provCtx;
    /** Library context object. */
    OSSL_LIB_CTX *libCtx;

    /** wolfProvider ECC object. */
    wp_Ecc* ecc;

    /** Operation being performed as an EVP define. */
    int op;

    /** wolfSSL hash object. */
    wc_HashAlg hash;
#if LIBWOLFSSL_VERSION_HEX < 0x05007004
    /** Hash algorithm to use on data to be signed. */
    enum wc_HashType hashType;
#endif

    /** Property query string. */
    char* propQuery;
    /** Name of hash algorithm. */
    char mdName[WP_MAX_MD_NAME_SIZE];
} wp_EcdsaSigCtx;


/* Prototype for wp_ecdsa_signverify_init() to use.  */
static int wp_ecdsa_set_ctx_params(wp_EcdsaSigCtx *ctx,
    const OSSL_PARAM params[]);

/**
 * Create a new ECDSA signature context object.
 *
 * @param [in] provCtx    wolfProvider context object.
 * @param [in] propQuery  Property query.
 * @return  NULL on failure.
 * @return  ECDSA signature context object on success.
 */
static wp_EcdsaSigCtx* wp_ecdsa_newctx(WOLFPROV_CTX* provCtx,
    const char* propQuery)
{
    wp_EcdsaSigCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int ok = 1;
        char* p = NULL;

        if (propQuery != NULL) {
            p = OPENSSL_strdup(propQuery);
            if (p == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            ctx->propQuery = p;
            ctx->provCtx = provCtx;
            ctx->libCtx = provCtx->libCtx;
        }

        if (!ok) {
            OPENSSL_free(p);
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Free an ECDSA signature context object.
 *
 * @param [in, out] ctx  ECDSA signature context object. May be NULL.
 */
static void wp_ecdsa_freectx(wp_EcdsaSigCtx* ctx)
{
    if (ctx != NULL) {
        wp_ecc_free(ctx->ecc);
        OPENSSL_free(ctx->propQuery);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate the ECDSA signature context object.
 *
 * @param [in] srcCtx  ECDSA signature context object.
 * @retturn  NULL on failure.
 * @return   ECDSA signature context object on success.
 */
static wp_EcdsaSigCtx* wp_ecdsa_dupctx(wp_EcdsaSigCtx* srcCtx)
{
    wp_EcdsaSigCtx* dstCtx = NULL;

    if (wolfssl_prov_is_running()) {
        int ok = 1;

        dstCtx = wp_ecdsa_newctx(srcCtx->provCtx, srcCtx->propQuery);
        if (dstCtx == NULL) {
            ok = 0;
        }

        if (ok && (!wp_hash_copy(&srcCtx->hash, &dstCtx->hash
#if LIBWOLFSSL_VERSION_HEX < 0x05007004
                        ,srcCtx->hashType
#endif
                        ))) {
            ok = 0;
        }
        if (ok && (!wp_ecc_up_ref(srcCtx->ecc))) {
            ok = 0;
        }
        if (ok) {
            dstCtx->ecc      = srcCtx->ecc;
#if LIBWOLFSSL_VERSION_HEX < 0x05007004
            dstCtx->hashType = srcCtx->hashType;
#endif
            dstCtx->op       = srcCtx->op;
            XMEMCPY(dstCtx->mdName, srcCtx->mdName, sizeof(srcCtx->mdName));
        }

        if (!ok) {
            wp_ecdsa_freectx(dstCtx);
            dstCtx = NULL;
        }
    }

    return dstCtx;
}

/**
 * Initialize ECDSA signature context object for signing/verification.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @param [in]      op      Signature operation to perform.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_signverify_init(wp_EcdsaSigCtx *ctx, wp_Ecc* ecc,
    const OSSL_PARAM params[], int op)
{
    int ok = 1;

    if (ctx == NULL || (ecc == NULL && ctx->ecc == NULL)) {
        ok = 0;
    }
    else if (ecc != NULL) {
        if (!wp_ecc_up_ref(ecc)) {
            ok = 0;
        }
        if (ok) {
            wp_ecc_free(ctx->ecc);
            ctx->ecc = ecc;
        }
    }

    if (ok) {
        ctx->op = op;

        if (!wp_ecdsa_set_ctx_params(ctx, params)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize ECDSA signature context object for signing.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_sign_init(wp_EcdsaSigCtx *ctx, wp_Ecc *ecc,
    const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecdsa_signverify_init(ctx, ecc, params, EVP_PKEY_OP_SIGN);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sign the data using an ECDSA key.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      ECDSA signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature data in bytes.
 * @param [in]      sigSize  Size of signature buffer in bytes.
 * @param [in]      tbs      Data to be signed.
 * @param [in]      tbsLen   Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_sign(wp_EcdsaSigCtx *ctx, unsigned char *sig,
    size_t *sigLen, size_t sigSize, const unsigned char *tbs, size_t tbsLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (sig == NULL) {
        *sigLen = wc_ecc_sig_size(wp_ecc_get_key(ctx->ecc));
    }
    else {
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        if ((ctx->hash.type != WC_HASH_TYPE_NONE) &&
            (tbsLen != (size_t)wc_HashGetDigestSize(ctx->hash.type)))
#else
        if ((ctx->hashType != WC_HASH_TYPE_NONE) &&
            (tbsLen != (size_t)wc_HashGetDigestSize(ctx->hashType)))
#endif
        {
            ok = 0;
        }
        else if ((ok = wp_ecc_check_usage(ctx->ecc))) {
            int rc;
            word32 len;

            if (sigSize == (size_t)-1) {
                sigSize = *sigLen;
            }
            len = (word32)sigSize;
            if (wp_lock(wp_ecc_get_mutex(ctx->ecc)) != 1) {
                ok = 0;
            }
            if (ok) {
                PRIVATE_KEY_UNLOCK();
                rc = wc_ecc_sign_hash(tbs, (word32)tbsLen, sig, &len,
                    wp_ecc_get_rng(ctx->ecc), wp_ecc_get_key(ctx->ecc));
                PRIVATE_KEY_LOCK();
                wp_unlock(wp_ecc_get_mutex(ctx->ecc));
                if (rc != 0) {
                    ok = 0;
                }
                else {
                    *sigLen = len;
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize ECDSA signature context object for verifying.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_verify_init(wp_EcdsaSigCtx *ctx, wp_Ecc *ecc,
    const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecdsa_signverify_init(ctx, ecc, params, EVP_PKEY_OP_VERIFY);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify an ECDSA signature.
 *
 * @param [in] ctx     ECDSA signature context object.
 * @param [in] sig     Signature data.
 * @param [in] sigLen  Length of signature data in bytes.
 * @param [in] tbs     Data to be signed.
 * @param [in] tbsLen  Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_verify(wp_EcdsaSigCtx *ctx, const unsigned char *sig,
    size_t sigLen, const unsigned char *tbs, size_t tbsLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        int res;
        int rc = wc_ecc_verify_hash(sig, (word32)sigLen, tbs, (word32)tbsLen,
            &res, wp_ecc_get_key(ctx->ecc));
        if (rc != 0) {
            ok = 0;
        }
        if (res == 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize ECDSA signature context object for verifying with recovery.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_verify_recover_init(wp_EcdsaSigCtx *ctx, wp_Ecc *ecc,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecdsa_signverify_init(ctx, ecc, params,
            EVP_PKEY_OP_VERIFYRECOVER);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify and recover an ECDSA signature.
 *
 * @param [in] ctx     ECDSA signature context object.
 * @param [in] sig     Signature data.
 * @param [in] sigLen  Length of signature data in bytes.
 * @param [in] tbs     Data to be signed.
 * @param [in] tbsLen  Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_verify_recover(wp_EcdsaSigCtx *ctx, const unsigned char *rout,
    size_t *routlen, size_t routsize, const unsigned char *sig, size_t sigLen)
{
    /* TODO: implement */
    (void)ctx;
    (void)rout;
    (void)routlen;
    (void)routsize;
    (void)sig;
    (void)sigLen;
    return 0;
}

/**
 * Setup the message digest based on name and properties.
 *
 * @param [in, out] ctx      ECDSA signature context object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @param [in]      op       Signature operation being performed.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_setup_md(wp_EcdsaSigCtx *ctx, const char *mdName,
    const char *mdProps, int op)
{
    int ok = 1;

    (void)op;

    if (mdProps == NULL) {
        mdProps = ctx->propQuery;
    }

    if (mdName != NULL) {
        int rc;

#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        ctx->hash.type = wp_name_to_wc_hash_type(ctx->libCtx, mdName, mdProps);
        if ((ctx->hash.type == WC_HASH_TYPE_NONE) ||
            (ctx->hash.type == WC_HASH_TYPE_MD5))
#else
        ctx->hashType = wp_name_to_wc_hash_type(ctx->libCtx, mdName, mdProps);
        if ((ctx->hashType == WC_HASH_TYPE_NONE) ||
            (ctx->hashType == WC_HASH_TYPE_MD5))
#endif
        {
            ok = 0;
        }
#ifdef HAVE_FIPS
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        if ((ctx->hash.type == WC_HASH_TYPE_SHA) && (op == EVP_PKEY_OP_SIGN))
#else
        if ((ctx->hashType == WC_HASH_TYPE_SHA) && (op == EVP_PKEY_OP_SIGN))
#endif
        {
            ok = 0;
        }
#endif

        if (ok) {
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            rc = wc_HashInit_ex(&ctx->hash, ctx->hash.type, NULL, INVALID_DEVID);
#else
            rc = wc_HashInit_ex(&ctx->hash, ctx->hashType, NULL, INVALID_DEVID);
#endif
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            OPENSSL_strlcpy(ctx->mdName, mdName, sizeof(ctx->mdName));
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize ECDSA signature context object for signing/verifying digested data.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @param [in]      op      Signature operation being performed.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_digest_signverify_init(wp_EcdsaSigCtx *ctx,
    const char *mdName, wp_Ecc *ecc, const OSSL_PARAM params[], int op)
{
    int ok;

    ok = wp_ecdsa_signverify_init(ctx, ecc, params, op);
    if (ok) {
        if ((mdName != NULL) && ((mdName[0] == '\0') ||
            (strcasecmp(ctx->mdName, mdName) != 0))) {
            ok = wp_ecdsa_setup_md(ctx, mdName, ctx->propQuery, op);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Digest data for signing/verification.
 *
 * @param [in, out] ctx       ECDSA signature context object.
 * @param [in]      data      Data to sign/verify.
 * @param [in]      dataLen   Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_digest_signverify_update(wp_EcdsaSigCtx *ctx,
    const unsigned char *data, size_t dataLen)
{
    int ok = 1;
    int rc = wc_HashUpdate(&ctx->hash,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            ctx->hash.type,
#else
            ctx->hashType,
#endif
            data, (word32)dataLen);
    if (rc != 0) {
        ok = 0;
    }
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize ECDSA signature context object for signing digested data.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_digest_sign_init(wp_EcdsaSigCtx *ctx, const char *mdName,
    wp_Ecc *ecc, const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecdsa_digest_signverify_init(ctx, mdName, ecc, params,
            EVP_PKEY_OP_SIGN);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the signing operation on data that is digested.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      ECDSA signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature in bytes.
 * @param [in]      sigSize  Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_digest_sign_final(wp_EcdsaSigCtx *ctx, unsigned char *sig,
    size_t *sigLen, size_t sigSize)
{
    int ok = 1;
    unsigned char digest[WC_MAX_DIGEST_SIZE];

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (sig != NULL) {
        int rc = wc_HashFinal(&ctx->hash,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type,
#else
                ctx->hashType,
#endif
                digest);
        if (rc != 0) {
            ok = 0;
        }
    }

    if (ok) {
        ok = wp_ecdsa_sign(ctx, sig, sigLen, sigSize, digest,
            wc_HashGetDigestSize(
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type
#else
                ctx->hashType
#endif
            ));
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize ECDSA signature context object for verifying digested data.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      ecc     ECC key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_digest_verify_init(wp_EcdsaSigCtx *ctx, const char *mdName,
    wp_Ecc *ecc, const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecdsa_digest_signverify_init(ctx, mdName, ecc, params,
            EVP_PKEY_OP_VERIFY);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the verification operation on data that is digested.
 *
 * @param [in, out] ctx      ECDSA signature context object.
 * @param [in]      sig      Signature data.
 * @param [in]      sigLen   Length of signature in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_digest_verify_final(wp_EcdsaSigCtx *ctx, unsigned char *sig,
    size_t sigLen)
{
    int ok = 1;
    unsigned char digest[WC_MAX_DIGEST_SIZE];

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        int rc = wc_HashFinal(&ctx->hash,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type,
#else
                ctx->hashType,
#endif
                digest);
        if (rc != 0) {
            ok = 0;
        }
    }

    if (ok) {
        ok = wp_ecdsa_verify(ctx,sig, sigLen, digest,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            wc_HashGetDigestSize(ctx->hash.type)
#else
            wc_HashGetDigestSize(ctx->hashType)
#endif
            );
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put DER encoding of the ECDSA signature algorithm in the parameter object.
 *
 * @param [in] ctx  ECDSA signature context object.
 * @param [in] p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_get_alg_id(wp_EcdsaSigCtx *ctx, OSSL_PARAM *p)
{
    int ok = 0;

    if (XMEMCMP(ctx->mdName, "SHA256", 7) == 0) {
        static const unsigned char ecdsa_sha256[] = {
            0x30, 0x0a, 0x06, 0x08, 42, 134, 72, 206, 61, 4, 3, 2
        };
        ok = OSSL_PARAM_set_octet_string(p, ecdsa_sha256, sizeof(ecdsa_sha256));
    }
    if (XMEMCMP(ctx->mdName, "SHA384", 7) == 0) {
        static const unsigned char ecdsa_sha384[] = {
            0x30, 0x0a, 0x06, 0x08, 42, 134, 72, 206, 61, 4, 3, 3
        };
        ok = OSSL_PARAM_set_octet_string(p, ecdsa_sha384, sizeof(ecdsa_sha384));
    }
    if (XMEMCMP(ctx->mdName, "SHA512", 7) == 0) {
        static const unsigned char ecdsa_sha512[] = {
            0x30, 0x0a, 0x06, 0x08, 42, 134, 72, 206, 61, 4, 3, 4
        };
        ok = OSSL_PARAM_set_octet_string(p, ecdsa_sha512, sizeof(ecdsa_sha512));
    }
    /* TODO: support more digests */

    return ok;
}

/**
 * Put data from ECDSA signture context object into parameter objects.
 *
 * @param [in] ctx     ECDSA signature context object.
 * @param [in] params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_get_ctx_params(wp_EcdsaSigCtx *ctx, OSSL_PARAM *params)
{
    int ok = 1;
    OSSL_PARAM *p;

    if (ctx == NULL) {
        ok = 0;
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL) {
            ok = wp_ecdsa_get_alg_id(ctx, p);
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, ctx->mdName)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Parameters that we support getting from the ECDSA signature context. */
static const OSSL_PARAM wp_supported_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};
/**
 * Returns an array of ECDSA signature context parameters that can be retrieved.
 *
 * @param [in] ctx      ECDSA signature context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_ecdsa_gettable_ctx_params(wp_EcdsaSigCtx *ctx,
    WOLFPROV_CTX *provCtx)
{
    (void)ctx;
    (void)provCtx;
    return wp_supported_gettable_ctx_params;
}

/**
 * Sets the digest to use into ECDSA signature context object.
 *
 * @param [in, out] ctx         ECDSA signature context object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_set_digest(wp_EcdsaSigCtx *ctx, const OSSL_PARAM *p,
    const OSSL_PARAM *propsParam)
{
    int ok = 1;
    char mdName[WP_MAX_MD_NAME_SIZE];
    char* pmdName = mdName;
    char mdProps[WP_MAX_MD_NAME_SIZE];
    char* pmdProps = NULL;

    if (!OSSL_PARAM_get_utf8_string(p, &pmdName, sizeof(mdName))) {
        ok = 0;
    }
    if (ok && propsParam != NULL) {
        pmdProps = mdProps;
        if (!OSSL_PARAM_get_utf8_string(propsParam, &pmdProps,
                                        sizeof(mdProps))) {
            ok = 0;
        }
    }
    if (ok) {
        ok = wp_ecdsa_setup_md(ctx, mdName, pmdProps, ctx->op);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into ECDSA signature context object.
 *
 * @param [in, out] ctx     ECDSA signature context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecdsa_set_ctx_params(wp_EcdsaSigCtx *ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM *p;
    const OSSL_PARAM *propsParam;

    if (params != NULL) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL) {
            propsParam = OSSL_PARAM_locate_const(params,
                OSSL_SIGNATURE_PARAM_PROPERTIES);
            ok = wp_ecdsa_set_digest(ctx, p, propsParam);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Parameters that we support setting into the ECDSA signature context. */
static const OSSL_PARAM wp_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};
/**
 * Returns an array of ECDSA signature context parameters that can be set.
 *
 * @param [in] ctx      ECDSA signature context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_ecdsa_settable_ctx_params(wp_EcdsaSigCtx *ctx,
    WOLFPROV_CTX* provCtx)
{
    (void)ctx;
    (void)provCtx;
    return wp_settable_ctx_params;
}

/**
 * Get the parameters of the digest object.
 *
 * @param [in] ctx     ECDSA signature context object.
 * @param [in] params  Array of parameter objects.
 * @param  0 on failure.
 */
static int wp_ecdsa_get_ctx_md_params(wp_EcdsaSigCtx *ctx, OSSL_PARAM *params)
{
    /* TODO: implement */
    (void)ctx;
    (void)params;
    return 0;
}

/**
 * Returns an array of digest parameters that can be retrieved.
 *
 * @param [in] ctx      ECDSA signature context object. Unused.
 * @return  NULL on failure.
 */
static const OSSL_PARAM* wp_ecdsa_gettable_ctx_md_params(wp_EcdsaSigCtx *ctx)
{
    /* TODO: implement */
    (void)ctx;
    return NULL;
}

/**
 * Set the parameters of the digest object.
 *
 * @param [in] ctx     ECDSA signature context object.
 * @param [in] params  Array of parameter objects.
 * @param  0 on failure.
 */
static int wp_ecdsa_set_ctx_md_params(wp_EcdsaSigCtx *ctx,
    const OSSL_PARAM params[])
{
    /* TODO: implement */
    (void)ctx;
    (void)params;
    return 0;
}

/**
 * Returns an array of digest parameters that can be set.
 *
 * @param [in] ctx      ECDSA signature context object. Unused.
 * @return  NULL on failure.
 */
static const OSSL_PARAM *wp_ecdsa_settable_ctx_md_params(wp_EcdsaSigCtx *ctx)
{
    /* TODO: implement */
    (void)ctx;
    return NULL;
}

/** Dspatch table for ECDSA signing and verification. */
const OSSL_DISPATCH wp_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,             (DFUNC)wp_ecdsa_newctx          },
    { OSSL_FUNC_SIGNATURE_FREECTX,            (DFUNC)wp_ecdsa_freectx         },
    { OSSL_FUNC_SIGNATURE_DUPCTX,             (DFUNC)wp_ecdsa_dupctx          },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,          (DFUNC)wp_ecdsa_sign_init       },
    { OSSL_FUNC_SIGNATURE_SIGN,               (DFUNC)wp_ecdsa_sign            },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,        (DFUNC)wp_ecdsa_verify_init     },
    { OSSL_FUNC_SIGNATURE_VERIFY,             (DFUNC)wp_ecdsa_verify          },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
                                     (DFUNC)wp_ecdsa_verify_recover_init      },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,     (DFUNC)wp_ecdsa_verify_recover  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
                                     (DFUNC)wp_ecdsa_digest_sign_init         },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
                                     (DFUNC)wp_ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
                                     (DFUNC)wp_ecdsa_digest_sign_final        },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
                                     (DFUNC)wp_ecdsa_digest_verify_init       },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
                                     (DFUNC)wp_ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
                                     (DFUNC)wp_ecdsa_digest_verify_final      },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,     (DFUNC)wp_ecdsa_get_ctx_params  },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_ecdsa_gettable_ctx_params      },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,     (DFUNC)wp_ecdsa_set_ctx_params  },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                                     (DFUNC)wp_ecdsa_settable_ctx_params      },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
                                     (DFUNC)wp_ecdsa_get_ctx_md_params        },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
                                     (DFUNC)wp_ecdsa_gettable_ctx_md_params   },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
                                     (DFUNC)wp_ecdsa_set_ctx_md_params        },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
                                     (DFUNC)wp_ecdsa_settable_ctx_md_params   },
    { 0, NULL }
};

#endif /* WP_HAVE_ECDSA */

