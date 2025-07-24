/* wp_rsa_sig.c
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
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_RSA

/* wolfCrypt FIPS does not have this defined */
#ifndef RSA_PSS_SALT_LEN_DEFAULT
    #define RSA_PSS_SALT_LEN_DEFAULT    -1
#endif

/**
 * Maximum DER digest size, taken from wolfSSL. Sum of the maximum size of the
 * encoded digest, algorithm tag, and sequence tag.
 */
#define MAX_DER_DIGEST_SZ       98

/** Array of supported padding modes mapping id/string. */
static OSSL_ITEM wp_pad_mode[] = {
    { RSA_PKCS1_PADDING,        (char*)OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           (char*)OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_X931_PADDING,         (char*)OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_PSS_PADDING,    (char*)OSSL_PKEY_RSA_PAD_MODE_PSS },
};

/** Length of padding mode array. */
#define WP_PAD_MODE_LEN    (sizeof(wp_pad_mode) / sizeof(*wp_pad_mode))

/** Default message digest for RSA. */
#define WP_RSA_DEFAULT_MD       "SHA256"

/**
 * RSA signature context.
 *
 * Used to store context and state of signing/verification operations.
 */
typedef struct wp_RsaSigCtx {
    /** wolfProvider context object. */
    WOLFPROV_CTX* provCtx;
    /** Library context object. */
    OSSL_LIB_CTX* libCtx;

    /** wolfProvider RSA object. */
    wp_Rsa* rsa;
    /** wolfSSL random number generator for signing. */
    WC_RNG rng;

    /** Operation being performed as an EVP define. */
    int op;
    /** Padding mode to use with operation. */
    int padMode;

    /** wolfSSL hash object. */
    wc_HashAlg hash;
#if LIBWOLFSSL_VERSION_HEX < 0x05007004
    /** Hash algorithm to use on data to be signed. */
    enum wc_HashType hashType;
#endif
    /** Length of salt to use when padding mode is PSS. */
    int saltLen;
    /** Minimum salt length when padding mode is PSS based on RSA key. */
    int minSaltLen;
    /** wolfSSL id of MGF operation to perform when padding mode is PSS. */
    int mgf;
    /** Indicates that the MGF id has been set explicitly. */
    unsigned int mgfSet:1;

    /** Property query string. */
    char* propQuery;
    /** Name of hash algorithm. */
    char mdName[WP_MAX_MD_NAME_SIZE];
    /** Name of hash algorithm used in MGF1 algorithm. */
    char mgf1MdName[WP_MAX_MD_NAME_SIZE];
} wp_RsaSigCtx;


/* Prototype for wp_rsa_signverify_init() to use.  */
static int wp_rsa_set_ctx_params(wp_RsaSigCtx* ctx, const OSSL_PARAM params[]);

/**
 * Setup the message digest based on name and properties.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @param [in]      op       Signature operation being performed.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_setup_md(wp_RsaSigCtx* ctx, const char* mdName,
    const char* mdProps, int op)
{
    int ok = 1;

    if (mdProps == NULL) {
        mdProps = ctx->propQuery;
    }

    if (mdName != NULL) {
        int rc;
        enum wc_HashType hashType;

        hashType = wp_name_to_wc_hash_type(ctx->libCtx, mdName, mdProps);
        if (ctx->padMode == RSA_NO_PADDING) {
            if (hashType != WC_HASH_TYPE_NONE) {
                ok = 0;
            }
        }
        else if ((hashType == WC_HASH_TYPE_NONE) ||
            (hashType == WC_HASH_TYPE_MD5)) {
            ok = 0;
        }
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        if (ok && (ctx->hash.type != WC_HASH_TYPE_NONE) &&
            (hashType != ctx->hash.type))
#else
        if (ok && (ctx->hashType != WC_HASH_TYPE_NONE) &&
            (hashType != ctx->hashType))
#endif
        {
            ok = 0;
        }
#ifdef HAVE_FIPS
        if (ok && (hashType == WC_HASH_TYPE_SHA) && (op == EVP_PKEY_OP_SIGN)) {
            ok = 0;
        }
#else
        (void)op;
#endif
        if (ok) {
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            ctx->hash.type = hashType;
#else
            ctx->hashType = hashType;
#endif
        }

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

        if (ok && (!ctx->mgfSet)) {
            ctx->mgf = wp_name_to_wc_mgf(ctx->libCtx, mdName, mdProps);
            if (ctx->mgf == WC_MGF1NONE) {
                if (ctx->padMode == RSA_PKCS1_PSS_PADDING) {
                    ok = 0;
                }
            }
            else {
                OPENSSL_strlcpy(ctx->mgf1MdName, mdName, sizeof(ctx->mdName));
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Setup the MGF1 digest algorithm based on name and properties.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_setup_mgf1_md(wp_RsaSigCtx* ctx, const char* mdName,
    const char* mdProps)
{
    int ok = 1;
    int mgf;

    if (mdName != NULL) {
        OPENSSL_strlcpy(ctx->mgf1MdName, mdName, sizeof(ctx->mgf1MdName));
        mgf = wp_name_to_wc_mgf(ctx->libCtx, mdName, mdProps);
        if (mgf == WC_MGF1NONE) {
            ok = 0;
        }
        if (ok && ctx->mgfSet && (ctx->mgf != mgf)) {
            ok = 0;
        }
        if (ok) {
            ctx->mgf    = mgf;
            ctx->mgfSet = 1;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a new RSA signature context object.
 *
 * @param [in] provCtx    wolfProvider context object.
 * @param [in] propQuery  Property query.
 * @return  NULL on failure.
 * @return  RSA signature context object on success.
 */
static wp_RsaSigCtx* wp_rsa_ctx_new(WOLFPROV_CTX* provCtx,
    const char* propQuery)
{
    wp_RsaSigCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int ok = 1;
        char* p = NULL;
        int rc;

        if (propQuery != NULL) {
            p = OPENSSL_strdup(propQuery);
            if (p == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_InitRng(&ctx->rng);
            if (rc != 0) {
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
 * Free an RSA signature context object.
 *
 * @param [in, out] ctx  RSA signature context object. May be NULL.
 */
static void wp_rsa_ctx_free(wp_RsaSigCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        wp_rsa_free(ctx->rsa);
        OPENSSL_free(ctx->propQuery);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate the RSA signature context object.
 *
 * @param [in] srcCtx  RSA signature context object.
 * @retturn  NULL on failure.
 * @return   RSA signature context object on success.
 */
static wp_RsaSigCtx* wp_rsa_ctx_dup(wp_RsaSigCtx* srcCtx)
{
    wp_RsaSigCtx* dstCtx = NULL;

    if (wolfssl_prov_is_running()) {
        int ok = 1;

        dstCtx = wp_rsa_ctx_new(srcCtx->provCtx, srcCtx->propQuery);
        if (dstCtx == NULL) {
            ok = 0;
        }

#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        if (ok && (srcCtx->hash.type != WC_HASH_TYPE_NONE) &&
            (!wp_hash_copy(&srcCtx->hash, &dstCtx->hash)))
#else
        if (ok && (srcCtx->hashType != WC_HASH_TYPE_NONE) &&
            (!wp_hash_copy(&srcCtx->hash, &dstCtx->hash,srcCtx->hashType)))
#endif
        {
            ok = 0;
        }
        if (ok && (!wp_rsa_up_ref(srcCtx->rsa))) {
            ok = 0;
        }
        if (ok) {
            dstCtx->rsa      = srcCtx->rsa;
#if LIBWOLFSSL_VERSION_HEX < 0x05007004
            dstCtx->hashType = srcCtx->hashType;
#endif
            dstCtx->mgf      = srcCtx->mgf;
            dstCtx->mgfSet   = srcCtx->mgfSet;
            dstCtx->padMode  = srcCtx->padMode;
            dstCtx->op       = srcCtx->op;
            dstCtx->saltLen  = srcCtx->saltLen;
            XMEMCPY(dstCtx->mdName, srcCtx->mdName, sizeof(srcCtx->mdName));
            XMEMCPY(dstCtx->mgf1MdName, srcCtx->mgf1MdName,
                sizeof(srcCtx->mgf1MdName));
        }

        if (!ok) {
            wp_rsa_ctx_free(dstCtx);
            dstCtx = NULL;
        }
    }

    return dstCtx;
}

/**
 * Convert OpenSSL PSS salt length to wolfCrypt value.
 *
 * @param [in] saltLen   OpenSSL salt length.
 * @param [in] hashType  Hash algorithm.
 * @param [in] key       RSA key.
 * @param [in] op        Signature operation being performed.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_pss_salt_len_to_wc(int saltLen, enum wc_HashType hashType,
    RsaKey* key, int op)
{
    (void)hashType;
    (void)key;
    (void)op;

    if (saltLen == RSA_PSS_SALTLEN_DIGEST) {
        saltLen = RSA_PSS_SALT_LEN_DEFAULT;
    }
    else if (saltLen == RSA_PSS_SALTLEN_MAX) {
        saltLen = wc_RsaEncryptSize(key) - wc_HashGetDigestSize(hashType) - 2;
        if (((mp_count_bits(&key->n) - 1) & 0x7) == 0) {
            saltLen--;
        }
    }
    else if (saltLen == RSA_PSS_SALTLEN_AUTO) {
    #ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
        saltLen = wc_HashGetDigestSize(hashType);
    #else
        saltLen = RSA_PSS_SALT_LEN_DISCOVER;
    #endif
    }
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    else if (saltLen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        saltLen = wc_HashGetDigestSize(hashType);
    }
#endif

    return saltLen;
}

/**
 * Check the validity of the PSS salt length.
 *
 * minSaltLen is from the key.
 * Validate minSaltLen is a positive value and not greater than maximum.
 * Validate saltLen is a valid special value and not less than minSaltLen.
 *
 * @param [in] ctx  RSA signature context object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_check_pss_salt_len(wp_RsaSigCtx* ctx)
{
    int ok = 1;
    int maxSaltLen;
    int bits = wp_rsa_get_bits(ctx->rsa);

#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
    maxSaltLen = ((bits + 7) / 8) - wc_HashGetDigestSize(ctx->hash.type) - 2;
#else
    maxSaltLen = ((bits + 7) / 8) - wc_HashGetDigestSize(ctx->hashType) - 2;
#endif
    if (((bits - 1) & 0x07) == 0) {
        maxSaltLen--;
    }

    if ((ctx->minSaltLen < 0) || (ctx->minSaltLen > maxSaltLen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
        ok = 0;
    }
    if (ok && (ctx->minSaltLen < 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
        ok = 0;
    }
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    if (ok && (ctx->saltLen < RSA_PSS_SALTLEN_AUTO_DIGEST_MAX)) {
        ok = 0;
    }
#else
    if (ok && (ctx->saltLen < RSA_PSS_SALTLEN_MAX)) {
        ok = 0;
    }
#endif
    if (ok && (ctx->saltLen >= 0) && (ctx->saltLen < ctx->minSaltLen)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA signature context object for signing/verification.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @param [in]      op      Signature operation to perform.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_signverify_init(wp_RsaSigCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[], int op)
{
    int ok = 1;

    if ((ctx == NULL) || (ctx->rsa == NULL && rsa == NULL)) {
        ok = 0;
    }
    else if (rsa != NULL) {
        if (!wp_rsa_up_ref(rsa)) {
            ok = 0;
        }
        if (ok) {
            wp_rsa_free(ctx->rsa);
            ctx->rsa = rsa;
        }
    }
    if (ok) {
        ctx->op = op;

        if (!wp_rsa_set_ctx_params(ctx, params)) {
            ok = 0;
        }
    }
    if (ok) {
        if (wp_rsa_get_type(ctx->rsa) == RSA_FLAG_TYPE_RSA) {
            if (ctx->padMode != RSA_X931_PADDING) {
                ctx->padMode = RSA_PKCS1_PADDING;
            }
        }
        else if (!wp_rsa_get_pss_params_set(ctx->rsa)) {
            ctx->padMode = RSA_PKCS1_PSS_PADDING;
        #ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
            ctx->saltLen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
        #else
            ctx->saltLen = WP_RSA_DEFAULT_SALT_LEN;
        #endif
            ctx->minSaltLen = 0;
        }
        else {
            char* mdName;
            char* mgfMdName;

            ctx->padMode = RSA_PKCS1_PSS_PADDING;
        #ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
            ctx->saltLen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
        #else
            ctx->saltLen = RSA_PSS_SALTLEN_AUTO;
        #endif

            wp_rsa_get_pss_mds(ctx->rsa, &mdName, &mgfMdName);
            if ((mdName == NULL) || (mdName[0] == '\0')) {
                mdName = (char*)WP_RSA_DEFAULT_MD;
            }
            if ((mgfMdName == NULL) || (mgfMdName[0] == '\0')) {
                mgfMdName = (char*)WP_RSA_DEFAULT_MD;
            }
            if (!wp_rsa_setup_md(ctx, mdName, NULL, EVP_PKEY_OP_VERIFY)) {
                ok = 0;
            }
            if (ok && (!wp_rsa_setup_mgf1_md(ctx, mgfMdName, NULL))) {
                ok = 0;
            }
            if (ok) {
                ctx->minSaltLen = wp_rsa_get_pss_salt_len(ctx->rsa);
                if (ok && !wp_rsa_check_pss_salt_len(ctx)) {
                    ok = 0;
               }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA signature context object for signing.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_sign_init(wp_RsaSigCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsa_signverify_init(ctx, rsa, params, EVP_PKEY_OP_SIGN);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sign the data using RSA PKCS #1.5 padding.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [out]     sig      Buffer to hold signature.
 * @param [in, out] sigLen   Length of signature data in bytes.
 * @param [in]      sigSize  Size of signature buffer in bytes.
 * @param [in]      tbs      Data to be signed.
 * @param [in]      tbsLen   Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_sign_pkcs1(wp_RsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* tbs, size_t tbsLen)
{
    int ok = 1;
    int rc;
    unsigned char* encodedDigest = NULL;
    int encodedDigestLen = 0;

#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
    if (ctx->hash.type != WC_HASH_TYPE_NONE)
#else
    if (ctx->hashType != WC_HASH_TYPE_NONE)
#endif
    {
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        if (tbsLen != (size_t)wc_HashGetDigestSize(ctx->hash.type))
#else
        if (tbsLen != (size_t)wc_HashGetDigestSize(ctx->hashType))
#endif
        {
            ok = 0;
        }
        if (ok) {
            encodedDigest = (unsigned char*)OPENSSL_malloc(MAX_DER_DIGEST_SZ);
            if (encodedDigest == NULL) {
                ok = 0;
            }
        }
        if (ok) {
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            encodedDigestLen = wc_EncodeSignature(encodedDigest, tbs,
                (word32)tbsLen, wc_HashGetOID(ctx->hash.type));
#else
            encodedDigestLen = wc_EncodeSignature(encodedDigest, tbs,
                (word32)tbsLen, wc_HashGetOID(ctx->hashType));
#endif
            if (encodedDigestLen <= 0) {
                ok = 0;
            }
        }
        if (ok) {
            tbs = encodedDigest;
            tbsLen = encodedDigestLen;
        }
    }
    if (ok) {
        if (wp_lock(wp_rsa_get_mutex(ctx->rsa)) != 1) {
            ok = 0;
        }
        if (ok) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaSSL_Sign(tbs, (word32)tbsLen, sig, (word32)sigSize,
                wp_rsa_get_key(ctx->rsa), &ctx->rng);
            PRIVATE_KEY_LOCK();
            wp_unlock(wp_rsa_get_mutex(ctx->rsa));
            if (rc <= 0) {
                ok = 0;
            }
        }
    }
    if (ok) {
        *sigLen = rc;
    }
    else {
        *sigLen = 0;
    }

    OPENSSL_free(encodedDigest);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sign the data using RSA PS5 padding.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [out]     sig      Buffer to hold signature.
 * @param [out]     sigLen   Length of signature data in bytes.
 * @param [in]      sigSize  Size of signature buffer in bytes.
 * @param [in]      tbs      Data to be signed.
 * @param [in]      tbsLen   Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_sign_pss(wp_RsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* tbs, size_t tbsLen)
{
    int ok = 1;
    int rc;
    int saltLen = wp_pss_salt_len_to_wc(ctx->saltLen,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        ctx->hash.type,
#else
        ctx->hashType,
#endif
        wp_rsa_get_key(ctx->rsa), EVP_PKEY_OP_SIGN);

    if (ok) {
        if (wp_lock(wp_rsa_get_mutex(ctx->rsa)) != 1) {
            ok = 0;
        }
        if (ok) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaPSS_Sign_ex(tbs, (word32)tbsLen, sig, (word32)sigSize,
        #if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type,
        #else
                ctx->hashType,
        #endif
                ctx->mgf, saltLen, wp_rsa_get_key(ctx->rsa),
                &ctx->rng);
            PRIVATE_KEY_LOCK();
            wp_unlock(wp_rsa_get_mutex(ctx->rsa));
            if (rc < 0) {
                ok = 0;
            }
            else {
                *sigLen = rc;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Add X9.31 padding to the input buffer, placing the result in the output
 * buffer.
 *
 * @param  to       [out]  Buffer to store padded result.
 * @param  toLen    [in]   Length of "to" buffer.
 * @param  from     [in]   Input buffer.
 * @param  fromLen  [in]   Length of input buffer.
 * @returns  1 on success and 0 on failure.
 */
static int wp_add_x931_padding(unsigned char* to, size_t toLen,
                               const unsigned char* from, size_t fromLen)
{
    int ok = 1;
    int padBytes;

    if (to == NULL || from == NULL) {
        WOLFPROV_ERROR_MSG(WP_LOG_PK, "Bad argument.");
        ok = 0;
    }
    else {
        /* Need at least two bytes for trailer and header. */
        padBytes = (int)(toLen - fromLen - 2);
        if (padBytes < 0) {
            WOLFPROV_ERROR_MSG(WP_LOG_PK, "Output buffer too small.");
            ok = 0;
        }
    }

    if (ok == 1) {
        if (padBytes == 0) {
            to[0] = 0x6A;
        }
        else {
            to[0] = 0x6B;
            if (padBytes > 1) {
                XMEMSET(&to[1], 0xBB, padBytes - 1);
            }
            to[padBytes] = 0xBA;
        }

        XMEMCPY(&to[padBytes + 1], from, fromLen);
        to[toLen - 1] = 0xCC;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);

    return ok;
}

/**
 * Sign the data using RSA without padding.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [out]     sig      Buffer to hold signature.
 * @param [out]     sigLen   Length of signature data in bytes.
 * @param [in]      sigSize  Size of signature buffer in bytes.
 * @param [in]      tbs      Data to be signed.
 * @param [in]      tbsLen   Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_sign_no_pad(wp_RsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* tbs, size_t tbsLen)
{
    int ok = 1;

    if (tbsLen != sigSize) {
        ok = 0;
    }
    if (ok) {
        word32 len = (word32)sigSize;
        int rc;
        if (wp_lock(wp_rsa_get_mutex(ctx->rsa)) != 1) {
            ok = 0;
        }
        if (ok) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaDirect((byte*)tbs, (word32)tbsLen, sig, &len,
                wp_rsa_get_key(ctx->rsa), RSA_PRIVATE_ENCRYPT, &ctx->rng);
            PRIVATE_KEY_LOCK();
            wp_unlock(wp_rsa_get_mutex(ctx->rsa));
            if (rc < 0) {
                ok = 0;
            }
            else {
                *sigLen = rc;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_rsa_get_x931_hash_code(enum wc_HashType hash) {
    int ret = 0;

    if (hash == WC_HASH_TYPE_SHA) {
        ret = 0x33;
    }
    else if (hash == WC_HASH_TYPE_SHA256) {
        ret = 0x34;
    }
    else if (hash == WC_HASH_TYPE_SHA384) {
        ret = 0x36;
    }
    else if (hash == WC_HASH_TYPE_SHA512) {
        ret = 0x35;
    }

    return ret;
}

/**
 * Sign the data using RSA with X931 padding.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [out]     sig      Buffer to hold signature.
 * @param [out]     sigLen   Length of signature data in bytes.
 * @param [in]      sigSize  Size of signature buffer in bytes.
 * @param [in]      tbs      Data to be signed.
 * @param [in]      tbsLen   Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_sign_x931(wp_RsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize, const unsigned char* tbs, size_t tbsLen)
{
    int ok = 1;
    int paddedSz = 0;
    unsigned char *padded = NULL;
    unsigned char *tbuf = NULL;
    int rc = 0;
    mp_int toMp;
    mp_int nMinusTo;

    paddedSz = wc_RsaEncryptSize(wp_rsa_get_key(ctx->rsa));
    if (paddedSz <= 0) {
        ok = 0;
    }
    if (ok) {
        tbuf = (unsigned char *)OPENSSL_malloc(paddedSz);
        if (tbuf == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        padded = (unsigned char *)OPENSSL_malloc(paddedSz);
        if (padded == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        XMEMCPY(tbuf, tbs, tbsLen);
        tbuf[tbsLen] = wp_rsa_get_x931_hash_code(
    #if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            ctx->hash.type
    #else
            ctx->hashType
    #endif
        );
    }
    if (ok) {
        if (wp_add_x931_padding(padded, paddedSz, tbuf, tbsLen + 1) != 1) {
            ok = 0;
        }
    }
    if (ok) {
        word32 len = (word32)sigSize;
        if (wp_lock(wp_rsa_get_mutex(ctx->rsa)) != 1) {
            ok = 0;
        }
        if (ok) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaDirect(padded, paddedSz, sig, &len,
                wp_rsa_get_key(ctx->rsa), RSA_PRIVATE_ENCRYPT, &ctx->rng);
            PRIVATE_KEY_LOCK();
            wp_unlock(wp_rsa_get_mutex(ctx->rsa));
            if (rc < 0) {
                ok = 0;
            }
            else {
                *sigLen = rc;
            }
        }
    }
    if (padded != NULL) {
        OPENSSL_free(padded);
    }
    if (tbuf != NULL) {
        OPENSSL_free(tbuf);
    }
    if (ok) {
        rc = mp_init_multi(&toMp, &nMinusTo, NULL, NULL, NULL, NULL);
        if (rc != MP_OKAY) {
            ok = 0;
        }
    }
    if (ok) {
        rc = mp_read_unsigned_bin(&toMp, sig, (word32)*sigLen);
        if (rc != MP_OKAY) {
            ok = 0;
        }
    }
    if (ok) {
        /*
         * X9.31 specifies, "The signature is either the result
         * or its complement to n, whichever is smaller."
         */
        rc = mp_sub(&(wp_rsa_get_key(ctx->rsa)->n), &toMp, &nMinusTo);
        if (rc != MP_OKAY) {
            ok = 0;
        }
        else if (mp_cmp(&toMp, &nMinusTo) == MP_GT) {
            rc = mp_to_unsigned_bin_len(&nMinusTo, sig, (int)*sigLen);
            if (rc != MP_OKAY) {
                ok = 0;
            }
        }
    }
    mp_free(&toMp);
    mp_free(&nMinusTo);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sign the data using an RSA key.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature data in bytes.
 * @param [in]      sigSize  Size of signature buffer in bytes.
 * @param [in]      tbs      Data to be signed.
 * @param [in]      tbsLen   Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_sign(wp_RsaSigCtx* ctx, unsigned char* sig, size_t* sigLen,
    size_t sigSize, const unsigned char* tbs, size_t tbsLen)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_PK, __FUNCTION__);

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (!wp_rsa_check_key_size(ctx->rsa, 0)) {
        ok = 0;
    }
    else if (sig == NULL) {
        *sigLen = wc_RsaEncryptSize(wp_rsa_get_key(ctx->rsa));
    }
    else {
        if (sigSize == (size_t)-1) {
            sigSize = *sigLen;
        }
        if (ctx->padMode == RSA_PKCS1_PADDING) {
            ok = wp_rsa_sign_pkcs1(ctx, sig, sigLen, sigSize, tbs, tbsLen);
        }
        else if (ctx->padMode == RSA_PKCS1_PSS_PADDING) {
            ok = wp_rsa_sign_pss(ctx, sig, sigLen, sigSize, tbs, tbsLen);
        }
        else if (ctx->padMode == RSA_NO_PADDING) {
            ok = wp_rsa_sign_no_pad(ctx, sig, sigLen, sigSize, tbs, tbsLen);
        }
        else if (ctx->padMode == RSA_X931_PADDING) {
            ok = wp_rsa_sign_x931(ctx, sig, sigLen, sigSize, tbs, tbsLen);
        }
        else {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA signature context object for verifying.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_init(wp_RsaSigCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsa_signverify_init(ctx, rsa, params, EVP_PKEY_OP_VERIFY);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify an RSA PKCS #1.5 padded signature.
 *
 * @param [in] ctx           RSA signature context object.
 * @param [in] sig           Signature data.
 * @param [in] sigLen        Length of signature data in bytes.
 * @param [in] tbs           Data to be signed.
 * @param [in] tbsLen        Length of data to be signed in bytes.
 * @param [in] decryptedSig  Buffer to hold decrypted signature.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_pkcs1(wp_RsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* tbs, size_t tbsLen,
    unsigned char* decryptedSig)
{
    int ok = 1;
    int rc;
    unsigned char* encodedDigest = NULL;
    int encodedDigestLen = 0;

    rc = wc_RsaSSL_Verify(sig, (word32)sigLen, decryptedSig, (word32)sigLen,
        wp_rsa_get_key(ctx->rsa));
    if (rc < 0) {
        ok = 0;
    }

    if (ok && ((size_t)rc > tbsLen)) {
        encodedDigest = (unsigned char*)OPENSSL_malloc(MAX_DER_DIGEST_SZ);
        if (encodedDigest == NULL) {
            ok = 0;
        }
        if (ok) {
            encodedDigestLen = wc_EncodeSignature(encodedDigest, tbs,
                (word32)tbsLen, wc_HashGetOID(
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                    ctx->hash.type
#else
                    ctx->hashType
#endif
                    ));
            if (encodedDigestLen <= 0) {
                ok = 0;
            }
        }
        if (ok && ((rc != encodedDigestLen) || (XMEMCMP(encodedDigest,
                decryptedSig, encodedDigestLen) != 0))) {
            ok = 0;
        }

        OPENSSL_free(encodedDigest);
    }
    else if (ok && (((size_t)rc != tbsLen) || ((XMEMCMP(tbs, decryptedSig,
            tbsLen) != 0)))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify an RSA PSS padded signature.
 *
 * @param [in] ctx           RSA signature context object.
 * @param [in] sig           Signature data.
 * @param [in] sigLen        Length of signature data in bytes.
 * @param [in] tbs           Data to be signed.
 * @param [in] tbsLen        Length of data to be signed in bytes.
 * @param [in] decryptedSig  Buffer to hold decrypted signature.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_pss(wp_RsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* tbs, size_t tbsLen,
    unsigned char* decryptedSig)
{
    int ok = 1;
    int rc;
    int saltLen;

#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
    if (ctx->hash.type == WC_HASH_TYPE_NONE)
#else
    if (ctx->hashType == WC_HASH_TYPE_NONE)
#endif
    {
        ok = wp_rsa_setup_md(ctx, WP_RSA_DEFAULT_MD, NULL, EVP_PKEY_OP_VERIFY);
    }
    if (ok) {
        saltLen = wp_pss_salt_len_to_wc(ctx->saltLen,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type,
#else
                ctx->hashType,
#endif
            wp_rsa_get_key(ctx->rsa), EVP_PKEY_OP_VERIFY);

        rc = wc_RsaPSS_Verify_ex((byte*)sig, (word32)sigLen, decryptedSig,
            (word32)sigLen,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            ctx->hash.type,
#else
            ctx->hashType,
#endif
            ctx->mgf, saltLen,
            wp_rsa_get_key(ctx->rsa));
        if (rc < 0) {
            ok = 0;
        }
    }
    if (ok) {
        rc = wc_RsaPSS_CheckPadding_ex(tbs, (word32)tbsLen, decryptedSig, rc,
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            ctx->hash.type,
#else
            ctx->hashType,
#endif
            saltLen, 0);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify an RSA PSS padded signature.
 *
 * @param [in] ctx           RSA signature context object.
 * @param [in] sig           Signature data.
 * @param [in] sigLen        Length of signature data in bytes.
 * @param [in] tbs           Data to be signed.
 * @param [in] tbsLen        Length of data to be signed in bytes.
 * @param [in] decryptedSig  Buffer to hold decrypted signature.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_no_pad(wp_RsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* tbs, size_t tbsLen,
    unsigned char* decryptedSig)
{
    int ok = 1;
    int rc;
    word32 len = (word32)sigLen;

    rc = wc_RsaDirect((byte*)sig, (word32)sigLen, decryptedSig, &len,
        wp_rsa_get_key(ctx->rsa), RSA_PUBLIC_DECRYPT, &ctx->rng);
    if (rc < 0) {
        ok = 0;
    }
    if (ok && (((size_t)rc != tbsLen) || ((XMEMCMP(tbs, decryptedSig,
            tbsLen) != 0)))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Remove X9.31 padding from the input buffer, placing the result in the output
 * buffer.
 *
 * @param  to       [out]  Pointer to buffer holding unpadded result. This
 *                         buffer will be allocated by this function if *to is
 *                         NULL.
 * @param  from     [in]   Input buffer.
 * @param  fromLen  [in]   Length of input buffer.
 * @returns  Length of unpadded result on success and -1 on failure.
 */
static int wp_remove_x931_padding(unsigned char** to, const unsigned char* from,
                                  size_t fromLen)
{
    int ret = -1;
    int ok = 1;
    size_t idx = 0;
    size_t numCopy = 0;

    if (to == NULL || from == NULL || fromLen < 2) {
        ok = 0;
    }
    else {
        if (from[fromLen - 1] != 0xCC) {
            ok = 0;
        }

        if (from[idx] == 0x6B) {
            while (++idx < fromLen && from[idx] == 0xBB) {}

            if (idx == fromLen || from[idx] != 0xBA) {
                ok = 0;
            }
        }
        else if (from[idx] != 0x6A) {
            ok = 0;
        }
    }

    if (ok) {
        ++idx;
        numCopy = fromLen - idx - 1;
        if (numCopy > 0) {
            if (*to == NULL) {
                *to = (unsigned char*)OPENSSL_malloc(numCopy);
                if (*to == NULL) {
                    ok = 0;
                }
            }
            if (ok){
                XMEMCPY(*to, from + idx, numCopy);
            }
        }
    }

    if (ok) {
        ret = (int)numCopy;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ret);
    return ret;
}

/**
 * Verify an RSA X931 padded signature.
 *
 * @param [in] ctx           RSA signature context object.
 * @param [in] sig           Signature data.
 * @param [in] sigLen        Length of signature data in bytes.
 * @param [in] tbs           Data to be signed.
 * @param [in] tbsLen        Length of data to be signed in bytes.
 * @param [in] decryptedSig  Buffer to hold decrypted signature.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_x931(wp_RsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* tbs, size_t tbsLen,
    unsigned char* decryptedSig)
{
    int ok = 1;
    int rc;
    word32 len = (word32)sigLen;
    unsigned char* unpadded = NULL;
    mp_int toMp;
    mp_int nMinusTo;

    rc = wc_RsaDirect((byte*)sig, (word32)sigLen, decryptedSig, &len,
        wp_rsa_get_key(ctx->rsa), RSA_PUBLIC_DECRYPT, &ctx->rng);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        /*
         * X9.31 specifies, "If e is odd, then
         *   - If RR = 12 mod 16, then IR = RR ;
         *   - If n - RR = 12 mod 16, then IR = n - RR ;"
         * RR is "to" and IR is the value to unpad in the next
         * step. Taking "to" mod 16 is the same as just checking the
         * lower 4 bits of "to."
         */
        if ((decryptedSig[sigLen-1] & 0x0F) != 12) {
            rc = mp_init_multi(&toMp, &nMinusTo, NULL, NULL, NULL, NULL);
            if (rc != MP_OKAY) {
                ok = 0;
            }
            if (ok) {
                rc = mp_read_unsigned_bin(&toMp, decryptedSig, (int)sigLen);
                if (rc != MP_OKAY) {
                    ok = 0;
                }
                else {
                    rc = mp_sub(&(wp_rsa_get_key(ctx->rsa)->n), &toMp, &nMinusTo);
                    if (rc != MP_OKAY) {
                        ok = 0;
                    }
                    else {
                        rc = mp_to_unsigned_bin(&nMinusTo, decryptedSig);
                        if (rc != MP_OKAY) {
                            ok = 0;
                        }
                    }
                }
            }
            mp_free(&toMp);
            mp_free(&nMinusTo);
        }
    }
    if (ok) {
        rc = wp_remove_x931_padding(&unpadded, decryptedSig, len);
        if (rc <= 0) {
            ok = 0;
        }
        else {
            XMEMCPY(decryptedSig, unpadded, rc);
            rc--;
        }
    }
    if (ok) {
        if (unpadded[rc] != wp_rsa_get_x931_hash_code(
    #if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            ctx->hash.type
    #else
            ctx->hashType
    #endif
        )) {
            ok = 0;
        }
    }
    if (ok && (((size_t)rc != tbsLen) || ((XMEMCMP(tbs, decryptedSig,
            tbsLen) != 0)))) {
        ok = 0;
    }
    if (NULL != unpadded) {
        OPENSSL_free(unpadded);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify an RSA signature.
 *
 * @param [in] ctx     RSA signature context object.
 * @param [in] sig     Signature data.
 * @param [in] sigLen  Length of signature data in bytes.
 * @param [in] tbs     Data to be signed.
 * @param [in] tbsLen  Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify(wp_RsaSigCtx* ctx, const unsigned char* sig,
    size_t sigLen, const unsigned char* tbs, size_t tbsLen)
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_PK, __FUNCTION__);

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (!wp_rsa_check_key_size(ctx->rsa, 1)) {
        ok = 0;
    }
    else {
        unsigned char* decryptedSig = (unsigned char*)OPENSSL_malloc(sigLen);

        if (decryptedSig == NULL) {
            ok = 0;
        }
        if (ok) {
            if (ctx->padMode == RSA_PKCS1_PADDING) {
                ok = wp_rsa_verify_pkcs1(ctx, sig, sigLen, tbs, tbsLen,
                    decryptedSig);
            }
            else if (ctx->padMode == RSA_PKCS1_PSS_PADDING) {
                ok = wp_rsa_verify_pss(ctx, sig, sigLen, tbs, tbsLen,
                    decryptedSig);
            }
            else if (ctx->padMode == RSA_NO_PADDING) {
                ok = wp_rsa_verify_no_pad(ctx, sig, sigLen, tbs, tbsLen,
                    decryptedSig);
            }
            else if (ctx->padMode == RSA_X931_PADDING) {
                ok = wp_rsa_verify_x931(ctx, sig, sigLen, tbs, tbsLen,
                    decryptedSig);
            }
            else {
                ok = 0;
            }
        }
        OPENSSL_free(decryptedSig);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA signature context object for verifying with recovery.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_recover_init(wp_RsaSigCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsa_signverify_init(ctx, rsa, params,
            EVP_PKEY_OP_VERIFYRECOVER);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Verify and recover an RSA signature.
 *
 * @param [in] ctx     RSA signature context object.
 * @param [in] sig     Signature data.
 * @param [in] sigLen  Length of signature data in bytes.
 * @param [in] tbs     Data to be signed.
 * @param [in] tbsLen  Length of data to be signed in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_verify_recover(wp_RsaSigCtx* ctx, unsigned char* rout,
    size_t* routlen, size_t routsize, const unsigned char* sig, size_t sigLen)
{
    int rc;
    int ok = 1;

    if ((ctx == NULL) || (rout == NULL) || (routlen == NULL) || (sig == NULL)) {
        ok = 0;
    }

    /* Only PKCS1 supported for now */
    if (ok && (ctx->padMode != RSA_PKCS1_PADDING)) {
        WOLFPROV_ERROR_MSG(WP_LOG_PK, "Only PKCS1 padding supported"
                                      " for verify recover");
        ok = 0;
    }

    if (ok) {
        rc = wc_RsaSSL_Verify(sig, (word32)sigLen, rout, (word32)routsize,
            wp_rsa_get_key(ctx->rsa));
        if (rc < 0) {
            ok = 0;
        }
    }
    if (ok) {
        *routlen = (size_t)rc;
    }

    return ok;
}

/**
 * Initialize RSA signature context object for signing/verifying digested data.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @param [in]      op      Signature operation being performed.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_digest_signverify_init(wp_RsaSigCtx* ctx, const char* mdName,
    wp_Rsa* rsa, const OSSL_PARAM params[], int op)
{
    int ok;

    ok = wp_rsa_signverify_init(ctx, rsa, params, op);
    if (ok && ((mdName != NULL) && ((mdName[0] == '\0') ||
        (XSTRNCASECMP(ctx->mdName, mdName, XSTRLEN(ctx->mdName) + 1) != 0)))) {
        ok = wp_rsa_setup_md(ctx, mdName, ctx->propQuery, op);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Digest data for signing/verification.
 *
 * @param [in, out] ctx       RSA signature context object.
 * @param [in]      data      Data to sign/verify.
 * @param [in]      dataLen   Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_digest_signverify_update(wp_RsaSigCtx* ctx,
    const unsigned char* data, size_t dataLen)
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
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA signature context object for signing digested data.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_digest_sign_init(wp_RsaSigCtx* ctx, const char* mdName,
    wp_Rsa* rsa, const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsa_digest_signverify_init(ctx, mdName, rsa, params,
            EVP_PKEY_OP_SIGN);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the signing operation on data that is digested.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature in bytes.
 * @param [in]      sigSize  Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_digest_sign_final(wp_RsaSigCtx* ctx, unsigned char* sig,
    size_t* sigLen, size_t sigSize)
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
        ok = wp_rsa_sign(ctx, sig, sigLen, sigSize, digest,
            wc_HashGetDigestSize(
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type
#else
                ctx->hashType
#endif
            ));
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA signature context object for verifying digested data.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_digest_verify_init(wp_RsaSigCtx* ctx, const char* mdName,
    wp_Rsa* rsa, const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsa_digest_signverify_init(ctx, mdName, rsa, params,
            EVP_PKEY_OP_VERIFY);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the verification operation on data that is digested.
 *
 * @param [in, out] ctx      RSA signature context object.
 * @param [in]      sig      Signature data.
 * @param [in]      sigLen   Length of signature in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_digest_verify_final(wp_RsaSigCtx* ctx, unsigned char* sig,
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
        ok = wp_rsa_verify(ctx,sig, sigLen, digest,
            wc_HashGetDigestSize(
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
                ctx->hash.type
#else
                ctx->hashType
#endif
            ));
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Maximum buffer size for encoding RSA-PSS parameters into. */
#define MAX_RSA_PSS_PARAMS_DER_LEN  128

/**
 * Get the RSA-PSS Algorithm ID DER encoding into the parameter.
 *
 * @param [in] ctx  RSA signature context object.
 * @param [in] p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_get_alg_id(wp_RsaSigCtx* ctx, OSSL_PARAM* p)
{
    int ok;
    byte pssAlgId[MAX_RSA_PSS_PARAMS_DER_LEN];
    word32 len = MAX_RSA_PSS_PARAMS_DER_LEN;

    /* Encode RSA-PSS parameters into buffer. */
    ok = wp_rsa_pss_encode_alg_id(ctx->rsa, ctx->mdName, ctx->mgf1MdName,
        ctx->saltLen, pssAlgId, &len);
    if (ok) {
        /* Set RSA-PSS parameters into OpenSSL parameter. */
        ok = OSSL_PARAM_set_octet_string(p, pssAlgId, len);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put DER encoding of the RSA signature algorithm in the parameter object.
 *
 * @param [in] ctx  RSA signature context object.
 * @param [in] p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_alg_id(wp_RsaSigCtx* ctx, OSSL_PARAM* p)
{
    int ok = 0;

    if (ctx->padMode == RSA_PKCS1_PSS_PADDING) {
        ok = wp_rsa_pss_get_alg_id(ctx, p);
    }
    else if ((XMEMCMP(ctx->mdName, "SHA256", 7) == 0) ||
        (XMEMCMP(ctx->mdName, "sha256", 7) == 0)) {
        static const byte sha256WithRSAEncryptionOid[] = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
        };
        ok = OSSL_PARAM_set_octet_string(p, sha256WithRSAEncryptionOid,
            sizeof(sha256WithRSAEncryptionOid));
    }
    else if ((XMEMCMP(ctx->mdName, "SHA384", 7) == 0) ||
             (XMEMCMP(ctx->mdName, "sha384", 7) == 0)) {
        static const byte sha384WithRSAEncryptionOid[] = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00
        };
        ok = OSSL_PARAM_set_octet_string(p, sha384WithRSAEncryptionOid,
            sizeof(sha384WithRSAEncryptionOid));
    }
    else if ((XMEMCMP(ctx->mdName, "SHA512", 7) == 0) ||
             (XMEMCMP(ctx->mdName, "sha512", 7) == 0)) {
        static const byte sha512WithRSAEncryptionOid[] = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00
        };
        ok = OSSL_PARAM_set_octet_string(p, sha512WithRSAEncryptionOid,
            sizeof(sha512WithRSAEncryptionOid));
    }
    /* TODO: support more digests */
    else {
        WOLFPROV_MSG(WP_LOG_PK, "Digest not supported: %s\n", ctx->mdName);
    }

    return ok;
}

/**
 * Put padding mode into parameter object.
 *
 * @param [in] padMode  Padding mode.
 * @param [in] p        Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_pad_mode(int padMode, OSSL_PARAM* p)
{
    int ok = 1;

    if (p->data_type == OSSL_PARAM_INTEGER) {
        if (!OSSL_PARAM_set_int(p, padMode)) {
            ok = 0;
        }
    }
    else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
        size_t i;

        for (i = 0; i < WP_PAD_MODE_LEN; i++) {
            if (padMode == (int)wp_pad_mode[i].id) {
                if (!OSSL_PARAM_set_utf8_string(p, wp_pad_mode[i].ptr)) {
                    ok = 0;
                }
                break;
            }
        }
    }
    else {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put salt length into parameter object.
 *
 * @param [in] saltLen  Length of salt for PSS.
 * @param [in] p        Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_salt_len(int saltLen, OSSL_PARAM* p)
{
    int ok = 1;

    if (p->data_type == OSSL_PARAM_INTEGER) {
        if (!OSSL_PARAM_set_int(p, saltLen)) {
            ok = 0;
        }
    }
    else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
        const char* saltLenStr = NULL;
        int len;

        switch (saltLen) {
        case RSA_PSS_SALTLEN_DIGEST:
            saltLenStr = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
            break;
        case RSA_PSS_SALTLEN_MAX:
            saltLenStr = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
            break;
        case RSA_PSS_SALTLEN_AUTO:
            saltLenStr = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
            break;
    #ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
        case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
            saltLenStr = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX;
            break;
    #endif
        default:
            len = XSNPRINTF(p->data, p->data_size, "%d", saltLen);
            if (len <= 0) {
                ok = 0;
            }
            else {
                p->return_size = len;
            }
            break;
        }
        if ((saltLenStr != NULL) &&
            (!OSSL_PARAM_set_utf8_string(p, saltLenStr))) {
            ok = 0;
        }
    }
    else {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put data from RSA signture context object into parameter objects.
 *
 * @param [in] ctx     RSA signature context object.
 * @param [in] params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_ctx_params(wp_RsaSigCtx* ctx, OSSL_PARAM* params)
{
    int ok = 1;
    OSSL_PARAM* p;

    if (ctx == NULL) {
        ok = 0;
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL) {
            ok = wp_rsa_get_alg_id(ctx, p);
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
        if (p != NULL) {
            ok = wp_rsa_get_pad_mode(ctx->padMode, p);
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, ctx->mdName)) {
            ok = 0;
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, ctx->mgf1MdName)) {
            ok = 0;
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
        if (p != NULL) {
            ok = wp_rsa_get_salt_len(ctx->saltLen, p);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns an array of RSA signature context parameters that can be retrieved.
 *
 * @param [in] ctx      RSA signature context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_rsa_gettable_ctx_params(wp_RsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /** Parameters that we support getting from the RSA signature context. */
    static const OSSL_PARAM wp_supported_gettable_ctx_params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_supported_gettable_ctx_params;
}

/**
 * Sets the digest to use into RSA signature context object.
 *
 * @param [in, out] ctx         RSA signature context object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_set_digest(wp_RsaSigCtx* ctx, const OSSL_PARAM* p,
    const OSSL_PARAM* propsParam)
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
        ok = wp_rsa_setup_md(ctx, mdName, pmdProps, ctx->op);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the padding mode to use into RSA signature context object.
 *
 * @param [in, out] ctx  RSA signature context object.
 * @param [in]      p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_set_pad_mode(wp_RsaSigCtx* ctx, const OSSL_PARAM* p)
{
    int ok = 1;
    int padMode = 0;

    if (p->data_type == OSSL_PARAM_INTEGER) {
        if (!OSSL_PARAM_get_int(p, &padMode)) {
            ok = 0;
        }
    }
    else if ((p->data_type == OSSL_PARAM_UTF8_STRING) &&
             (p->data != NULL)) {
        size_t i;
        for (i = 0; i < WP_PAD_MODE_LEN; i++) {
            if (XSTRCMP(p->data, wp_pad_mode[i].ptr) == 0) {
                padMode = wp_pad_mode[i].id;
                break;
            }
        }
        if (i == WP_PAD_MODE_LEN) {
            ok = 0;
        }
    }
    else {
        ok = 0;
    }

    if (ok) {
        if (padMode == RSA_PKCS1_PSS_PADDING) {
            /* Nothing to do. */
        }
        else if (padMode == RSA_PKCS1_PADDING) {
            if (wp_rsa_get_type(ctx->rsa) != RSA_FLAG_TYPE_RSA) {
                ok = 0;
            }
        }
        else if (padMode == RSA_NO_PADDING) {
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
            if (ctx->hash.type != WC_HASH_TYPE_NONE)
#else
            if (ctx->hashType != WC_HASH_TYPE_NONE)
#endif
            {
                ok = 0;
            }
        }
        else if (padMode == RSA_X931_PADDING) {
            if (wp_rsa_get_type(ctx->rsa) != RSA_FLAG_TYPE_RSA) {
                ok = 0;
            }
        }
        else {
            ok = 0;
        }
    }
    if (ok) {
        ctx->padMode = padMode;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the salt length for PSS to use into RSA signature context object.
 *
 * @param [in, out] ctx  RSA signature context object.
 * @param [in]      p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_set_salt_len(wp_RsaSigCtx* ctx, const OSSL_PARAM* p)
{
    int ok = 1;

    if (p->data_type == OSSL_PARAM_INTEGER) {
        if (!OSSL_PARAM_get_int(p, &ctx->saltLen)) {
            ok = 0;
        }
    }
    else if ((p->data_type == OSSL_PARAM_UTF8_STRING) &&
             (p->data != NULL)) {
        if (XSTRNCMP(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST,
                     p->data_size) == 0) {
            ctx->saltLen = RSA_PSS_SALTLEN_DIGEST;
        }
        else if (XSTRNCMP(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX,
                          p->data_size) == 0) {
            ctx->saltLen = RSA_PSS_SALTLEN_MAX;
        }
        else if (XSTRNCMP(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO,
                          p->data_size) == 0) {
            ctx->saltLen = RSA_PSS_SALTLEN_AUTO;
        }
    #ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
        else if (XSTRNCMP(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX,
                          p->data_size) == 0) {
            ctx->saltLen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
        }
    #endif
        else {
            ctx->saltLen = XATOI(p->data);
        }
    }
    else {
        ok = 0;
    }
    /* RSA_PSS_SALTLEN_MAX is the smallest negative value supported. */
    if (ok && (ctx->saltLen < RSA_PSS_SALTLEN_MAX)) {
        ok = 0;
    }
    if (ok && (ctx->saltLen >= 0) && (ctx->saltLen < ctx->minSaltLen)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the digest to use with MGF1 for PSS into RSA signature context object.
 *
 * @param [in, out] ctx         RSA signature context object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_set_mgf1_digest(wp_RsaSigCtx* ctx, const OSSL_PARAM* p,
    const OSSL_PARAM* propsParam)
{
    int ok = 1;
    char mgfMdName[WP_MAX_MD_NAME_SIZE] = "";
    char* pmgfMdName = mgfMdName;
    char mgfMdProps[WP_MAX_MD_NAME_SIZE] = "";
    char* pmgfMdProps = NULL;

    if (!OSSL_PARAM_get_utf8_string(p, &pmgfMdName, sizeof(mgfMdName))) {
        ok = 0;
    }
    if (ok && propsParam != NULL) {
        pmgfMdProps = mgfMdProps;
        if (!OSSL_PARAM_get_utf8_string(propsParam, &pmgfMdProps,
                                        sizeof(mgfMdProps))) {
            ok = 0;
        }
    }
    if (ok) {
        ok = wp_rsa_setup_mgf1_md(ctx, mgfMdName, pmgfMdProps);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into RSA signature context object.
 *
 * @param [in, out] ctx     RSA signature context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_set_ctx_params(wp_RsaSigCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;
    const OSSL_PARAM* propsParam;

    if (params != NULL) {
        p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
        if (p != NULL) {
            propsParam = OSSL_PARAM_locate_const(params,
                OSSL_SIGNATURE_PARAM_PROPERTIES);
            ok = wp_rsa_set_digest(ctx, p, propsParam);
        }

        if (ok) {
            p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
            if (p != NULL) {
                ok = wp_rsa_set_pad_mode(ctx, p);
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
            if (p != NULL) {
                if (ctx->padMode != RSA_PKCS1_PSS_PADDING) {
                    ok = 0;
                }
                else {
                    ok = wp_rsa_set_salt_len(ctx, p);
                }
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
            if (p != NULL) {
                if (ctx->padMode != RSA_PKCS1_PSS_PADDING) {
                    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MGF1_MD);
                    ok = 0;
                }
                else {
                    propsParam = OSSL_PARAM_locate_const(params,
                        OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);
                    ok = wp_rsa_set_mgf1_digest(ctx, p,propsParam);
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns an array of RSA signature context parameters that can be set.
 *
 * @param [in] ctx      RSA signature context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_rsa_settable_ctx_params(wp_RsaSigCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /** Parameters that we support setting into the RSA signature context. */
    static const OSSL_PARAM wp_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_settable_ctx_params;
}

/**
 * Get the parameters of the digest object.
 *
 * @param [in] ctx     RSA signature context object.
 * @param [in] params  Array of parameter objects.
 * @param  0 on failure.
 */
static int wp_rsa_get_ctx_md_params(wp_RsaSigCtx* ctx, OSSL_PARAM* params)
{
    /* TODO: implement */
    (void)ctx;
    (void)params;
    return 0;
}

/**
 * Returns an array of digest parameters that can be retrieved.
 *
 * @param [in] ctx      RSA signature context object. Unused.
 * @return  NULL on failure.
 */
static const OSSL_PARAM* wp_rsa_gettable_ctx_md_params(wp_RsaSigCtx* ctx)
{
    /* TODO: implement */
    (void)ctx;
    return NULL;
}

/**
 * Set the parameters of the digest object.
 *
 * @param [in] ctx     RSA signature context object.
 * @param [in] params  Array of parameter objects.
 * @param  0 on failure.
 */
static int wp_rsa_set_ctx_md_params(wp_RsaSigCtx* ctx,
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
 * @param [in] ctx      RSA signature context object. Unused.
 * @return  NULL on failure.
 */
static const OSSL_PARAM* wp_rsa_settable_ctx_md_params(wp_RsaSigCtx* ctx)
{
    /* TODO: implement */
    (void)ctx;
    return NULL;
}

/** Dspatch table for RSA signing and verification. */
const OSSL_DISPATCH wp_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,             (DFUNC)wp_rsa_ctx_new           },
    { OSSL_FUNC_SIGNATURE_FREECTX,            (DFUNC)wp_rsa_ctx_free          },
    { OSSL_FUNC_SIGNATURE_DUPCTX,             (DFUNC)wp_rsa_ctx_dup           },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,          (DFUNC)wp_rsa_sign_init         },
    { OSSL_FUNC_SIGNATURE_SIGN,               (DFUNC)wp_rsa_sign              },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,        (DFUNC)wp_rsa_verify_init       },
    { OSSL_FUNC_SIGNATURE_VERIFY,             (DFUNC)wp_rsa_verify            },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT,
                                       (DFUNC)wp_rsa_verify_recover_init      },
    { OSSL_FUNC_SIGNATURE_VERIFY_RECOVER,     (DFUNC)wp_rsa_verify_recover    },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,   (DFUNC)wp_rsa_digest_sign_init  },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
                                       (DFUNC)wp_rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,  (DFUNC)wp_rsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
                                       (DFUNC)wp_rsa_digest_verify_init       },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
                                       (DFUNC)wp_rsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
                                       (DFUNC)wp_rsa_digest_verify_final      },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,     (DFUNC)wp_rsa_get_ctx_params    },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                                       (DFUNC)wp_rsa_gettable_ctx_params      },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,     (DFUNC)wp_rsa_set_ctx_params    },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
                                       (DFUNC)wp_rsa_settable_ctx_params      },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,  (DFUNC)wp_rsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
                                       (DFUNC)wp_rsa_gettable_ctx_md_params   },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,  (DFUNC)wp_rsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
                                       (DFUNC)wp_rsa_settable_ctx_md_params   },
    { 0, NULL }
};

#endif /* WP_HAVE_RSA */

