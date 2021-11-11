/* wp_ecx_sig.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <wolfprovider/alg_funcs.h>

/**
 * ECX signature context.
 *
 * Used to store context and state of signing/verification operations.
 */
typedef struct wp_EcxSigCtx {
    /** wolfProvider context object. */
    WOLFPROV_CTX *provCtx;
    /** Library context object. */
    OSSL_LIB_CTX *libCtx;

    /** wolfProvider ECX object. */
    wp_Ecx* ecx;

    /** Operation being performed as an EVP define. */
    int op;

    /** wolfSSL hash object. */
    wc_HashAlg hash;
    /** Hash algorithm to use on data to be signed. */
    enum wc_HashType hashType;

    /** Property query string. */
    char* propQuery;
    /** Name of hash algorithm. */
    char mdName[WP_MAX_MD_NAME_SIZE];
} wp_EcxSigCtx;


/**
 * Create a new ECX signature context object.
 *
 * @param [in] provCtx    wolfProvider context object.
 * @param [in] propQuery  Property query.
 * @return  NULL on failure.
 * @return  ECX signature context object on success.
 */
static wp_EcxSigCtx* wp_ecx_newctx(WOLFPROV_CTX* provCtx,
    const char* propQuery)
{
    wp_EcxSigCtx* ctx = NULL;

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
 * Free an ECX signature context object.
 *
 * @param [in, out] ctx  ECX signature context object. May be NULL.
 */
static void wp_ecx_freectx(wp_EcxSigCtx* ctx)
{
    if (ctx != NULL) {
        wp_ecx_free(ctx->ecx);
        OPENSSL_free(ctx->propQuery);
        OPENSSL_free(ctx);
    }
}


/**
 * Copies the underlying hash algorithm object.
 *
 * @param [in]  src       Hash object to copy.
 * @param [out] dst       Hash object to copy into.
 * @param [in]  hashType  Type of hash algorithm.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hash_copy(wc_HashAlg* src, wc_HashAlg* dst,
    enum wc_HashType hashType)
{
    int ok = 1;
    int rc = 0;

    switch (hashType) {
    case WC_HASH_TYPE_MD5:
        rc = wc_Md5Copy(&src->md5, &dst->md5);
        break;
    case WC_HASH_TYPE_SHA:
        rc = wc_ShaCopy(&src->sha, &dst->sha);
        break;
    case WC_HASH_TYPE_SHA224:
        rc = wc_Sha224Copy(&src->sha224, &dst->sha224);
        break;
    case WC_HASH_TYPE_SHA256:
        rc = wc_Sha256Copy(&src->sha256, &dst->sha256);
        break;
    case WC_HASH_TYPE_SHA384:
        rc = wc_Sha384Copy(&src->sha384, &dst->sha384);
        break;
    case WC_HASH_TYPE_SHA512:
        rc = wc_Sha512Copy(&src->sha512, &dst->sha512);
        break;
    case WC_HASH_TYPE_SHA512_224:
        rc = wc_Sha512_224Copy(&src->sha512, &dst->sha512);
        break;
    case WC_HASH_TYPE_SHA512_256:
        rc = wc_Sha512_256Copy(&src->sha512, &dst->sha512);
        break;
    case WC_HASH_TYPE_SHA3_224:
        rc = wc_Sha3_224_Copy(&src->sha3, &dst->sha3);
        break;
    case WC_HASH_TYPE_SHA3_256:
        rc = wc_Sha3_256_Copy(&src->sha3, &dst->sha3);
        break;
    case WC_HASH_TYPE_SHA3_384:
        rc = wc_Sha3_384_Copy(&src->sha3, &dst->sha3);
        break;
    case WC_HASH_TYPE_SHA3_512:
        rc = wc_Sha3_512_Copy(&src->sha3, &dst->sha3);
        break;
    case WC_HASH_TYPE_NONE:
    case WC_HASH_TYPE_MD2:
    case WC_HASH_TYPE_MD4:
    case WC_HASH_TYPE_MD5_SHA:
    case WC_HASH_TYPE_BLAKE2B:
    case WC_HASH_TYPE_BLAKE2S:
    case WC_HASH_TYPE_SHAKE128:
    case WC_HASH_TYPE_SHAKE256:
    default:
        ok = 0;
        break;
    }
    if (rc != 0) {
        ok = 0;
    }

    return ok;
}

/**
 * Duplicate the ECX signature context object.
 *
 * @param [in] srcCtx  ECX signature context object.
 * @retturn  NULL on failure.
 * @return   ECX signature context object on success.
 */
static wp_EcxSigCtx* wp_ecx_dupctx(wp_EcxSigCtx* srcCtx)
{
    wp_EcxSigCtx* dstCtx = NULL;

    if (wolfssl_prov_is_running()) {
        int ok = 1;

        dstCtx = wp_ecx_newctx(srcCtx->provCtx, srcCtx->propQuery);
        if (dstCtx == NULL) {
            ok = 0;
        }

        if (ok && (!wp_hash_copy(&srcCtx->hash, &dstCtx->hash,
                                 srcCtx->hashType))) {
            ok = 0;
        }
        if (ok && (!wp_ecx_up_ref(srcCtx->ecx))) {
            ok = 0;
        }
        if (ok) {
            dstCtx->ecx      = srcCtx->ecx;
            dstCtx->hashType = srcCtx->hashType;
            dstCtx->op       = srcCtx->op;
            XMEMCPY(dstCtx->mdName, srcCtx->mdName, sizeof(srcCtx->mdName));
        }

        if (!ok) {
            wp_ecx_freectx(dstCtx);
            dstCtx = NULL;
        }
    }

    return dstCtx;
}

/**
 * Initialize ECX signature context object for signing/verifying digested data.
 *
 * @param [in, out] ctx     ECX signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      ecx     ECX key object.
 * @param [in]      params  Parameters to initialize with. Unused.
 * @param [in]      op      Signature operation being performed.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_digest_signverify_init(wp_EcxSigCtx *ctx,
    const char *mdName, wp_Ecx *ecx, const OSSL_PARAM params[], int op)
{
    int ok = 1;

    (void)params;

    if ((mdName != NULL) && (mdName[0] != '\0')) {
        ok = 0;
    }

    if (ok && (ctx->ecx != ecx)) {
        wp_ecx_free(ctx->ecx);
        if (!wp_ecx_up_ref(ecx)) {
            ok = 0;
        }
    }
    if (ok) {
        ctx->ecx = ecx;
        ctx->op = op;
    }

    return ok;
}

/**
 * Initialize ECX signature context object for signing digested data.
 *
 * @param [in, out] ctx     ECX signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      ecx     ECX key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_digest_sign_init(wp_EcxSigCtx *ctx, const char *mdName,
    wp_Ecx *ecx, const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecx_digest_signverify_init(ctx, mdName, ecx, params,
            EVP_PKEY_OP_SIGN);
    }

    return ok;
}

/**
 * Initialize ECX signature context object for verifying digested data.
 *
 * @param [in, out] ctx     ECX signature context object.
 * @param [in]      mdName  Name of digest algorithm to use on data.
 * @param [in]      ecx     ECX key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_digest_verify_init(wp_EcxSigCtx *ctx, const char *mdName,
    wp_Ecx *ecx, const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_ecx_digest_signverify_init(ctx, mdName, ecx, params,
            EVP_PKEY_OP_VERIFY);
    }

    return ok;
}

/**
 * Put DER encoding of the ECX signature algorithm in the parameter object.
 *
 * @param [in] ctx  ECX signature context object.
 * @param [in] p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_get_alg_id(wp_EcxSigCtx *ctx, OSSL_PARAM *p)
{
    /* TODO: implement */
    (void)ctx;
    (void)p;
    return 0;
}

/**
 * Put data from ECX signture context object into parameter objects.
 *
 * @param [in] ctx     ECX signature context object.
 * @param [in] params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_get_ctx_params(wp_EcxSigCtx *ctx, OSSL_PARAM *params)
{
    int ok = 1;
    OSSL_PARAM *p;

    if (ctx == NULL) {
        ok = 0;
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        if (p != NULL) {
            ok = wp_ecx_get_alg_id(ctx, p);
        }
    }

    return ok;
}

/** Parameters that we support getting from the ECX signature context. */
static const OSSL_PARAM wp_supported_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};
/**
 * Returns an array of ECX signature context parameters that can be retrieved.
 *
 * @param [in] ctx      ECX signature context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM *wp_ecx_gettable_ctx_params(wp_EcxSigCtx *ctx,
    WOLFPROV_CTX *provCtx)
{
    (void)ctx;
    (void)provCtx;
    return wp_supported_gettable_ctx_params;
}

/*
 * Ed25519
 */

/**
 * Sign the data using an Ed25519 key.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      ECX signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature in bytes.
 * @param [in]      sigSize  Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ed25519_digest_sign(wp_EcxSigCtx *ctx, unsigned char *sig,
    size_t *sigLen, size_t sigSize, const unsigned char *tbs, size_t tbsLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (sig == NULL) {
        *sigLen = ED25519_SIG_SIZE;
    }
    else if (*sigLen != ED25519_SIG_SIZE) {
        ok = 0;
    }
    else {
        int rc;
        word32 len;
        ed25519_key* ed25519 = (ed25519_key*)wp_ecx_get_key(ctx->ecx);

        if (sigSize == (size_t)-1) {
            sigSize = *sigLen;
        }
        len = sigSize;

        if (!ed25519->pubKeySet) {
            unsigned char pubKey[ED25519_PUB_KEY_SIZE];

            rc = wc_ed25519_make_public(ed25519, pubKey, sizeof(pubKey));
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                rc = wc_ed25519_import_public(pubKey, sizeof(pubKey), ed25519);
                if (rc != 0) {
                    ok = 0;
                }
            }
        }
        if (ok) {
            rc = wc_ed25519_sign_msg(tbs, tbsLen, sig, &len, ed25519);
            if (rc != 0) {
                ok = 0;
            }
            else {
                *sigLen = len;
            }
        }
    }

    return ok;
}

/** s part of signature must be less than order. */
static const byte wp_ed25519_order[ED25519_KEY_SIZE] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/**
 * Verify an Ed25519 signature.
 *
 * @param [in, out] ctx      ECX signature context object.
 * @param [in]      sig      Signature data.
 * @param [in]      sigLen   Length of signature in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ed25519_digest_verify(wp_EcxSigCtx *ctx, unsigned char *sig,
    size_t sigLen, const unsigned char *tbs, size_t tbsLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (sigLen != ED25519_SIG_SIZE)) {
        ok = 0;
    }
    if (ok) {
        int i;
        for (i = ED25519_KEY_SIZE - 1; i >= 0; i--) {
            if (sig[ED25519_KEY_SIZE + i] > wp_ed25519_order[i]) {
                ok = 0;
            }
            if (sig[ED25519_KEY_SIZE + i] != wp_ed25519_order[i]) {
                break;
            }
        }
    }
    if (ok) {
        int res;
        int rc = wc_ed25519_verify_msg(sig, sigLen, tbs, tbsLen, &res,
            wp_ecx_get_key(ctx->ecx));
        if (rc != 0) {
            ok = 0;
        }
        if (res == 0) {
            ok = 0;
        }
    }

    return ok;
}

/** Dspatch table for Ed25519 signing and verification. */
const OSSL_DISPATCH wp_ed25519_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,           (DFUNC)wp_ecx_newctx              },
    { OSSL_FUNC_SIGNATURE_FREECTX,          (DFUNC)wp_ecx_freectx             },
    { OSSL_FUNC_SIGNATURE_DUPCTX,           (DFUNC)wp_ecx_dupctx              },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (DFUNC)wp_ecx_digest_sign_init    },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,      (DFUNC)wp_ed25519_digest_sign     },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
                                            (DFUNC)wp_ecx_digest_verify_init  },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,    (DFUNC)wp_ed25519_digest_verify   },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,   (DFUNC)wp_ecx_get_ctx_params      },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_ecx_gettable_ctx_params },
    { 0, NULL }
};

/*
 * Ed448
 */

/**
 * Sign the data using an Ed448 key.
 *
 * When sig is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      ECX signature context object.
 * @param [out]     sig      Buffer to hold signature. May be NULL.
 * @param [out]     sigLen   Length of signature in bytes.
 * @param [in]      sigSize  Size of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ed448_digest_sign(wp_EcxSigCtx *ctx, unsigned char *sig,
    size_t *sigLen, size_t sigSize, const unsigned char *tbs, size_t tbsLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (sig == NULL) {
        *sigLen = ED448_SIG_SIZE;
    }
    else {
        int rc;
        word32 len;
        ed448_key* ed448 = (ed448_key*)wp_ecx_get_key(ctx->ecx);

        if (sigSize == (size_t)-1) {
            sigSize = *sigLen;
        }
        len = sigSize;

        if (!ed448->pubKeySet) {
            unsigned char pubKey[ED448_PUB_KEY_SIZE];

            rc = wc_ed448_make_public(ed448, pubKey, sizeof(pubKey));
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                rc = wc_ed448_import_public(pubKey, sizeof(pubKey), ed448);
                if (rc != 0) {
                    ok = 0;
                }
            }
        }
        if (ok) {
            rc = wc_ed448_sign_msg(tbs, tbsLen, sig, &len,
                (ed448_key*)wp_ecx_get_key(ctx->ecx), NULL, 0);
            if (rc != 0) {
                ok = 0;
            }
            else {
                *sigLen = len;
            }
        }
    }

    return ok;
}

/** s part of signature must be less than order. */
static const word8 wp_ed448_order[ED448_KEY_SIZE] = {
    0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23,
    0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C, 0x21,
    0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4,
    0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F,
    0x00
};


/**
 * Verify an Ed448 signature.
 *
 * @param [in, out] ctx      ECX signature context object.
 * @param [in]      sig      Signature data.
 * @param [in]      sigLen   Length of signature in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ed448_digest_verify(wp_EcxSigCtx *ctx, unsigned char *sig,
    size_t sigLen, const unsigned char *tbs, size_t tbsLen)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (sigLen != ED448_SIG_SIZE)) {
        ok = 0;
    }
    if (ok) {
        int i;
        for (i = ED448_KEY_SIZE - 1; i >= 0; i--) {
            if (sig[ED448_KEY_SIZE + i] > wp_ed448_order[i]) {
                ok = 0;
            }
            if (sig[ED448_KEY_SIZE + i] != wp_ed448_order[i]) {
                break;
            }
        }
    }
    if (ok) {
        int res;
        int rc = wc_ed448_verify_msg(sig, sigLen, tbs, tbsLen, &res,
            wp_ecx_get_key(ctx->ecx), NULL, 0);
        if (rc != 0) {
            ok = 0;
        }
        if (res == 0) {
            ok = 0;
        }
    }

    return ok;
}

/** Dspatch table for Ed448 signing and verification. */
const OSSL_DISPATCH wp_ed448_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,           (DFUNC)wp_ecx_newctx              },
    { OSSL_FUNC_SIGNATURE_FREECTX,          (DFUNC)wp_ecx_freectx             },
    { OSSL_FUNC_SIGNATURE_DUPCTX,           (DFUNC)wp_ecx_dupctx              },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (DFUNC)wp_ecx_digest_sign_init    },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,      (DFUNC)wp_ed448_digest_sign       },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
                                            (DFUNC)wp_ecx_digest_verify_init  },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,    (DFUNC)wp_ed448_digest_verify     },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,   (DFUNC)wp_ecx_get_ctx_params      },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
                                            (DFUNC)wp_ecx_gettable_ctx_params },
    { 0, NULL }
};

