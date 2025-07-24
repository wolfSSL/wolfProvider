/* wp_rsaa_asym.c
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

/* This define taken from ssl.h.
 * Can't include this header as it redeclares OpenSSL types.
 */
#define WOLFSSL_MAX_MASTER_KEY_LENGTH   48

/** Array of supported padding modes mapping id/string. */
static OSSL_ITEM wp_pad_mode[] = {
    { RSA_PKCS1_PADDING,        (char*)OSSL_PKEY_RSA_PAD_MODE_PKCSV15 },
    { RSA_NO_PADDING,           (char*)OSSL_PKEY_RSA_PAD_MODE_NONE },
    { RSA_X931_PADDING,         (char*)OSSL_PKEY_RSA_PAD_MODE_X931 },
    { RSA_PKCS1_OAEP_PADDING,   (char*)OSSL_PKEY_RSA_PAD_MODE_OAEP },
    /* Misspelled somewhere? */
    { RSA_PKCS1_OAEP_PADDING,   (char*)"oeap" },
};

/** Length of padding mode array. */
#define WP_PAD_MODE_LEN    (sizeof(wp_pad_mode) / sizeof(*wp_pad_mode))


/**
 * RSA asymmetric cipher context.
 *
 * Used to store context and state of encryption/decryption operations.
 */
typedef struct wp_RsaAsymCtx {
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

    /** Hash algorithm to use on data with OAEP. */
    enum wc_HashType oaepHashType;
    /** wolfSSL id of MGF operation to perform when padding mode is PSS. */
    int mgf;
    /** Indicates that the MGF id has been set explicitly. */
    unsigned int mgfSet:1;
    /** Label to use with OAEP. */
    unsigned char* label;
    /** Length of label. */
    size_t labelLen;

    /** Name of hash algorithm. */
    char oaepMdName[WP_MAX_MD_NAME_SIZE];
    /** Name of hash algorithm used in MGF1 algorithm. */
    char mgf1MdName[WP_MAX_MD_NAME_SIZE];

    /** Client TLS version. */
    unsigned int clientVersion;
    /** Negotiated TLS version. */
    unsigned int negVersion;
} wp_RsaAsymCtx;


/* Prototype for wp_rsaa_signverify_init() to use.  */
static int wp_rsaa_set_ctx_params(wp_RsaAsymCtx* ctx,
    const OSSL_PARAM params[]);

/**
 * Create a new RSA asymmetric cipher context object.
 *
 * @param [in] provCtx    wolfProvider context object.
 * @return  NULL on failure.
 * @return  RSA asymmetric cipher context object on success.
 */
static wp_RsaAsymCtx* wp_rsaa_ctx_new(WOLFPROV_CTX* provCtx)
{
    wp_RsaAsymCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
        ctx->libCtx = provCtx->libCtx;
    }

    return ctx;
}

/**
 * Free an RSA asymmetric cipher context object.
 *
 * @param [in, out] ctx  RSA asymmetric cipher context object. May be NULL.
 */
static void wp_rsaa_ctx_free(wp_RsaAsymCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        wp_rsa_free(ctx->rsa);
        OPENSSL_free(ctx->label);
        OPENSSL_free(ctx);
    }
}

/**
 * Duplicate the RSA asymmetric cipher context object.
 *
 * @param [in] srcCtx  RSA asymmetric cipher context object.
 * @retturn  NULL on failure.
 * @return   RSA asymmetric cipher context object on success.
 */
static wp_RsaAsymCtx* wp_rsaa_ctx_dup(wp_RsaAsymCtx* srcCtx)
{
    wp_RsaAsymCtx* dstCtx = NULL;

    if (wolfssl_prov_is_running()) {
        int ok = 1;

        dstCtx = wp_rsaa_ctx_new(srcCtx->provCtx);
        if (dstCtx == NULL) {
            ok = 0;
        }
        if (ok && (srcCtx->labelLen > 0)) {
            dstCtx->label = OPENSSL_malloc(srcCtx->labelLen);
            if (dstCtx->label == NULL) {
                ok = 0;
            }
        }

        if (ok && (!wp_rsa_up_ref(srcCtx->rsa))) {
            ok = 0;
        }
        if (ok) {
            dstCtx->rsa          = srcCtx->rsa;
            dstCtx->oaepHashType = srcCtx->oaepHashType;
            dstCtx->mgf          = srcCtx->mgf;
            dstCtx->mgfSet       = srcCtx->mgfSet;
            dstCtx->padMode      = srcCtx->padMode;
            dstCtx->op           = srcCtx->op;
            XMEMCPY(dstCtx->oaepMdName, srcCtx->oaepMdName,
                sizeof(srcCtx->oaepMdName));
            XMEMCPY(dstCtx->mgf1MdName, srcCtx->mgf1MdName,
                sizeof(srcCtx->mgf1MdName));
            XMEMCPY(dstCtx->label, srcCtx->label, srcCtx->labelLen);
            dstCtx->labelLen     = srcCtx->labelLen;
        }

        if (!ok) {
            wp_rsaa_ctx_free(dstCtx);
            dstCtx = NULL;
        }
    }

    return dstCtx;
}

/**
 * Initialize RSA aymmetric cipher context object for encryption/decryption.
 *
 * @param [in, out] ctx     RSA asymmetric cipher context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @param [in]      op      Signature operation to perform.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_init(wp_RsaAsymCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[], int op)
{
    int ok = 1;

    if (ctx->rsa != rsa) {
        if (wp_rsa_get_type(rsa) != RSA_FLAG_TYPE_RSA) {
            ERR_raise_data(ERR_LIB_PROV,
                PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                "operation: %d", op);
            ok = 0;
        }
        if (ok) {
            wp_rsa_free(ctx->rsa);
            ctx->rsa = NULL;
            if (!wp_rsa_up_ref(rsa)) {
                ok = 0;
            }
        }
    }
    if (ok) {
        ctx->rsa = rsa;
        ctx->op = op;
        ctx->padMode = RSA_PKCS1_PADDING;

        if (!wp_rsaa_set_ctx_params(ctx, params)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA asymmetric cipher context object for encrypting.
 *
 * @param [in, out] ctx     RSA asymmetric cipher context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_encrypt_init(wp_RsaAsymCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsaa_init(ctx, rsa, params, EVP_PKEY_OP_SIGN);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encrypt the data using an RSA key.
 *
 * When out is NULL, only calculate the length of the signature.
 * sigSize may be -1 indicating that the sigLen was set to buffer size.
 *
 * @param [in, out] ctx      RSA asymmetric cipher context object.
 * @param [out]     out      Buffer to hold encrypted data. May be NULL.
 * @param [in, out] outLen   Length of encrypred data in bytes.
 * @param [in]      outSize  Size of encrypted data buffer in bytes.
 * @param [in]      in       Data to be encrypted.
 * @param [in]      inLen    Length of data to be encrypted in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_encrypt(wp_RsaAsymCtx* ctx, unsigned char* out,
    size_t* outLen, size_t outSize, const unsigned char* in, size_t inLen)
{
    int ok = 1;
    word32 sz;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (!wp_rsa_check_key_size(ctx->rsa, 1)) {
        ok = 0;
    }
    else if (out == NULL) {
        *outLen = wc_RsaEncryptSize(wp_rsa_get_key(ctx->rsa));
    }
    else {
        int rc = 0;

        if (outSize == (size_t)-1) {
            outSize = *outLen;
        }
        if ((ctx->padMode == RSA_PKCS1_PADDING) ||
            (ctx->padMode == RSA_PKCS1_WITH_TLS_PADDING)) {
            rc = wc_RsaPublicEncrypt(in, (word32)inLen, out, (word32)outSize,
                wp_rsa_get_key(ctx->rsa), &ctx->rng);
            if (rc < 0) {
                ok = 0;
            }
        }
        else if (ctx->padMode == RSA_PKCS1_OAEP_PADDING) {
            if (ctx->oaepHashType == 0) {
                ctx->oaepHashType = WC_HASH_TYPE_SHA;
                ctx->mgf = WC_MGF1SHA1;
            }
            /* OpenSSL ignores the 'outSize' parameter and allows 0. 
             * See rsa_encrypt() in providers/implementations/asymciphers/rsa_enc.c.
             * Meanwhile, wolfSSL does not allow this. As a workaround, assume 
             * the 'out' buffer is properly sized for the given RSA key size. */
            outSize = wp_rsa_get_bits(ctx->rsa) / 8;
            rc = wc_RsaPublicEncrypt_ex(in, (word32)inLen, out, (word32)outSize,
                wp_rsa_get_key(ctx->rsa), &ctx->rng, WC_RSA_OAEP_PAD,
                ctx->oaepHashType, ctx->mgf, ctx->label, (word32)ctx->labelLen);
            if (rc < 0) {
                ok = 0;
            }
        }
        else if (ctx->padMode == RSA_NO_PADDING) {
            sz = (word32)outSize;
            rc = wc_RsaDirect((byte*)in, (word32)inLen, out, &sz,
                wp_rsa_get_key(ctx->rsa), RSA_PUBLIC_ENCRYPT, &ctx->rng);
            if (rc < 0) {
                ok = 0;
            }
        }
        else {
            ok = 0;
        }
        if (ok) {
            *outLen = rc;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Initialize RSA asymmetric cipher context object for decryption.
 *
 * @param [in, out] ctx     RSA asymmetric cipher context object.
 * @param [in]      rsa     RSA key object.
 * @param [in]      params  Parameters to initialize with.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_decrypt_init(wp_RsaAsymCtx* ctx, wp_Rsa* rsa,
    const OSSL_PARAM params[])
{
    int ok;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else {
        ok = wp_rsaa_init(ctx, rsa, params, EVP_PKEY_OP_DECRYPT);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decrypt using an RSA key.
 *
 * @param [in, out] ctx      RSA asymmetric cipher context object.
 * @param [out]     out      Buffer to hold encrypted data. May be NULL.
 * @param [in, out] outLen   Length of encrypred data in bytes.
 * @param [in]      outSize  Size of encrypted data buffer in bytes.
 * @param [in]      in       Data to be encrypted.
 * @param [in]      inLen    Length of data to be encrypted in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_decrypt(wp_RsaAsymCtx* ctx, unsigned char* out,
    size_t* outLen, size_t outSize, const unsigned char* in, size_t inLen)
{
    int ok = 1;
    word32 sz;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    else if (!wp_rsa_check_key_size(ctx->rsa, 1)) {
        ok = 0;
    }
    else if (out == NULL) {
         if (ctx->padMode == RSA_PKCS1_WITH_TLS_PADDING) {
             *outLen = WOLFSSL_MAX_MASTER_KEY_LENGTH;
         }
         else {
             *outLen = wc_RsaEncryptSize(wp_rsa_get_key(ctx->rsa));
         }
    }
    else {
        int rc = 0;

        if (outSize == (size_t)-1) {
            outSize = *outLen;
        }
#ifdef WC_RSA_BLINDING
        /* TODO: not thread safe */
        rc = wc_RsaSetRNG(wp_rsa_get_key(ctx->rsa), &ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        if (!ok) {
        }
        else
#endif /* WC_RSA_BLINDING */
        if (ctx->padMode == RSA_PKCS1_PADDING) {
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaPrivateDecrypt(in, (word32)inLen, out, (word32)outSize,
                wp_rsa_get_key(ctx->rsa));
            PRIVATE_KEY_LOCK();
            if (rc < 0) {
                ok = 0;
            }
        }
        else if (ctx->padMode == RSA_PKCS1_OAEP_PADDING) {
            if (ctx->oaepHashType == 0) {
                ctx->oaepHashType = WC_HASH_TYPE_SHA;
                ctx->mgf = WC_MGF1SHA1;
            }
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaPrivateDecrypt_ex(in, (word32)inLen, out,
                (word32)outSize, wp_rsa_get_key(ctx->rsa), WC_RSA_OAEP_PAD,
                ctx->oaepHashType, ctx->mgf, ctx->label, (word32)ctx->labelLen);
            PRIVATE_KEY_LOCK();
            if (rc < 0) {
                ok = 0;
            }
        }
        else if (ctx->padMode == RSA_PKCS1_WITH_TLS_PADDING) {
            if (ctx->clientVersion <= 0) {
                ok = 0;
            }
            if (ok) {
                byte mask;
                byte negMask;

                XMEMSET(out, 0, outSize);
                PRIVATE_KEY_UNLOCK();
                rc = wc_RsaPrivateDecrypt(in, (word32)inLen, out,
                    (word32)outSize, wp_rsa_get_key(ctx->rsa));
                PRIVATE_KEY_LOCK();

                /* Constant time checking of master secret. */
                mask  = wp_ct_byte_mask_eq(out[0], ctx->clientVersion >> 8);
                mask &= wp_ct_byte_mask_eq(out[1], ctx->clientVersion);
                if (ctx->negVersion > 0) {
                    /* Check for negotiated version as well. */
                    negMask  = wp_ct_byte_mask_eq(out[0], ctx->negVersion >> 8);
                    negMask &= wp_ct_byte_mask_eq(out[1], ctx->negVersion);
                    mask |= negMask;
                }
                rc &= (int)(char)mask;

                if (rc <= 0) {
                    ok = 0;
                }
            }
        }
        else if (ctx->padMode == RSA_NO_PADDING) {
            sz = (word32)outSize;
            PRIVATE_KEY_UNLOCK();
            rc = wc_RsaDirect((byte*)in, (word32)inLen, out, &sz,
                wp_rsa_get_key(ctx->rsa), RSA_PRIVATE_DECRYPT, &ctx->rng);
            PRIVATE_KEY_LOCK();
            if (rc < 0) {
                ok = 0;
            }
        }
        else {
            ok = 0;
        }
#ifdef WC_RSA_BLINDING
        wc_RsaSetRNG(wp_rsa_get_key(ctx->rsa), NULL);
#endif
        if (ok) {
            *outLen = rc;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Setup the OAEP message digest based on name and properties.
 *
 * @param [in, out] ctx      RSA asymmetric cipher context object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_setup_md(wp_RsaAsymCtx* ctx, const char* mdName,
    const char* mdProps)
{
    int ok = 1;

    if (mdName != NULL) {
        ctx->oaepHashType = wp_name_to_wc_hash_type(ctx->libCtx, mdName,
            mdProps);
        if ((ctx->oaepHashType == WC_HASH_TYPE_NONE) ||
            (ctx->oaepHashType == WC_HASH_TYPE_MD5)) {
            ok = 0;
        }

        if (ok) {
            OPENSSL_strlcpy(ctx->oaepMdName, mdName, sizeof(ctx->oaepMdName));
        }

        if (ok && (!ctx->mgfSet)) {
            ctx->mgf = wp_name_to_wc_mgf(ctx->libCtx, mdName, mdProps);
            if (ctx->mgf == WC_MGF1NONE) {
                ok = 0;
            }
            else {
                OPENSSL_strlcpy(ctx->mgf1MdName, mdName,
                    sizeof(ctx->oaepMdName));
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Setup the MGF1 digest algorithm based on name and properties.
 *
 * @param [in, out] ctx      RSA asymmetric cipher context object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_setup_mgf1_md(wp_RsaAsymCtx* ctx, const char* mdName,
    const char* mdProps)
{
    int ok = 1;

    OPENSSL_strlcpy(ctx->mgf1MdName, mdName, sizeof(ctx->mgf1MdName));
    ctx->mgf = wp_name_to_wc_mgf(ctx->libCtx, mdName, mdProps);
    if (ctx->mgf == WC_MGF1NONE) {
        ok = 0;
    }
    else {
        ctx->mgfSet = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
static int wp_rsaa_get_pad_mode(int padMode, OSSL_PARAM* p)
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
 * Put data from RSA asymmetric cipher context object into parameter objects.
 *
 * @param [in] ctx     RSA asymmetric cipher context object.
 * @param [in] params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_get_ctx_params(wp_RsaAsymCtx* ctx, OSSL_PARAM* params)
{
    int ok = 1;
    OSSL_PARAM* p;

    if (ctx == NULL) {
        ok = 0;
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
        if (p != NULL) {
            ok = wp_rsaa_get_pad_mode(ctx->padMode, p);
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, ctx->oaepMdName)) {
            ok = 0;
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, ctx->mgf1MdName)) {
            ok = 0;
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
        if ((p != NULL) && !OSSL_PARAM_set_octet_ptr(p, ctx->label,
                ctx->labelLen)) {
            ok = 0;
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params,
            OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
        if ((p != NULL) && !OSSL_PARAM_set_uint(p, ctx->clientVersion)) {
            ok = 0;
        }
    }

    if (ok) {
        p = OSSL_PARAM_locate(params,
            OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
        if ((p != NULL) && !OSSL_PARAM_set_uint(p, ctx->negVersion)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns an array of RSA asym cipher context parameters that can be retrieved.
 *
 * @param [in] ctx      RSA asymmetric cipher context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_rsaa_gettable_ctx_params(wp_RsaAsymCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters that we support getting from the RSA asymmetric cipher
     * context.
     */
    static const OSSL_PARAM wp_supported_gettable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR,
            NULL, 0),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_supported_gettable_ctx_params;
}

/**
 * Sets the digest to use into RSA asymmetric cipher context object.
 *
 * @param [in, out] ctx         RSA asymmetric cipher context object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_set_digest(wp_RsaAsymCtx* ctx, const OSSL_PARAM* p,
    const OSSL_PARAM* propsParam)
{
    int ok = 1;
    char mdName[WP_MAX_MD_NAME_SIZE];
    char* pmdName = mdName;
    char mdProps[WP_MAX_PROPS_SIZE];
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
        ok = wp_rsaa_setup_md(ctx, mdName, pmdProps);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the padding mode to use into RSA asymmetric cipher context object.
 *
 * @param [in, out] ctx  RSA asymmetric cipher context object.
 * @param [in]      p    Parameter object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_set_pad_mode(wp_RsaAsymCtx* ctx, const OSSL_PARAM* p)
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
        ctx->padMode = padMode;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the digest to use with MGF1 for PSS into RSA asym cipher context object.
 *
 * @param [in, out] ctx         RSA asymmetric cipher context object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_set_mgf1_digest(wp_RsaAsymCtx* ctx, const OSSL_PARAM* p,
    const OSSL_PARAM* propsParam)
{
    int ok = 1;
    char mgfMdName[WP_MAX_MD_NAME_SIZE] = "";
    char* pmgfMdName = mgfMdName;
    char mgfMdProps[WP_MAX_PROPS_SIZE] = "";
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
        ok = wp_rsaa_setup_mgf1_md(ctx, mgfMdName, pmgfMdProps);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters to use into RSA asymmetric cipher context object.
 *
 * @param [in, out] ctx     RSA asymmetric cipher context object.
 * @param [in]      params  Array of parameter objects.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsaa_set_ctx_params(wp_RsaAsymCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;
    const OSSL_PARAM* propsParam;

    if (params != NULL) {
        p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
        if (p != NULL) {
            propsParam = OSSL_PARAM_locate_const(params,
                OSSL_ASYM_CIPHER_PARAM_PROPERTIES);
            ok = wp_rsaa_set_digest(ctx, p, propsParam);
        }

        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
            if (p != NULL) {
                ok = wp_rsaa_set_pad_mode(ctx, p);
            }
        }

        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
            if (p != NULL) {
                if (ctx->padMode != RSA_PKCS1_OAEP_PADDING) {
                    ok = 0;
                }
                else {
                    propsParam = OSSL_PARAM_locate_const(params,
                        OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
                    ok = wp_rsaa_set_mgf1_digest(ctx, p,propsParam);
                }
            }
        }

        if (ok && (!wp_params_get_octet_string(params,
                OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, &ctx->label, &ctx->labelLen,
                1))) {
            ok = 0;
        }

        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
            if ((p != NULL) && (!OSSL_PARAM_get_uint(p,
                    &ctx->clientVersion))) {
                ok = 0;
            }
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
            if ((p != NULL) && (!OSSL_PARAM_get_uint(p,
                    &ctx->negVersion))) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Returns an array of RSA asymmetric cipher context parameters that can be set.
 *
 * @param [in] ctx      RSA asymmetric cipher context object. Unused.
 * @param [in] provCtx  wolfProvider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_rsaa_settable_ctx_params(wp_RsaAsymCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Parameters that we support setting into the RSA asymmetric cipher
     * context.
     */
    static const OSSL_PARAM wp_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL,
            0),
        OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
        OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_settable_ctx_params;
}

/** Dspatch table for RSA encryption and decryption. */
const OSSL_DISPATCH wp_rsa_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,             (DFUNC)wp_rsaa_ctx_new        },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX,            (DFUNC)wp_rsaa_ctx_free       },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX,             (DFUNC)wp_rsaa_ctx_dup        },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,       (DFUNC)wp_rsaa_encrypt_init   },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,            (DFUNC)wp_rsaa_encrypt        },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,       (DFUNC)wp_rsaa_decrypt_init   },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,            (DFUNC)wp_rsaa_decrypt        },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,     (DFUNC)wp_rsaa_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
                                           (DFUNC)wp_rsaa_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,     (DFUNC)wp_rsaa_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
                                           (DFUNC)wp_rsaa_settable_ctx_params },
    { 0, NULL }
};

#endif /* WP_HAVE_RSA */
