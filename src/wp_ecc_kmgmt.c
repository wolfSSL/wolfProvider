/* wp_ecc_kmgmt.c
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
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/wp_fips.h>

#ifdef WP_HAVE_ECC

/* Note: Explicit parameters are not supported. A predefined curve MUST be used.
 */

/** Name of default digest to use. */
#define WP_ECC_DEFAULT_MD          "SHA256"

/** Supported selections (key parts) in this key manager for ECC. */
#define WP_ECC_POSSIBLE_SELECTIONS                                             \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/** Maximum size of the group name string. */
#define WP_MAX_EC_GROUP_NAME_SZ    20


/**
 * ECC key.
 */
struct wp_Ecc {
    /** wolfSSL ECC key object.  */
    ecc_key key;
    /** wolfSSL random number generator for key generation and signing. */
    WC_RNG rng;

#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;

    /** Provider context - useful when duplicating. */
    WOLFPROV_CTX* provCtx;

    /** wolfSSL curve identifier. */
    int curveId;
    /** Number of bits in curve. */
    int bits;
    /** Boolean for indicating use of cofactor in ECC. */
    int cofactor;
    /** Include public key in ASN.1 encoding of private key. */
    int includePublic;
    /** Public key available. */
    unsigned int hasPub:1;
    /** Private key available. */
    unsigned int hasPriv:1;
};

/**
 * ECC key generation context.
 */
typedef struct wp_EccGenCtx {
    /** Provider context - used when creating an ECC key. */
    WOLFPROV_CTX* provCtx;
    /** The parts of a ECC key to generate. */
    int selection;

    /** Boolean for indicating use of cofactor in ECC. */
    int cofactor;
    /** Name of curve to use. */
    char curveName[WP_MAX_EC_GROUP_NAME_SZ];
} wp_EccGenCtx;

/**
 * ECC mapping of curve name to wolfSSL data.
 */
typedef struct wp_EccGroupMap {
    /** OpenSSL name as a string for curve.  */
    const char* name;
    /** wolfSSL curve identifier. */
    int curveId;
    /** Number of bits in curve. */
    int bits;
} wp_EccGroupMap;


/* Prototype for generation initialization. */
static int wp_ecc_gen_set_params(wp_EccGenCtx* ctx, const OSSL_PARAM params[]);


/** Mapping of OpenSSL curve name to wolfSSL elliptic curve information. */
static const wp_EccGroupMap wp_ecc_group_map[] = {
    { SN_X9_62_prime192v1, ECC_SECP192R1, 192 },
    { "P-192"            , ECC_SECP192R1, 192 },
    { SN_secp224r1       , ECC_SECP224R1, 224 },
    { "P-224"            , ECC_SECP224R1, 224 },
    { SN_X9_62_prime256v1, ECC_SECP256R1, 256 },
    { "P-256"            , ECC_SECP256R1, 256 },
    { SN_secp384r1       , ECC_SECP384R1, 384 },
    { "P-384"            , ECC_SECP384R1, 384 },
    { SN_secp521r1       , ECC_SECP521R1, 521 },
    { "P-521"            , ECC_SECP521R1, 521 },
};

/** Number of entries in elliptic curve mapping. */
#define WP_ECC_GROUP_MAP_SZ  \
    (sizeof(wp_ecc_group_map) / sizeof(*wp_ecc_group_map))

/**
 * Set the parameters into the ECC key object based on group name.
 *
 * @param [in, out] ecc   ECC key object.
 * @param [in]      name  OpenSSL string name for elliptic curve.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_map_group_name(wp_Ecc* ecc, const char* name)
{
    int ok = 1;
    size_t i;

    for (i = 0; i < WP_ECC_GROUP_MAP_SZ; i++) {
        if (strcasecmp(wp_ecc_group_map[i].name, name) == 0) {
            ecc->curveId = wp_ecc_group_map[i].curveId;
            ecc->bits    = wp_ecc_group_map[i].bits;
            break;
        }
    }
    /* Index at size means it didn't find any match. */
    if (i == WP_ECC_GROUP_MAP_SZ) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the OpenSSL string for the elliptic curve set in the ECC key object.
 *
 * @param [in] ecc  ECC key object.
 * @return  NULL on failure.
 * @return  OpenSSL elliptic curve name string.
 */
static const char* wp_ecc_get_group_name(wp_Ecc* ecc)
{
    const char* name = NULL;
    size_t i;

    for (i = 0; i < WP_ECC_GROUP_MAP_SZ; i++) {
        if (ecc->curveId == wp_ecc_group_map[i].curveId) {
            name = wp_ecc_group_map[i].name;
            break;
        }
    }

    return name;
}

/**
 * Set the number of bits into ECC key object based on curve id.
 *
 * wolfSSL only has number of bytes.
 *
 * @param [in, out] ecc  ECC key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_set_bits(wp_Ecc* ecc)
{
    int ok = 0;
    size_t i;

    for (i = 0; i < WP_ECC_GROUP_MAP_SZ; i++) {
        if (ecc->curveId == wp_ecc_group_map[i].curveId) {
            ecc->bits = wp_ecc_group_map[i].bits;
            ok = 1;
            break;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check whether the curve is valid for private key operations.
 *
 * For FIPS, public key operations available for P-192 but not private.
 *
 * @param [in] curveId  ECC key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_ecc_check_usage(wp_Ecc* ecc)
{
    int ret = 1;

    if ((wolfProvider_GetFipsChecks() & WP_FIPS_CHECK_P192) &&
            (ecc->curveId == ECC_SECP192R1)) {
        ret = 0;
    }

    return ret;
}

/*
 * ECC key
 */

/**
 * Increment reference count for key.
 *
 * Used in key generation, signing/verify and key exchange.
 *
 * @param [in, out] ecc  ECC key object.
 * @return  1 on success.
 * @return  0 when multi-threaded and locking fails.
 */
int wp_ecc_up_ref(wp_Ecc* ecc)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&ecc->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        ecc->refCnt++;
        wc_UnLockMutex(&ecc->mutex);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    ecc->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the wolfSSL ECC object from the ECC key object.
 *
 * @param [in] ecc  ECC key object.
 * @return  Pointer to wolfSSL ECC key object.
 */
ecc_key* wp_ecc_get_key(wp_Ecc* ecc)
{
    return &ecc->key;
}

/**
 * Get the wolfSSL RNG object from the ECC key object.
 *
 * @param [in] ecc  ECC key object.
 * @return  Pointer to wolfSSL RNG object.
 */
WC_RNG* wp_ecc_get_rng(wp_Ecc* ecc)
{
    return &ecc->rng;
}

/**
 * Get the maximum size of a secret in bytes.
 *
 * @param [in] ecc  ECC key object.
 * @return  Maximum number of bytes in a secret.
 */
int wp_ecc_get_size(wp_Ecc* ecc)
{
    return (ecc->bits + 7) / 8;
}

/**
 * Get the mutex object from the ECC key object.
 *
 * @param [in] ecc  ECC key object.
 * @return  Pointer to wolfSSL mutex object.
 */
wolfSSL_Mutex* wp_ecc_get_mutex(wp_Ecc* ecc)
{
    return &ecc->mutex;
}

/**
 * Create a new ECC key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC key object on success.
 * @return  NULL on failure.
 */
static wp_Ecc* wp_ecc_new(WOLFPROV_CTX *provCtx)
{
    wp_Ecc* ecc = NULL;

    if (wolfssl_prov_is_running()) {
        ecc = (wp_Ecc*)OPENSSL_zalloc(sizeof(*ecc));
    }
    if (ecc != NULL) {
        int ok = 1;
        int rc;

        rc = wc_ecc_init_ex(&ecc->key, NULL, INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }

        if (ok) {
            /* RNG's tied to lifecycle of key in wolfSSL. */
            rc = wc_InitRng(&ecc->rng);
            if (rc != 0) {
                wc_ecc_free(&ecc->key);
                ok = 0;
            }
        }

    #ifndef SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&ecc->mutex);
            if (rc != 0) {
                wc_FreeRng(&ecc->rng);
                wc_ecc_free(&ecc->key);
                ok = 0;
            }
        }
    #endif

        if (ok) {
    #if !defined(HAVE_FIPS) || \
        (defined(HAVE_FIPS_VERSION) && HAVE_FIPS_VERSION > 2)
        #ifdef ECC_TIMING_RESISTANT
            (void)wc_ecc_set_rng(&ecc->key, &ecc->rng);
        #endif
    #endif
            ecc->provCtx = provCtx;
            ecc->refCnt = 1;
            ecc->includePublic = 1;
        }

        if (!ok) {
            OPENSSL_free(ecc);
            ecc = NULL;
        }
    }

    return ecc;
}

/**
 * Dispose of ECC key object.
 *
 * @param [in, out] ecc  ECC key object.
 */
void wp_ecc_free(wp_Ecc* ecc)
{
    if (ecc != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&ecc->mutex);
        cnt = --ecc->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&ecc->mutex);
        }
    #else
        cnt = --ecc->refCnt;
    #endif

        if (cnt == 0) {
    #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&ecc->mutex);
    #endif
            wc_FreeRng(&ecc->rng);
            wc_ecc_free(&ecc->key);
            OPENSSL_free(ecc);
        }
    }
}

/**
 * Duplicate specific parts of a ECC key object.
 *
 * @param [in] src        Source ECC key object.
 * @param [in] selection  Parts of key to include.
 * @return  NULL on failure.
 * @return  New ECC key object on success.
 */
static wp_Ecc* wp_ecc_dup(const wp_Ecc *src, int selection)
{
    wp_Ecc* dst;

    dst = wp_ecc_new(src->provCtx);
    if (dst != NULL) {
        int ok = 1;
        int rc;

        /* Copy curve if requested. */
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
            rc = wc_ecc_set_curve(&dst->key, (src->bits + 7) / 8, src->curveId);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                dst->curveId = src->curveId;
                dst->bits    = src->bits;
            }
        }
        /* Copy public key if available and requested. */
        if (ok && src->hasPub &&
            ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
            dst->hasPub = 1;
            rc = wc_ecc_copy_point((ecc_point*)&src->key.pubkey,
                &dst->key.pubkey);
            if (rc != 0) {
                ok = 0;
            }
        }
        /* Copy private key if available and requested. */
        if (ok && src->hasPriv &&
            ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
            dst->hasPriv = 1;
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
            rc = mp_copy(wc_ecc_key_get_priv(&src->key),
                wc_ecc_key_get_priv(&dst->key));
#else
            rc = mp_copy(&(src->key.k), &(dst->key.k));
#endif
            if (rc != 0) {
                ok = 0;
            }
        }
        /* Copy other stuff if requested. */
        if (ok && ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)) {
            dst->cofactor      = src->cofactor;
            dst->includePublic = src->includePublic;
        }

        if (!ok) {
            wp_ecc_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Load the ECC key.
 *
 * Return the ECC key object taken out of the reference.
 *
 * @param [in, out] pEcc  Pointer to a ECC key object.
 * @param [in]      size  Size of data structure that is the ECC key object.
 *                        Unused.
 * @return  NULL when no ECC key object at reference.
 * @return  ECC key object from reference on success.
 */
static const wp_Ecc* wp_ecc_load(const wp_Ecc** pEcc, size_t size)
{
    const wp_Ecc* ecc = *pEcc;
    /* TODO: validate the object is a wp_Ecc? */
    (void)size;
    *pEcc = NULL;
    return ecc;
}

/**
 * Return an array of supported settable parameters for the ECC key.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecc_settable_params(WOLFPROV_CTX* provCtx)
{
   /**
     * Supported settable parameters for ECC key.
     */
    static const OSSL_PARAM wp_ecc_supported_settable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_ecc_supported_settable_params;
}

/**
 * Set the encoded public key parameter into ECC key object.
 *
 * @param [in, out] ecc     ECC key object.
 * @param [in]      params  Array of parameters and values.
 * @param [in]      key     String to look for.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_set_params_enc_pub_key(wp_Ecc *ecc, const OSSL_PARAM params[],
    const char* key)
{
    int ok = 1;
    unsigned char* data = NULL;
    size_t len;

    if (!wp_params_get_octet_string_ptr(params, key, &data, &len)) {
        ok = 0;
    }
    if (ok && (data != NULL)) {
        int rc = wc_ecc_import_x963_ex(data, (word32)len, &ecc->key,
            ecc->curveId);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            ecc->hasPub = 1;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the public key values into ECC key object.
 *
 * @param [in, out] ecc     ECC key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_set_params_pub(wp_Ecc *ecc, const OSSL_PARAM params[])
{
    int ok = 1;
    int set = 0;

    if (!wp_params_get_mp(params, OSSL_PKEY_PARAM_EC_PUB_X,
            ecc->key.pubkey.x, &set)) {
        ok = 0;
    }
    if (ok && (set == 1)) {
        if (mp_iszero(ecc->key.pubkey.x)) {
            ok = 0;
        }
        if (ok) {
            ecc->key.type = ECC_PUBLICKEY;
            ecc->hasPub = 1;
        }
    }
    if (!wp_params_get_mp(params, OSSL_PKEY_PARAM_EC_PUB_Y,
            ecc->key.pubkey.y, NULL)) {
        ok = 0;
    }
    if (wp_ecc_set_params_enc_pub_key(ecc, params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) != 1) {
        ok = 0;
    }
    if (wp_ecc_set_params_enc_pub_key(ecc, params,
        OSSL_PKEY_PARAM_PUB_KEY) != 1) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the ECC key parameters.
 *
 * @param [in, out] ecc     ECC key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_set_params(wp_Ecc *ecc, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM *p;

    if (params != NULL) {
        if (!wp_ecc_set_params_pub(ecc, params)) {
            ok = 0;
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                    OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
            if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ecc->includePublic))) {
                ok = 0;
            }
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params,
                    OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
            if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ecc->cofactor))) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported gettable parameters for the ECC key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_ecc_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for ECC key object.
     */
    static const OSSL_PARAM wp_ecc_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, NULL,
            0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_PUB_X, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_PUB_Y, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_ecc_supported_gettable_params;
}

/**
 * Get the security bits for an ECC key.
 *
 * @param [in] ecc  ECC key object.
 * @return  Security bits on success.
 * @return  0 on failure.
 */
static int wp_ecc_get_security_bits(wp_Ecc* ecc)
{
    int bits = 0;

    if (ecc->bits >= 512) {
        bits = 256;
    }
    else if (ecc->bits >= 384) {
        bits = 192;
    }
    else if (ecc->bits >= 256) {
        bits = 128;
    }
    else if (ecc->bits >= 224) {
        bits = 112;
    }
    else if (ecc->bits >= 160) {
        bits = 80;
    }

    return bits;
}

/**
 * Get the encoded public key into parameters.
 *
 * @param [in]      ecc     ECC key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_get_params_enc_pub_key(wp_Ecc* ecc, OSSL_PARAM params[],
    const char* key)
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, key);
    if (p != NULL) {
        int rc;
        word32 outLen = (word32)p->return_size;

        if (ecc->hasPub == 0) {
            ok = 0;
        }
        if (ok) {
            if (p->data == NULL) {
                outLen = 1 + 2 * ((ecc->bits + 7) / 8);
            }
            else {
                rc = wc_ecc_export_x963_ex(&ecc->key, p->data, &outLen, 0);
                if (rc != 0) {
                    ok = 0;
                }
            }
            p->return_size = outLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the public key into parameters.
 *
 * @param [in]      ecc     ECC key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_get_params_pub(wp_Ecc* ecc, OSSL_PARAM params[])
{
    int ok = 1;

    if (!wp_params_set_mp(params, OSSL_PKEY_PARAM_EC_PUB_X, ecc->key.pubkey.x,
                          (ecc->hasPub == 1))) {
        ok = 0;
    }
    if (!wp_params_set_mp(params, OSSL_PKEY_PARAM_EC_PUB_Y, ecc->key.pubkey.y,
                          (ecc->hasPub == 1))) {
        ok = 0;
    }
    /* Encoded public key. */
    if (ok && (!wp_ecc_get_params_enc_pub_key(ecc, params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY))) {
        ok = 0;
    }
    /* Public key. */
    if (ok && (!wp_ecc_get_params_enc_pub_key(ecc, params,
            OSSL_PKEY_PARAM_PUB_KEY))) {
        ok = 0;
    }

    return ok;
}

/**
 * Get the ECC key parameters.
 *
 * @param [in]      ecc     ECC key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_get_params(wp_Ecc* ecc, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    /* Maximum secret size. */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if ((p != NULL) && !OSSL_PARAM_set_int(p, wc_ecc_sig_size(&ecc->key))) {
        ok = 0;
    }
    if (ok) {
        /* Curve bit size. */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, ecc->bits)) {
            ok = 0;
        }
    }
    if (ok) {
        /* Security bits of curve. */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p,
                wp_ecc_get_security_bits(ecc)))) {
            ok = 0;
        }
    }
    if (ok) {
        /* Curve name string. */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p,
                wp_ecc_get_group_name(ecc)))) {
            ok = 0;
        }
    }
    if (ok) {
        /* String of default digest. */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p,
                WP_ECC_DEFAULT_MD))) {
            ok = 0;
        }
    }
    if (ok) {
        /* String for default digest. */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, 1)) {
            ok = 0;
        }
    }
    /* Public key */
    if (ok) {
        ok = wp_ecc_get_params_pub(ecc, params);
    }
    if (ok && (!wp_params_set_mp(params, OSSL_PKEY_PARAM_PRIV_KEY,
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
            wc_ecc_key_get_priv(&ecc->key),
#else
            &(ecc->key.k),
#endif
            ecc->hasPriv))) {
        ok = 0;
    }
    /* Private key. */
    if (ok) {
        /* Compressed or uncompressed point format. */
        p = OSSL_PARAM_locate(params,
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, "uncompressed"))) {
            ok = 0;
        }
    }

    if (ok) {
        /* Always assume not decoded from explicit params for now */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, 0)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check ECC key object has the components required.
 *
 * @param [in] ecc        ECC key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_has(const wp_Ecc* ecc, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
       ok = 0;
    }
    if (ecc == NULL) {
       ok = 0;
    }
    if (ok && ((selection & WP_ECC_POSSIBLE_SELECTIONS) != 0)) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok &= ecc->hasPub;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok &= ecc->hasPriv;
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
            ok &= ecc->curveId != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two ECC key objects match for the components specified.
 *
 * @param [in] ecc1       First ECC key object.
 * @param [in] ecc2       Second ECC key object.
 * @param [in] selection  Parts of key to match.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_match(wp_Ecc* ecc1, wp_Ecc* ecc2, int selection)
{
    int ok = 1;
    int checked = 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    /* Check the curve ID to see whether the parameters are the same. */
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) &&
            (ecc1->curveId != ecc2->curveId)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)) {
        if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
            if (wc_ecc_cmp_point((ecc_point*)&ecc1->key.pubkey,
                            (ecc_point*)&ecc2->key.pubkey) != MP_EQ) {
                ok = 0;
            } else {
                checked = 1;
            }
        }
        if (ok && checked == 0 &&
            ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        #if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
                if (mp_cmp(wc_ecc_key_get_priv(&ecc1->key),
                    wc_ecc_key_get_priv(&ecc2->key)) != MP_EQ)
        #else
                if (mp_cmp(&(ecc1->key.k), &(ecc2->key.k)) != MP_EQ)
        #endif
                {
                    ok = 0;
                } else {
                    checked = 1;
                }
        }
        ok = ok && checked;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
/**
 * Quick validate the ECC public key.
 *
 * Check for infinity and point is on curve.
 *
 * @param [in] ecc        ECC key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_validate_public_key_quick(const wp_Ecc* ecc)
{
    int ok = 1;

    if (wc_ecc_point_is_at_infinity((ecc_point*)&ecc->key.pubkey)) {
        ok = 0;
    }
#ifdef USE_ECC_B_PARAM
    if (ok && (!wc_ecc_point_is_on_curve((ecc_point*)&ecc->key.pubkey,
            ecc->curveId))) {
        ok = 0;
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Validate the ECC key.
 *
 * @param [in] ecc        ECC key object.
 * @param [in] selection  Parts of key to validate.
 * @param [in] checkType  How thorough to check key. Values:
 *                          OSSL_KEYMGMT_VALIDATE_FULL_CHECK or
 *                          OSSL_KEYMGMT_VALIDATE_QUICK_CHECK.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_validate(const wp_Ecc* ecc, int selection, int checkType)
{
    int ok = 1;
    int origType;
    int rc;

    /* Only named curves supported. */
    if (((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) &&
        (ecc->curveId == 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) && (!ecc->hasPub)) {
        ok = 0;
    }
    if (ok && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        /* TODO: Quick check for older versions? */
        if (checkType == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK) {
            if (!wp_ecc_validate_public_key_quick(ecc)) {
                ok = 0;
            }
        }
        else
    #else
       (void)checkType;
    #endif
        {
            /* We may have a private key inside that does not match the public
             * key that has been set, which is OK. Override the internal type
             * to force a public key only check */
            origType = ecc->key.type;
            ((wp_Ecc*)ecc)->key.type = ECC_PUBLICKEY;
            rc = wc_ecc_check_key((ecc_key*)&ecc->key);
            ((wp_Ecc*)ecc)->key.type = origType;
            if (rc != 0) {
                ok = 0;
            }
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
        (!ecc->hasPriv)) {
        ok = 0;
    }
    if ((ok && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        rc = wc_ecc_check_key((ecc_key*)&ecc->key);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the group into ECC key object from parameters.
 *
 * @param [in, out] ecc     ECC key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_import_group(wp_Ecc* ecc, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        const char* name = NULL;

        if (p->data_type == OSSL_PARAM_UTF8_STRING) {
            name = (const char*)p->data;
            if (name == NULL) {
                ok = 0;
            }
        }
        else if (p->data_type == OSSL_PARAM_UTF8_PTR) {
            if (!OSSL_PARAM_get_utf8_ptr(p, &name)) {
                ok = 0;
            }
        }
        if (ok && (name != NULL) && (!wp_ecc_map_group_name(ecc, name))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key pair into ECC key object from parameters.
 *
 * @param [in, out] ecc     ECC key object.
 * @param [in]      params  Array of parameters and values.
 * @param [in]      priv    Private key is to be imported.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_import_keypair(wp_Ecc* ecc, const OSSL_PARAM params[],
    int priv)
{
    int ok = 1;

    if (wp_ecc_set_params_pub(ecc, params) != 1) {
        ok = 0;
    }
    if (ok && priv && (!wp_params_get_mp(params, OSSL_PKEY_PARAM_PRIV_KEY,
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
            wc_ecc_key_get_priv(&ecc->key),
#else
            &(ecc->key.k),
#endif
            NULL))) {
        ok = 0;
    }
    if (ok &&
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
            (!mp_iszero(wc_ecc_key_get_priv(&ecc->key)))
#else
            (!mp_iszero(&(ecc->key.k)))
#endif
        ) {
        ecc->key.type = ECC_PRIVATEKEY;
        ecc->hasPriv = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import other ECC key fields: cofactor, include public in ASN.1 encoding.
 *
 * @param [in, out] ecc     ECC key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_import_other(wp_Ecc* ecc, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    /* Use cofactor when performing ECDH. */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if ((p != NULL) && !OSSL_PARAM_get_int(p, &ecc->cofactor)) {
        ok = 0;
    }

    if (ok) {
        /* Include public key when encoding ECC key. */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC);
        if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ecc->includePublic))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key into ECC key object from parameters.
 *
 * @param [in, out] ecc        ECC key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_import(wp_Ecc* ecc, int selection, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ecc == NULL) {
        ok = 0;
    }
    if (ok && ((selection & WP_ECC_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok & ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)) {
        ok = 0;
    }
    if (ok && (!wp_ecc_import_group(ecc, params))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) &&
        (!wp_ecc_import_keypair(ecc, params,
            (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) &&
        (!wp_ecc_import_other(ecc, params))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** ECC private key parameters. */
#define WP_ECC_PRIVATE_KEY_PARAMS                                              \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
/** ECC public key parameters. */
#define WP_ECC_PUBLIC_KEY_PARAMS                                               \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
/** ECC domain/curve parameters. */
#define WP_ECC_DOMAIN_PARAMS                                                   \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0)
/** Other ECC key parameters. */
#define WP_ECC_OTHER_PARAMS                                                    \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),                   \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, NULL)

/**
 * Table of key parameters for difference selections.
 */
static const OSSL_PARAM wp_ecc_key_params[] = {
    /* 0 */
    OSSL_PARAM_END,

    /* 1 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 3 */
    WP_ECC_PUBLIC_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 5 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_PUBLIC_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 8 */
    WP_ECC_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 10 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 13 */
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 16 */
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 21 */
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 24 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 28 */
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 32 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 37 */
    WP_ECC_DOMAIN_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 41 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_DOMAIN_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 46 */
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_DOMAIN_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,

    /* 51 */
    WP_ECC_PRIVATE_KEY_PARAMS,
    WP_ECC_PUBLIC_KEY_PARAMS,
    WP_ECC_DOMAIN_PARAMS,
    WP_ECC_OTHER_PARAMS,
    OSSL_PARAM_END,
};

/**
 * Get the key parameters for a selection.
 *
 * @param [in] selection  Parts of key to import/export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_ecc_key_types(int selection)
{
    int idx = 0;
    int extra = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) {
        idx += 21;
        /* There are two 'other' parameters. */
        extra += 2;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        idx += 8 + 4 * extra;
        extra++;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        idx += 3 + 2 * extra;
        extra++;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        idx += 1 + extra;
    }

    return &wp_ecc_key_params[idx];
}

/**
 * Get the key parameters when importing for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_ecc_import_types(int selection)
{
    return wp_ecc_key_types(selection);
}

/**
 * Put the ECC key's group name into the parameters.
 *
 * @param [in]      ecc     ECC key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_export_params(wp_Ecc* ecc, OSSL_PARAM* params, int* pIdx)
{
    int ok = 1;
    int i = *pIdx;

    wp_param_set_utf8_string_ptr(&params[i++], OSSL_PKEY_PARAM_GROUP_NAME,
        wp_ecc_get_group_name(ecc));

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Encoded public key size: format byte | x-ordinate | y-ordinate */
#define WP_ECC_PUBLIC_KEY_SIZE(ecc) (1 + 2 * ((ecc->bits + 7) / 8))

/**
 * Get the size of allocated data needed for key pair.
 *
 * Called when exporting.
 *
 * @param [in] ecc   ECC key object.
 * @param [in] priv  Private key is being exported.
 * @return  Size of buffer to hold allocated key pair data.
 */
static size_t wp_ecc_export_keypair_alloc_size(wp_Ecc* ecc, int priv)
{
    /* Public key. */
    size_t len = WP_ECC_PUBLIC_KEY_SIZE(ecc);
    if (priv) {
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
        len += mp_unsigned_bin_size(wc_ecc_key_get_priv(&ecc->key));
#else
        len += mp_unsigned_bin_size(&(ecc->key.k));
#endif
    }
    return len;
}

/**
 * Put the ECC key pair data into the parameter.
 *
 * Assumes data buffer is big enough.
 *
 * @param [in]      ecc     ECC key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @param [in, out] data    Data buffer to place group data into.
 * @param [in, out] idx     Pointer to current index into data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_export_keypair(wp_Ecc* ecc, OSSL_PARAM* params, int* pIdx,
    unsigned char* data, size_t* idx, int priv)
{
    int ok = 1;
    int rc;
    int i = *pIdx;
    word32 outLen;

    outLen = WP_ECC_PUBLIC_KEY_SIZE(ecc);
    rc = wc_ecc_export_x963_ex(&ecc->key, data + *idx, &outLen, 0);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        wp_param_set_octet_string_ptr(&params[i++], OSSL_PKEY_PARAM_PUB_KEY,
            data + *idx, outLen);
        *idx += outLen;
        if (priv && (!wp_param_set_mp(&params[i++], OSSL_PKEY_PARAM_PRIV_KEY,
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && LIBWOLFSSL_VERSION_HEX >= 0x05006002
                wc_ecc_key_get_priv(&ecc->key),
#else
                &(ecc->key.k),
#endif
                data, idx))) {
            ok = 0;
        }
    }

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Put the other ECC key data into the parameter: cofactor and include public.
 *
 * @param [in]      ecc     ECC key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_export_other(wp_Ecc* ecc, OSSL_PARAM* params, int* pIdx)
{
    int ok = 1;
    int i = *pIdx;

    wp_param_set_int(&params[i++], OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
        &ecc->cofactor);
    wp_param_set_int(&params[i++], OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
        &ecc->includePublic);

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the ECC key.
 *
 * Key data placed in parameters and then passed to callback.
 *
 * @param [in] ecc        ECC key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Function to pass constructed parameters to.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_export(wp_Ecc *ecc, int selection, OSSL_CALLBACK *paramCb,
    void *cbArg)
{
    int ok = 1;
    OSSL_PARAM params[6];
    int paramsSz = 0;
    unsigned char* data = NULL;
    size_t len = 0;
    int expParams = (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0;
    int expKeyPair = (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
    int expPub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    int expPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int expOther = (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0;

    if (!expParams) {
        ok = 0;
    }
    if (ok && expPriv && (!expPub)) {
        ok = 0;
    }
    if (ok && expOther && (!expKeyPair)) {
        ok = 0;
    }
    if (ok) {
        XMEMSET(params, 0, sizeof(params));
        /* Always include the domain parameters. */
        if (!wp_ecc_export_params(ecc, params, &paramsSz)) {
            ok = 0;
        }
    }
    if (ok && expKeyPair) {
        data = OPENSSL_malloc(wp_ecc_export_keypair_alloc_size(ecc, expPriv));
        if (data == NULL) {
            ok = 0;
        }
        if (ok && !wp_ecc_export_keypair(ecc, params, &paramsSz, data, &len,
                expPriv)) {
            ok = 0;
        }
    }
    if (ok && expOther && (!wp_ecc_export_other(ecc, params, &paramsSz))) {
        ok = 0;
    }
    if (ok) {
        ok = paramCb(params, cbArg);
    }
    OPENSSL_clear_free(data, len);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the key parameters when exporting for a selection.
 *
 * @param [in] selection  Parts of key to export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM *wp_ecc_export_types(int selection)
{
    return wp_ecc_key_types(selection);
}

/**
 * Return the operation name as a string.
 *
 * @param [in] op  Operationn type being performed.
 * @return  Name of operation.
 */
static const char* wp_ecc_query_operation_name(int op)
{
    const char* name = NULL;

    if (op == OSSL_OP_KEYEXCH) {
        name = "ECDH";
    }
    else if (op == OSSL_OP_SIGNATURE) {
        name = "ECDSA";
    }

    return name;
}

/*
 * ECC generation
 */

/**
 * Create ECC generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New ECC generation context object on success.
 * @return  NULL on failure.
 */
static wp_EccGenCtx* wp_ecc_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    wp_EccGenCtx* ctx = NULL;

    if (wolfssl_prov_is_running() &&
        ((selection & WP_ECC_POSSIBLE_SELECTIONS) != 0)) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int ok = 1;

        if (!wp_ecc_gen_set_params(ctx, params)) {
            ok = 0;
        }
        if (ok) {
            ctx->provCtx   = provCtx;
            ctx->selection = selection;
        }

        if (!ok) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Set a template key.
 *
 * Gets the name of the curve and sets it into ECC generation context object.
 *
 * @param [in, out] ctx  ECC generation context object.
 * @param [in]      ecc  ECC key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_gen_set_template(wp_EccGenCtx* ctx, wp_Ecc* ecc)
{
    int ok = 1;
    const char* name = NULL;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok) {
        name = wp_ecc_get_group_name(ecc);
        if (name == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        XSTRNCPY(ctx->curveName, name, sizeof(ctx->curveName)-1);
        ctx->curveName[sizeof(ctx->curveName)-1] = '\0';
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#define WP_EC_ENCODING_NAMED_CURVE_STR "named_curve"
#define WP_EC_ENCODING_NAMED_CURVE_STR_LEN 11

/**
 * Sets the parameters into the ECC generation context object.
 *
 * @param [in, out] ctx     ECC generation context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_gen_set_params(wp_EccGenCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ctx->cofactor))) {
        ok = 0;
    }
    if (ok && (!wp_params_get_utf8_string(params, OSSL_PKEY_PARAM_GROUP_NAME,
        ctx->curveName, sizeof(ctx->curveName)))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_ENCODING);
        if (p != NULL) {
            if (p->data_type != OSSL_PARAM_UTF8_STRING) {
                ok = 0;
            }
            else if (p->data_size != WP_EC_ENCODING_NAMED_CURVE_STR_LEN) {
                ok = 0;
            }
            else if (XMEMCMP(p->data, WP_EC_ENCODING_NAMED_CURVE_STR,
                        p->data_size) != 0) {
                ok = 0;
            }
            if (!ok) {
                WOLFPROV_ERROR_MSG(WP_LOG_PK,
                    "only named curve encoding supported");
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate ECC key pair using wolfSSL.
 *
 * @param [in, out] ctx    ECC generation context object.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument to pass to callback. Unused.
 * @return  NULL on failure.
 * @return  ECC key object on success.
 */
static wp_Ecc* wp_ecc_gen(wp_EccGenCtx *ctx, OSSL_CALLBACK *cb, void *cbArg)
{
    wp_Ecc* ecc = NULL;

    (void)cb;
    (void)cbArg;

    if (ctx->curveName[0] != '\0') {
        ecc = wp_ecc_new(ctx->provCtx);
    }
    if (ecc != NULL) {
        int ok = 1;
        int rc;

        if (!wp_ecc_map_group_name(ecc, ctx->curveName)) {
            ok = 0;
        }
        if (ok && ((ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)) {
            ok = wp_ecc_check_usage(ecc);
            if (ok) {
                /* Generate key pair with wolfSSL. */
                PRIVATE_KEY_UNLOCK();
            #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
                rc = wc_ecc_make_key_ex2(&ecc->rng, (ecc->bits + 7) / 8,
                    &ecc->key, ecc->curveId, WC_ECC_FLAG_NONE);
            #else
                rc = wc_ecc_make_key_ex(&ecc->rng, (ecc->bits + 7) / 8,
                    &ecc->key, ecc->curveId);
            #endif
                PRIVATE_KEY_LOCK();
                if (rc != 0) {
                    ok = 0;
                }
                else {
                    ecc->cofactor = ctx->cofactor;
                    ecc->hasPub = 1;
                    ecc->hasPriv = 1;
                }
            }
        }
        if (ok && ((ctx->selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)) {
            rc = wc_ecc_set_curve(&ecc->key, 0, ecc->curveId);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (!ok) {
            wp_ecc_free(ecc);
            ecc = NULL;
        }
    }

    return ecc;
}

/**
 * Dispose of the ECC generation context object.
 *
 * @param [in, out] ctx  ECC generation context object.
 */
static void wp_ecc_gen_cleanup(wp_EccGenCtx *ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return an array of supported settable parameters for the ECC gen context.
 *
 * @param [in] ctx      ECC generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecc_gen_settable_params(wp_EccGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for ECC generation context.
     */
    static OSSL_PARAM wp_ecc_gen_supported_settable_params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_ecc_gen_supported_settable_params;
}

/** Dispatch table for ECC key management. */
const OSSL_DISPATCH wp_ecc_keymgmt_functions[] = {
    /* ECC key. */
    { OSSL_FUNC_KEYMGMT_NEW,               (DFUNC)wp_ecc_new                  },
    { OSSL_FUNC_KEYMGMT_FREE,              (DFUNC)wp_ecc_free                 },
    { OSSL_FUNC_KEYMGMT_DUP,               (DFUNC)wp_ecc_dup                  },
    { OSSL_FUNC_KEYMGMT_LOAD,              (DFUNC)wp_ecc_load                 },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,        (DFUNC)wp_ecc_get_params           },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,   (DFUNC)wp_ecc_gettable_params      },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,        (DFUNC)wp_ecc_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,   (DFUNC)wp_ecc_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS,               (DFUNC)wp_ecc_has                  },
    { OSSL_FUNC_KEYMGMT_MATCH,             (DFUNC)wp_ecc_match                },
    { OSSL_FUNC_KEYMGMT_VALIDATE,          (DFUNC)wp_ecc_validate             },
    { OSSL_FUNC_KEYMGMT_IMPORT,            (DFUNC)wp_ecc_import               },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,      (DFUNC)wp_ecc_import_types         },
    { OSSL_FUNC_KEYMGMT_EXPORT,            (DFUNC)wp_ecc_export               },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,      (DFUNC)wp_ecc_export_types         },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
                                           (DFUNC)wp_ecc_query_operation_name },
    /* ECC key generation. */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,          (DFUNC)wp_ecc_gen_init             },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,    (DFUNC)wp_ecc_gen_set_params       },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                           (DFUNC)wp_ecc_gen_settable_params  },
    { OSSL_FUNC_KEYMGMT_GEN,               (DFUNC)wp_ecc_gen                  },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,       (DFUNC)wp_ecc_gen_cleanup          },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,  (DFUNC)wp_ecc_gen_set_template     },
    { 0, NULL }
};


/*
 * ECC encoding/decoding.
 */

/**
 * Encode/decode ECC public/private key.
 */
typedef struct wp_EccEncDecCtx {
    /** Provider context - used when creating ECC key. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to export. */
    int selection;

    /** Supported format. */
    int format;
    /** Data format: DER or PEM. */
    int encoding;

    /** Cipher to use when encoding EncryptedPrivateKeyInfo. */
    int cipher;
    /** Name of cipher to use when encoding EncryptedPrivateKeyInfo. */
    const char* cipherName;
} wp_EccEncDecCtx;


/**
 * Create a new ECC encoder/decoder context.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] format    Supported format.
 * @param [in] encoding  Data format.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_enc_dec_new(WOLFPROV_CTX* provCtx, int format,
    int encoding)
{
    wp_EccEncDecCtx *ctx = NULL;
    if (wolfssl_prov_is_running()) {
        ctx = (wp_EccEncDecCtx*)OPENSSL_zalloc(sizeof(wp_EccEncDecCtx));
    }
    if (ctx != NULL) {
        ctx->provCtx  = provCtx;
        ctx->format   = format;
        ctx->encoding = encoding;
    }
    return ctx;
}

/**
 * Dispose of ECC encoder/decoder context object.
 *
 * @param [in, out] ctx  ECC encoder/decoder context object.
 */
static void wp_ecc_enc_dec_free(wp_EccEncDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return the settable parameters for the ECC encoder/decoder context.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecc_enc_dec_settable_ctx_params(
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_ecc_enc_dec_supported_settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    (void)provCtx;
    return wp_ecc_enc_dec_supported_settables;
}

/**
 * Set the ECC encoder/decoder context parameters.
 *
 * @param [in, out] ctx     ECC encoder/decoder context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_enc_dec_set_ctx_params(wp_EccEncDecCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wp_cipher_from_params(params, &ctx->cipher, &ctx->cipherName)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if LIBWOLFSSL_VERSION_HEX < 0x05000000
/* List of OID sums to curve ids to lookup and compare with corresponding OIDs.
 */
static const struct {
    int oidSum;
    int curveId;
} wp_oid_sum_to_curve_id[] = {
    { ECC_SECP192R1_OID, ECC_SECP192R1 },
    { ECC_SECP224R1_OID, ECC_SECP224R1 },
    { ECC_SECP256R1_OID, ECC_SECP256R1 },
    { ECC_SECP384R1_OID, ECC_SECP384R1 },
    { ECC_SECP521R1_OID, ECC_SECP521R1 },
};
/* Size of array of oid sum to curve ids mappings. */
#define WP_OID_SUM_TO_CURVE_ID_SZ  \
    ((int)(sizeof(wp_oid_sum_to_curve_id) / sizeof(*wp_oid_sum_to_curve_id)))

/*
 * Get the curve id for the OID passed in.
 *
 * @param [in] oid  OID to identify.
 * @param [in] len  Length of OID data in bytes.
 * @return  ECC_CURVE_INVALID on failure.
 * @return  wolfSSL curve id on success.
 */
static int wp_ecc_get_curve_id_from_oid(unsigned char* oid, int len)
{
    int curveId = ECC_CURVE_INVALID;
    int i;

    for (i = 0; i < WP_OID_SUM_TO_CURVE_ID_SZ; i++) {
         const byte* wcOid;
         word32 wcOidSz;
         int rc;

         /* Get the OID for the OID sum. */
         rc = wc_ecc_get_oid(wp_oid_sum_to_curve_id[i].oidSum, &wcOid,
             &wcOidSz);
         if (rc < 0)
             break;

         /* Compare retrieved OID with one passed in. */
         if ((len == (int)wcOidSz) && (XMEMCMP(oid, wcOid, len) == 0)) {
             curveId = wp_oid_sum_to_curve_id[i].curveId;
             break;
         }
    }

    return curveId;
}
#endif

/**
 * Decode the DER encoded ECC parameters into the ECC key object.
 *
 * @param [in, out] ecc   ECC key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_decode_params(wp_Ecc* ecc, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 oidLen;

    /* TODO: manually decoding as wolfSSL doesn't offer API to do this. */
    if (len < 3) {
        ok = 0;
    }
    if (ok && (data[0] != 0x06)) {
        WOLFPROV_MSG(WP_LOG_PK, "Invalid data");
        ok = 0;
    }
    if (ok) {
        oidLen = data[1];
        if ((oidLen >= 0x80) || (oidLen + 2 > len)) {
            WOLFPROV_MSG(WP_LOG_PK, "OID out of bounds");
            ok = 0;
        }
    }
    if (ok) {
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        ecc->curveId = wc_ecc_get_curve_id_from_oid(data + 2, oidLen);
    #else
        ecc->curveId = wp_ecc_get_curve_id_from_oid(data + 2, oidLen);
    #endif
        if (ecc->curveId == ECC_CURVE_INVALID) {
            WOLFPROV_MSG(WP_LOG_PK, "Invalid curve");
            ok = 0;
        }
    }

    if (ok) {
        rc = wc_ecc_set_curve(&ecc->key, 0, ecc->curveId);
        if (rc != 0) {
            WOLFPROV_MSG(WP_LOG_PK, "Can't set curve: %d",rc);
            ok = 0;
        }
    }
    if (ok && (!wp_ecc_set_bits(ecc))) {
        WOLFPROV_MSG(WP_LOG_PK, "Can't set bits");
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

static int wp_ecc_decode_x963_pub(wp_Ecc* ecc, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;

    rc = wc_ecc_import_x963((const byte *)data, len, &ecc->key);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        ecc->curveId = ecc->key.dp->id;
        ecc->hasPub = 1;
        /* Needs curveId set. */
        if (!wp_ecc_set_bits(ecc)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the SubjectPublicInfo DER encoded ECC key into the ECC key object.
 *
 * @param [in, out] ecc   ECC key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_decode_spki(wp_Ecc* ecc, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;

    rc = wc_EccPublicKeyDecode(data, &idx, &ecc->key, len);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        ecc->curveId = ecc->key.dp->id;
        ecc->hasPub = 1;
        /* Needs curveId set. */
        if (!wp_ecc_set_bits(ecc)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the PrivateKeyInfo DER encoded ECC key into the ECC key object.
 *
 * @param [in, out] ecc   ECC key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_decode_pki(wp_Ecc* ecc, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;

    rc = wc_EccPrivateKeyDecode(data, &idx, &ecc->key, len);
    if (rc != 0) {
        ok = 0;
    }
#if LIBWOLFSSL_VERSION_HEX < 0x05000000
    if (!ok) {
        idx = 0;
        rc = wc_GetPkcs8TraditionalOffset(data, &idx, len);
        if (rc >= 0) {
            rc = wc_EccPrivateKeyDecode(data, &idx, &ecc->key, len);
            if (rc == 0) {
                 ok = 1;
            }
        }
    }
#endif
    if (ok) {
        ecc->curveId = ecc->key.dp->id;
        ecc->hasPriv = 1;
        /* Needs curveId set. */
        if (!wp_ecc_set_bits(ecc)) {
            ok = 0;
        }

        /* Keys decoded from pki should always have public key */
        if (ecc->key.type == ECC_PRIVATEKEY_ONLY) {
#ifdef ECC_TIMING_RESISTANT
            rc = wc_ecc_make_pub_ex(&ecc->key, NULL, &ecc->rng);
#else
            rc = wc_ecc_make_pub_ex(&ecc->key, NULL, NULL);
#endif
        }
        ecc->hasPub = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Construct parameters from ECC key and pass off to callback.
 *
 * @param [in] ecc        ECC key object.
 * @param [in] dataCb     Callback to pass ECC key in parameters to.
 * @param [in] dataCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_dec_send_params(wp_Ecc* ecc, OSSL_CALLBACK *dataCb,
    void *dataCbArg)
{
    int ok = 1;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char*)"EC", 0);
    /* The address of the key object becomes the octet string pointer. */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &ecc, sizeof(ecc));
    params[3] = OSSL_PARAM_construct_end();

    /* Callback to do something with ECC key object. */
    if (!dataCb(params, dataCbArg)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the data in the core BIO.
 *
 * The format of the key must be the same as the decoder's format.
 *
 * @param [in, out] ctx        ECC encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to read data from.
 * @param [in]      selection  Parts of key to export.
 * @param [in]      dataCb     Callback to pass ECC key in parameters to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_decode(wp_EccEncDecCtx* ctx, OSSL_CORE_BIO *cBio,
    int selection, OSSL_CALLBACK *dataCb, void *dataCbArg,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    int ok = 1;
    int decoded = 1;
    wp_Ecc* ecc = NULL;
    unsigned char* data = NULL;
    word32 len = 0;

    (void)pwCb;
    (void)pwCbArg;

    ctx->selection = selection;

    ecc = wp_ecc_new(ctx->provCtx);
    if (ecc == NULL) {
        ok = 0;
    }
    if (ok && (!wp_read_der_bio(ctx->provCtx, cBio, &data, &len))) {
        ok = 0;
    }
    if (ok && ((ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC) ||
               (ctx->format == WP_ENC_FORMAT_X9_62))) {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (!wp_ecc_decode_pki(ecc, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
        else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if (!wp_ecc_decode_x963_pub(ecc, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
        else {
            if (!wp_ecc_decode_params(ecc, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        if (!wp_ecc_decode_spki(ecc, data, len)) {
            ok = 0;
            decoded = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        if (!wp_ecc_decode_pki(ecc, data, len)) {
            ok = 0;
            decoded = 0;
        }
    }

    OPENSSL_clear_free(data, len);

    if (ok && decoded && (!wp_ecc_dec_send_params(ecc, dataCb, dataCbArg))) {
        ok = 0;
    }

    if (!ok) {
        /* Callback takes key. */
        wp_ecc_free(ecc);
        if (!decoded) {
            ok = 1;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the Parameters encoding size for the key.
 *
 * @param [in]  ecc     ECC key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_params_size(const wp_Ecc *ecc, size_t* keyLen)
{
    int ok = 1;
    word32 len = 0;

    if (wc_ecc_get_oid(ecc->key.dp->oidSum, NULL, &len) <= 0) {
        ok = 0;
    }
    if (ok) {
        /* ASN.1 type, len and data. */
        *keyLen = len + 2;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECC key in a Parameters format.
 *
 * @param [in]      ecc      ECC key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_params(const wp_Ecc *ecc, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    word32 len;
    const byte *oid;

    if (wc_ecc_get_oid(ecc->key.dp->oidSum, &oid, &len) <= 0) {
        ok = 0;
    }
    if (ok) {
        keyData[0] = 0x06;
        keyData[1] = len;
        XMEMCPY(keyData + 2, oid, len);
        *keyLen = len + 2;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the public key encoding size.
 *
 * @param [in]  ecc     ECC key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_pub_size(const wp_Ecc *ecc, size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len;

    rc = wc_ecc_export_x963_ex((ecc_key*)&ecc->key, NULL, &len, 0);
    if (rc != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECC public key.
 *
 * @param [in]      ecc      ECC key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_pub(const wp_Ecc *ecc, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len = (word32)*keyLen;

    rc = wc_ecc_export_x963_ex((ecc_key*)&ecc->key, keyData, &len, 0);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the PKCS#8 encoding size for the key.
 *
 * @param [in]  ecc     ECC key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_priv_size(const wp_Ecc *ecc, size_t* keyLen)
{
    int ok = 1;
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    int rc;

    rc = wc_EccKeyDerSize((ecc_key*)&ecc->key, 1);
    if (rc <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = rc;
    }
#else
    int sz;

    sz = wc_ecc_size((ecc_key*)&ecc->key);
    if (sz == 0) {
        ok = 0;
    }
    if (ok) {
        /* TODO: better approximate! */
        *keyLen = sz * 3 + 20;
    }
#endif

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECC key in a PKCS#8 format.
 *
 * @param [in]      ecc      ECC key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_priv(const wp_Ecc *ecc, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len = (word32)*keyLen;

    rc = wc_EccKeyToDer((ecc_key*)&ecc->key, keyData, len);
    if (rc <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = rc;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the SubjectPublicKeyInfo encoding size for the key.
 *
 * @param [in]  ecc     ECC key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_spki_size(const wp_Ecc *ecc, size_t* keyLen)
{
    int ok = 1;
    int rc;

    rc = wc_EccPublicKeyDerSize((ecc_key*)&ecc->key, 1);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = rc;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECC key in a SubjectPublicKeyInfo format.
 *
 * @param [in]      ecc      ECC key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_spki(const wp_Ecc *ecc, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len = (word32)*keyLen;

    rc = wc_EccPublicKeyToDer((ecc_key*)&ecc->key, keyData, len, 1);
    if (rc <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = rc;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the PKCS#8 encoding size for the key.
 *
 * @param [in]  ecc     ECC key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_pki_size(const wp_Ecc *ecc, size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len;

    PRIVATE_KEY_UNLOCK();
    rc = wc_EccKeyToPKCS8((ecc_key*)&ecc->key, NULL, &len);
    PRIVATE_KEY_LOCK();
    if (rc != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECC key in a PKCS#8 format.
 *
 * @param [in]      ecc      ECC key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_pki(const wp_Ecc *ecc, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len = (word32)*keyLen;

    /* TODO: for older versions, curve is always included! */
    PRIVATE_KEY_UNLOCK();
    rc = wc_EccKeyToPKCS8((ecc_key*)&ecc->key, keyData, &len);
    PRIVATE_KEY_LOCK();
    if (rc <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS
/**
 * Get the Encrypted PKCS#8 encoding size for the key.
 *
 * @param [in]  ecc     ECC key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_epki_size(const wp_Ecc *ecc, size_t* keyLen)
{
    int ok = 1;
    int rc;
    word32 len;

    PRIVATE_KEY_UNLOCK();
    rc = wc_EccKeyToPKCS8((ecc_key*)&ecc->key, NULL, &len);
    PRIVATE_KEY_LOCK();
    if (rc != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ((len + 15) / 16) * 16;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECC key in an Encrypted PKCS#8 format.
 *
 * @param [in]      ctx         ECC encoder/decoder context object.
 * @param [in]      ecc         ECC key object.
 * @param [out]     keyData     Buffer to hold encoded data.
 * @param [in, out] keyLen      On in, length of buffer in bytes.
 *                              On out, length of encoding in bytes.
 * @param [in]      pwCb        Password callback.
 * @param [in]      pwCbArg     Argument to pass to password callback.
 * @param [out]     cipherInfo  Information about encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode_epki(const wp_EccEncDecCtx* ctx, const wp_Ecc *ecc,
    unsigned char* keyData, size_t* keyLen, OSSL_PASSPHRASE_CALLBACK *pwCb,
    void *pwCbArg, byte** cipherInfo)
{
    int ok = 1;
    int rc;
    word32 len = (word32)*keyLen;

    /* Encode key. */
    PRIVATE_KEY_UNLOCK();
    rc = wc_EccKeyToPKCS8((ecc_key*)&ecc->key, keyData, &len);
    PRIVATE_KEY_LOCK();
    if (rc <= 0) {
        ok = 0;
    }
    if (ok && (!wp_encrypt_key(ctx->provCtx, ctx->cipherName, keyData, keyLen,
            len, pwCb, pwCbArg, cipherInfo))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Encode the ECC key.
 *
 * @param [in]      ctx        ECC encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      key        ECC key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode. Unused.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_encode(wp_EccEncDecCtx* ctx, OSSL_CORE_BIO *cBio,
    const wp_Ecc *key, const OSSL_PARAM* params, int selection,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    int ok = 1;
    int rc;
    BIO* out = wp_corebio_get_bio(ctx->provCtx, cBio);
    unsigned char* keyData = NULL;
    size_t keyLen;
    unsigned char* derData = NULL;
    size_t derLen = 0;
    unsigned char* pemData = NULL;
    size_t pemLen = 0;
    int pemType = PKCS8_PRIVATEKEY_TYPE;
    int private = 0;
    byte* cipherInfo = NULL;

    (void)params;
    (void)pwCb;
    (void)pwCbArg;

    if (out == NULL) {
        ok = 0;
    }

    if (ok && ((ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC) ||
               (ctx->format == WP_ENC_FORMAT_X9_62))) {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            private = 1;
            if (!wp_ecc_encode_priv_size(key, &derLen)) {
                ok = 0;
            }
        }
        else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            if (!wp_ecc_encode_pub_size(key, &derLen)) {
                ok = 0;
            }
        }
        else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            if (!wp_ecc_encode_params_size(key, &derLen)) {
                ok = 0;
            }
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        if (!wp_ecc_encode_spki_size(key, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        private = 1;
        if (!wp_ecc_encode_pki_size(key, &derLen)) {
            ok = 0;
        }
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        private = 1;
        if (!wp_ecc_encode_epki_size(key, &derLen)) {
            ok = 0;
        }
    }
#endif

    if (ok) {
        keyLen = derLen;
        keyData = derData = OPENSSL_malloc(derLen);
        if (derData == NULL) {
            ok = 0;
        }
    }

    if (ok && ((ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC) ||
               (ctx->format == WP_ENC_FORMAT_X9_62))) {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            pemType = ECC_PRIVATEKEY_TYPE;
            private = 1;
            if (!wp_ecc_encode_priv(key, derData, &derLen)) {
                ok = 0;
            }
        }
        else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            pemType = PUBLICKEY_TYPE;
            if (!wp_ecc_encode_pub(key, derData, &derLen)) {
                ok = 0;
            }
        }
        else if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
            pemType = DH_PARAM_TYPE;
            if (!wp_ecc_encode_params(key, derData, &derLen)) {
                ok = 0;
            }
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        pemType = PUBLICKEY_TYPE;
        if (!wp_ecc_encode_spki(key, derData, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        private = 1;
        if (!wp_ecc_encode_pki(key, derData, &derLen)) {
            ok = 0;
        }
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        private = 1;
        if (!wp_ecc_encode_epki(ctx, key, derData, &derLen, pwCb, pwCbArg,
                (ctx->encoding == WP_FORMAT_PEM) ? &cipherInfo : NULL)) {
            ok = 0;
        }
    }
#endif

    if (ok && (ctx->encoding == WP_FORMAT_DER)) {
        keyLen = derLen;
    }
    else if (ok && (ctx->encoding == WP_FORMAT_PEM)) {
        rc = wc_DerToPemEx(derData, (word32)derLen, NULL, 0, cipherInfo,
            pemType);
        if (rc <= 0) {
            ok = 0;
        }
        if (ok) {
            pemLen = rc;
            pemData = OPENSSL_malloc(pemLen);
            if (pemData == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_DerToPemEx(derData, (word32)derLen, pemData, (word32)pemLen,
                cipherInfo, pemType);
            if (rc <= 0) {
                ok = 0;
            }
        }
        if (ok) {
            keyLen = pemLen = rc;
            keyData = pemData;
        }
        if (ok && ((ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC) ||
               (ctx->format == WP_ENC_FORMAT_X9_62)) &&
               ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) &&
               (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) {
            pemData[11] = 'E';
            pemData[12] = 'C';
            pemData[pemLen - 19] = 'E';
            pemData[pemLen - 18] = 'C';
        }
    }
    if (ok) {
        rc = BIO_write(out, keyData, (int)keyLen);
        if (rc <= 0) {
            ok = 0;
        }
    }

    if (private) {
        OPENSSL_clear_free(derData, derLen);
        OPENSSL_clear_free(pemData, pemLen);
    }
    else {
        OPENSSL_free(derData);
        OPENSSL_free(pemData);
    }
    OPENSSL_free(cipherInfo);
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the ECC key object.
 *
 * @param [in] ctx          ECC encoder/decoder context object.
 * @param [in] ecc          ECC key object.
 * @param [in] size         Size of key object.
 * @param [in] exportCb     Callback to export key.
 * @param [in] exportCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecc_export_object(wp_EccEncDecCtx* ctx, wp_Ecc* ecc, size_t size,
    OSSL_CALLBACK *exportCb, void *exportCbArg)
{
    /* TODO: check size to ensure it really is a wc_Ecc object.  */
    (void)size;
    return wp_ecc_export(ecc, ctx->selection, exportCb, exportCbArg);
}

/*
 * ECC Type-Specific
 */

/**
 * Create a new ECC encoder/decoder context that handles decoding type-specific.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_type_specific_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_TYPE_SPECIFIC, 0);
}

/**
 * Return whether the type-specific decoder/encoder handles the part of the key.
 *
 * @param [in] ctx        ECC encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_ecc_type_specific_does_selection(WOLFPROV_CTX* provCtx,
    int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for type-specific decoder.
 */
const OSSL_DISPATCH wp_ecc_type_specific_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ecc_type_specific_dec_new   },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                   (DFUNC)wp_ecc_type_specific_does_selection },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecc_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecc_export_object           },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding params in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_type_specific_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_TYPE_SPECIFIC,
        WP_FORMAT_DER);
}

/**
 * Dispatch table for type-specific to DER encoder.
 */
const OSSL_DISPATCH wp_ecc_type_specific_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,    (DFUNC)wp_ecc_type_specific_der_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                   (DFUNC)wp_ecc_enc_dec_settable_ctx_params  },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
                                   (DFUNC)wp_ecc_type_specific_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding t-s in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_type_specific_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_TYPE_SPECIFIC,
        WP_FORMAT_PEM);
}

/**
 * Dispatch table for type-specific to PEM encoder.
 */
const OSSL_DISPATCH wp_ecc_type_specific_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,
                                   (DFUNC)wp_ecc_type_specific_pem_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                  (DFUNC)wp_ecc_enc_dec_settable_ctx_params   },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
                                   (DFUNC)wp_ecc_type_specific_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/*
 * ECC SubkectPublicKeyInfo
 */

/**
 * Create a new ECC encoder/decoder context that handles decoding SPKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_SPKI, 0);
}

/**
 * Return whether the SPKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        ECC encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_ecc_spki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for SPKI decoder.
 */
const OSSL_DISPATCH wp_ecc_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ecc_spki_dec_new            },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_ecc_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecc_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecc_export_object           },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding SPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_SPKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_ecc_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_spki_der_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecc_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecc_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding SPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_SPKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for SPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ecc_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_spki_pem_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecc_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecc_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/*
 * ECC PrivateKeyInfo
 */

/**
 * Create a new ECC encoder/decoder context that handles decoding PKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_PKI, 0);
}

/**
 * Return whether the PKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        ECC encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_ecc_pki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for PKI decoder.
 */
const OSSL_DISPATCH wp_ecc_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ecc_pki_dec_new             },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_ecc_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecc_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecc_export_object           },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_PKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_ecc_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_pki_der_enc_new         },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecc_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecc_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_PKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ecc_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_pki_pem_enc_new         },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecc_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecc_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/*
 * ECC EncryptedPrivateKeyInfo
 */

/**
 * Create a new ECC encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_EPKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for EPKI to DER encoder.
 */
const OSSL_DISPATCH wp_ecc_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_epki_der_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecc_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecc_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_EPKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for EPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ecc_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_epki_pem_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecc_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecc_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/*
 * ECC X9.62
 */

/**
 * Create a new ECC encoder/decoder context that handles decoding X9.62.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_x9_62_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_X9_62, 0);
}

/**
 * Return whether the X9.62 decoder/encoder handles the part of the key.
 *
 * @param [in] ctx        ECC encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_ecc_x9_62_does_selection(WOLFPROV_CTX* provCtx,
    int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & (OSSL_KEYMGMT_SELECT_ALL_PARAMETERS |
                           OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for x9_62 decoder.
 */
const OSSL_DISPATCH wp_ecc_x9_62_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ecc_x9_62_dec_new           },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecc_x9_62_does_selection    },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecc_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecc_export_object           },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding params in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_x9_62_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_X9_62, WP_FORMAT_DER);
}

/**
 * Dispatch table for X9.62 to DER encoder.
 */
const OSSL_DISPATCH wp_ecc_x9_62_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ecc_x9_62_der_enc_new       },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                   (DFUNC)wp_ecc_enc_dec_settable_ctx_params  },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
                                        (DFUNC)wp_ecc_x9_62_does_selection    },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

/**
 * Create a new ECC encoder/decoder context that handles encoding X9.62 in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECC encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EccEncDecCtx* wp_ecc_x9_62_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecc_enc_dec_new(provCtx, WP_ENC_FORMAT_X9_62, WP_FORMAT_PEM);
}

/**
 * Dispatch table for X9.62 to PEM encoder.
 */
const OSSL_DISPATCH wp_ecc_x9_62_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,
                                        (DFUNC)wp_ecc_x9_62_pem_enc_new       },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecc_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                  (DFUNC)wp_ecc_enc_dec_settable_ctx_params   },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecc_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
                                        (DFUNC)wp_ecc_x9_62_does_selection    },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecc_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecc_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecc_free                    },
    { 0, NULL }
};

#endif /* WP_HAVE_ECC */
