/* wp_ecx_kmgmt.c
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
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#if defined(WP_HAVE_X25519) || defined(WP_HAVE_ED25519) || \
    defined(WP_HAVE_X448) || defined(WP_HAVE_ED448)

/** Supported selections (key parts) in this key manager for ECX. */
#define WP_ECX_POSSIBLE_SELECTIONS                                             \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/** Curve25519 for ECDH. */
#define WP_KEY_TYPE_X25519      1
/** Curve448 for ECDH. */
#define WP_KEY_TYPE_X448        2
/** Ed25519 for ECDSA. */
#define WP_KEY_TYPE_ED25519     3
/** Ed448 for ECDSA. */
#define WP_KEY_TYPE_ED448       4

/** Maximum key size. Used for exporting when comparing keys. */
#ifdef WP_HAVE_ED448
#define WP_MAX_KEY_SIZE         ED448_KEY_SIZE
#elif defined(WP_HAVE_X448)
#define WP_MAX_KEY_SIZE         CURVE448_KEY_SIZE
#elif defined(WP_HAVE_ED25519)
#define WP_MAX_KEY_SIZE         ED25519_KEY_SIZE
#else
#define WP_MAX_KEY_SIZE         CURVE25519_KEYSIZE
#endif

#ifdef WP_HAVE_X25519
    #define ECX_LITTLE_ENDIAN       EC25519_LITTLE_ENDIAN
#elif defined(WP_HAVE_X448)
    #define ECX_LITTLE_ENDIAN       EC448_LITTLE_ENDIAN
#else
    #define ECX_LITTLE_ENDIAN       0
#endif


/** Type for function that initializes a wolfSSL key. */
typedef int (*WP_ECX_INIT)(void* key);
/** Type for function that frees a wolfSSL key. */
typedef void (*WP_ECX_FREE)(void* key);
/** Type for function that generates a wolfSSL key. */
typedef int (*WP_ECX_MAKE_KEY)(WC_RNG* rmg, int keySize, void* key);
/** Type for function that imports a public key into wolfSSL key. */
typedef int (*WP_ECX_IMPORT_PUB)(const byte* in, word32 inLen, void* key,
    int endian);
/** Type for function that exports a public key from a wolfSSL key. */
typedef int (*WP_ECX_EXPORT_PUB)(void* key, const byte* out, word32* outLen,
    int endian);
/** Type for function that imports a private key into wolfSSL key. */
typedef int (*WP_ECX_IMPORT_PRIV)(const byte* priv, word32 privLen, void* key,
    int endian);
/** Type for function that exports a private key from a wolfSSL key. */
typedef int (*WP_ECX_EXPORT_PRIV)(void* key, const byte* out, word32* outLen);
/** Type for a wolfSSL function that checks a public key. */
typedef int (*WP_ECX_CHECK_PUB)(const byte* pub, word32 pubLen, int endian);
/** Type for a wolfSSL function that checks a key. */
typedef int (*WP_ECX_CHECK_KEY)(void* key);


/**
 * ECX data and wolfSSL functions.
 */
typedef struct wp_EcxData {
    /** Type of key. */
    int keyType;
    /** Cryptographic length in bits. */
    int bits;
    /** Length of curve in bytes. */
    int len;

    /* wolfSSL APIs. */
    /** Initialize wolfSSL key object. */
    WP_ECX_INIT        initKey;
    /** Free wolfSSL key object. */
    WP_ECX_FREE        freeKey;
    /** wolfSSL make key. */
    WP_ECX_MAKE_KEY    makeKey;
    /** Import public key into wolfSSL key object. */
    WP_ECX_IMPORT_PUB  importPub;
    /** Export public key from wolfSSL key object. */
    WP_ECX_EXPORT_PUB  exportPub;
    /** Import private key into wolfSSL key object. */
    WP_ECX_IMPORT_PRIV importPriv;
    /** Export private key from wolfSSL key object. */
    WP_ECX_EXPORT_PRIV exportPriv;
    /** wolfSSL check of public key value. */
    WP_ECX_CHECK_PUB   checkPub;
    /** wolfSSL check of public/private key. */
    WP_ECX_CHECK_KEY   checkKey;
} wp_EcxData;

/**
 * ECX key.
 */
struct wp_Ecx {
    /** wolfSSL key - see data field for type. */
    union {
    #ifdef WP_HAVE_X25519
        /** Curve25519 key object for ECDH. */
        curve25519_key x25519;
    #endif
    #ifdef WP_HAVE_X448
        /** Curve448 key object for ECDH. */
        curve448_key   x448;
    #endif
    #ifdef WP_HAVE_ED25519
        /** Ed25519 key object for ECDSA. */
        ed25519_key    ed25519;
    #endif
    #ifdef WP_HAVE_ED448
        /** Ed448 key object for ECDSA. */
        ed448_key      ed448;
    #endif
    } key;
    /** Data including method table that operates on a wolfSSL key. */
    const wp_EcxData* data;

    /** Unclamped values to restore on export. */
    byte unclamped[2];

#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;

    /** Provider context - for duplicating key. */
    WOLFPROV_CTX* provCtx;

    /** Include public key in ASN.1 encoding of private key. */
    int includePublic;
    /** Public key available. */
    unsigned int hasPub:1;
    /** Private key available. */
    unsigned int hasPriv:1;
    /* Private key was imported and has been clamped */
    unsigned int clamped:1;
};

/**
 * ECX key generation context.
 */
typedef struct wp_EcxGenCtx {
    /** wolfSSL random number generator. */
    WC_RNG rng;
    /** Data including method table that operates on a wolfSSL key. */
    const wp_EcxData* data;

    /** Provider context - used when creating an ECX key. */
    WOLFPROV_CTX* provCtx;
    /** The parts of a ECX key to generate. */
    int selection;

    /** Name of group. */
    const char* name;
} wp_EcxGenCtx;


/* Prototype for ECX generation initialization. */
static int wp_ecx_gen_set_params(wp_EcxGenCtx* ctx, const OSSL_PARAM params[]);
static size_t wp_ecx_export_keypair_alloc_size(wp_Ecx* ecx, int priv);

/*
 * ECX key
 */

/**
 * Increment reference count for key.
 *
 * Used in key generation, signing/verify and key exchange.
 *
 * @param [in, out] ecx  ECX key object.
 * @return  1 on success.
 * @return  0 when multi-threaded and locking fails.
 */
int wp_ecx_up_ref(wp_Ecx* ecx)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&ecx->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        ecx->refCnt++;
        wc_UnLockMutex(&ecx->mutex);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    ecx->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the wolfSSL object from the ECX key object.
 *
 * @param [in] ecx  ECX key object.
 * @return  Pointer to wolfSSL object.
 */
void* wp_ecx_get_key(wp_Ecx* ecx)
{
    return (void*)&ecx->key;
}

/**
 * Get the mutex object from the ECX key object.
 *
 * @param [in] ecx  ECX key object.
 * @return  Pointer to wolfSSL mutex object.
 */
wolfSSL_Mutex* wp_ecx_get_mutex(wp_Ecx* ecx)
{
    return &ecx->mutex;
}

/**
 * Create a new ECX key object. Base function.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] data      wolfSSL data for curve.
 * @return  New ECX key object on success.
 * @return  NULL on failure.
 */
static wp_Ecx* wp_ecx_new(WOLFPROV_CTX* provCtx, const wp_EcxData* data)
{
    wp_Ecx* ecx = NULL;

    if (wolfssl_prov_is_running()) {
        ecx = (wp_Ecx*)OPENSSL_zalloc(sizeof(*ecx));
    }
    if (ecx != NULL) {
        int ok = 1;
        int rc;

        rc = (*data->initKey)((void*)&ecx->key);
        if (rc != 0) {
            ok = 0;
        }

    #ifndef SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&ecx->mutex);
            if (rc != 0) {
                (*data->freeKey)(&ecx->key);
                ok = 0;
            }
        }
    #endif

        if (ok) {
            ecx->provCtx = provCtx;
            ecx->refCnt  = 1;
            ecx->data    = data;
        }

        if (!ok) {
            OPENSSL_free(ecx);
            ecx = NULL;
        }
    }

    return ecx;
}


/**
 * Dispose of ECX key object.
 *
 * @param [in, out] ecx  ECX key object.
 */
void wp_ecx_free(wp_Ecx* ecx)
{
    if (ecx != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&ecx->mutex);
        cnt = --ecx->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&ecx->mutex);
        }
    #else
        cnt = --ecx->refCnt;
    #endif

        if (cnt == 0) {
    #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&ecx->mutex);
    #endif
            (*ecx->data->freeKey)((void*)&ecx->key);
            OPENSSL_free(ecx);
        }
    }
}

/**
 * Duplicate specific parts of a ECX key object.
 *
 * @param [in] src        Source ECX key object.
 * @param [in] selection  Parts of key to include.
 * @return  NULL on failure.
 * @return  New ECX key object on success.
 */
static wp_Ecx* wp_ecx_dup(const wp_Ecx* src, int selection)
{
    wp_Ecx* dst;

    (void)selection;

    dst = wp_ecx_new(src->provCtx, src->data);
    if (dst != NULL) {
        XMEMCPY(&dst->key, &src->key, sizeof(src->key));
        dst->includePublic = src->includePublic;
        dst->hasPub        = src->hasPub;
        dst->hasPriv       = src->hasPriv;
    }

    return dst;
}

/**
 * Load the ECX key.
 *
 * Return the ECX key object taken out of the reference.
 *
 * @param [in, out] pEcx  Pointer to a ECX key object.
 * @param [in]      size  Size of data structure that is the ECX key object.
 *                        Unused.
 * @return  NULL when no ECX key object at reference.
 * @return  ECX key object from reference on success.
 */
static const wp_Ecx* wp_ecx_load(const wp_Ecx** pEcx, size_t size)
{
    const wp_Ecx* ecx = *pEcx;
    /* TODO: validate the object is a wp_Ecx? */
    (void)size;
    *pEcx = NULL;
    return ecx;
}

/**
 * Return an array of supported settable parameters for the ECX key.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecx_settable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for ECX key.
     */
    static const OSSL_PARAM wp_ecx_supported_settable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_ecx_supported_settable_params;
}

/**
 * Set the ECX key parameters.
 *
 * @param [in, out] ecx     ECX key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_set_params(wp_Ecx* ecx, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* data = NULL;
    size_t len;

    if (!wp_params_get_octet_string_ptr(params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &data, &len)) {
        ok = 0;
    }
    if (ok && (data != NULL)) {
        int rc = (*ecx->data->importPub)(data, (word32)len, (void*)&ecx->key,
            ECX_LITTLE_ENDIAN);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            ecx->hasPub = 1;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported gettable parameters for the ECX key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecx_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for ECX key object.
     */
    static const OSSL_PARAM wp_ecx_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_ecx_supported_gettable_params;
}

/**
 * Get the security bits for an ECX key.
 *
 * @param [in] ecx  ECX key object.
 * @return  Security bits on success.
 * @return  0 on failure.
 */
static int wp_ecx_get_security_bits(wp_Ecx* ecx)
{
    int bits = 0;

    if (ecx->data->bits >= 456) {
        bits = 224;
    }
    else if (ecx->data->bits >= 256) {
        bits = 128;
    }

    return bits;
}

/**
 * Get the encoded public key into parameters.
 *
 * @param [in]      ecx     ECX key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_get_params_enc_pub_key(wp_Ecx* ecx, OSSL_PARAM params[],
    const char* key)
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, key);
    if (p != NULL) {
        word32 outLen = (word32)p->return_size;

        if (p->data == NULL) {
            outLen = ecx->data->len;
        }
        else {
            int rc = (*ecx->data->exportPub)((void*)&ecx->key, p->data,
                &outLen, ECX_LITTLE_ENDIAN);
            if (rc != 0) {
                ok = 0;
            }
        }
        p->return_size = outLen;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the encoded private key into parameters.
 *
 * @param [in]      ecx     ECX key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_get_params_priv_key(wp_Ecx* ecx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        word32 outLen = (word32)p->return_size;

        if (p->data == NULL) {
            outLen = ecx->data->len;
        }
        else {
            int rc = (*ecx->data->exportPriv)((void*)&ecx->key, p->data,
                &outLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        p->return_size = outLen;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the ECX key parameters.
 *
 * @param [in]      ecx     ECX key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_get_params(wp_Ecx* ecx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_set_int(p, (int)wp_ecx_export_keypair_alloc_size(ecx, 1))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, ecx->data->bits)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p,
                wp_ecx_get_security_bits(ecx)))) {
            ok = 0;
        }
    }
    if (ok && (!wp_ecx_get_params_enc_pub_key(ecx, params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY))) {
        ok = 0;
    }
    if (ok && (!wp_ecx_get_params_enc_pub_key(ecx, params,
            OSSL_PKEY_PARAM_PUB_KEY))) {
        ok = 0;
    }
    if (ok && (!wp_ecx_get_params_priv_key(ecx, params))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check ECX key object has the components required.
 *
 * @param [in] ecx        ECX key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_has(const wp_Ecx* ecx, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
       ok = 0;
    }
    if (ecx == NULL) {
       ok = 0;
    }
    if (ok && ((selection & WP_ECX_POSSIBLE_SELECTIONS) != 0)) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok &= ecx->hasPub;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok &= ecx->hasPriv;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two ECX key objects' private keys match.
 *
 * @param [in] ecx1       First ECX key object.
 * @param [in] ecx2       Second ECX key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_match_priv_key(const wp_Ecx* ecx1, const wp_Ecx* ecx2)
{
    int ok = 1;
    int rc;
    unsigned char key1[WP_MAX_KEY_SIZE];
    word32 len1;
    unsigned char key2[WP_MAX_KEY_SIZE];
    word32 len2;

    XMEMSET(key1, 0, sizeof(key1));
    XMEMSET(key2, 0, sizeof(key2));
    ok &= ecx1->hasPriv && ecx2->hasPriv;
    if (ok) {
        len1 = ecx1->data->len;
        rc = (*ecx1->data->exportPriv)((void*)&ecx1->key, key1, &len1);
        if (rc != 0) {
             ok = 0;
        }
    }
    if (ok) {
        len2 = ecx2->data->len;
        rc = (*ecx2->data->exportPriv)((void*)&ecx2->key, key2, &len2);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok && (len1 != len2)) {
        ok = 0;
    }
    if (ok && (XMEMCMP(key1, key2, len1) != 0)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two ECX key objects' public keys match.
 *
 * @param [in] ecx1       First ECX key object.
 * @param [in] ecx2       Second ECX key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_match_pub_key(const wp_Ecx* ecx1, const wp_Ecx* ecx2)
{
    int ok = 1;
    int rc;
    unsigned char key1[WP_MAX_KEY_SIZE];
    word32 len1;
    unsigned char key2[WP_MAX_KEY_SIZE];
    word32 len2;

    XMEMSET(key1, 0, sizeof(key1));
    XMEMSET(key2, 0, sizeof(key2));
    ok &= ecx1->hasPub && ecx2->hasPub;
    if (ok) {
        len1 = ecx1->data->len;
        rc = (*ecx1->data->exportPub)((void*)&ecx1->key, key1, &len1,
            ECX_LITTLE_ENDIAN);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        len2 = ecx2->data->len;
        rc = (*ecx2->data->exportPub)((void*)&ecx2->key, key2, &len2,
            ECX_LITTLE_ENDIAN);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok && (len1 != len2)) {
        ok = 0;
    }
    if (ok && (XMEMCMP(key1, key2, len1) != 0)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two ECX key objects match for the components specified.
 *
 * @param [in] ecx1       First ECX key object.
 * @param [in] ecx2       Second ECX key object.
 * @param [in] selection  Parts of key to match.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_match(const wp_Ecx* ecx1, const wp_Ecx* ecx2, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (selection != 0)) {
        /* Check for domain parameters, private key and public key. */
        ok &= ecx1->data->keyType == ecx2->data->keyType;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
        (!wp_ecx_match_priv_key(ecx1, ecx2))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) &&
        (!wp_ecx_match_pub_key(ecx1, ecx2))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if defined(WP_HAVE_X25519) || defined(WP_HAVE_X448)
/**
 * Validate the ECX public key - X25519 and X448 only.
 *
 * @param [in] ecx        ECX key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_validate_pub_key(const wp_Ecx* ecx)
{
    int ok = 1;
    int rc;
    unsigned char key[WP_MAX_KEY_SIZE] = {0};
    word32 len = ecx->data->len;

    ok &= ecx->hasPub;
    if (ok) {
        /* Get the public key out. */
        rc = (*ecx->data->exportPub)((void*)&ecx->key, key, &len,
            ECX_LITTLE_ENDIAN);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        /* Check the public key is valid. */
        rc = (*ecx->data->checkPub)(key, len, ECX_LITTLE_ENDIAN);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Validate the ECX key - X25519 and X448 only.
 *
 * @param [in] ecx        ECX key object.
 * @param [in] selection  Parts of key to validate.
 * @param [in] checkType  How thorough to check key. Values:
 *                          OSSL_KEYMGMT_VALIDATE_FULL_CHECK or
 *                          OSSL_KEYMGMT_VALIDATE_QUICK_CHECK.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_x_validate(const wp_Ecx* ecx, int selection, int checkType)
{
    int ok = 1;

    (void)checkType;

    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) &&
        (!wp_ecx_validate_pub_key(ecx))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= ecx->hasPriv;
        /* Nothing to do. The private key is valid as it has been clamped. */
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

#if defined(WP_HAVE_ED25519) || defined(WP_HAVE_ED448)
/**
 * Validate the ECX key - Ed25519 and Ed448 only.
 *
 * @param [in] ecx        ECX key object.
 * @param [in] selection  Parts of key to validate.
 * @param [in] checkType  How thorough to check key. Values:
 *                          OSSL_KEYMGMT_VALIDATE_FULL_CHECK or
 *                          OSSL_KEYMGMT_VALIDATE_QUICK_CHECK.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_ed_validate(const wp_Ecx* ecx, int selection, int checkType)
{
    int ok = 1;

    (void)checkType;

    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok &= ecx->hasPub;
        /* Nothing to do. The public key is validated on import. */
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= ecx->hasPriv;
        /* Nothing to do. The private key is validated on import. */
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) ==
            OSSL_KEYMGMT_SELECT_KEYPAIR)) {
        int rc = (*ecx->data->checkKey)((void*)&ecx->key);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Import the key into ECX key object from parameters.
 *
 * @param [in, out] ecx        ECX key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_import(wp_Ecx* ecx, int selection, const OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    unsigned char* privData = NULL;
    unsigned char* pubData = NULL;
    size_t len;

    if ((!wolfssl_prov_is_running()) || (ecx == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_ECX_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PRIV_KEY,
            &privData, &len)) {
            ok = 0;
        }
        if (ok && (privData != NULL)) {
            ecx->unclamped[0] = privData[0];
            ecx->unclamped[1] = privData[len - 1];
            rc = (*ecx->data->importPriv)(privData, (word32)len, (void*)&ecx->key,
                ECX_LITTLE_ENDIAN);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                ecx->hasPriv = 1;
                ecx->hasPub = 1;
                ecx->clamped = 1;
            }
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PUB_KEY,
            &pubData, &len)) {
            ok = 0;
        }
        if (ok && (pubData != NULL)) {
            rc = (*ecx->data->importPub)(pubData, (word32)len, (void*)&ecx->key,
                ECX_LITTLE_ENDIAN);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                ecx->hasPub = 1;
            }
        }
    }
    if (ok && (privData == NULL) && (pubData == NULL)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** ECX private key parameters. */
#define WP_ECX_PRIVATE_KEY_PARAMS                                              \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
/** ECX public key parameters. */
#define WP_ECX_PUBLIC_KEY_PARAMS                                               \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)

/**
 * Table of key parameters for difference selections.
 */
static const OSSL_PARAM wp_ecx_key_params[] = {
    /* 0 */
    OSSL_PARAM_END,

    /* 1 */
    WP_ECX_PRIVATE_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 3 */
    WP_ECX_PUBLIC_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 5 */
    WP_ECX_PRIVATE_KEY_PARAMS,
    WP_ECX_PUBLIC_KEY_PARAMS,
    OSSL_PARAM_END,
};

/**
 * Get the key parameters for a selection.
 *
 * @param [in] selection  Parts of key to import/export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_ecx_key_types(int selection)
{
    int idx = 0;
    int extra = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        idx += 3;
        extra++;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        idx += 1 + extra;
    }

    return &wp_ecx_key_params[idx];
}

/**
 * Get the key parameters when importing for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_ecx_import_types(int selection)
{
    return wp_ecx_key_types(selection);
}

/**
 * Get the size of allocated data needed for key pair.
 *
 * Called when exporting.
 *
 * @param [in] ecx   ECX key object.
 * @param [in] priv  Private key is being exported.
 * @return  Size of buffer to hold allocated key pair data.
 */
static size_t wp_ecx_export_keypair_alloc_size(wp_Ecx* ecx, int priv)
{
    /* Public key. */
    size_t len = ecx->data->len;
    if (priv) {
        len += ecx->data->len;
    }
    return len;
}

/**
 * Put the ECX key pair data into the parameter.
 *
 * Assumes data buffer is big enough.
 *
 * @param [in]      ecx     ECX key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @param [in, out] data    Data buffer to place group data into.
 * @param [in, out] idx     Pointer to current index into data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_export_keypair(wp_Ecx* ecx, OSSL_PARAM* params, int* pIdx,
    unsigned char* data, size_t* idx, int priv)
{
    int ok = 1;
    int rc;
    int i = *pIdx;
    word32 outLen;

    outLen = ecx->data->len;
    rc = (*ecx->data->exportPub)((void*)&ecx->key, data + *idx, &outLen,
        ECX_LITTLE_ENDIAN);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        wp_param_set_octet_string_ptr(&params[i++], OSSL_PKEY_PARAM_PUB_KEY,
            data + *idx, outLen);
        *idx += outLen;
    }
    if (ok && priv) {
        outLen = ecx->data->len;
        rc = (*ecx->data->exportPriv)((void*)&ecx->key, data + *idx, &outLen);
        if (ok) {
            if (ecx->clamped) {
                data[*idx + 0         ] = ecx->unclamped[0];
                data[*idx + outLen - 1] = ecx->unclamped[1];
            }
            wp_param_set_octet_string_ptr(&params[i++],
                OSSL_PKEY_PARAM_PRIV_KEY, data + *idx, outLen);
        }
    }

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the ECX key.
 *
 * Key data placed in parameters and then passed to callback.
 *
 * @param [in] ecx        ECX key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Function to pass constructed parameters to.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_export(wp_Ecx* ecx, int selection, OSSL_CALLBACK* paramCb,
    void* cbArg)
{
    int ok = 1;
    OSSL_PARAM params[3];
    int paramsSz = 0;
    unsigned char* data = NULL;
    size_t len = 0;
    int expPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    XMEMSET(params, 0, sizeof(params));
    data = OPENSSL_malloc(wp_ecx_export_keypair_alloc_size(ecx, expPriv));
    if (data == NULL) {
        ok = 0;
    }
    if (ok && !wp_ecx_export_keypair(ecx, params, &paramsSz, data, &len,
            expPriv)) {
        ok = 0;
    }
    if (ok) {
        ok = paramCb(params, cbArg);
    }
    OPENSSL_clear_free(data, len);

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the key parameters when exporting for a selection.
 *
 * @param [in] selection  Parts of key to export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_ecx_export_types(int selection)
{
    return wp_ecx_key_types(selection);
}


/*
 * ECX generation
 */

/**
 * Create ECX generation context object. Base function.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @param [in] data       wolfSSL data for curve.
 * @param [in] name       Name of curve.
 * @return  New ECX generation context object on success.
 * @return  NULL on failure.
 */
static wp_EcxGenCtx* wp_ecx_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], const wp_EcxData* data,
    const char* name)
{
    wp_EcxGenCtx* ctx = NULL;

    if (wolfssl_prov_is_running() &&
        ((selection & WP_ECX_POSSIBLE_SELECTIONS) != 0)) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int rc;
        int ok = 1;

        rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            ctx->provCtx = provCtx;
            ctx->name = name;
            if (!wp_ecx_gen_set_params(ctx, params)) {
                wc_FreeRng(&ctx->rng);
                ok = 0;
            }
        }
        if (ok) {
            ctx->selection = selection;
            ctx->data      = data;
        }

        if (!ok) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Return an array of supported settable parameters for the ECX gen context.
 *
 * @param [in] ctx      ECX generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecx_gen_settable_params(wp_EcxGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for ECX generation context.
     */
    static OSSL_PARAM wp_ecx_gen_settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_ecx_gen_settable;
}

/**
 * Sets the parameters into the ECX generation context object.
 *
 * @param [in, out] ctx     ECX generation context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_gen_set_params(wp_EcxGenCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const char* name = NULL;

    (void)ctx;

    if (!wp_params_get_utf8_string_ptr(params, OSSL_PKEY_PARAM_GROUP_NAME,
            &name)) {
        ok = 0;
    }
    if (ok && (name != NULL) && (XSTRNCMP(name, ctx->name,
            XSTRLEN(name)) != 0)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate ECX key pair using wolfSSL.
 *
 * @param [in, out] ctx    ECX generation context object.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument to pass to callback. Unused.
 * @return  NULL on failure.
 * @return  ECX key object on success.
 */
static wp_Ecx* wp_ecx_gen(wp_EcxGenCtx* ctx, OSSL_CALLBACK* osslcb, void* cbarg)
{
    wp_Ecx* ecx;
    int keyPair = (ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;

    (void)osslcb;
    (void)cbarg;

    ecx = wp_ecx_new(ctx->provCtx, ctx->data);
    if ((ecx != NULL) && keyPair) {
        int rc = (*ctx->data->makeKey)(&ctx->rng, ctx->data->len,
            (void*)&ecx->key);
        if (rc != 0) {
            wp_ecx_free(ecx);
            ecx = NULL;
        }
        else {
            ecx->hasPub = 1;
            ecx->hasPriv = 1;
        }
    }

    return ecx;
}

/**
 * Dispose of the ECX generation context object.
 *
 * @param [in, out] ctx  ECX generation context object.
 */
static void wp_ecx_gen_cleanup(wp_EcxGenCtx* ctx)
{
    wc_FreeRng(&ctx->rng);
    OPENSSL_free(ctx);
}

/*
 * Dispatch tables
 */

/** Declares an ECX dispatch table. */
#define IMPLEMENT_ECX_KEYMGMT_DISPATCH(alg, type)                              \
const OSSL_DISPATCH wp_##alg##_keymgmt_functions[] = {                         \
    { OSSL_FUNC_KEYMGMT_NEW,         (DFUNC)wp_##alg##_new                  }, \
    { OSSL_FUNC_KEYMGMT_FREE,        (DFUNC)wp_ecx_free                     }, \
    { OSSL_FUNC_KEYMGMT_DUP,         (DFUNC)wp_ecx_dup                      }, \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,    (DFUNC)wp_##alg##_gen_init             }, \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                        \
                                     (DFUNC)wp_ecx_gen_set_params           }, \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                   \
                                     (DFUNC)wp_ecx_gen_settable_params      }, \
    { OSSL_FUNC_KEYMGMT_GEN,         (DFUNC)wp_ecx_gen                      }, \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (DFUNC)wp_ecx_gen_cleanup              }, \
    { OSSL_FUNC_KEYMGMT_LOAD,        (DFUNC)wp_ecx_load                     }, \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,  (DFUNC)wp_ecx_get_params               }, \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                       \
                                     (DFUNC)wp_ecx_gettable_params          }, \
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,  (DFUNC)wp_ecx_set_params               }, \
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                       \
                                     (DFUNC)wp_ecx_settable_params          }, \
    { OSSL_FUNC_KEYMGMT_HAS,         (DFUNC)wp_ecx_has                      }, \
    { OSSL_FUNC_KEYMGMT_MATCH,       (DFUNC)wp_ecx_match                    }, \
    { OSSL_FUNC_KEYMGMT_VALIDATE,    (DFUNC)wp_ecx_##type##_validate        }, \
    { OSSL_FUNC_KEYMGMT_IMPORT,      (DFUNC)wp_ecx_import                   }, \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                          \
                                     (DFUNC)wp_ecx_import_types             }, \
    { OSSL_FUNC_KEYMGMT_EXPORT,      (DFUNC)wp_ecx_export                   }, \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                          \
                                     (DFUNC)wp_ecx_export_types             }, \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                  \
                                     (DFUNC)wp_##alg##_query_operation_name }, \
    { 0, NULL }                                                                \
};

#ifdef WP_HAVE_X25519

/*
 * X25519
 */

/**
 * Import the X25519 public key.
 *
 * @param [in]      in      Buffer holding DER encoded X25519 public key.
 * @param [in]      inLen   Length of data in bytes.
 * @param [in, out] key     wolfSSL X25519 key object.
 * @param [in]      endian  Which endian the bytes are in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_x25519_import_public(const byte* in, word32 inLen,
    curve25519_key* key, int endian)
{
    unsigned char data[CURVE25519_KEYSIZE];

    /* OpenSSL masks off top bit of public key. */
    if ((in[CURVE25519_KEYSIZE - 1] & 0x80) != 0x00) {
        XMEMCPY(data, in, CURVE25519_KEYSIZE);
        data[CURVE25519_KEYSIZE - 1] &= 0x7f;
        in = data;
    }
    return wc_curve25519_import_public_ex(in, inLen, key, endian);
}

/**
 * Export the X25519 private key.
 *
 * @param [in]      key     wolfSSL X25519 key object.
 * @param [out]     out     Buffer to hold DER encoded X25519 private key.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, length of data in bytes.
 */
static int wp_curve25519_export_private_raw(curve25519_key* key, byte* out,
    word32* outLen)
{
    return wc_curve25519_export_private_raw_ex(key, out, outLen,
        EC25519_LITTLE_ENDIAN);
}

/** X25519 data and wolfSSL functions. */
static const wp_EcxData x25519Data = {
    WP_KEY_TYPE_X25519,
    255,
    CURVE25519_KEYSIZE,

    (WP_ECX_INIT)&wc_curve25519_init,
    (WP_ECX_FREE)&wc_curve25519_free,
    (WP_ECX_MAKE_KEY)&wc_curve25519_make_key,
    (WP_ECX_IMPORT_PUB)&wp_x25519_import_public,
    (WP_ECX_EXPORT_PUB)&wc_curve25519_export_public_ex,
    (WP_ECX_IMPORT_PRIV)&wc_curve25519_import_private_ex,
    (WP_ECX_EXPORT_PRIV)&wp_curve25519_export_private_raw,
    (WP_ECX_CHECK_PUB)&wc_curve25519_check_public,
    NULL,
};

/**
 * Create a new X25519 key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX key object on success.
 * @return  NULL on failure.
 */
static wp_Ecx* wp_x25519_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_new(provCtx, &x25519Data);
}

/**
 * Create X25519 generation context object. Base function.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New ECX generation context object on success.
 * @return  NULL on failure.
 */
static wp_EcxGenCtx* wp_x25519_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_ecx_gen_init(provCtx, selection, params, &x25519Data, SN_X25519);
}

/**
 * Return the X25519 operation name as a string.
 *
 * @param [in] op  Operationn type being performed. Unused.
 * @return  Name of operation.
 */
static const char* wp_x25519_query_operation_name(int op)
{
    (void)op;
    return "X25519";
}

/** Dispatch table for X25519 key management. */
IMPLEMENT_ECX_KEYMGMT_DISPATCH(x25519, x)

#endif /* WP_HAVE_X25519 */

#ifdef WP_HAVE_X448

/*
 * X448
 */

/**
 * Export the X448 private key.
 *
 * @param [in]      key     wolfSSL X448 key object.
 * @param [out]     out     Buffer to hold DER encoded X448 private key.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, length of data in bytes.
 */
static int wp_curve448_export_private_raw(curve448_key* key, byte* out,
    word32* outLen)
{
    return wc_curve448_export_private_raw_ex(key, out, outLen,
        EC448_LITTLE_ENDIAN);
}

/** X448 data and wolfSSL functions. */
static const wp_EcxData x448Data = {
    WP_KEY_TYPE_X448,
    448,
    CURVE448_KEY_SIZE,

    (WP_ECX_INIT)&wc_curve448_init,
    (WP_ECX_FREE)&wc_curve448_free,
    (WP_ECX_MAKE_KEY)&wc_curve448_make_key,
    (WP_ECX_IMPORT_PUB)&wc_curve448_import_public_ex,
    (WP_ECX_EXPORT_PUB)&wc_curve448_export_public_ex,
    (WP_ECX_IMPORT_PRIV)&wc_curve448_import_private_ex,
    (WP_ECX_EXPORT_PRIV)&wp_curve448_export_private_raw,
    (WP_ECX_CHECK_PUB)&wc_curve448_check_public,
    NULL,
};

/**
 * Create a new X448 key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX key object on success.
 * @return  NULL on failure.
 */
static wp_Ecx* wp_x448_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_new(provCtx, &x448Data);
}

/**
 * Create X448 generation context object. Base function.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New ECX generation context object on success.
 * @return  NULL on failure.
 */
static wp_EcxGenCtx* wp_x448_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_ecx_gen_init(provCtx, selection, params, &x448Data, SN_X448);
}

/**
 * Return the X448 operation name as a string.
 *
 * @param [in] op  Operationn type being performed. Unused.
 * @return  Name of operation.
 */
static const char* wp_x448_query_operation_name(int op)
{
    (void)op;
    return "X448";
}

/** Dispatch table for X448 key management. */
IMPLEMENT_ECX_KEYMGMT_DISPATCH(x448, x)

#endif /* WP_HAVE_X448 */

#ifdef WP_HAVE_ED25519

/*
 * Ed25519
 */

/**
 * Import the Ed25519 public key.
 *
 * @param [in]      in      Buffer holding DER encoded Ed25519 public key.
 * @param [in]      inLen   Length of data in bytes.
 * @param [in, out] key     wolfSSL Ed25519 key object.
 * @param [in]      endian  Which endian the bytes are in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_ed25519_import_public(const byte* in, word32 inLen,
    ed25519_key* key, int endian)
{
    (void)endian;
    return wc_ed25519_import_public(in, inLen, key);
}

/**
 * Export the Ed25519 public key.
 *
 * @param [in]      key     wolfSSL Ed25519 key object.
 * @param [out]     out     Buffer to hold exported key.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, length of data in bytes.
 * @param [in]      endian  Which endian the bytes are to be encoded in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_ed25519_export_public(ed25519_key* key, const byte* out,
    word32* outLen, int endian)
{
    int ret;

    (void)endian;

    if (!key->pubKeySet) {
        ret = wc_ed25519_make_public(key, (byte*)out, *outLen);
        if (ret == 0) {
            /* Store the generated public key in the key object for future use. */
            ret = wc_ed25519_import_public((byte*)out, *outLen, key);
        }
    }
    else {
        ret = wc_ed25519_export_public(key, (byte*)out, outLen);
    }

    return ret;
}

/**
 * Import the Ed25519 private key.
 *
 * @param [in]      in      Buffer holding DER encoded Ed25519 private key.
 * @param [in]      inLen   Length of data in bytes.
 * @param [in, out] key     wolfSSL Ed25519 key object.
 * @param [in]      endian  Which endian the bytes are in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_ed25519_import_private(const byte* in, word32 inLen,
    ed25519_key* key, int endian)
{
    (void)endian;
    return wc_ed25519_import_private_only(in, inLen, key);
}

/** Ed25519 data and wolfSSL functions. */
static const wp_EcxData ed25519Data = {
    WP_KEY_TYPE_ED25519,
    ED25519_KEY_SIZE * 8,
    ED25519_KEY_SIZE,

    (WP_ECX_INIT)&wc_ed25519_init,
    (WP_ECX_FREE)&wc_ed25519_free,
    (WP_ECX_MAKE_KEY)&wc_ed25519_make_key,
    (WP_ECX_IMPORT_PUB)&wp_ed25519_import_public,
    (WP_ECX_EXPORT_PUB)&wp_ed25519_export_public,
    (WP_ECX_IMPORT_PRIV)&wp_ed25519_import_private,
    (WP_ECX_EXPORT_PRIV)&wc_ed25519_export_private_only,
    NULL,
    (WP_ECX_CHECK_KEY)&wc_ed25519_check_key,
};

/**
 * Create a new Ed25519 key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX key object on success.
 * @return  NULL on failure.
 */
static wp_Ecx* wp_ed25519_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_new(provCtx, &ed25519Data);
}

/**
 * Create Ed25519 generation context object. Base function.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New ECX generation context object on success.
 * @return  NULL on failure.
 */
static wp_EcxGenCtx* wp_ed25519_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_ecx_gen_init(provCtx, selection, params, &ed25519Data,
        SN_ED25519);
}

/**
 * Return the Ed25519 operation name as a string.
 *
 * @param [in] op  Operationn type being performed. Unused.
 * @return  Name of operation.
 */
static const char* wp_ed25519_query_operation_name(int op)
{
    (void)op;
    return "ED25519";
}

/** Dispatch table for Ed25519 key management. */
IMPLEMENT_ECX_KEYMGMT_DISPATCH(ed25519, ed)

#endif /* WP_HAVE_ED25519 */

#ifdef WP_HAVE_ED448

/*
 * Ed448
 */

/**
 * Import the Ed448 public key.
 *
 * @param [in]      in      Buffer holding DER encoded Ed448 public key.
 * @param [in]      inLen   Length of data in bytes.
 * @param [in, out] key     wolfSSL Ed448 key object.
 * @param [in]      endian  Which endian the bytes are in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_ed448_import_public(const byte* in, word32 inLen, ed448_key* key,
    int endian)
{
    (void)endian;
    return wc_ed448_import_public(in, inLen, key);
}

/**
 * Export the Ed448 public key.
 *
 * @param [in]      key     wolfSSL Ed448 key object.
 * @param [out]     out     Buffer to hold exported key.
 * @param [in, out] outLen  On in, length of buffer in bytes.
 *                          On out, length of data in bytes.
 * @param [in]      endian  Which endian the bytes are to be encoded in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_ed448_export_public(ed448_key* key, const byte* out,
    word32* outLen, int endian)
{
    int ret;

    (void)endian;

    if (!key->pubKeySet) {
        ret = wc_ed448_make_public(key, (byte*)out, *outLen);
        if (ret == 0) {
            /* Store the generated public key in the key object for future use. */
            ret = wc_ed448_import_public((byte*)out, *outLen, key);
        }
    }
    else {
        ret = wc_ed448_export_public(key, (byte*)out, outLen);
    }

    return ret;
}

/**
 * Import the Ed448 private key.
 *
 * @param [in]      in      Buffer holding DER encoded Ed448 private key.
 * @param [in]      inLen   Length of data in bytes.
 * @param [in, out] key     wolfSSL Ed448 key object.
 * @param [in]      endian  Which endian the bytes are in. Unused.
 * @return  0 on success.
 * @return  -ve on failure.
 */
static int wp_ed448_import_private(const byte* in, word32 inLen,
    ed448_key* key, int endian)
{
    (void)endian;
    return wc_ed448_import_private_only(in, inLen, key);
}

/** Ed448 data and wolfSSL functions. */
static const wp_EcxData ed448Data = {
    WP_KEY_TYPE_ED448,
    ED448_KEY_SIZE * 8,
    ED448_KEY_SIZE,

    (WP_ECX_INIT)&wc_ed448_init,
    (WP_ECX_FREE)&wc_ed448_free,
    (WP_ECX_MAKE_KEY)&wc_ed448_make_key,
    (WP_ECX_IMPORT_PUB)&wp_ed448_import_public,
    (WP_ECX_EXPORT_PUB)&wp_ed448_export_public,
    (WP_ECX_IMPORT_PRIV)&wp_ed448_import_private,
    (WP_ECX_EXPORT_PRIV)&wc_ed448_export_private_only,
    NULL,
    (WP_ECX_CHECK_KEY)&wc_ed448_check_key,
};

/**
 * Create a new Ed448 key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX key object on success.
 * @return  NULL on failure.
 */
static wp_Ecx* wp_ed448_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_new(provCtx, &ed448Data);
}

/**
 * Create Ed448 generation context object. Base function.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New ECX generation context object on success.
 * @return  NULL on failure.
 */
static wp_EcxGenCtx* wp_ed448_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_ecx_gen_init(provCtx, selection, params, &ed448Data, SN_ED448);
}
/**
 * Return the Ed448 operation name as a string.
 *
 * @param [in] op  Operationn type being performed. Unused.
 * @return  Name of operation.
 */
static const char* wp_ed448_query_operation_name(int op)
{
    (void)op;
    return "ED448";
}

/** Dispatch table for Ed448 key management. */
IMPLEMENT_ECX_KEYMGMT_DISPATCH(ed448, ed)

#endif /* WP_HAVE_ED448 */

/*
 * ECX encoding/decoding.
 */

/** Type for function that decodes a key into a wolfSSL key. */
typedef int (*WP_ECX_DECODE)(const byte* data, word32* idx, void* key,
    word32 len);
/* TODO: withAlg is a parameter to Public encoding API but not to Private. */
/** Type for function that encodes a key from a wolfSSL key. */
typedef int (*WP_ECX_ENCODE)(void* key, byte* output, word32 inLen);

/**
 * Encode/decode ECX public/private key.
 */
typedef struct wp_EcxEncDecCtx {
    /** wolfSSL function to decode ECX key from DER. */
    WP_ECX_DECODE decode;
    /** wolfSSL function to encode ECX key to DER. */
    WP_ECX_ENCODE encode;

    /** Provider context - used when creating ECX key. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to export. */
    int selection;

    /** Type of key. */
    int keyType;
    /** Supported format. */
    int format;
    /** Data format. */
    int encoding;

    /** Cipher to use when encoding EncryptedPrivateKeyInfo. */
    int cipher;
    /** Name of cipher to use when encoding EncryptedPrivateKeyInfo. */
    const char* cipherName;
} wp_EcxEncDecCtx;

/**
 * Create a new ECX encoder/decoder context.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] format    Supported format.
 * @param [in] encoder   Indicates whether this an encoder.
 * @param [in] keyType   Type of key.
 * @param [in] format    Supported key format.
 * @param [in] encoding  Data format.
 * @param [in] decode    Function to decode DER data to a key.
 * @param [in] encode    Function to encode key to DER data.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ecx_enc_dec_new(WOLFPROV_CTX* provCtx,
    int keyType, int format, int encoding, WP_ECX_DECODE decode,
    WP_ECX_ENCODE encode)
{
    wp_EcxEncDecCtx *ctx = NULL;
    if (wolfssl_prov_is_running()) {
        ctx = (wp_EcxEncDecCtx*)OPENSSL_zalloc(sizeof(wp_EcxEncDecCtx));
    }
    if (ctx != NULL) {
        ctx->decode   = decode;
        ctx->encode   = encode;
        ctx->provCtx  = provCtx;
        ctx->keyType  = keyType;
        ctx->format   = format;
        ctx->encoding = encoding;
    }
    return ctx;
}

/**
 * Dispose of ECX encoder/decoder context object.
 *
 * @param [in, out] ctx  ECX encoder/decoder context object.
 */
static void wp_ecx_enc_dec_free(wp_EcxEncDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return the settable parameters for the ECX encoder/decoder context.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_ecx_enc_dec_settable_ctx_params(
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_ecx_enc_dec_supported_settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    (void)provCtx;
    return wp_ecx_enc_dec_supported_settables;
}

/**
 * Set the ECX encoder/decoder context parameters.
 *
 * @param [in, out] ctx     ECX encoder/decoder context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_enc_dec_set_ctx_params(wp_EcxEncDecCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wp_cipher_from_params(params, &ctx->cipher, &ctx->cipherName)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Construct parameters from ECX key and pass off to callback.
 *
 * @param [in] ecx        ECX key object.
 * @param [in] dataCb     Callback to pass ECX key in parameters to.
 * @param [in] dataCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_dec_send_params(wp_Ecx* ecx, const char* dataType,
    OSSL_CALLBACK* dataCb, void* dataCbArg)
{
    int ok = 1;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char*)dataType, 0);
    /* The address of the key object becomes the octet string pointer. */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &ecx, sizeof(ecx));
    params[3] = OSSL_PARAM_construct_end();

    /* Callback to do something with ECX key object. */
    if (!dataCb(params, dataCbArg)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the data in the core BIO.
 *
 * The format of the key must be the same as the decoder's format.
 *
 * @param [in, out] ctx        ECX encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to read data from.
 * @param [in]      selection  Parts of key to export.
 * @param [in]      dataCb     Callback to pass ECX key in parameters to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_decode(wp_EcxEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int decoded = 1;
    int rc;
    unsigned char* data = NULL;
    word32 len = 0;
    word32 idx = 0;
    wp_Ecx* ecx;
    const char* dataType = NULL;

    (void)pwCb;
    (void)pwCbArg;

    ctx->selection = selection;
#ifdef WP_HAVE_X25519
    if (ctx->keyType == WP_KEY_TYPE_X25519) {
        ecx = wp_x25519_new(ctx->provCtx);
        dataType = "X25519";
    }
    else
#endif /* WP_HAVE_X25519 */
#ifdef WP_HAVE_ED25519
    if (ctx->keyType == WP_KEY_TYPE_ED25519) {
        ecx = wp_ed25519_new(ctx->provCtx);
        dataType = "ED25519";
    }
    else
#endif /* WP_HAVE_ED25519 */
#ifdef WP_HAVE_X448
    if (ctx->keyType == WP_KEY_TYPE_X448) {
        ecx = wp_x448_new(ctx->provCtx);
        dataType = "X448";
    }
    else
#endif /* WP_HAVE_X448 */
#ifdef WP_HAVE_ED448
    if (ctx->keyType == WP_KEY_TYPE_ED448) {
        ecx = wp_ed448_new(ctx->provCtx);
        dataType = "ED448";
    }
    else
#endif /* WP_HAVE_ED448 */
    {
        ecx = NULL;
    }
    if (ecx == NULL) {
        ok = 0;
    }

    if (ok) {
        ok = wp_read_der_bio(ctx->provCtx, cBio, &data, &len);
    }
    if (ok) {
        rc = ctx->decode(data, &idx, (void*)&ecx->key, len);
        if (rc != 0) {
            ok = 0;
            decoded = 0;
        }
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        ecx->hasPub = 1;
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        ecx->hasPub = 1;
        ecx->hasPriv = 1;
    }

    OPENSSL_clear_free(data, len);

    if (ok && (!wp_ecx_dec_send_params(ecx, dataType, dataCb, dataCbArg))) {
        ok = 0;
    }

    if (!ok) {
        wp_ecx_free(ecx);
        if (!decoded) {
            ok = 1;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ECX key.
 *
 * @param [in]      ctx        ECX encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      key        ECX key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode. Unused.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_encode(wp_EcxEncDecCtx* ctx, OSSL_CORE_BIO *cBio,
    const wp_Ecx *ecx, const OSSL_PARAM* params, int selection,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    int ok = 1;
    int rc;
    BIO* out = wp_corebio_get_bio(ctx->provCtx, cBio);
    unsigned char* keyData = NULL;
    size_t keyLen = 0;
    unsigned char derData[160];
    size_t derLen = 0;
    unsigned char* pemData = NULL;
    size_t pemLen = 0;
    int pemType = (ctx->format == WP_ENC_FORMAT_SPKI) ? PUBLICKEY_TYPE :
                                                        PKCS8_PRIVATEKEY_TYPE;
    int private = (ctx->format == WP_ENC_FORMAT_PKI) ||
                  (ctx->format == WP_ENC_FORMAT_EPKI);
    byte* cipherInfo = NULL;

    (void)params;
    (void)selection;

    if (out == NULL) {
        ok = 0;
    }

    if (ok) {
        rc = ctx->encode((void*)&ecx->key, derData, sizeof(derData));
        if (rc <= 0) {
            ok = 0;
        }
        else {
            derLen = rc;
        }
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        if (!wp_encrypt_key(ctx->provCtx, ctx->cipherName, derData, &derLen, rc,
            pwCb, pwCbArg, &cipherInfo)) {
            ok = 0;
        }
    }

    if (ok && (ctx->encoding == WP_FORMAT_DER)) {
        keyData = derData;
        keyLen = derLen;
    }
    else if (ok && (ctx->encoding == WP_FORMAT_PEM)) {
        rc = wc_DerToPemEx(derData, (word32)derLen, NULL, 0, cipherInfo, pemType);
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
            rc = wc_DerToPemEx(derData, (word32)derLen, pemData, (word32)pemLen, cipherInfo,
                pemType);
            if (rc <= 0) {
                ok = 0;
            }
        }
        if (ok) {
            keyLen = pemLen = rc;
            keyData = pemData;
        }
    }
    if (ok) {
        rc = BIO_write(out, keyData, (int)keyLen);
        if (rc <= 0) {
            ok = 0;
        }
    }

    if (private) {
        OPENSSL_cleanse(derData, derLen);
        OPENSSL_clear_free(pemData, pemLen);
    }
    else {
        OPENSSL_free(pemData);
    }
    OPENSSL_free(cipherInfo);
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the ECX key object.
 *
 * @param [in] ctx          ECX encoder/decoder context object.
 * @param [in] ecx          ECX key object.
 * @param [in] size         Size of key object.
 * @param [in] exportCb     Callback to export key.
 * @param [in] exportCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_ecx_export_object(wp_EcxEncDecCtx* ctx, wp_Ecx* ecx, size_t size,
    OSSL_CALLBACK* exportCb, void* exportCbArg)
{
    /* TODO: check size to ensure it really is a wc_Ecx object.  */
    (void)size;
    return wp_ecx_export(ecx, ctx->selection, exportCb, exportCbArg);
}

/*
 * ECX SubkectPublicKeyInfo
 */

/**
 * Return whether the SPKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        ECX encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_ecx_spki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok = 0;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/*
 * ECX PrivateKeyInfo
 */

/**
 * Return whether the PKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        ECX encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_ecx_pki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WP_HAVE_X25519

/*
 * X25519 Public Key
 */

/**
 * Decode public X25519 key.
 *
 * Loads little-endian public key.
 *
 * @param [in]      input     Buffer holding X25519 public key data.
 * @param [in, out] inOutIdx  On in, index into buffer of data.
 *                            On out, index into buffer after data.
 * @param [in, out] key       X25519 key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when data is not valid.
 * @return  BUFFER_E when data is not valid.
 */
static int wp_x25519_pub_decode(const byte* input, word32* inOutIdx,
    curve25519_key* key, word32 inSz)
{
    int ret;

    ret = wc_Curve25519PublicKeyDecode(input, inOutIdx, key, inSz);
    if (ret == 0) {
        /* Load little-endian instead. */
        ret = wc_curve25519_import_public_ex(input + inSz - CURVE25519_KEYSIZE,
            CURVE25519_KEYSIZE, key, EC25519_LITTLE_ENDIAN);
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles decoding public keys
 * for X25519 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_SPKI,
        0, (WP_ECX_DECODE)wp_x25519_pub_decode, NULL);
}

/**
 * Dispatch table for X25519 SPKI decoder.
 */
const OSSL_DISPATCH wp_x25519_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_x25519_spki_dec_new         },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Encode the public part of an X25519 key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       X25519 key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  inLen     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int wp_Curve25519PublicKeyToDer(curve25519_key* key, byte* output,
    word32 inLen)
{
    int ret;

    /* Always include the algorithm. */
    ret = wc_Curve25519PublicKeyToDer(key, output, inLen, 1);
    if (ret > 0) {
        /* Reverse the order of the key. */
        int i;
        byte* p = output + ret - CURVE25519_KEYSIZE;

        for (i = 0; i < CURVE25519_KEYSIZE / 2; i++) {
            byte t = p[i];
            p[i] = p[CURVE25519_KEYSIZE - 1 - i];
            p[CURVE25519_KEYSIZE - 1 - i] = t;
        }
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Curve25519PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_x25519_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x25519_spki_der_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Curve25519PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_x25519_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x25519_spki_pem_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * X25519 Private Key
 */

/**
 * Decode private X25519 key.
 *
 * Loads little-endian private key.
 *
 * @param [in]      input     Buffer holding X25519 private key data.
 * @param [in, out] inOutIdx  On in, index into buffer of data.
 *                            On out, index into buffer after data.
 * @param [in, out] key       X25519 key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when data is not valid.
 * @return  BUFFER_E when data is not valid.
 */
static int wp_x25519_priv_decode(const byte* input, word32* inOutIdx,
    curve25519_key* key, word32 inSz)
{
    int ret;

    ret = wc_Curve25519PrivateKeyDecode(input, inOutIdx, key, inSz);
    if (ret == 0) {
        /* TODO: not always last bytes! */
        /* Load little-endian instead. */
        ret = wc_curve25519_import_private_ex(input + inSz - CURVE25519_KEYSIZE,
            CURVE25519_KEYSIZE, key, EC25519_LITTLE_ENDIAN);
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles decoding public keys
 * for X25519 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_PKI,
        0, (WP_ECX_DECODE)wp_x25519_priv_decode, NULL);
}

/**
 * Dispatch table for X25519 PKI decoder.
 */
const OSSL_DISPATCH wp_x25519_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_x25519_pki_dec_new          },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Encode the private part of an X25519 key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       X25519 key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  inLen     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int wp_Curve25519PrivateKeyToDer(curve25519_key* key, byte* output,
    word32 inLen)
{
    int ret;

    ret = wc_Curve25519PrivateKeyToDer(key, output, inLen);
    if (ret > 0) {
        /* Reverse the order of the key. */
        int i;
        byte* p = output + ret - CURVE25519_KEYSIZE;

        for (i = 0; i < CURVE25519_KEYSIZE / 2; i++) {
            byte t = p[i];
            p[i] = p[CURVE25519_KEYSIZE - 1 - i];
            p[CURVE25519_KEYSIZE - 1 - i] = t;
        }
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_PKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Curve25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_x25519_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x25519_pki_der_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_PKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Curve25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_x25519_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x25519_pki_pem_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * X25519 EncryptedPrivateKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Curve25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_x25519_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x25519_epki_der_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x25519_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X25519, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Curve25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_x25519_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x25519_epki_pem_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

#endif /* WP_HAVE_X25519 */

#ifdef WP_HAVE_ED25519

/*
 * Ed25519 SubkectPublicKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles decoding SPKI for
 * Ed25519 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_SPKI,
        0, (WP_ECX_DECODE)wc_Ed25519PublicKeyDecode, NULL);
}

/**
 * Dispatch table for Ed25519 SPKI decoder.
 */
const OSSL_DISPATCH wp_ed25519_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ed25519_spki_dec_new        },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Encode the public part of an Ed25519 key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       Ed25519 key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  inLen     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int wp_Ed25519PublicKeyToDer(ed25519_key* key, byte* output,
    word32 inLen)
{
    int ok = 1;

    /* Check if this is private key only. */
    if (!key->pubKeySet) {
        int rc;
        /* Make the public key to encode. */
        rc = wc_ed25519_make_public(key, key->p, ED25519_PUB_KEY_SIZE);
        ok = key->pubKeySet = (rc == 0);
    }
    if (ok) {
        /* Always include the algorithm. */
        ok = wc_Ed25519PublicKeyToDer(key, output, inLen, 1);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Ed25519PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_ed25519_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed25519_spki_der_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Ed25519PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ed25519_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed25519_spki_pem_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * Ed25519 PrivateKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles decoding PKI for
 * Ed25519 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_PKI,
        0, (WP_ECX_DECODE)wc_Ed25519PrivateKeyDecode, NULL);
}

/**
 * Dispatch table for Ed25519 PKI decoder.
 */
const OSSL_DISPATCH wp_ed25519_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ed25519_pki_dec_new         },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_PKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wc_Ed25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_ed25519_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed25519_pki_der_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_PKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wc_Ed25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ed25519_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed25519_pki_pem_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * Ed25519 EncryptedPrivateKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wc_Ed25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_ed25519_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed25519_epki_der_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed25519_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED25519, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wc_Ed25519PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ed25519_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed25519_epki_pem_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

#endif /* WP_HAVE_ED25519 */

#ifdef WP_HAVE_X448

/*
 * X448 Public Key
 */

/**
 * Decode public X448 key.
 *
 * Loads little-endian public key.
 *
 * @param [in]      input     Buffer holding X448 public key data.
 * @param [in, out] inOutIdx  On in, index into buffer of data.
 *                            On out, index into buffer after data.
 * @param [in, out] key       X448 key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when data is not valid.
 * @return  BUFFER_E when data is not valid.
 */
static int wp_x448_pub_decode(const byte* input, word32* inOutIdx,
    curve448_key* key, word32 inSz)
{
    int ret;

    ret = wc_Curve448PublicKeyDecode(input, inOutIdx, key, inSz);
    if (ret == 0) {
        ret = wc_curve448_import_public_ex(input + inSz - CURVE448_KEY_SIZE,
            CURVE448_KEY_SIZE, key, EC448_LITTLE_ENDIAN);
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles decoding public keys
 * for X448 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_SPKI,
        0, (WP_ECX_DECODE)wp_x448_pub_decode, NULL);
}

/**
 * Dispatch table for X448 SPKI decoder.
 */
const OSSL_DISPATCH wp_x448_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_x448_spki_dec_new           },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Encode the public part of an X448 key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       X448 key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  outLen    Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int wp_Curve448PublicKeyToDer(curve448_key* key, byte* output,
    word32 inLen)
{
    int ret;

    /* Always include the algorithm. */
    ret = wc_Curve448PublicKeyToDer(key, output, inLen, 1);
    if (ret > 0) {
        /* Reverse the order of the key. */
        int i;
        byte* p = output + ret - CURVE448_KEY_SIZE;

        for (i = 0; i < CURVE448_KEY_SIZE / 2; i++) {
            byte t = p[i];
            p[i] = p[CURVE448_KEY_SIZE - 1 - i];
            p[CURVE448_KEY_SIZE - 1 - i] = t;
        }
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Curve448PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_x448_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x448_spki_der_enc_new       },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Curve448PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_x448_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x448_spki_pem_enc_new       },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * X448 Private Key
 */

/**
 * Decode private X448 key.
 *
 * Loads little-endian private key.
 *
 * @param [in]      input     Buffer holding X448 private key data.
 * @param [in, out] inOutIdx  On in, index into buffer of data.
 *                            On out, index into buffer after data.
 * @param [in, out] key       X448 key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success.
 * @return  ASN_PARSE_E when data is not valid.
 * @return  BUFFER_E when data is not valid.
 */
static int wp_x448_priv_decode(const byte* input, word32* inOutIdx,
    curve448_key* key, word32 inSz)
{
    int ret;

    ret = wc_Curve448PrivateKeyDecode(input, inOutIdx, key, inSz);
    if (ret == 0) {
        /* TODO: not always last bytes! */
        /* Load little-endian instead. */
        ret = wc_curve448_import_private_ex(input + inSz - CURVE448_KEY_SIZE,
            CURVE448_KEY_SIZE, key, EC448_LITTLE_ENDIAN);
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles decoding public keys
 * for X448 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_PKI,
        0, (WP_ECX_DECODE)wp_x448_priv_decode, NULL);
}

/**
 * Dispatch table for X448 PKI decoder.
 */
const OSSL_DISPATCH wp_x448_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_x448_pki_dec_new            },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Encode the private part of an X448 key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       X448 key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  inLen     Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int wp_Curve448PrivateKeyToDer(curve448_key* key, byte* output,
    word32 inLen)
{
    int ret;

    ret = wc_Curve448PrivateKeyToDer(key, output, inLen);
    if (ret > 0) {
        /* Reverse the order of the key. */
        int i;
        byte* p = output + ret - CURVE448_KEY_SIZE;

        for (i = 0; i < CURVE448_KEY_SIZE / 2; i++) {
            byte t = p[i];
            p[i] = p[CURVE448_KEY_SIZE - 1 - i];
            p[CURVE448_KEY_SIZE - 1 - i] = t;
        }
    }

    return ret;
}

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_PKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Curve448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_x448_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x448_pki_der_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_PKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Curve448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_x448_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x448_pki_pem_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * X448 EncryptedPrivateKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Curve448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_x448_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x448_epki_der_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_x448_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_X448, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Curve448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_x448_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_x448_epki_pem_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

#endif /* WP_HAVE_X448 */

#ifdef WP_HAVE_ED448

/*
 * Ed448 SubkectPublicKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles decoding SPKI for
 * Ed448 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_SPKI,
        0, (WP_ECX_DECODE)wc_Ed448PublicKeyDecode, NULL);
}

/**
 * Dispatch table for Ed448 SPKI decoder.
 */
const OSSL_DISPATCH wp_ed448_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ed448_spki_dec_new          },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Encode the public part of an Ed448 key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       Ed448 key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  outLen    Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
static int wp_Ed448PublicKeyToDer(ed448_key* key, byte* output, word32 inLen)
{
    int ok = 1;

    /* Check if this is private key only. */
    if (!key->pubKeySet) {
        int rc;
        /* Make the public key to encode. */
        rc = wc_ed448_make_public(key, key->p, ED448_PUB_KEY_SIZE);
        ok = key->pubKeySet = (rc == 0);
    }
    if (ok) {
        /* Always include the algorithm. */
        ok = wc_Ed448PublicKeyToDer(key, output, inLen, 1);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wp_Ed448PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_ed448_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed448_spki_der_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding SPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wp_Ed448PublicKeyToDer);
}

/**
 * Dispatch table for SPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ed448_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed448_spki_pem_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * Ed448 PrivateKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles decoding PKI for
 * Ed448 keys.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_PKI,
        0, (WP_ECX_DECODE)wc_Ed448PrivateKeyDecode, NULL);
}

/**
 * Dispatch table for Ed448 PKI decoder.
 */
const OSSL_DISPATCH wp_ed448_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_ed448_pki_dec_new           },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                        (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_ecx_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_ecx_export_object           },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_PKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wc_Ed448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_ed448_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed448_pki_der_enc_new       },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_PKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wc_Ed448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ed448_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed448_pki_pem_enc_new       },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/*
 * Ed448 EncryptedPrivateKeyInfo
 */

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_DER, NULL, (WP_ECX_ENCODE)wc_Ed448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_ed448_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed448_epki_der_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

/**
 * Create a new ECX encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New ECX encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_EcxEncDecCtx* wp_ed448_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_ecx_enc_dec_new(provCtx, WP_KEY_TYPE_ED448, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_PEM, NULL, (WP_ECX_ENCODE)wc_Ed448PrivateKeyToDer);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_ed448_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_ed448_epki_pem_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_ecx_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_ecx_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_ecx_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_ecx_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_ecx_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_ecx_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_ecx_free                    },
    { 0, NULL }
};

#endif /* WP_HAVE_ED448 */

#endif /* WP_HAVE_X25519 || WP_HAVE_ED25519 || WP_HAVE_X448 || WP_HAVE_ED448 */

