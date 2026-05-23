/* wp_mlkem_kmgmt.c
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
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_MLKEM

#include <wolfssl/wolfcrypt/wc_mlkem.h>

/** Supported selections (key parts) in this key manager for ML-KEM. */
#define WP_MLKEM_POSSIBLE_SELECTIONS                                           \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/**
 * ML-KEM parameter set data.
 */
typedef struct wp_MlKemData {
    /** wolfSSL parameter type (WC_ML_KEM_512/768/1024). */
    int type;
    /** Public key size in bytes. */
    word32 pubKeySize;
    /** Private key size in bytes. */
    word32 privKeySize;
    /** Ciphertext size in bytes. */
    word32 ctSize;
    /** Security bits. */
    int securityBits;
    /** Algorithm name string. */
    const char* name;
} wp_MlKemData;

/**
 * ML-KEM key object.
 */
struct wp_MlKem {
    /** wolfSSL ML-KEM key. */
    MlKemKey key;
    /** Parameter set data. */
    const wp_MlKemData* data;

#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;

    /** Provider context. */
    WOLFPROV_CTX* provCtx;

    /** Public key available. */
    unsigned int hasPub:1;
    /** Private key available. */
    unsigned int hasPriv:1;
};

typedef struct wp_MlKem wp_MlKem;

/**
 * ML-KEM key generation context.
 */
typedef struct wp_MlKemGenCtx {
    /** wolfSSL random number generator. */
    WC_RNG rng;
    /** Parameter set data. */
    const wp_MlKemData* data;
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to generate. */
    int selection;
} wp_MlKemGenCtx;


/* Parameter set tables. */
static const wp_MlKemData mlkem512Data = {
    WC_ML_KEM_512,
    WC_ML_KEM_512_PUBLIC_KEY_SIZE,
    WC_ML_KEM_512_PRIVATE_KEY_SIZE,
    WC_ML_KEM_512_CIPHER_TEXT_SIZE,
    128,
    "ML-KEM-512"
};

static const wp_MlKemData mlkem768Data = {
    WC_ML_KEM_768,
    WC_ML_KEM_768_PUBLIC_KEY_SIZE,
    WC_ML_KEM_768_PRIVATE_KEY_SIZE,
    WC_ML_KEM_768_CIPHER_TEXT_SIZE,
    192,
    "ML-KEM-768"
};

static const wp_MlKemData mlkem1024Data = {
    WC_ML_KEM_1024,
    WC_ML_KEM_1024_PUBLIC_KEY_SIZE,
    WC_ML_KEM_1024_PRIVATE_KEY_SIZE,
    WC_ML_KEM_1024_CIPHER_TEXT_SIZE,
    256,
    "ML-KEM-1024"
};


/**
 * Increment reference count for key.
 *
 * @param [in, out] mlkem  ML-KEM key object.
 * @return  1 on success, 0 on failure.
 */
int wp_mlkem_up_ref(wp_MlKem* mlkem)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&mlkem->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        mlkem->refCnt++;
        wc_UnLockMutex(&mlkem->mutex);
    }
    return ok;
#else
    mlkem->refCnt++;
    return 1;
#endif
}

/**
 * Get the wolfSSL ML-KEM key from the wp_MlKem object.
 *
 * @param [in] mlkem  ML-KEM key object.
 * @return  Pointer to wolfSSL MlKemKey, returned as void*.
 */
void* wp_mlkem_get_key(wp_MlKem* mlkem)
{
    return &mlkem->key;
}

/**
 * Get the parameter set data from the wp_MlKem object.
 *
 * @param [in] mlkem  ML-KEM key object.
 * @return  Pointer to parameter set data.
 */
const wp_MlKemData* wp_mlkem_get_data(const wp_MlKem* mlkem)
{
    return mlkem->data;
}

/**
 * Get the ciphertext size for an ML-KEM parameter set.
 *
 * @param [in] data  Parameter set data.
 * @return  Ciphertext size in bytes.
 */
word32 wp_mlkem_data_ct_size(const wp_MlKemData* data)
{
    return data->ctSize;
}

/**
 * Create a new ML-KEM key object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] data     Parameter set data.
 * @return  New ML-KEM key object on success, NULL on failure.
 */
static wp_MlKem* wp_mlkem_new(WOLFPROV_CTX* provCtx, const wp_MlKemData* data)
{
    wp_MlKem* mlkem = NULL;

    if (wolfssl_prov_is_running()) {
        mlkem = (wp_MlKem*)OPENSSL_zalloc(sizeof(*mlkem));
    }
    if (mlkem != NULL) {
        int ok = 1;
        int rc;

        rc = wc_MlKemKey_Init(&mlkem->key, data->type, NULL, INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }
    #ifndef WP_SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&mlkem->mutex);
            if (rc != 0) {
                wc_MlKemKey_Free(&mlkem->key);
                ok = 0;
            }
        }
    #endif
        if (ok) {
            mlkem->provCtx = provCtx;
            mlkem->refCnt  = 1;
            mlkem->data    = data;
        }
        if (!ok) {
            OPENSSL_free(mlkem);
            mlkem = NULL;
        }
    }

    return mlkem;
}

/**
 * Dispose of ML-KEM key object.
 *
 * @param [in, out] mlkem  ML-KEM key object. May be NULL.
 */
void wp_mlkem_free(wp_MlKem* mlkem)
{
    if (mlkem != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&mlkem->mutex);
        cnt = --mlkem->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&mlkem->mutex);
        }
    #else
        cnt = --mlkem->refCnt;
    #endif

        if (cnt == 0) {
        #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&mlkem->mutex);
        #endif
            wc_MlKemKey_Free(&mlkem->key);
            OPENSSL_free(mlkem);
        }
    }
}

/**
 * Duplicate ML-KEM key object.
 *
 * @param [in] src        Source ML-KEM key object.
 * @param [in] selection  Parts of key to include. Unused; always full dup.
 * @return  New ML-KEM key object on success, NULL on failure.
 */
static wp_MlKem* wp_mlkem_dup(const wp_MlKem* src, int selection)
{
    wp_MlKem* dst = NULL;
    unsigned char* pubBuf = NULL;
    unsigned char* privBuf = NULL;
    word32 pubLen;
    word32 privLen;
    int rc;
    int ok = 1;
    int dupPub = ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
                  && src != NULL && src->hasPub;
    int dupPriv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
                  && src != NULL && src->hasPriv;

    if (!wolfssl_prov_is_running() || (src == NULL)) {
        return NULL;
    }

    dst = wp_mlkem_new(src->provCtx, src->data);
    if (dst == NULL) {
        return NULL;
    }

    if (dupPub) {
        pubLen = src->data->pubKeySize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePublicKey((MlKemKey*)&src->key, pubBuf,
                pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlKemKey_DecodePublicKey(&dst->key, pubBuf, pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            dst->hasPub = 1;
        }
        OPENSSL_free(pubBuf);
        pubBuf = NULL;
    }

    if (ok && dupPriv) {
        privLen = src->data->privKeySize;
        privBuf = (unsigned char*)OPENSSL_malloc(privLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePrivateKey((MlKemKey*)&src->key, privBuf,
                privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlKemKey_DecodePrivateKey(&dst->key, privBuf, privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            dst->hasPriv = 1;
        }
        OPENSSL_clear_free(privBuf, privLen);
    }

    if (!ok) {
        wp_mlkem_free(dst);
        return NULL;
    }
    return dst;
}

/**
 * Load an ML-KEM key from a reference.
 *
 * @param [in, out] pMlKem  Pointer to an ML-KEM key reference.
 * @param [in]      size    Size of reference object. Unused.
 * @return  ML-KEM key object on success.
 */
static const wp_MlKem* wp_mlkem_load(const wp_MlKem** pMlKem, size_t size)
{
    const wp_MlKem* mlkem = *pMlKem;
    (void)size;
    *pMlKem = NULL;
    return mlkem;
}

/**
 * Check ML-KEM key object has the components required.
 *
 * @param [in] mlkem      ML-KEM key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_has(const wp_MlKem* mlkem, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (mlkem == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok &= mlkem->hasPub;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= mlkem->hasPriv;
    }
    return ok;
}

/**
 * Compare two ML-KEM keys.
 *
 * @param [in] a          First ML-KEM key.
 * @param [in] b          Second ML-KEM key.
 * @param [in] selection  Parts of key to compare.
 * @return  1 if match, 0 otherwise.
 */
static int wp_mlkem_match(const wp_MlKem* a, const wp_MlKem* b, int selection)
{
    int ok = 1;
    unsigned char* bufA = NULL;
    unsigned char* bufB = NULL;
    word32 lenA;
    word32 lenB;
    int rc;

    if (!wolfssl_prov_is_running() || (a == NULL) || (b == NULL)) {
        return 0;
    }
    if (a->data->type != b->data->type) {
        return 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        lenA = a->data->pubKeySize;
        lenB = b->data->pubKeySize;
        bufA = (unsigned char*)OPENSSL_malloc(lenA);
        bufB = (unsigned char*)OPENSSL_malloc(lenB);
        if ((bufA == NULL) || (bufB == NULL)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePublicKey((MlKemKey*)&a->key, bufA, lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePublicKey((MlKemKey*)&b->key, bufB, lenB);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok && ((lenA != lenB) || (XMEMCMP(bufA, bufB, lenA) != 0))) {
            ok = 0;
        }
        OPENSSL_free(bufA);
        OPENSSL_free(bufB);
        bufA = NULL;
        bufB = NULL;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        lenA = a->data->privKeySize;
        lenB = b->data->privKeySize;
        bufA = (unsigned char*)OPENSSL_malloc(lenA);
        bufB = (unsigned char*)OPENSSL_malloc(lenB);
        if ((bufA == NULL) || (bufB == NULL)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePrivateKey((MlKemKey*)&a->key, bufA, lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePrivateKey((MlKemKey*)&b->key, bufB, lenB);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok && ((lenA != lenB) || (XMEMCMP(bufA, bufB, lenA) != 0))) {
            ok = 0;
        }
        OPENSSL_clear_free(bufA, lenA);
        OPENSSL_clear_free(bufB, lenB);
    }
    return ok;
}

/**
 * Import an ML-KEM key from parameters.
 *
 * @param [in, out] mlkem      ML-KEM key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_import(wp_MlKem* mlkem, int selection,
    const OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    unsigned char* privData = NULL;
    unsigned char* pubData = NULL;
    size_t privLen = 0;
    size_t pubLen = 0;
    unsigned char* derivedPub = NULL;
    word32 derivedPubLen = 0;

    if (!wolfssl_prov_is_running() || (mlkem == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_MLKEM_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PRIV_KEY,
                &privData, &privLen)) {
            ok = 0;
        }
        if (ok && (privData != NULL)) {
            rc = wc_MlKemKey_DecodePrivateKey(&mlkem->key, privData,
                (word32)privLen);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                mlkem->hasPriv = 1;
                /* Probe whether private-key import gave us the public part
                 * (FIPS 203 private keys embed the public component). */
                derivedPubLen = mlkem->data->pubKeySize;
                derivedPub = (unsigned char*)OPENSSL_malloc(derivedPubLen);
                if (derivedPub != NULL) {
                    if (wc_MlKemKey_EncodePublicKey(&mlkem->key, derivedPub,
                            derivedPubLen) == 0) {
                        mlkem->hasPub = 1;
                    }
                }
            }
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PUB_KEY,
                &pubData, &pubLen)) {
            ok = 0;
        }
        /* Consistency check: if both priv and pub were supplied AND priv
         * import gave us a derived pub, the supplied pub must match.
         * Rejects attacker-supplied or corrupted mismatched keypairs. */
        if (ok && (pubData != NULL) && (privData != NULL)
                && (derivedPub != NULL) && mlkem->hasPub) {
            if ((derivedPubLen != pubLen) ||
                    (XMEMCMP(derivedPub, pubData, pubLen) != 0)) {
                ok = 0;
            }
        }
        if (ok && (pubData != NULL)) {
            rc = wc_MlKemKey_DecodePublicKey(&mlkem->key, pubData,
                (word32)pubLen);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                mlkem->hasPub = 1;
            }
        }
    }
    if (ok && (privData == NULL) && (pubData == NULL)) {
        ok = 0;
    }
    OPENSSL_free(derivedPub);
    return ok;
}

/** ML-KEM key parameters for import/export type queries. */
static const OSSL_PARAM wp_mlkem_key_params[] = {
    /* 0: none */
    OSSL_PARAM_END,

    /* 1: private only */
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END,

    /* 3: public only */
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END,

    /* 5: both */
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END,
};

static const OSSL_PARAM* wp_mlkem_key_types(int selection)
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
    return &wp_mlkem_key_params[idx];
}

static const OSSL_PARAM* wp_mlkem_import_types(int selection)
{
    return wp_mlkem_key_types(selection);
}

static const OSSL_PARAM* wp_mlkem_export_types(int selection)
{
    return wp_mlkem_key_types(selection);
}

/**
 * Export ML-KEM key data via callback.
 *
 * @param [in] mlkem      ML-KEM key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Callback to receive constructed parameters.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_export(wp_MlKem* mlkem, int selection,
    OSSL_CALLBACK* paramCb, void* cbArg)
{
    int ok = 1;
    int rc;
    OSSL_PARAM params[3];
    int paramsSz = 0;
    unsigned char* pubBuf = NULL;
    unsigned char* privBuf = NULL;
    word32 pubLen = 0;
    word32 privLen = 0;
    int expPub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    int expPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    if (!wolfssl_prov_is_running() || (mlkem == NULL)) {
        ok = 0;
    }
    XMEMSET(params, 0, sizeof(params));

    if (ok && expPub && mlkem->hasPub) {
        pubLen = mlkem->data->pubKeySize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePublicKey(&mlkem->key, pubBuf, pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            wp_param_set_octet_string_ptr(&params[paramsSz++],
                OSSL_PKEY_PARAM_PUB_KEY, pubBuf, pubLen);
        }
    }
    if (ok && expPriv && mlkem->hasPriv) {
        privLen = mlkem->data->privKeySize;
        privBuf = (unsigned char*)OPENSSL_malloc(privLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePrivateKey(&mlkem->key, privBuf, privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            wp_param_set_octet_string_ptr(&params[paramsSz++],
                OSSL_PKEY_PARAM_PRIV_KEY, privBuf, privLen);
        }
    }
    if (ok) {
        ok = paramCb(params, cbArg);
    }
    OPENSSL_free(pubBuf);
    OPENSSL_clear_free(privBuf, privLen);
    return ok;
}

/**
 * Gettable parameters for ML-KEM key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of supported gettable parameters.
 */
static const OSSL_PARAM* wp_mlkem_gettable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlkem_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_mlkem_supported_gettable_params;
}

/**
 * Get ML-KEM key parameters.
 *
 * @param [in]      mlkem   ML-KEM key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlkem_get_params(wp_MlKem* mlkem, OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    OSSL_PARAM* p;

    if (mlkem == NULL) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if ((p != NULL) && !OSSL_PARAM_set_int(p, (int)mlkem->data->pubKeySize * 8)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, mlkem->data->securityBits)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, (int)mlkem->data->ctSize)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            word32 outLen = mlkem->data->pubKeySize;
            if (p->data == NULL) {
                p->return_size = outLen;
            }
            else if (mlkem->hasPub) {
                if (p->data_size < outLen) {
                    ok = 0;
                }
                else {
                    rc = wc_MlKemKey_EncodePublicKey(&mlkem->key,
                        (unsigned char*)p->data, outLen);
                    if (rc != 0) {
                        ok = 0;
                    }
                    else {
                        p->return_size = outLen;
                    }
                }
            }
            else {
                /* Buffer supplied but no public key available. */
                p->return_size = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            word32 outLen = mlkem->data->privKeySize;
            if (p->data == NULL) {
                p->return_size = outLen;
            }
            else if (mlkem->hasPriv) {
                if (p->data_size < outLen) {
                    ok = 0;
                }
                else {
                    rc = wc_MlKemKey_EncodePrivateKey(&mlkem->key,
                        (unsigned char*)p->data, outLen);
                    if (rc != 0) {
                        ok = 0;
                    }
                    else {
                        p->return_size = outLen;
                    }
                }
            }
            else {
                /* Buffer supplied but no private key available. */
                p->return_size = 0;
            }
        }
    }
    return ok;
}

/**
 * Settable parameters for ML-KEM key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Empty parameter list.
 */
static const OSSL_PARAM* wp_mlkem_settable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlkem_supported_settable_params[] = {
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_mlkem_supported_settable_params;
}

/**
 * Set ML-KEM key parameters. None supported.
 *
 * @param [in] mlkem   ML-KEM key object. Unused.
 * @param [in] params  Array of parameters. Unused.
 * @return  1 always.
 */
static int wp_mlkem_set_params(wp_MlKem* mlkem, const OSSL_PARAM params[])
{
    (void)mlkem;
    (void)params;
    return 1;
}

/*
 * ML-KEM generation
 */

/**
 * Create ML-KEM generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @param [in] data       Parameter set data.
 * @return  New ML-KEM generation context on success, NULL on failure.
 */
static wp_MlKemGenCtx* wp_mlkem_gen_init_base(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], const wp_MlKemData* data)
{
    wp_MlKemGenCtx* ctx = NULL;

    (void)params;

    if (wolfssl_prov_is_running() &&
            ((selection & WP_MLKEM_POSSIBLE_SELECTIONS) != 0)) {
        ctx = (wp_MlKemGenCtx*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int rc;
        int ok = 1;

        rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            ctx->provCtx   = provCtx;
            ctx->data      = data;
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
 * Generate ML-KEM key pair.
 *
 * @param [in, out] ctx    ML-KEM generation context.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument for callback. Unused.
 * @return  ML-KEM key object on success, NULL on failure.
 */
static wp_MlKem* wp_mlkem_gen(wp_MlKemGenCtx* ctx, OSSL_CALLBACK* osslcb,
    void* cbarg)
{
    wp_MlKem* mlkem;
    int keyPair = (ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;

    (void)osslcb;
    (void)cbarg;

    mlkem = wp_mlkem_new(ctx->provCtx, ctx->data);
    if ((mlkem != NULL) && keyPair) {
        int rc = wc_MlKemKey_MakeKey(&mlkem->key, &ctx->rng);
        if (rc != 0) {
            wp_mlkem_free(mlkem);
            mlkem = NULL;
        }
        else {
            mlkem->hasPub = 1;
            mlkem->hasPriv = 1;
        }
    }
    return mlkem;
}

/**
 * Set parameters into ML-KEM generation context. None supported.
 *
 * @param [in] ctx     Generation context. Unused.
 * @param [in] params  Array of parameters. Unused.
 * @return  1 always.
 */
static int wp_mlkem_gen_set_params(wp_MlKemGenCtx* ctx,
    const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

/**
 * Settable parameters for ML-KEM generation context.
 *
 * @param [in] ctx      Generation context. Unused.
 * @param [in] provCtx  Provider context. Unused.
 * @return  Empty parameter list.
 */
static const OSSL_PARAM* wp_mlkem_gen_settable_params(wp_MlKemGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static OSSL_PARAM wp_mlkem_gen_settable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mlkem_gen_settable;
}

/**
 * Free ML-KEM generation context.
 *
 * @param [in, out] ctx  Generation context.
 */
static void wp_mlkem_gen_cleanup(wp_MlKemGenCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        OPENSSL_free(ctx);
    }
}

/**
 * Return the algorithm name for OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME.
 *
 * ML-KEM has no associated operation name lookup; return NULL so OpenSSL
 * falls back to the algorithm name from the dispatch table.
 *
 * @param [in] op  Operation type. Unused.
 * @return  NULL.
 */
static const char* wp_mlkem_query_operation_name(int op)
{
    (void)op;
    return NULL;
}

/* Per-level new() and gen_init() trampolines. */

static wp_MlKem* wp_mlkem512_new(WOLFPROV_CTX* provCtx)
{
    return wp_mlkem_new(provCtx, &mlkem512Data);
}

static wp_MlKem* wp_mlkem768_new(WOLFPROV_CTX* provCtx)
{
    return wp_mlkem_new(provCtx, &mlkem768Data);
}

static wp_MlKem* wp_mlkem1024_new(WOLFPROV_CTX* provCtx)
{
    return wp_mlkem_new(provCtx, &mlkem1024Data);
}

static wp_MlKemGenCtx* wp_mlkem512_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mlkem_gen_init_base(provCtx, selection, params, &mlkem512Data);
}

static wp_MlKemGenCtx* wp_mlkem768_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mlkem_gen_init_base(provCtx, selection, params, &mlkem768Data);
}

static wp_MlKemGenCtx* wp_mlkem1024_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mlkem_gen_init_base(provCtx, selection, params, &mlkem1024Data);
}

/*
 * Dispatch tables
 */

#define IMPLEMENT_MLKEM_KEYMGMT_DISPATCH(alg)                                  \
const OSSL_DISPATCH wp_##alg##_keymgmt_functions[] = {                         \
    { OSSL_FUNC_KEYMGMT_NEW,                                                   \
        (DFUNC)wp_##alg##_new                                  },              \
    { OSSL_FUNC_KEYMGMT_FREE,           (DFUNC)wp_mlkem_free   },              \
    { OSSL_FUNC_KEYMGMT_DUP,            (DFUNC)wp_mlkem_dup    },              \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,                                              \
        (DFUNC)wp_##alg##_gen_init                             },              \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                        \
        (DFUNC)wp_mlkem_gen_set_params                         },              \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                   \
        (DFUNC)wp_mlkem_gen_settable_params                    },              \
    { OSSL_FUNC_KEYMGMT_GEN,            (DFUNC)wp_mlkem_gen    },              \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                           \
        (DFUNC)wp_mlkem_gen_cleanup                            },              \
    { OSSL_FUNC_KEYMGMT_LOAD,           (DFUNC)wp_mlkem_load   },              \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                            \
        (DFUNC)wp_mlkem_get_params                             },              \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                       \
        (DFUNC)wp_mlkem_gettable_params                        },              \
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                            \
        (DFUNC)wp_mlkem_set_params                             },              \
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                       \
        (DFUNC)wp_mlkem_settable_params                        },              \
    { OSSL_FUNC_KEYMGMT_HAS,            (DFUNC)wp_mlkem_has    },              \
    { OSSL_FUNC_KEYMGMT_MATCH,          (DFUNC)wp_mlkem_match  },              \
    { OSSL_FUNC_KEYMGMT_IMPORT,         (DFUNC)wp_mlkem_import },              \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                          \
        (DFUNC)wp_mlkem_import_types                           },              \
    { OSSL_FUNC_KEYMGMT_EXPORT,         (DFUNC)wp_mlkem_export },              \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                          \
        (DFUNC)wp_mlkem_export_types                           },              \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                  \
        (DFUNC)wp_mlkem_query_operation_name                   },              \
    { 0, NULL }                                                                \
};

IMPLEMENT_MLKEM_KEYMGMT_DISPATCH(mlkem512)
IMPLEMENT_MLKEM_KEYMGMT_DISPATCH(mlkem768)
IMPLEMENT_MLKEM_KEYMGMT_DISPATCH(mlkem1024)

#endif /* WP_HAVE_MLKEM */
