/* wp_mldsa_kmgmt.c
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

#ifdef WP_HAVE_MLDSA

#include <wolfssl/wolfcrypt/dilithium.h>

/** Supported selections (key parts) in this key manager for ML-DSA. */
#define WP_MLDSA_POSSIBLE_SELECTIONS                                           \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/**
 * ML-DSA parameter set data.
 */
typedef struct wp_MlDsaData {
    /** Level byte passed to wc_MlDsaKey_SetParams (2/3/5). */
    byte level;
    /** Public key size in bytes. */
    word32 pubKeySize;
    /** Private key size in bytes (raw, excludes embedded pub). */
    word32 privKeySize;
    /** Signature size in bytes. */
    word32 sigSize;
    /** Security bits. */
    int securityBits;
    /** Algorithm name string. */
    const char* name;
} wp_MlDsaData;

/**
 * ML-DSA key object.
 */
struct wp_MlDsa {
    /** wolfSSL ML-DSA key. */
    MlDsaKey key;
    /** Parameter set data. */
    const wp_MlDsaData* data;

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

typedef struct wp_MlDsa wp_MlDsa;

/**
 * ML-DSA key generation context.
 */
typedef struct wp_MlDsaGenCtx {
    /** wolfSSL random number generator. */
    WC_RNG rng;
    /** Parameter set data. */
    const wp_MlDsaData* data;
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to generate. */
    int selection;
} wp_MlDsaGenCtx;


/* Parameter set tables. */
static const wp_MlDsaData mldsa44Data = {
    WC_ML_DSA_44,
    ML_DSA_LEVEL2_PUB_KEY_SIZE,
    ML_DSA_LEVEL2_KEY_SIZE,
    ML_DSA_LEVEL2_SIG_SIZE,
    128,
    "ML-DSA-44"
};

static const wp_MlDsaData mldsa65Data = {
    WC_ML_DSA_65,
    ML_DSA_LEVEL3_PUB_KEY_SIZE,
    ML_DSA_LEVEL3_KEY_SIZE,
    ML_DSA_LEVEL3_SIG_SIZE,
    192,
    "ML-DSA-65"
};

static const wp_MlDsaData mldsa87Data = {
    WC_ML_DSA_87,
    ML_DSA_LEVEL5_PUB_KEY_SIZE,
    ML_DSA_LEVEL5_KEY_SIZE,
    ML_DSA_LEVEL5_SIG_SIZE,
    256,
    "ML-DSA-87"
};


/**
 * Increment reference count for key.
 *
 * @param [in, out] mldsa  ML-DSA key object.
 * @return  1 on success, 0 on failure.
 */
int wp_mldsa_up_ref(wp_MlDsa* mldsa)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&mldsa->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        mldsa->refCnt++;
        wc_UnLockMutex(&mldsa->mutex);
    }
    return ok;
#else
    mldsa->refCnt++;
    return 1;
#endif
}

/**
 * Get the wolfSSL ML-DSA key from the wp_MlDsa object.
 *
 * @param [in] mldsa  ML-DSA key object.
 * @return  Pointer to wolfSSL MlDsaKey, returned as void*.
 */
void* wp_mldsa_get_key(wp_MlDsa* mldsa)
{
    return &mldsa->key;
}

/**
 * Get the ML-DSA level (2/3/5) for the key.
 *
 * @param [in] mldsa  ML-DSA key object.
 * @return  Level value, or 0 if mldsa is NULL.
 */
int wp_mldsa_get_level(const wp_MlDsa* mldsa)
{
    if (mldsa == NULL) {
        return 0;
    }
    return mldsa->data->level;
}

/**
 * Get the maximum signature size for the key.
 *
 * @param [in] mldsa  ML-DSA key object.
 * @return  Signature size in bytes, or 0 if mldsa is NULL.
 */
int wp_mldsa_get_sig_size(const wp_MlDsa* mldsa)
{
    if (mldsa == NULL) {
        return 0;
    }
    return (int)mldsa->data->sigSize;
}

/**
 * Create a new ML-DSA key object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] data     Parameter set data.
 * @return  New ML-DSA key object on success, NULL on failure.
 */
static wp_MlDsa* wp_mldsa_new(WOLFPROV_CTX* provCtx, const wp_MlDsaData* data)
{
    wp_MlDsa* mldsa = NULL;

    if (wolfssl_prov_is_running()) {
        mldsa = (wp_MlDsa*)OPENSSL_zalloc(sizeof(*mldsa));
    }
    if (mldsa != NULL) {
        int ok = 1;
        int rc;

        rc = wc_dilithium_init_ex(&mldsa->key, NULL, INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wc_dilithium_set_level(&mldsa->key, data->level);
            if (rc != 0) {
                wc_dilithium_free(&mldsa->key);
                ok = 0;
            }
        }
    #ifndef WP_SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&mldsa->mutex);
            if (rc != 0) {
                wc_dilithium_free(&mldsa->key);
                ok = 0;
            }
        }
    #endif
        if (ok) {
            mldsa->provCtx = provCtx;
            mldsa->refCnt  = 1;
            mldsa->data    = data;
        }
        if (!ok) {
            OPENSSL_free(mldsa);
            mldsa = NULL;
        }
    }
    return mldsa;
}

/**
 * Dispose of ML-DSA key object.
 *
 * @param [in, out] mldsa  ML-DSA key object. May be NULL.
 */
void wp_mldsa_free(wp_MlDsa* mldsa)
{
    if (mldsa != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&mldsa->mutex);
        cnt = --mldsa->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&mldsa->mutex);
        }
    #else
        cnt = --mldsa->refCnt;
    #endif

        if (cnt == 0) {
        #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&mldsa->mutex);
        #endif
            wc_dilithium_free(&mldsa->key);
            OPENSSL_free(mldsa);
        }
    }
}

/**
 * Duplicate ML-DSA key object via raw export/import.
 *
 * @param [in] src        Source ML-DSA key object.
 * @param [in] selection  Parts of key to include. Unused; always full dup.
 * @return  New ML-DSA key object on success, NULL on failure.
 */
static wp_MlDsa* wp_mldsa_dup(const wp_MlDsa* src, int selection)
{
    wp_MlDsa* dst = NULL;
    unsigned char* pubBuf = NULL;
    unsigned char* privBuf = NULL;
    word32 pubLen;
    word32 privLen;
    int rc;
    int ok = 1;

    (void)selection;

    if (!wolfssl_prov_is_running() || (src == NULL)) {
        return NULL;
    }

    dst = wp_mldsa_new(src->provCtx, src->data);
    if (dst == NULL) {
        return NULL;
    }

    if (src->hasPub) {
        pubLen = src->data->pubKeySize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_dilithium_export_public((MlDsaKey*)&src->key, pubBuf,
                &pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_dilithium_import_public(pubBuf, pubLen, &dst->key);
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

    if (ok && src->hasPriv) {
        privLen = src->data->privKeySize;
        privBuf = (unsigned char*)OPENSSL_malloc(privLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_dilithium_export_private((MlDsaKey*)&src->key, privBuf,
                &privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_dilithium_import_private(privBuf, privLen, &dst->key);
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
        wp_mldsa_free(dst);
        return NULL;
    }
    return dst;
}

/**
 * Load an ML-DSA key from a reference.
 *
 * @param [in, out] pMlDsa  Pointer to an ML-DSA key reference.
 * @param [in]      size    Size of reference object. Unused.
 * @return  ML-DSA key object on success.
 */
static const wp_MlDsa* wp_mldsa_load(const wp_MlDsa** pMlDsa, size_t size)
{
    const wp_MlDsa* mldsa = *pMlDsa;
    (void)size;
    *pMlDsa = NULL;
    return mldsa;
}

/**
 * Check ML-DSA key object has the components required.
 *
 * @param [in] mldsa      ML-DSA key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_has(const wp_MlDsa* mldsa, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (mldsa == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok &= mldsa->hasPub;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= mldsa->hasPriv;
    }
    return ok;
}

/**
 * Compare two ML-DSA keys.
 *
 * @param [in] a          First ML-DSA key.
 * @param [in] b          Second ML-DSA key.
 * @param [in] selection  Parts of key to compare.
 * @return  1 if match, 0 otherwise.
 */
static int wp_mldsa_match(const wp_MlDsa* a, const wp_MlDsa* b, int selection)
{
    int ok = 1;
    int rc;
    unsigned char* bufA = NULL;
    unsigned char* bufB = NULL;
    word32 lenA;
    word32 lenB;

    if (!wolfssl_prov_is_running() || (a == NULL) || (b == NULL)) {
        return 0;
    }
    if (a->data->level != b->data->level) {
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
            rc = wc_dilithium_export_public((MlDsaKey*)&a->key, bufA, &lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_dilithium_export_public((MlDsaKey*)&b->key, bufB, &lenB);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok && ((lenA != lenB) || (XMEMCMP(bufA, bufB, lenA) != 0))) {
            ok = 0;
        }
        OPENSSL_free(bufA);
        OPENSSL_free(bufB);
    }
    return ok;
}

/**
 * Import an ML-DSA key from parameters.
 *
 * @param [in, out] mldsa      ML-DSA key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_import(wp_MlDsa* mldsa, int selection,
    const OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    unsigned char* privData = NULL;
    unsigned char* pubData = NULL;
    size_t privLen = 0;
    size_t pubLen = 0;

    if (!wolfssl_prov_is_running() || (mldsa == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_MLDSA_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PRIV_KEY,
                &privData, &privLen)) {
            ok = 0;
        }
        if (ok && (privData != NULL)) {
            rc = wc_dilithium_import_private(privData, (word32)privLen,
                &mldsa->key);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                mldsa->hasPriv = 1;
            }
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PUB_KEY,
                &pubData, &pubLen)) {
            ok = 0;
        }
        if (ok && (pubData != NULL)) {
            rc = wc_dilithium_import_public(pubData, (word32)pubLen,
                &mldsa->key);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                mldsa->hasPub = 1;
            }
        }
    }
    if (ok && (privData == NULL) && (pubData == NULL)) {
        ok = 0;
    }
    return ok;
}

/** ML-DSA key parameters for import/export type queries. */
static const OSSL_PARAM wp_mldsa_key_params[] = {
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

static const OSSL_PARAM* wp_mldsa_key_types(int selection)
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
    return &wp_mldsa_key_params[idx];
}

static const OSSL_PARAM* wp_mldsa_import_types(int selection)
{
    return wp_mldsa_key_types(selection);
}

static const OSSL_PARAM* wp_mldsa_export_types(int selection)
{
    return wp_mldsa_key_types(selection);
}

/**
 * Export ML-DSA key data via callback.
 *
 * @param [in] mldsa      ML-DSA key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Callback to receive constructed parameters.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_export(wp_MlDsa* mldsa, int selection,
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

    if (!wolfssl_prov_is_running() || (mldsa == NULL)) {
        ok = 0;
    }
    XMEMSET(params, 0, sizeof(params));

    if (ok && expPub && mldsa->hasPub) {
        pubLen = mldsa->data->pubKeySize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_dilithium_export_public(&mldsa->key, pubBuf, &pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            wp_param_set_octet_string_ptr(&params[paramsSz++],
                OSSL_PKEY_PARAM_PUB_KEY, pubBuf, pubLen);
        }
    }
    if (ok && expPriv && mldsa->hasPriv) {
        privLen = mldsa->data->privKeySize;
        privBuf = (unsigned char*)OPENSSL_malloc(privLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_dilithium_export_private(&mldsa->key, privBuf, &privLen);
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
 * Gettable parameters for ML-DSA key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of supported gettable parameters.
 */
static const OSSL_PARAM* wp_mldsa_gettable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_mldsa_supported_gettable_params;
}

/**
 * Get ML-DSA key parameters.
 *
 * @param [in]      mldsa   ML-DSA key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_get_params(wp_MlDsa* mldsa, OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if ((p != NULL) &&
            !OSSL_PARAM_set_int(p, (int)mldsa->data->pubKeySize * 8)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, mldsa->data->securityBits)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, (int)mldsa->data->sigSize)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            word32 outLen = mldsa->data->pubKeySize;
            if (p->data == NULL) {
                p->return_size = outLen;
            }
            else if (mldsa->hasPub) {
                rc = wc_dilithium_export_public(&mldsa->key,
                    (unsigned char*)p->data, &outLen);
                if (rc != 0) {
                    ok = 0;
                }
                else {
                    p->return_size = outLen;
                }
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            word32 outLen = mldsa->data->privKeySize;
            if (p->data == NULL) {
                p->return_size = outLen;
            }
            else if (mldsa->hasPriv) {
                rc = wc_dilithium_export_private(&mldsa->key,
                    (unsigned char*)p->data, &outLen);
                if (rc != 0) {
                    ok = 0;
                }
                else {
                    p->return_size = outLen;
                }
            }
        }
    }
    return ok;
}

/**
 * Settable parameters for ML-DSA key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Empty parameter list.
 */
static const OSSL_PARAM* wp_mldsa_settable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_supported_settable_params[] = {
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_mldsa_supported_settable_params;
}

/**
 * Set ML-DSA key parameters. None supported.
 *
 * @param [in] mldsa   ML-DSA key object. Unused.
 * @param [in] params  Array of parameters. Unused.
 * @return  1 always.
 */
static int wp_mldsa_set_params(wp_MlDsa* mldsa, const OSSL_PARAM params[])
{
    (void)mldsa;
    (void)params;
    return 1;
}

/*
 * ML-DSA generation
 */

/**
 * Create ML-DSA generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @param [in] data       Parameter set data.
 * @return  New ML-DSA generation context on success, NULL on failure.
 */
static wp_MlDsaGenCtx* wp_mldsa_gen_init_base(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], const wp_MlDsaData* data)
{
    wp_MlDsaGenCtx* ctx = NULL;

    (void)params;

    if (wolfssl_prov_is_running() &&
            ((selection & WP_MLDSA_POSSIBLE_SELECTIONS) != 0)) {
        ctx = (wp_MlDsaGenCtx*)OPENSSL_zalloc(sizeof(*ctx));
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
 * Generate ML-DSA key pair.
 *
 * @param [in, out] ctx    ML-DSA generation context.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument for callback. Unused.
 * @return  ML-DSA key object on success, NULL on failure.
 */
static wp_MlDsa* wp_mldsa_gen(wp_MlDsaGenCtx* ctx, OSSL_CALLBACK* osslcb,
    void* cbarg)
{
    wp_MlDsa* mldsa;
    int keyPair = (ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;

    (void)osslcb;
    (void)cbarg;

    mldsa = wp_mldsa_new(ctx->provCtx, ctx->data);
    if ((mldsa != NULL) && keyPair) {
        int rc = wc_dilithium_make_key(&mldsa->key, &ctx->rng);
        if (rc != 0) {
            wp_mldsa_free(mldsa);
            mldsa = NULL;
        }
        else {
            mldsa->hasPub = 1;
            mldsa->hasPriv = 1;
        }
    }
    return mldsa;
}

/**
 * Set parameters into ML-DSA generation context. None supported.
 *
 * @param [in] ctx     Generation context. Unused.
 * @param [in] params  Array of parameters. Unused.
 * @return  1 always.
 */
static int wp_mldsa_gen_set_params(wp_MlDsaGenCtx* ctx,
    const OSSL_PARAM params[])
{
    (void)ctx;
    (void)params;
    return 1;
}

/**
 * Settable parameters for ML-DSA generation context.
 *
 * @param [in] ctx      Generation context. Unused.
 * @param [in] provCtx  Provider context. Unused.
 * @return  Empty parameter list.
 */
static const OSSL_PARAM* wp_mldsa_gen_settable_params(wp_MlDsaGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static OSSL_PARAM wp_mldsa_gen_settable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mldsa_gen_settable;
}

/**
 * Free ML-DSA generation context.
 *
 * @param [in, out] ctx  Generation context.
 */
static void wp_mldsa_gen_cleanup(wp_MlDsaGenCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        OPENSSL_free(ctx);
    }
}

/* Per-level new() and gen_init() trampolines. */

static wp_MlDsa* wp_mldsa44_new(WOLFPROV_CTX* provCtx)
{
    return wp_mldsa_new(provCtx, &mldsa44Data);
}

static wp_MlDsa* wp_mldsa65_new(WOLFPROV_CTX* provCtx)
{
    return wp_mldsa_new(provCtx, &mldsa65Data);
}

static wp_MlDsa* wp_mldsa87_new(WOLFPROV_CTX* provCtx)
{
    return wp_mldsa_new(provCtx, &mldsa87Data);
}

static const char* wp_mldsa44_query_operation_name(int op)
{
    (void)op;
    return "ML-DSA-44";
}

static const char* wp_mldsa65_query_operation_name(int op)
{
    (void)op;
    return "ML-DSA-65";
}

static const char* wp_mldsa87_query_operation_name(int op)
{
    (void)op;
    return "ML-DSA-87";
}

static wp_MlDsaGenCtx* wp_mldsa44_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mldsa_gen_init_base(provCtx, selection, params, &mldsa44Data);
}

static wp_MlDsaGenCtx* wp_mldsa65_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mldsa_gen_init_base(provCtx, selection, params, &mldsa65Data);
}

static wp_MlDsaGenCtx* wp_mldsa87_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mldsa_gen_init_base(provCtx, selection, params, &mldsa87Data);
}

/*
 * Dispatch tables
 */

#define IMPLEMENT_MLDSA_KEYMGMT_DISPATCH(alg)                                  \
const OSSL_DISPATCH wp_##alg##_keymgmt_functions[] = {                         \
    { OSSL_FUNC_KEYMGMT_NEW,                                                   \
        (DFUNC)wp_##alg##_new                                  },              \
    { OSSL_FUNC_KEYMGMT_FREE,           (DFUNC)wp_mldsa_free   },              \
    { OSSL_FUNC_KEYMGMT_DUP,            (DFUNC)wp_mldsa_dup    },              \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,                                              \
        (DFUNC)wp_##alg##_gen_init                             },              \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                        \
        (DFUNC)wp_mldsa_gen_set_params                         },              \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                   \
        (DFUNC)wp_mldsa_gen_settable_params                    },              \
    { OSSL_FUNC_KEYMGMT_GEN,            (DFUNC)wp_mldsa_gen    },              \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                           \
        (DFUNC)wp_mldsa_gen_cleanup                            },              \
    { OSSL_FUNC_KEYMGMT_LOAD,           (DFUNC)wp_mldsa_load   },              \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                            \
        (DFUNC)wp_mldsa_get_params                             },              \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                       \
        (DFUNC)wp_mldsa_gettable_params                        },              \
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                            \
        (DFUNC)wp_mldsa_set_params                             },              \
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                       \
        (DFUNC)wp_mldsa_settable_params                        },              \
    { OSSL_FUNC_KEYMGMT_HAS,            (DFUNC)wp_mldsa_has    },              \
    { OSSL_FUNC_KEYMGMT_MATCH,          (DFUNC)wp_mldsa_match  },              \
    { OSSL_FUNC_KEYMGMT_IMPORT,         (DFUNC)wp_mldsa_import },              \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                          \
        (DFUNC)wp_mldsa_import_types                           },              \
    { OSSL_FUNC_KEYMGMT_EXPORT,         (DFUNC)wp_mldsa_export },              \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                          \
        (DFUNC)wp_mldsa_export_types                           },              \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                  \
        (DFUNC)wp_##alg##_query_operation_name                 },              \
    { 0, NULL }                                                                \
};

IMPLEMENT_MLDSA_KEYMGMT_DISPATCH(mldsa44)
IMPLEMENT_MLDSA_KEYMGMT_DISPATCH(mldsa65)
IMPLEMENT_MLDSA_KEYMGMT_DISPATCH(mldsa87)

#endif /* WP_HAVE_MLDSA */
