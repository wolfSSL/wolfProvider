/* wp_mldsa_kmgmt.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/wc_mldsa.h>

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
    wc_MlDsaKey key;
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
/* FIPS 204 keygen seed (xi), in bytes. */
#define WP_MLDSA_SEED_SZ 32

typedef struct wp_MlDsaGenCtx {
    /** wolfSSL random number generator. */
    WC_RNG rng;
    /** Parameter set data. */
    const wp_MlDsaData* data;
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to generate. */
    int selection;
    /** Deterministic keygen seed (xi); empty = use RNG. */
    unsigned char seed[WP_MLDSA_SEED_SZ];
    /** Length of seed (0 = not set). */
    size_t seedLen;
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

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_up_ref");

    rc = wc_LockMutex(&mldsa->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        mldsa->refCnt++;
        wc_UnLockMutex(&mldsa->mutex);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_up_ref");
    mldsa->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the wolfSSL ML-DSA key from the wp_MlDsa object.
 *
 * @param [in] mldsa  ML-DSA key object.
 * @return  Pointer to wolfSSL wc_MlDsaKey, returned as void*.
 */
void* wp_mldsa_get_key(wp_MlDsa* mldsa)
{
    return &mldsa->key;
}

/**
 * Get the ML-DSA parameter level (WC_ML_DSA_44/65/87) for the key.
 *
 * @param [in] mldsa  ML-DSA key object.
 * @return  Level value, or 0 when not available.
 */
int wp_mldsa_get_level(wp_MlDsa* mldsa)
{
    int level = 0;

    if ((mldsa != NULL) && (mldsa->data != NULL)) {
        level = mldsa->data->level;
    }
    return level;
}

/**
 * Get the maximum signature size for the key.
 *
 * @param [in] mldsa  ML-DSA key object.
 * @return  Signature size in bytes, or 0 if mldsa is NULL.
 */
int wp_mldsa_get_sig_size(const wp_MlDsa* mldsa)
{
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_get_sig_size");
    if (mldsa == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), (int)mldsa->data->sigSize);
    return (int)mldsa->data->sigSize;
}

/**
 * Report whether the key has a usable private component.
 *
 * @param [in] mldsa  ML-DSA key.
 * @return  1 if a private key is present, 0 otherwise.
 */
int wp_mldsa_has_private(const wp_MlDsa* mldsa)
{
    return (mldsa != NULL) && (mldsa->hasPriv != 0);
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

        rc = wc_MlDsaKey_Init(&mldsa->key, NULL, INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlDsaKey_SetParams(&mldsa->key, data->level);
            if (rc != 0) {
                wc_MlDsaKey_Free(&mldsa->key);
                ok = 0;
            }
        }
    #ifndef WP_SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&mldsa->mutex);
            if (rc != 0) {
                wc_MlDsaKey_Free(&mldsa->key);
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
        if (rc == 0) {
            cnt = --mldsa->refCnt;
            wc_UnLockMutex(&mldsa->mutex);
        }
        else {
            /* Cannot safely decrement without the lock; keep the object. */
            cnt = mldsa->refCnt;
        }
    #else
        cnt = --mldsa->refCnt;
    #endif

        if (cnt == 0) {
        #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&mldsa->mutex);
        #endif
            wc_MlDsaKey_Free(&mldsa->key);
            OPENSSL_free(mldsa);
        }
    }
}

/**
 * Duplicate ML-DSA key object via raw export/import.
 *
 * @param [in] src        Source ML-DSA key object.
 * @param [in] selection  Parts of key (public/private) to duplicate.
 * @return  New ML-DSA key object on success, NULL on failure.
 */
static wp_MlDsa* wp_mldsa_dup(const wp_MlDsa* src, int selection)
{
    wp_MlDsa* dst = NULL;
    unsigned char* pubBuf = NULL;
    unsigned char* privBuf = NULL;
    word32 pubLen;
    word32 privLen;
    word32 privAllocLen = 0;
    int rc;
    int ok = 1;
    int dupPub;
    int dupPriv;

    if (!wolfssl_prov_is_running() || (src == NULL)) {
        return NULL;
    }
    dupPub = ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) && src->hasPub;
    dupPriv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
              && src->hasPriv;

    dst = wp_mldsa_new(src->provCtx, src->data);
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
            rc = wc_MlDsaKey_ExportPubRaw((wc_MlDsaKey*)&src->key, pubBuf,
                &pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlDsaKey_ImportPubRaw(&dst->key, pubBuf, pubLen);
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
        privAllocLen = src->data->privKeySize;
        privLen = privAllocLen;
        privBuf = (unsigned char*)OPENSSL_malloc(privAllocLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlDsaKey_ExportPrivRaw((wc_MlDsaKey*)&src->key, privBuf,
                &privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlDsaKey_ImportPrivRaw(&dst->key, privBuf, privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            dst->hasPriv = 1;
        }
        /* Zero the full allocation, not just the (possibly-truncated) out len. */
        OPENSSL_clear_free(privBuf, privAllocLen);
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

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_has");

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
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    word32 allocA = 0;
    word32 allocB = 0;
    int checked = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_match");

    if (!wolfssl_prov_is_running() || (a == NULL) || (b == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (a->data->level != b->data->level) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    /* Presence mismatch fails; both-present compares; neither-present skips. */
    if (((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) &&
            (a->hasPub != b->hasPub)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) &&
            a->hasPub && b->hasPub) {
        checked = 1;
        lenA = a->data->pubKeySize;
        lenB = b->data->pubKeySize;
        bufA = (unsigned char*)OPENSSL_malloc(lenA);
        bufB = (unsigned char*)OPENSSL_malloc(lenB);
        if ((bufA == NULL) || (bufB == NULL)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlDsaKey_ExportPubRaw((wc_MlDsaKey*)&a->key, bufA, &lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlDsaKey_ExportPubRaw((wc_MlDsaKey*)&b->key, bufB, &lenB);
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
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
            (a->hasPriv != b->hasPriv)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
            a->hasPriv && b->hasPriv) {
        checked = 1;
        allocA = a->data->privKeySize;
        allocB = b->data->privKeySize;
        lenA = allocA;
        lenB = allocB;
        bufA = (unsigned char*)OPENSSL_malloc(allocA);
        bufB = (unsigned char*)OPENSSL_malloc(allocB);
        if ((bufA == NULL) || (bufB == NULL)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlDsaKey_ExportPrivRaw((wc_MlDsaKey*)&a->key, bufA, &lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlDsaKey_ExportPrivRaw((wc_MlDsaKey*)&b->key, bufB, &lenB);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok && ((lenA != lenB) || (CRYPTO_memcmp(bufA, bufB, lenA) != 0))) {
            ok = 0;
        }
        /* Zero full allocations even if export truncated the out lengths. */
        OPENSSL_clear_free(bufA, allocA);
        OPENSSL_clear_free(bufB, allocB);
    }
    /* A public/private selection with no component present in both is not a match. */
    if (ok && !checked &&
            ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                           OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) != 0)) {
        ok = 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_import");

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
        /* FIPS 204 priv keys are fixed-size; equality check before word32 cast
         * also catches truncation on 64-bit platforms. */
        if (ok && (privData != NULL) && (privLen != mldsa->data->privKeySize)) {
            ok = 0;
        }
        if (ok && (privData != NULL)) {
            rc = wc_MlDsaKey_ImportPrivRaw(&mldsa->key, privData,
                (word32)privLen);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                /* A FIPS 204 raw private key does not yield the public key:
                 * wc_MlDsaKey_ExportPubRaw fails unless a public was imported
                 * (wc_mldsa.c). The public comes only from an explicit import
                 * below, so advertise private only here. */
                mldsa->hasPriv = 1;
            }
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PUB_KEY,
                &pubData, &pubLen)) {
            ok = 0;
        }
        if (ok && (pubData != NULL) && (pubLen != mldsa->data->pubKeySize)) {
            ok = 0;
        }
        if (ok && (pubData != NULL)) {
            rc = wc_MlDsaKey_ImportPubRaw(&mldsa->key, pubData,
                (word32)pubLen);
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
#ifdef WOLFSSL_MLDSA_CHECK_KEY
    /* Validate the imported private key when the public component is
     * available: catches mismatched pub/priv and out-of-range s1/s2
     * coefficients that ImportPrivRaw alone accepts. */
    if (ok && (privData != NULL) && mldsa->hasPub) {
        if (wc_MlDsaKey_CheckKey(&mldsa->key) != 0) {
            ok = 0;
        }
    }
#endif
    if (!ok) {
        /* Clear flags on failure so partial-init state is not advertised. */
        mldsa->hasPriv = 0;
        mldsa->hasPub = 0;
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    word32 privAllocLen = 0;
    int expPub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    int expPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_export");

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
            rc = wc_MlDsaKey_ExportPubRaw(&mldsa->key, pubBuf, &pubLen);
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
        privAllocLen = mldsa->data->privKeySize;
        privLen = privAllocLen;
        privBuf = (unsigned char*)OPENSSL_malloc(privAllocLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlDsaKey_ExportPrivRaw(&mldsa->key, privBuf, &privLen);
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
    /* Zero full allocation in case ExportPrivRaw truncated privLen. */
    OPENSSL_clear_free(privBuf, privAllocLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY, NULL),
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

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_get_params");

    if (mldsa == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }

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
        /* NIST security category equals the ML-DSA level (2, 3 or 5). */
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, (int)mldsa->data->level)) {
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
            if (!mldsa->hasPub) {
                ok = 0;
            }
            else if (p->data == NULL) {
                /* Size query. */
                p->return_size = outLen;
            }
            else if (p->data_size < outLen) {
                /* Buffer too small: report required size and fail so the
                 * caller can retry; do not claim a completed export. */
                p->return_size = outLen;
                ok = 0;
            }
            else {
                outLen = (word32)p->data_size;
                rc = wc_MlDsaKey_ExportPubRaw(&mldsa->key,
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
            if (!mldsa->hasPriv) {
                ok = 0;
            }
            else if (p->data == NULL) {
                p->return_size = outLen;
            }
            else if (p->data_size < outLen) {
                p->return_size = outLen;
                ok = 0;
            }
            else {
                outLen = (word32)p->data_size;
                rc = wc_MlDsaKey_ExportPrivRaw(&mldsa->key,
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
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
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
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_set_params");
    (void)mldsa;
    (void)params;
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
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
static int wp_mldsa_gen_set_params(wp_MlDsaGenCtx* ctx,
    const OSSL_PARAM params[]);

static wp_MlDsaGenCtx* wp_mldsa_gen_init_base(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], const wp_MlDsaData* data)
{
    wp_MlDsaGenCtx* ctx = NULL;

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
            /* Apply init-time params (e.g. the deterministic keygen seed) so
             * the seed and its length validation are honored at init, not
             * only via a later gen_set_params call. */
            if (!wp_mldsa_gen_set_params(ctx, params)) {
                ok = 0;
            }
        }
        if (!ok) {
            wc_FreeRng(&ctx->rng);
            OPENSSL_clear_free(ctx, sizeof(*ctx));
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
        int rc;
        /* Deterministic keygen from a supplied seed (xi), else RNG. */
        if (ctx->seedLen == WP_MLDSA_SEED_SZ) {
            rc = wc_MlDsaKey_MakeKeyFromSeed(&mldsa->key, ctx->seed);
        }
        else {
            rc = wc_MlDsaKey_MakeKey(&mldsa->key, &ctx->rng);
        }
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
 * Set parameters into ML-DSA generation context.
 *
 * @param [in] ctx     Generation context.
 * @param [in] params  Array of parameters (ML-DSA keygen seed).
 * @return  1 on success, 0 on failure.
 */
static int wp_mldsa_gen_set_params(wp_MlDsaGenCtx* ctx,
    const OSSL_PARAM params[])
{
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_gen_set_params");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (params == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
    if (p != NULL) {
        void* vp = ctx->seed;
        ctx->seedLen = 0;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->seed),
                &ctx->seedLen)) {
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
        /* A seed shorter than the required size would silently fall back to
         * RNG keygen, breaking the caller's reproducibility contract. Reject
         * any length other than the exact FIPS 204 seed size. */
        if (ctx->seedLen != WP_MLDSA_SEED_SZ) {
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
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
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
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
        /* ctx holds the deterministic keygen seed (FIPS 204 xi); cleanse it. */
        OPENSSL_clear_free(ctx, sizeof(*ctx));
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

/*
 * ML-DSA encoder/decoder
 */

/* Extra slack added to the queried DER length before allocating. */
#define WP_MLDSA_DER_SLACK 32

/** Type for function that decodes a key into a wolfSSL key. */
typedef int (*WP_MLDSA_DECODE)(const byte* input, word32* inOutIdx, void* key,
    word32 inSz);
/** Type for function that encodes a key from a wolfSSL key. */
typedef int (*WP_MLDSA_ENCODE)(void* key, byte* output, word32 inLen);

/** Function to create an ML-DSA key object preset to a level. */
typedef wp_MlDsa* (*WP_MLDSA_NEW)(WOLFPROV_CTX* provCtx);

/**
 * Encode/decode ML-DSA public/private key.
 */
typedef struct wp_MlDsaEncDecCtx {
    /** wolfSSL function to decode ML-DSA key from DER. */
    WP_MLDSA_DECODE decode;
    /** wolfSSL function to encode ML-DSA key to DER. */
    WP_MLDSA_ENCODE encode;
    /** Function to create the level-specific ML-DSA key object. */
    WP_MLDSA_NEW newKey;

    /** Provider context - used when creating ML-DSA key. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to export. */
    int selection;

    /** Data type name passed to the data callback. */
    const char* dataType;
    /** Supported format. */
    int format;
    /** Data format. */
    int encoding;

    /** Cipher to use when encoding EncryptedPrivateKeyInfo. */
    int cipher;
    /** Name of cipher to use when encoding EncryptedPrivateKeyInfo. */
    const char* cipherName;
} wp_MlDsaEncDecCtx;

/**
 * Create a new ML-DSA encoder/decoder context.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] newKey    Function to create level-specific ML-DSA key.
 * @param [in] dataType  Data type name passed to data callback.
 * @param [in] format    Supported key format.
 * @param [in] encoding  Data format.
 * @param [in] decode    Function to decode DER data to a key.
 * @param [in] encode    Function to encode key to DER data.
 * @return  New ML-DSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_MlDsaEncDecCtx* wp_mldsa_enc_dec_new(WOLFPROV_CTX* provCtx,
    WP_MLDSA_NEW newKey, const char* dataType, int format, int encoding,
    WP_MLDSA_DECODE decode, WP_MLDSA_ENCODE encode)
{
    wp_MlDsaEncDecCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_MlDsaEncDecCtx*)OPENSSL_zalloc(sizeof(wp_MlDsaEncDecCtx));
    }
    if (ctx != NULL) {
        ctx->decode   = decode;
        ctx->encode   = encode;
        ctx->newKey   = newKey;
        ctx->provCtx  = provCtx;
        ctx->dataType = dataType;
        ctx->format   = format;
        ctx->encoding = encoding;
    }
    return ctx;
}

/**
 * Dispose of ML-DSA encoder/decoder context object.
 *
 * @param [in, out] ctx  ML-DSA encoder/decoder context object.
 */
static void wp_mldsa_enc_dec_free(wp_MlDsaEncDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return the settable parameters for the ML-DSA encoder/decoder context.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_mldsa_enc_dec_settable_ctx_params(
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mldsa_enc_dec_supported_settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    (void)provCtx;
    return wp_mldsa_enc_dec_supported_settables;
}

/**
 * Set the ML-DSA encoder/decoder context parameters.
 *
 * @param [in, out] ctx     ML-DSA encoder/decoder context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mldsa_enc_dec_set_ctx_params(wp_MlDsaEncDecCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_enc_dec_set_ctx_params");

    if (!wp_cipher_from_params(params, &ctx->cipher, &ctx->cipherName)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Construct parameters from ML-DSA key and pass off to callback.
 *
 * @param [in] mldsa      ML-DSA key object.
 * @param [in] dataType   Data type name passed to the callback.
 * @param [in] dataCb     Callback to pass ML-DSA key in parameters to.
 * @param [in] dataCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mldsa_dec_send_params(wp_MlDsa* mldsa, const char* dataType,
    OSSL_CALLBACK* dataCb, void* dataCbArg)
{
    int ok = 1;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_dec_send_params");

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char*)dataType, 0);
    /* The address of the key object becomes the octet string pointer. */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &mldsa, sizeof(mldsa));
    params[3] = OSSL_PARAM_construct_end();

    /* Callback to do something with ML-DSA key object. */
    if (!dataCb(params, dataCbArg)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the data in the core BIO.
 *
 * The level of the key is preset on the created key object so decode only
 * succeeds when the DER's algorithm OID matches this decoder's level.
 *
 * @param [in, out] ctx        ML-DSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to read data from.
 * @param [in]      selection  Parts of key to export.
 * @param [in]      dataCb     Callback to pass ML-DSA key in parameters to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mldsa_decode(wp_MlDsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int decoded = 1;
    int rc;
    unsigned char* data = NULL;
    word32 len = 0;
    word32 idx = 0;
    wp_MlDsa* mldsa = NULL;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_decode");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    (void)pwCb;
    (void)pwCbArg;

    if (ok) {
        ctx->selection = selection;
        mldsa = ctx->newKey(ctx->provCtx);
        if (mldsa == NULL) {
            ok = 0;
        }
    }

    if (ok) {
        ok = wp_read_der_bio(ctx->provCtx, cBio, &data, &len);
    }
    if (ok) {
        rc = ctx->decode(data, &idx, (void*)&mldsa->key, len);
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "decode", rc);
            ok = 0;
            decoded = 0;
        }
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        mldsa->hasPub = 1;
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        mldsa->hasPriv = 1;
        /* Advertise the public only if the decoded private actually carried or
         * derived it; a private-only PKCS8 (expanded key, no seed/public) does
         * not, and must not claim a public it cannot export. */
        mldsa->hasPub = mldsa->key.pubKeySet ? 1 : 0;
    }

    OPENSSL_clear_free(data, len);

    if (ok && (!wp_mldsa_dec_send_params(mldsa, ctx->dataType, dataCb,
            dataCbArg))) {
        ok = 0;
    }

    if (!ok) {
        wp_mldsa_free(mldsa);
        if (!decoded) {
            ok = 1;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the ML-DSA key.
 *
 * ML-DSA keys are large so the DER buffer is sized from a query-length call
 * (output == NULL) and then allocated, rather than using a fixed buffer.
 *
 * @param [in]      ctx        ML-DSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      mldsa      ML-DSA key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode. Unused.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mldsa_encode(wp_MlDsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    const wp_MlDsa* mldsa, const OSSL_PARAM* params, int selection,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int rc;
    BIO* out = wp_corebio_get_bio(ctx->provCtx, cBio);
    unsigned char* keyData = NULL;
    size_t keyLen = 0;
    unsigned char* derData = NULL;
    word32 derAllocLen = 0;
    size_t derLen = 0;
    unsigned char* pemData = NULL;
    size_t pemLen = 0;
    int pemType = (ctx->format == WP_ENC_FORMAT_SPKI) ? PUBLICKEY_TYPE :
                                                        PKCS8_PRIVATEKEY_TYPE;
    int private = (ctx->format == WP_ENC_FORMAT_PKI) ||
                  (ctx->format == WP_ENC_FORMAT_EPKI);
    byte* cipherInfo = NULL;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_mldsa_encode");

    (void)params;
    (void)selection;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (out == NULL)) {
        ok = 0;
    }

    if (ok) {
        rc = ctx->encode((void*)&mldsa->key, NULL, 0);
        if (rc <= 0) {
            ok = 0;
        }
        else {
            derAllocLen = (word32)rc;
            /* EPKI encrypts in place: round up to the AES block size so the
             * buffer has room for the padded ciphertext. */
            if (ctx->format == WP_ENC_FORMAT_EPKI) {
                derAllocLen = ((derAllocLen + 15) / 16) * 16;
            }
            else {
                derAllocLen += WP_MLDSA_DER_SLACK;
            }
        }
    }
    if (ok) {
        derData = (unsigned char*)OPENSSL_malloc(derAllocLen);
        if (derData == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        rc = ctx->encode((void*)&mldsa->key, derData, derAllocLen);
        if (rc <= 0) {
            ok = 0;
        }
        else {
            derLen = (size_t)rc;
        }
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        size_t encLen = derAllocLen;
        if (!wp_encrypt_key(ctx->provCtx, ctx->cipherName, derData, &encLen,
                (word32)derLen, pwCb, pwCbArg, &cipherInfo)) {
            ok = 0;
        }
        else {
            derLen = encLen;
        }
    }

    if (ok && (ctx->encoding == WP_FORMAT_DER)) {
        keyData = derData;
        keyLen = derLen;
    }
    else if (ok && (ctx->encoding == WP_FORMAT_PEM)) {
        rc = wc_DerToPemEx(derData, (word32)derLen, NULL, 0, cipherInfo,
            pemType);
        if (rc <= 0) {
            ok = 0;
        }
        if (ok) {
            pemLen = (size_t)rc;
            pemData = (unsigned char*)OPENSSL_malloc(pemLen);
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
            keyLen = pemLen = (size_t)rc;
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
        if (derData != NULL) {
            OPENSSL_clear_free(derData, derAllocLen);
        }
        OPENSSL_clear_free(pemData, pemLen);
    }
    else {
        OPENSSL_free(derData);
        OPENSSL_free(pemData);
    }
    OPENSSL_free(cipherInfo);
    BIO_free(out);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the ML-DSA key object.
 *
 * @param [in] ctx          ML-DSA encoder/decoder context object.
 * @param [in] mldsa        ML-DSA key object.
 * @param [in] size         Size of key object.
 * @param [in] exportCb     Callback to export key.
 * @param [in] exportCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mldsa_export_object(wp_MlDsaEncDecCtx* ctx, wp_MlDsa* mldsa,
    size_t size, OSSL_CALLBACK* exportCb, void* exportCbArg)
{
    (void)size;
    return wp_mldsa_export(mldsa, ctx->selection, exportCb, exportCbArg);
}

/**
 * Return whether the SPKI decoder/encoder handles this part of the key.
 *
 * @param [in] provCtx    Provider context. Unused.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_mldsa_spki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    WOLFPROV_ENTER_SILENT(WP_LOG_COMP_PQC, WOLFPROV_FUNC_NAME);

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    }

    WOLFPROV_LEAVE_SILENT(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return whether the PKI decoder/encoder handles this part of the key.
 *
 * @param [in] provCtx    Provider context. Unused.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_mldsa_pki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    WOLFPROV_ENTER_SILENT(WP_LOG_COMP_PQC, WOLFPROV_FUNC_NAME);

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    }

    WOLFPROV_LEAVE_SILENT(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode a public ML-DSA key from SPKI DER.
 *
 * @param [in]      input     Buffer holding SPKI DER data.
 * @param [in, out] inOutIdx  On in, index into buffer. On out, index after.
 * @param [in, out] key       ML-DSA key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success, negative on error.
 */
static int wp_mldsa_pub_decode(const byte* input, word32* inOutIdx, void* key,
    word32 inSz)
{
    return wc_MlDsaKey_PublicKeyDecode((wc_MlDsaKey*)key, input, inSz, inOutIdx);
}

/**
 * Decode a private ML-DSA key from PKCS8 PrivateKeyInfo DER.
 *
 * @param [in]      input     Buffer holding PKCS8 DER data.
 * @param [in, out] inOutIdx  On in, index into buffer. On out, index after.
 * @param [in, out] key       ML-DSA key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success, negative on error.
 */
static int wp_mldsa_priv_decode(const byte* input, word32* inOutIdx, void* key,
    word32 inSz)
{
    return wc_MlDsaKey_PrivateKeyDecode((wc_MlDsaKey*)key, input, inSz,
        inOutIdx);
}

/**
 * Encode the public part of an ML-DSA key as SubjectPublicKeyInfo DER.
 *
 * Pass NULL for output to query the required length.
 *
 * @param [in]  key     ML-DSA key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  inLen   Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success, negative on error.
 */
static int wp_mldsa_pub_encode(void* key, byte* output, word32 inLen)
{
    return wc_MlDsaKey_PublicKeyToDer((wc_MlDsaKey*)key, output, inLen, 1);
}

/**
 * Encode the private part of an ML-DSA key as PKCS8 PrivateKeyInfo DER.
 *
 * Pass NULL for output to query the required length.
 *
 * @param [in]  key     ML-DSA key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  inLen   Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success, negative on error.
 */
static int wp_mldsa_priv_encode(void* key, byte* output, word32 inLen)
{
    int ret;

    /* Prefer the form that carries the public key so a reloaded key can be
     * used to build a certificate; fall back to the private-only encoding when
     * the public part is not available. */
    ret = wc_MlDsaKey_KeyToDer((wc_MlDsaKey*)key, output, inLen);
    if (ret <= 0) {
        ret = wc_MlDsaKey_PrivateKeyToDer((wc_MlDsaKey*)key, output, inLen);
    }
    return ret;
}

/*
 * Per-level encoder/decoder context constructors and dispatch tables.
 */

#define IMPLEMENT_MLDSA_DECODER(alg, dataType)                                 \
static wp_MlDsaEncDecCtx* wp_##alg##_spki_dec_new(WOLFPROV_CTX* provCtx)        \
{                                                                              \
    return wp_mldsa_enc_dec_new(provCtx, wp_##alg##_new, dataType,             \
        WP_ENC_FORMAT_SPKI, 0, wp_mldsa_pub_decode, NULL);                     \
}                                                                              \
const OSSL_DISPATCH wp_##alg##_spki_decoder_functions[] = {                    \
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_##alg##_spki_dec_new       },\
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_mldsa_enc_dec_free         },\
    { OSSL_FUNC_DECODER_DOES_SELECTION,                                        \
                                        (DFUNC)wp_mldsa_spki_does_selection  },\
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_mldsa_decode               },\
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_mldsa_export_object        },\
    { 0, NULL }                                                               \
};                                                                            \
static wp_MlDsaEncDecCtx* wp_##alg##_pki_dec_new(WOLFPROV_CTX* provCtx)         \
{                                                                              \
    return wp_mldsa_enc_dec_new(provCtx, wp_##alg##_new, dataType,             \
        WP_ENC_FORMAT_PKI, 0, wp_mldsa_priv_decode, NULL);                     \
}                                                                              \
const OSSL_DISPATCH wp_##alg##_pki_decoder_functions[] = {                     \
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_##alg##_pki_dec_new        },\
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_mldsa_enc_dec_free         },\
    { OSSL_FUNC_DECODER_DOES_SELECTION,                                        \
                                        (DFUNC)wp_mldsa_pki_does_selection   },\
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_mldsa_decode               },\
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_mldsa_export_object        },\
    { 0, NULL }                                                               \
};

#define IMPLEMENT_MLDSA_ENCODER_TABLE(alg, fmt, enc, dsel)                     \
static wp_MlDsaEncDecCtx* wp_##alg##_##fmt##_##enc##_enc_new(                   \
    WOLFPROV_CTX* provCtx)                                                     \
{                                                                              \
    return wp_mldsa_enc_dec_new(provCtx, wp_##alg##_new, NULL,                 \
        WP_ENC_FORMAT_##fmt##_VAL, WP_FORMAT_##enc##_VAL, NULL,                \
        WP_ENC_##fmt##_ENCODE);                                               \
}                                                                              \
const OSSL_DISPATCH wp_##alg##_##fmt##_##enc##_encoder_functions[] = {          \
    { OSSL_FUNC_ENCODER_NEWCTX,                                                \
        (DFUNC)wp_##alg##_##fmt##_##enc##_enc_new                  },          \
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_mldsa_enc_dec_free         },\
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                                   \
                                (DFUNC)wp_mldsa_enc_dec_settable_ctx_params  },\
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                        \
                                (DFUNC)wp_mldsa_enc_dec_set_ctx_params       },\
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)dsel                        },  \
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_mldsa_encode               },\
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_mldsa_import               },\
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_mldsa_free                 },\
    { 0, NULL }                                                               \
};

/* Format/encoding value and encode-function selectors for the table macro. */
#define WP_ENC_FORMAT_spki_VAL      WP_ENC_FORMAT_SPKI
#define WP_ENC_FORMAT_pki_VAL       WP_ENC_FORMAT_PKI
#define WP_ENC_FORMAT_epki_VAL      WP_ENC_FORMAT_EPKI
#define WP_FORMAT_der_VAL           WP_FORMAT_DER
#define WP_FORMAT_pem_VAL           WP_FORMAT_PEM
#define WP_ENC_spki_ENCODE          wp_mldsa_pub_encode
#define WP_ENC_pki_ENCODE           wp_mldsa_priv_encode
#define WP_ENC_epki_ENCODE          wp_mldsa_priv_encode

#define IMPLEMENT_MLDSA_ENCODERS(alg)                                          \
    IMPLEMENT_MLDSA_ENCODER_TABLE(alg, spki, der, wp_mldsa_spki_does_selection)\
    IMPLEMENT_MLDSA_ENCODER_TABLE(alg, spki, pem, wp_mldsa_spki_does_selection)\
    IMPLEMENT_MLDSA_ENCODER_TABLE(alg, pki, der, wp_mldsa_pki_does_selection)  \
    IMPLEMENT_MLDSA_ENCODER_TABLE(alg, pki, pem, wp_mldsa_pki_does_selection)  \
    IMPLEMENT_MLDSA_ENCODER_TABLE(alg, epki, der, wp_mldsa_pki_does_selection) \
    IMPLEMENT_MLDSA_ENCODER_TABLE(alg, epki, pem, wp_mldsa_pki_does_selection)

IMPLEMENT_MLDSA_DECODER(mldsa44, "ML-DSA-44")
IMPLEMENT_MLDSA_DECODER(mldsa65, "ML-DSA-65")
IMPLEMENT_MLDSA_DECODER(mldsa87, "ML-DSA-87")

IMPLEMENT_MLDSA_ENCODERS(mldsa44)
IMPLEMENT_MLDSA_ENCODERS(mldsa65)
IMPLEMENT_MLDSA_ENCODERS(mldsa87)

#endif /* WP_HAVE_MLDSA */
