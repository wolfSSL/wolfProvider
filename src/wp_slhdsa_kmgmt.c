/* wp_slhdsa_kmgmt.c
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
#include <stdint.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_SLHDSA

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>

/* Supported selections (key parts) in this key manager for SLH-DSA. */
#define WP_SLHDSA_POSSIBLE_SELECTIONS                                          \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/* Largest keygen seed: SK.seed || SK.prf || PK.seed, each n bytes. */
#define WP_SLHDSA_MAX_SEED_SZ   (3 * 32)

/* SLH-DSA parameter set data. */
typedef struct wp_SlhDsaData {
    enum SlhDsaParam param;
    word32 pubKeySize;
    word32 privKeySize;
    word32 sigSize;
    int securityBits;
    int securityCategory;
    const char* name;
} wp_SlhDsaData;

/* SLH-DSA key object. */
struct wp_SlhDsa {
    SlhDsaKey key;
    /* Immutable after construction and safe to read without keyMutex. */
    const wp_SlhDsaData* data;

#ifndef WP_SINGLE_THREADED
    wolfSSL_Mutex refMutex;
    wolfSSL_Mutex keyMutex;
#endif
    int refCnt;

    WOLFPROV_CTX* provCtx;

    unsigned int hasPub:1;
    unsigned int hasPriv:1;
};

typedef struct wp_SlhDsa wp_SlhDsa;

#ifdef WP_HAVE_SLHDSA_PRIVATE
/* SLH-DSA key generation context. */
typedef struct wp_SlhDsaGenCtx {
    WC_RNG rng;
    const wp_SlhDsaData* data;
    WOLFPROV_CTX* provCtx;
    int selection;
    unsigned char seed[WP_SLHDSA_MAX_SEED_SZ];
    size_t seedLen;
} wp_SlhDsaGenCtx;
#endif /* WP_HAVE_SLHDSA_PRIVATE */


/* Parameter set tables. Security category follows FIPS 205 Table 2. */
#ifdef WP_HAVE_SLH_DSA_SHAKE_128S
static const wp_SlhDsaData slhdsaShake128sData = {
    SLHDSA_SHAKE128S,
    WC_SLHDSA_SHAKE128S_PUB_LEN,
    WC_SLHDSA_SHAKE128S_PRIV_LEN,
    WC_SLHDSA_SHAKE128S_SIG_LEN,
    128, 1,
    "SLH-DSA-SHAKE-128s"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_128F
static const wp_SlhDsaData slhdsaShake128fData = {
    SLHDSA_SHAKE128F,
    WC_SLHDSA_SHAKE128F_PUB_LEN,
    WC_SLHDSA_SHAKE128F_PRIV_LEN,
    WC_SLHDSA_SHAKE128F_SIG_LEN,
    128, 1,
    "SLH-DSA-SHAKE-128f"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192S
static const wp_SlhDsaData slhdsaShake192sData = {
    SLHDSA_SHAKE192S,
    WC_SLHDSA_SHAKE192S_PUB_LEN,
    WC_SLHDSA_SHAKE192S_PRIV_LEN,
    WC_SLHDSA_SHAKE192S_SIG_LEN,
    192, 3,
    "SLH-DSA-SHAKE-192s"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192F
static const wp_SlhDsaData slhdsaShake192fData = {
    SLHDSA_SHAKE192F,
    WC_SLHDSA_SHAKE192F_PUB_LEN,
    WC_SLHDSA_SHAKE192F_PRIV_LEN,
    WC_SLHDSA_SHAKE192F_SIG_LEN,
    192, 3,
    "SLH-DSA-SHAKE-192f"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256S
static const wp_SlhDsaData slhdsaShake256sData = {
    SLHDSA_SHAKE256S,
    WC_SLHDSA_SHAKE256S_PUB_LEN,
    WC_SLHDSA_SHAKE256S_PRIV_LEN,
    WC_SLHDSA_SHAKE256S_SIG_LEN,
    256, 5,
    "SLH-DSA-SHAKE-256s"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256F
static const wp_SlhDsaData slhdsaShake256fData = {
    SLHDSA_SHAKE256F,
    WC_SLHDSA_SHAKE256F_PUB_LEN,
    WC_SLHDSA_SHAKE256F_PRIV_LEN,
    WC_SLHDSA_SHAKE256F_SIG_LEN,
    256, 5,
    "SLH-DSA-SHAKE-256f"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128S
static const wp_SlhDsaData slhdsaSha2128sData = {
    SLHDSA_SHA2_128S,
    WC_SLHDSA_SHA2_128S_PUB_LEN,
    WC_SLHDSA_SHA2_128S_PRIV_LEN,
    WC_SLHDSA_SHA2_128S_SIG_LEN,
    128, 1,
    "SLH-DSA-SHA2-128s"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128F
static const wp_SlhDsaData slhdsaSha2128fData = {
    SLHDSA_SHA2_128F,
    WC_SLHDSA_SHA2_128F_PUB_LEN,
    WC_SLHDSA_SHA2_128F_PRIV_LEN,
    WC_SLHDSA_SHA2_128F_SIG_LEN,
    128, 1,
    "SLH-DSA-SHA2-128f"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192S
static const wp_SlhDsaData slhdsaSha2192sData = {
    SLHDSA_SHA2_192S,
    WC_SLHDSA_SHA2_192S_PUB_LEN,
    WC_SLHDSA_SHA2_192S_PRIV_LEN,
    WC_SLHDSA_SHA2_192S_SIG_LEN,
    192, 3,
    "SLH-DSA-SHA2-192s"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192F
static const wp_SlhDsaData slhdsaSha2192fData = {
    SLHDSA_SHA2_192F,
    WC_SLHDSA_SHA2_192F_PUB_LEN,
    WC_SLHDSA_SHA2_192F_PRIV_LEN,
    WC_SLHDSA_SHA2_192F_SIG_LEN,
    192, 3,
    "SLH-DSA-SHA2-192f"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256S
static const wp_SlhDsaData slhdsaSha2256sData = {
    SLHDSA_SHA2_256S,
    WC_SLHDSA_SHA2_256S_PUB_LEN,
    WC_SLHDSA_SHA2_256S_PRIV_LEN,
    WC_SLHDSA_SHA2_256S_SIG_LEN,
    256, 5,
    "SLH-DSA-SHA2-256s"
};
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256F
static const wp_SlhDsaData slhdsaSha2256fData = {
    SLHDSA_SHA2_256F,
    WC_SLHDSA_SHA2_256F_PUB_LEN,
    WC_SLHDSA_SHA2_256F_PRIV_LEN,
    WC_SLHDSA_SHA2_256F_SIG_LEN,
    256, 5,
    "SLH-DSA-SHA2-256f"
};
#endif


/**
 * Increment reference count for key.
 *
 * @param [in, out] slhdsa  SLH-DSA key object.
 * @return  1 on success, 0 on failure.
 */
int wp_slhdsa_up_ref(wp_SlhDsa* slhdsa)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_up_ref");

    rc = wc_LockMutex(&slhdsa->refMutex);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        slhdsa->refCnt++;
        wc_UnLockMutex(&slhdsa->refMutex);
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_up_ref");
    slhdsa->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the wolfSSL SLH-DSA key from the wp_SlhDsa object.
 *
 * @param [in] slhdsa  SLH-DSA key object.
 * @return  Pointer to wolfSSL SlhDsaKey, returned as void*.
 */
void* wp_slhdsa_get_key(wp_SlhDsa* slhdsa)
{
    return &slhdsa->key;
}

/**
 * Get the mutex from an SLH-DSA key object.
 *
 * @param [in] slhdsa  SLH-DSA key object.
 * @return  Pointer to wolfSSL mutex object.
 */
wolfSSL_Mutex* wp_slhdsa_get_mutex(wp_SlhDsa* slhdsa)
{
#ifndef WP_SINGLE_THREADED
    return &slhdsa->keyMutex;
#else
    (void)slhdsa;
    return NULL;
#endif
}

/* Callers must hold keyMutex while using these availability accessors. */
int wp_slhdsa_has_public(const wp_SlhDsa* slhdsa)
{
    return (slhdsa != NULL) && slhdsa->hasPub;
}

int wp_slhdsa_has_private(const wp_SlhDsa* slhdsa)
{
    return (slhdsa != NULL) && slhdsa->hasPriv;
}

/**
 * Get the SLH-DSA parameter id for the key.
 *
 * @param [in] slhdsa  SLH-DSA key object.
 * @return  Parameter id, or -1 when not available.
 */
int wp_slhdsa_get_param(wp_SlhDsa* slhdsa)
{
    int param = -1;

    if ((slhdsa != NULL) && (slhdsa->data != NULL)) {
        param = (int)slhdsa->data->param;
    }
    return param;
}

/**
 * Get the FIPS 205 security parameter n for the key.
 *
 * @param [in] slhdsa  SLH-DSA key object.
 * @return  n in bytes (16, 24 or 32), or 0 if slhdsa is NULL.
 */
int wp_slhdsa_get_n(const wp_SlhDsa* slhdsa)
{
    if ((slhdsa == NULL) || (slhdsa->data == NULL)) {
        return 0;
    }
    /* The public key is PK.seed || PK.root, n bytes each. */
    return (int)(slhdsa->data->pubKeySize / 2);
}

/**
 * Get the maximum signature size for the key.
 *
 * @param [in] slhdsa  SLH-DSA key object.
 * @return  Signature size in bytes, or 0 if slhdsa is NULL.
 */
int wp_slhdsa_get_sig_size(const wp_SlhDsa* slhdsa)
{
    if ((slhdsa == NULL) || (slhdsa->data == NULL)) {
        return 0;
    }
    return (int)slhdsa->data->sigSize;
}


/**
 * Create a new SLH-DSA key object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] data     Parameter set data.
 * @return  New SLH-DSA key object on success, NULL on failure.
 */
static wp_SlhDsa* wp_slhdsa_new(WOLFPROV_CTX* provCtx,
    const wp_SlhDsaData* data)
{
    wp_SlhDsa* slhdsa = NULL;

    if (wolfssl_prov_is_running()) {
        slhdsa = (wp_SlhDsa*)OPENSSL_zalloc(sizeof(*slhdsa));
    }
    if (slhdsa != NULL) {
        int ok = 1;
        int rc;

        rc = wc_SlhDsaKey_Init(&slhdsa->key, data->param, NULL, INVALID_DEVID);
        if (rc != 0) {
            wc_SlhDsaKey_Free(&slhdsa->key);
            ok = 0;
        }
    #ifndef WP_SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&slhdsa->refMutex);
            if (rc != 0) {
                wc_SlhDsaKey_Free(&slhdsa->key);
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_InitMutex(&slhdsa->keyMutex);
            if (rc != 0) {
                wc_FreeMutex(&slhdsa->refMutex);
                wc_SlhDsaKey_Free(&slhdsa->key);
                ok = 0;
            }
        }
    #endif
        if (ok) {
            slhdsa->provCtx = provCtx;
            slhdsa->refCnt  = 1;
            slhdsa->data    = data;
        }
        if (!ok) {
            OPENSSL_clear_free(slhdsa, sizeof(*slhdsa));
            slhdsa = NULL;
        }
    }
    return slhdsa;
}

/**
 * Dispose of SLH-DSA key object.
 *
 * @param [in, out] slhdsa  SLH-DSA key object. May be NULL.
 */
void wp_slhdsa_free(wp_SlhDsa* slhdsa)
{
    if (slhdsa != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&slhdsa->refMutex);
        if (rc == 0) {
            cnt = --slhdsa->refCnt;
            wc_UnLockMutex(&slhdsa->refMutex);
        }
        else {
            /* Cannot safely decrement without the lock; keep the object. */
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_ERROR,
                "wc_LockMutex", rc);
            cnt = 1;
        }
    #else
        cnt = --slhdsa->refCnt;
    #endif

        if (cnt == 0) {
        #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&slhdsa->keyMutex);
            wc_FreeMutex(&slhdsa->refMutex);
        #endif
            wc_SlhDsaKey_Free(&slhdsa->key);
            OPENSSL_clear_free(slhdsa, sizeof(*slhdsa));
        }
    }
}

/**
 * Duplicate SLH-DSA key object via raw export/import.
 *
 * @param [in] src        Source SLH-DSA key object.
 * @param [in] selection  Parts of key (public/private) to duplicate.
 * @return  New SLH-DSA key object on success, NULL on failure.
 */
static wp_SlhDsa* wp_slhdsa_dup(const wp_SlhDsa* src, int selection)
{
    wp_SlhDsa* dst = NULL;
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
    if (wp_lock(wp_slhdsa_get_mutex((wp_SlhDsa*)src)) != 1) {
        return NULL;
    }
    dupPub = ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) && src->hasPub;
    dupPriv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
              && src->hasPriv;

    dst = wp_slhdsa_new(src->provCtx, src->data);
    if (dst == NULL) {
        ok = 0;
    }

    if (ok && dupPub) {
        pubLen = src->data->pubKeySize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPublic((SlhDsaKey*)&src->key, pubBuf,
                &pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_SlhDsaKey_ImportPublic(&dst->key, pubBuf, pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        OPENSSL_free(pubBuf);
        pubBuf = NULL;
    }

#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ok && dupPriv) {
        privAllocLen = src->data->privKeySize;
        privLen = privAllocLen;
        privBuf = (unsigned char*)OPENSSL_malloc(privAllocLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPrivate((SlhDsaKey*)&src->key, privBuf,
                &privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_SlhDsaKey_ImportPrivate(&dst->key, privBuf, privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        /* Zero the full allocation, not just the (possibly-truncated) out len. */
        OPENSSL_clear_free(privBuf, privAllocLen);
    }
#else
    (void)privBuf;
    (void)privLen;
    (void)privAllocLen;
    (void)dupPriv;
#endif

    wp_unlock(wp_slhdsa_get_mutex((wp_SlhDsa*)src));

    if (!ok) {
        wp_slhdsa_free(dst);
        return NULL;
    }
    dst->hasPub =
        ((dst->key.flags & WC_SLHDSA_FLAG_PUBLIC) != 0) ? 1 : 0;
    dst->hasPriv =
        ((dst->key.flags & WC_SLHDSA_FLAG_PRIVATE) != 0) ? 1 : 0;
    return dst;
}

/**
 * Load an SLH-DSA key from a reference.
 *
 * @param [in, out] pSlhDsa  Pointer to an SLH-DSA key reference.
 * @param [in]      size     Size of reference object.
 * @return  SLH-DSA key object on success.
 */
static const wp_SlhDsa* wp_slhdsa_load(const wp_SlhDsa** pSlhDsa, size_t size)
{
    const wp_SlhDsa* slhdsa;

    if ((pSlhDsa == NULL) || (size != sizeof(*pSlhDsa))) {
        return NULL;
    }
    slhdsa = *pSlhDsa;
    *pSlhDsa = NULL;
    return slhdsa;
}

/**
 * Check SLH-DSA key object has the components required.
 *
 * @param [in] slhdsa     SLH-DSA key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_has(const wp_SlhDsa* slhdsa, int selection)
{
    int ok = 1;
    int locked = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_has");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (slhdsa == NULL)) {
        ok = 0;
    }
    if (ok && (wp_lock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa)) != 1)) {
        ok = 0;
    }
    else if (ok) {
        locked = 1;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok &= slhdsa->hasPub;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= slhdsa->hasPriv;
    }
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa));
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Compare two SLH-DSA keys.
 *
 * @param [in] a          First SLH-DSA key.
 * @param [in] b          Second SLH-DSA key.
 * @param [in] selection  Parts of key to compare.
 * @return  1 if match, 0 otherwise.
 */
static int wp_slhdsa_match(const wp_SlhDsa* a, const wp_SlhDsa* b,
    int selection)
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
    wp_SlhDsa* first;
    wp_SlhDsa* second;
    int firstLocked = 0;
    int secondLocked = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_match");

    if (!wolfssl_prov_is_running() || (a == NULL) || (b == NULL)) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if ((uintptr_t)a <= (uintptr_t)b) {
        first = (wp_SlhDsa*)a;
        second = (wp_SlhDsa*)b;
    }
    else {
        first = (wp_SlhDsa*)b;
        second = (wp_SlhDsa*)a;
    }
    if (wp_lock(wp_slhdsa_get_mutex(first)) != 1) {
        ok = 0;
    }
    else {
        firstLocked = 1;
    }
    if (ok && (second != first)) {
        if (wp_lock(wp_slhdsa_get_mutex(second)) != 1) {
            ok = 0;
        }
        else {
            secondLocked = 1;
        }
    }
    if (ok && (a->data->param != b->data->param)) {
        ok = 0;
    }
    /* Presence mismatch fails; both-present compares; neither-present skips. */
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) &&
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
            rc = wc_SlhDsaKey_ExportPublic((SlhDsaKey*)&a->key, bufA, &lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPublic((SlhDsaKey*)&b->key, bufB, &lenB);
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
#ifdef WP_HAVE_SLHDSA_PRIVATE
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
            rc = wc_SlhDsaKey_ExportPrivate((SlhDsaKey*)&a->key, bufA, &lenA);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPrivate((SlhDsaKey*)&b->key, bufB, &lenB);
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
#else
    (void)allocA;
    (void)allocB;
#endif
    /* A public/private selection with no component present in both is not a match. */
    if (ok && !checked &&
            ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                           OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) != 0)) {
        ok = 0;
    }
    if (secondLocked) {
        wp_unlock(wp_slhdsa_get_mutex(second));
    }
    if (firstLocked) {
        wp_unlock(wp_slhdsa_get_mutex(first));
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* Validate that the selected SLH-DSA components are present and consistent. */
static int wp_slhdsa_validate(const wp_SlhDsa* slhdsa, int selection,
    int checkType)
{
    int ok;
    int locked = 0;
#ifdef WP_HAVE_SLHDSA_PRIVATE
    wp_SlhDsa* copy = NULL;
    unsigned char* priv = NULL;
    word32 privLen = 0;
    word32 privAllocLen = 0;
    int rc;
#endif

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_validate");

    ok = wolfssl_prov_is_running() && (slhdsa != NULL) &&
        ((selection & WP_SLHDSA_POSSIBLE_SELECTIONS) != 0);
    if (ok && (wp_lock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa)) != 1)) {
        ok = 0;
    }
    else if (ok) {
        locked = 1;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok = slhdsa->hasPub;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok = slhdsa->hasPriv;
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
            (checkType != OSSL_KEYMGMT_VALIDATE_QUICK_CHECK)) {
        copy = wp_slhdsa_new(slhdsa->provCtx, slhdsa->data);
        if (copy == NULL) {
            ok = 0;
        }
        if (ok) {
            privLen = privAllocLen = slhdsa->data->privKeySize;
            priv = (unsigned char*)OPENSSL_malloc(privAllocLen);
            if (priv == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPrivate((SlhDsaKey*)&slhdsa->key, priv,
                &privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        /* The copy is private to this call; drop the source key lock before the
         * expensive CheckKey so concurrent operations are not blocked by it. */
        if (locked) {
            wp_unlock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa));
            locked = 0;
        }
        if (ok) {
            rc = wc_SlhDsaKey_ImportPrivate(&copy->key, priv, privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            ok = wc_SlhDsaKey_CheckKey(&copy->key) == 0;
        }
        OPENSSL_clear_free(priv, privAllocLen);
        wp_slhdsa_free(copy);
    }
#else
    (void)checkType;
#endif
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa));
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import an SLH-DSA key from parameters.
 *
 * @param [in, out] slhdsa     SLH-DSA key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_import(wp_SlhDsa* slhdsa, int selection,
    const OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    unsigned char* privData = NULL;
    unsigned char* pubData = NULL;
    size_t privLen = 0;
    size_t pubLen = 0;
    int locked = 0;
    int keyTouched = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_import");

    if (!wolfssl_prov_is_running() || (slhdsa == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_SLHDSA_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && (wp_lock(wp_slhdsa_get_mutex(slhdsa)) != 1)) {
        ok = 0;
    }
    else if (ok) {
        locked = 1;
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PRIV_KEY,
                &privData, &privLen)) {
            ok = 0;
        }
        /* FIPS 205 priv keys are fixed-size; equality check before word32 cast
         * also catches truncation on 64-bit platforms. */
        if (ok && (privData != NULL) &&
                (privLen != slhdsa->data->privKeySize)) {
            ok = 0;
        }
        if (ok && (privData != NULL)) {
            keyTouched = 1;
            rc = wc_SlhDsaKey_ImportPrivate(&slhdsa->key, privData,
                (word32)privLen);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                slhdsa->hasPriv =
                    ((slhdsa->key.flags & WC_SLHDSA_FLAG_PRIVATE) != 0) ? 1 : 0;
                slhdsa->hasPub =
                    ((slhdsa->key.flags & WC_SLHDSA_FLAG_PUBLIC) != 0) ? 1 : 0;
            }
        }
    }
#else
    (void)privLen;
#endif
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PUB_KEY,
                &pubData, &pubLen)) {
            ok = 0;
        }
        if (ok && (pubData != NULL) && (pubLen != slhdsa->data->pubKeySize)) {
            ok = 0;
        }
        if (ok && (pubData != NULL)) {
            keyTouched = 1;
            rc = wc_SlhDsaKey_ImportPublic(&slhdsa->key, pubData,
                (word32)pubLen);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                slhdsa->hasPub = 1;
            }
        }
    }
    if (ok && (privData == NULL) && (pubData == NULL)) {
        ok = 0;
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    /* Validate the private key once, after any public part is imported so the
     * same check also confirms the two agree. */
    if (ok && ((slhdsa->key.flags & WC_SLHDSA_FLAG_PRIVATE) != 0)) {
        if (wc_SlhDsaKey_CheckKey(&slhdsa->key) != 0) {
            ok = 0;
        }
    }
#endif
    if (ok && locked) {
        /* Derive availability from wolfSSL because an imported private key
         * embeds and may expose its public component too. */
        slhdsa->hasPriv =
            ((slhdsa->key.flags & WC_SLHDSA_FLAG_PRIVATE) != 0) ? 1 : 0;
        slhdsa->hasPub =
            ((slhdsa->key.flags & WC_SLHDSA_FLAG_PUBLIC) != 0) ? 1 : 0;
    }
    else if (locked && keyTouched) {
        /* Never retain or advertise a partially imported key. */
        wc_SlhDsaKey_Free(&slhdsa->key);
        rc = wc_SlhDsaKey_Init(&slhdsa->key, slhdsa->data->param, NULL,
            INVALID_DEVID);
        if (rc != 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_ERROR,
                "wc_SlhDsaKey_Init", rc);
        }
        slhdsa->hasPriv = 0;
        slhdsa->hasPub = 0;
    }
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex(slhdsa));
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* SLH-DSA key parameters for import/export type queries. */
static const OSSL_PARAM wp_slhdsa_no_key_params[] = {
    OSSL_PARAM_END,
};

#ifdef WP_HAVE_SLHDSA_PRIVATE
static const OSSL_PARAM wp_slhdsa_private_key_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END,
};
#endif

static const OSSL_PARAM wp_slhdsa_public_key_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END,
};

#ifdef WP_HAVE_SLHDSA_PRIVATE
static const OSSL_PARAM wp_slhdsa_keypair_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END,
};
#endif

static const OSSL_PARAM* wp_slhdsa_key_types(int selection)
{
    int hasPublic =
        (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
#ifdef WP_HAVE_SLHDSA_PRIVATE
    int hasPrivate =
        (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    if (hasPublic && hasPrivate) {
        return wp_slhdsa_keypair_params;
    }
    if (hasPrivate) {
        return wp_slhdsa_private_key_params;
    }
#endif
    if (hasPublic) {
        return wp_slhdsa_public_key_params;
    }
    return wp_slhdsa_no_key_params;
}

static const OSSL_PARAM* wp_slhdsa_import_types(int selection)
{
    return wp_slhdsa_key_types(selection);
}

static const OSSL_PARAM* wp_slhdsa_export_types(int selection)
{
    return wp_slhdsa_key_types(selection);
}

/**
 * Export SLH-DSA key data via callback.
 *
 * @param [in] slhdsa     SLH-DSA key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Callback to receive constructed parameters.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_export(wp_SlhDsa* slhdsa, int selection,
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
    int locked = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_export");

    if (!wolfssl_prov_is_running() || (slhdsa == NULL)) {
        ok = 0;
    }
    if (ok && (wp_lock(wp_slhdsa_get_mutex(slhdsa)) != 1)) {
        ok = 0;
    }
    else if (ok) {
        locked = 1;
    }
    XMEMSET(params, 0, sizeof(params));

    if (ok && expPub && slhdsa->hasPub) {
        pubLen = slhdsa->data->pubKeySize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPublic(&slhdsa->key, pubBuf, &pubLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            wp_param_set_octet_string_ptr(&params[paramsSz++],
                OSSL_PKEY_PARAM_PUB_KEY, pubBuf, pubLen);
        }
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ok && expPriv && slhdsa->hasPriv) {
        privAllocLen = slhdsa->data->privKeySize;
        privLen = privAllocLen;
        privBuf = (unsigned char*)OPENSSL_malloc(privAllocLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wc_SlhDsaKey_ExportPrivate(&slhdsa->key, privBuf, &privLen);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            wp_param_set_octet_string_ptr(&params[paramsSz++],
                OSSL_PKEY_PARAM_PRIV_KEY, privBuf, privLen);
        }
    }
#else
    (void)expPriv;
    (void)privLen;
#endif
    if (ok && (paramsSz == 0) && (expPub || expPriv)) {
        ok = 0;
    }
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex(slhdsa));
        locked = 0;
    }
    if (ok) {
        ok = paramCb(params, cbArg);
    }
    OPENSSL_free(pubBuf);
    /* Zero full allocation in case ExportPrivate truncated privLen. */
    OPENSSL_clear_free(privBuf, privAllocLen);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Gettable parameters for SLH-DSA key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of supported gettable parameters.
 */
static const OSSL_PARAM* wp_slhdsa_gettable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_slhdsa_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_CATEGORY, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
#ifdef WP_HAVE_SLHDSA_PRIVATE
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
#endif
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_slhdsa_supported_gettable_params;
}

/**
 * Get SLH-DSA key parameters.
 *
 * @param [in]      slhdsa  SLH-DSA key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_get_params(wp_SlhDsa* slhdsa, OSSL_PARAM params[])
{
    int ok = 1;
    int rc;
    OSSL_PARAM* p;
    int locked = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_get_params");

    if (slhdsa == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (wp_lock(wp_slhdsa_get_mutex(slhdsa)) != 1) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC,
            __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    locked = 1;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if ((p != NULL) &&
            !OSSL_PARAM_set_int(p, (int)slhdsa->data->pubKeySize * 8)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, slhdsa->data->securityBits)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, slhdsa->data->securityCategory)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, (int)slhdsa->data->sigSize)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, "")) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            word32 outLen = slhdsa->data->pubKeySize;
            if (!slhdsa->hasPub) {
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
                rc = wc_SlhDsaKey_ExportPublic(&slhdsa->key,
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
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            word32 outLen = slhdsa->data->privKeySize;
            if (!slhdsa->hasPriv) {
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
                rc = wc_SlhDsaKey_ExportPrivate(&slhdsa->key,
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
#endif
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex(slhdsa));
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Settable parameters for SLH-DSA key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Empty parameter list.
 */
static const OSSL_PARAM* wp_slhdsa_settable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_slhdsa_supported_settable_params[] = {
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_slhdsa_supported_settable_params;
}

/**
 * Set SLH-DSA key parameters. None supported.
 *
 * @param [in] slhdsa  SLH-DSA key object. Unused.
 * @param [in] params  Array of parameters. Unused.
 * @return  1 always.
 */
static int wp_slhdsa_set_params(wp_SlhDsa* slhdsa, const OSSL_PARAM params[])
{
    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_set_params");
    (void)slhdsa;
    (void)params;
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/*
 * SLH-DSA generation
 */

#ifdef WP_HAVE_SLHDSA_PRIVATE

static int wp_slhdsa_gen_set_params(wp_SlhDsaGenCtx* ctx,
    const OSSL_PARAM params[]);

static size_t wp_slhdsa_seed_size(const wp_SlhDsaData* data)
{
    return (size_t)(3 * (data->pubKeySize / 2));
}

/**
 * Create SLH-DSA generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @param [in] data       Parameter set data.
 * @return  New SLH-DSA generation context on success, NULL on failure.
 */
static wp_SlhDsaGenCtx* wp_slhdsa_gen_init_base(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], const wp_SlhDsaData* data)
{
    wp_SlhDsaGenCtx* ctx = NULL;

    if (wolfssl_prov_is_running() &&
            ((selection & WP_SLHDSA_POSSIBLE_SELECTIONS) != 0)) {
        ctx = (wp_SlhDsaGenCtx*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int rc;
        int ok = 1;
        int rngInit = 0;

        rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        else {
            rngInit = 1;
        }
        if (ok) {
            ctx->provCtx   = provCtx;
            ctx->data      = data;
            ctx->selection = selection;
            /* Apply init-time params (e.g. the deterministic keygen seed) so
             * the seed and its length validation are honored at init, not
             * only via a later gen_set_params call. */
            if (!wp_slhdsa_gen_set_params(ctx, params)) {
                ok = 0;
            }
        }
        if (!ok) {
            if (rngInit) {
                wc_FreeRng(&ctx->rng);
            }
            OPENSSL_clear_free(ctx, sizeof(*ctx));
            ctx = NULL;
        }
    }
    return ctx;
}

/**
 * Generate SLH-DSA key pair.
 *
 * @param [in, out] ctx     SLH-DSA generation context.
 * @param [in]      osslcb  Progress callback. Unused.
 * @param [in]      cbarg   Argument for callback. Unused.
 * @return  SLH-DSA key object on success, NULL on failure.
 */
static wp_SlhDsa* wp_slhdsa_gen(wp_SlhDsaGenCtx* ctx, OSSL_CALLBACK* osslcb,
    void* cbarg)
{
    wp_SlhDsa* slhdsa;
    int keyPair = (ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;

    (void)osslcb;
    (void)cbarg;

    slhdsa = wp_slhdsa_new(ctx->provCtx, ctx->data);
    if ((slhdsa != NULL) && keyPair) {
        int rc;
        word32 n = ctx->data->pubKeySize / 2;

        if (ctx->seedLen == wp_slhdsa_seed_size(ctx->data)) {
            /* Seed is SK.seed || SK.prf || PK.seed, n bytes each. */
            rc = wc_SlhDsaKey_MakeKeyWithRandom(&slhdsa->key, ctx->seed, n,
                ctx->seed + n, n, ctx->seed + (2 * n), n);
        }
        else {
            rc = wc_SlhDsaKey_MakeKey(&slhdsa->key, &ctx->rng);
        }
        if (rc != 0) {
            wp_slhdsa_free(slhdsa);
            slhdsa = NULL;
        }
        else {
            slhdsa->hasPub = 1;
            slhdsa->hasPriv = 1;
        }
    }
    return slhdsa;
}

/**
 * Set parameters into SLH-DSA generation context.
 *
 * @param [in] ctx     Generation context.
 * @param [in] params  Array of parameters (SLH-DSA keygen seed).
 * @return  1 on success, 0 on failure.
 */
static int wp_slhdsa_gen_set_params(wp_SlhDsaGenCtx* ctx,
    const OSSL_PARAM params[])
{
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_gen_set_params");

    if (ctx == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
        return 0;
    }
    if (params == NULL) {
        WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
        return 1;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SLH_DSA_SEED);
    if (p != NULL) {
        void* vp = ctx->seed;
        ctx->seedLen = 0;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->seed),
                &ctx->seedLen) ||
                (ctx->seedLen != wp_slhdsa_seed_size(ctx->data))) {
            OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
            ctx->seedLen = 0;
            WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
            return 0;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Settable parameters for SLH-DSA generation context.
 *
 * @param [in] ctx      Generation context. Unused.
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of settable parameters.
 */
static const OSSL_PARAM* wp_slhdsa_gen_settable_params(wp_SlhDsaGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_slhdsa_gen_settable[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_slhdsa_gen_settable;
}

/**
 * Free SLH-DSA generation context.
 *
 * @param [in, out] ctx  Generation context.
 */
static void wp_slhdsa_gen_cleanup(wp_SlhDsaGenCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        /* ctx holds the deterministic keygen seed; cleanse it. */
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

#endif /* WP_HAVE_SLHDSA_PRIVATE */

/*
 * Per-parameter-set trampolines and dispatch tables
 */

/* Verify-only builds omit the GEN_* entries entirely rather than stubbing
 * them: OpenSSL then fails keygen with "operation not supported for this key
 * type" instead of a generic error. */
#ifdef WP_HAVE_SLHDSA_PRIVATE
#define WP_SLHDSA_GEN_DISPATCH(alg)                                            \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,                                              \
        (DFUNC)wp_##alg##_gen_init                              },             \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                        \
        (DFUNC)wp_slhdsa_gen_set_params                         },             \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                   \
        (DFUNC)wp_slhdsa_gen_settable_params                    },             \
    { OSSL_FUNC_KEYMGMT_GEN,            (DFUNC)wp_slhdsa_gen    },             \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                           \
        (DFUNC)wp_slhdsa_gen_cleanup                            },
#define WP_SLHDSA_GEN_TRAMPOLINE(alg, dataName)                                \
static wp_SlhDsaGenCtx* wp_##alg##_gen_init(WOLFPROV_CTX* provCtx,             \
    int selection, const OSSL_PARAM params[])                                  \
{                                                                              \
    return wp_slhdsa_gen_init_base(provCtx, selection, params, &dataName);     \
}
#else
#define WP_SLHDSA_GEN_DISPATCH(alg)
#define WP_SLHDSA_GEN_TRAMPOLINE(alg, dataName)
#endif

#define IMPLEMENT_SLHDSA_KEYMGMT(alg, dataName, algName)                       \
static wp_SlhDsa* wp_##alg##_new(WOLFPROV_CTX* provCtx)                        \
{                                                                              \
    return wp_slhdsa_new(provCtx, &dataName);                                  \
}                                                                              \
static const char* wp_##alg##_query_operation_name(int op)                     \
{                                                                              \
    (void)op;                                                                  \
    return algName;                                                            \
}                                                                              \
WP_SLHDSA_GEN_TRAMPOLINE(alg, dataName)                                        \
const OSSL_DISPATCH wp_##alg##_keymgmt_functions[] = {                         \
    { OSSL_FUNC_KEYMGMT_NEW,                                                   \
        (DFUNC)wp_##alg##_new                                   },             \
    { OSSL_FUNC_KEYMGMT_FREE,           (DFUNC)wp_slhdsa_free   },             \
    { OSSL_FUNC_KEYMGMT_DUP,            (DFUNC)wp_slhdsa_dup    },             \
    WP_SLHDSA_GEN_DISPATCH(alg)                                                \
    { OSSL_FUNC_KEYMGMT_LOAD,           (DFUNC)wp_slhdsa_load   },             \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                            \
        (DFUNC)wp_slhdsa_get_params                             },             \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                       \
        (DFUNC)wp_slhdsa_gettable_params                        },             \
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                            \
        (DFUNC)wp_slhdsa_set_params                             },             \
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                       \
        (DFUNC)wp_slhdsa_settable_params                        },             \
    { OSSL_FUNC_KEYMGMT_HAS,            (DFUNC)wp_slhdsa_has    },             \
    { OSSL_FUNC_KEYMGMT_MATCH,          (DFUNC)wp_slhdsa_match  },             \
    { OSSL_FUNC_KEYMGMT_VALIDATE,       (DFUNC)wp_slhdsa_validate },           \
    { OSSL_FUNC_KEYMGMT_IMPORT,         (DFUNC)wp_slhdsa_import },             \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                          \
        (DFUNC)wp_slhdsa_import_types                           },             \
    { OSSL_FUNC_KEYMGMT_EXPORT,         (DFUNC)wp_slhdsa_export },             \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                          \
        (DFUNC)wp_slhdsa_export_types                           },             \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                  \
        (DFUNC)wp_##alg##_query_operation_name                  },             \
    { 0, NULL }                                                                \
};

#ifdef WP_HAVE_SLH_DSA_SHAKE_128S
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_shake_128s, slhdsaShake128sData,
    "SLH-DSA-SHAKE-128s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_128F
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_shake_128f, slhdsaShake128fData,
    "SLH-DSA-SHAKE-128f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192S
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_shake_192s, slhdsaShake192sData,
    "SLH-DSA-SHAKE-192s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192F
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_shake_192f, slhdsaShake192fData,
    "SLH-DSA-SHAKE-192f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256S
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_shake_256s, slhdsaShake256sData,
    "SLH-DSA-SHAKE-256s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256F
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_shake_256f, slhdsaShake256fData,
    "SLH-DSA-SHAKE-256f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128S
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_sha2_128s, slhdsaSha2128sData,
    "SLH-DSA-SHA2-128s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128F
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_sha2_128f, slhdsaSha2128fData,
    "SLH-DSA-SHA2-128f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192S
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_sha2_192s, slhdsaSha2192sData,
    "SLH-DSA-SHA2-192s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192F
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_sha2_192f, slhdsaSha2192fData,
    "SLH-DSA-SHA2-192f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256S
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_sha2_256s, slhdsaSha2256sData,
    "SLH-DSA-SHA2-256s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256F
IMPLEMENT_SLHDSA_KEYMGMT(slhdsa_sha2_256f, slhdsaSha2256fData,
    "SLH-DSA-SHA2-256f")
#endif

/*
 * SLH-DSA encoder/decoder
 */

/* Extra slack added to the queried DER length before allocating. */
#define WP_SLHDSA_DER_SLACK 32

/* Functions used by the encoder and decoder implementations. */
typedef int (*WP_SLHDSA_DECODE)(const byte* input, word32* inOutIdx, void* key,
    word32 inSz);
typedef int (*WP_SLHDSA_ENCODE)(void* key, byte* output, word32 inLen);

typedef wp_SlhDsa* (*WP_SLHDSA_NEW)(WOLFPROV_CTX* provCtx);

/* SLH-DSA encoder and decoder context. */
typedef struct wp_SlhDsaEncDecCtx {
    WP_SLHDSA_DECODE decode;
    WP_SLHDSA_ENCODE encode;
    WP_SLHDSA_NEW newKey;

    WOLFPROV_CTX* provCtx;
    int selection;

    const char* dataType;
    int format;
    int encoding;

    int cipher;
    const char* cipherName;
} wp_SlhDsaEncDecCtx;

/**
 * Create a new SLH-DSA encoder/decoder context.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] newKey    Function to create parameter-set SLH-DSA key.
 * @param [in] dataType  Data type name passed to data callback.
 * @param [in] format    Supported key format.
 * @param [in] encoding  Data format.
 * @param [in] decode    Function to decode DER data to a key.
 * @param [in] encode    Function to encode key to DER data.
 * @return  New SLH-DSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_SlhDsaEncDecCtx* wp_slhdsa_enc_dec_new(WOLFPROV_CTX* provCtx,
    WP_SLHDSA_NEW newKey, const char* dataType, int format, int encoding,
    WP_SLHDSA_DECODE decode, WP_SLHDSA_ENCODE encode)
{
    wp_SlhDsaEncDecCtx* ctx = NULL;

    if (wolfssl_prov_is_running()) {
        ctx = (wp_SlhDsaEncDecCtx*)OPENSSL_zalloc(sizeof(wp_SlhDsaEncDecCtx));
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
 * Dispose of SLH-DSA encoder/decoder context object.
 *
 * @param [in, out] ctx  SLH-DSA encoder/decoder context object.
 */
static void wp_slhdsa_enc_dec_free(wp_SlhDsaEncDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return the settable parameters for the SLH-DSA encoder/decoder context.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_slhdsa_enc_dec_settable_ctx_params(
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_slhdsa_enc_dec_supported_settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    (void)provCtx;
    return wp_slhdsa_enc_dec_supported_settables;
}

/**
 * Set the SLH-DSA encoder/decoder context parameters.
 *
 * @param [in, out] ctx     SLH-DSA encoder/decoder context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_slhdsa_enc_dec_set_ctx_params(wp_SlhDsaEncDecCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_enc_dec_set_ctx_params");

    if (!wp_cipher_from_params(params, &ctx->cipher, &ctx->cipherName)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Construct parameters from SLH-DSA key and pass off to callback.
 *
 * @param [in] slhdsa     SLH-DSA key object.
 * @param [in] dataType   Data type name passed to the callback.
 * @param [in] dataCb     Callback to pass SLH-DSA key in parameters to.
 * @param [in] dataCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_slhdsa_dec_send_params(wp_SlhDsa* slhdsa, const char* dataType,
    OSSL_CALLBACK* dataCb, void* dataCbArg)
{
    int ok = 1;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_dec_send_params");

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char*)dataType, 0);
    /* The address of the key object becomes the octet string pointer. */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &slhdsa, sizeof(slhdsa));
    params[3] = OSSL_PARAM_construct_end();

    if (!dataCb(params, dataCbArg)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if defined(WP_HAVE_PKCS8_ENC) && defined(WP_HAVE_SLHDSA_PRIVATE)
/**
 * Decode an encrypted PKCS#8 DER SLH-DSA private key into the key object.
 *
 * @param [in]      ctx      SLH-DSA encoder/decoder context object.
 * @param [in, out] slhdsa   SLH-DSA key object.
 * @param [in]      data     DER encoding (decrypted in place).
 * @param [in]      len      Length, in bytes, of DER encoding.
 * @param [in]      pwCb     Password callback.
 * @param [in]      pwCbArg  Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_slhdsa_decode_enc_pki(wp_SlhDsaEncDecCtx* ctx, wp_SlhDsa* slhdsa,
    unsigned char* data, word32 len, OSSL_PASSPHRASE_CALLBACK* pwCb,
    void* pwCbArg)
{
    int ok = 1;
    word32 idx = 0;

    WOLFPROV_ENTER_SILENT(WP_LOG_COMP_PQC, WOLFPROV_FUNC_NAME);

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    /* Decrypt the PBES2 EncryptedPrivateKeyInfo in place. */
    if (ok && (pwCb == NULL ||
            !wp_decrypt_key_pkcs8(data, &len, pwCb, pwCbArg))) {
        ok = 0;
    }
    /* Decode the recovered plaintext private key. */
    if (ok && ((ctx->decode(data, &idx, (void*)&slhdsa->key, len) != 0) ||
            (idx != len))) {
        ok = 0;
    }

    WOLFPROV_LEAVE_SILENT(WP_LOG_COMP_PQC,
        __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Decode the data in the core BIO.
 *
 * The parameter set is preset on the created key object so decode only
 * succeeds when the DER's algorithm OID matches this decoder's set.
 *
 * @param [in, out] ctx        SLH-DSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to read data from.
 * @param [in]      selection  Parts of key to export.
 * @param [in]      dataCb     Callback to pass SLH-DSA key in parameters to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_slhdsa_decode(wp_SlhDsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int decoded = 1;
    int rc;
    unsigned char* data = NULL;
    word32 len = 0;
    word32 idx = 0;
    wp_SlhDsa* slhdsa = NULL;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_decode");

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

#if !defined(WP_HAVE_PKCS8_ENC) || !defined(WP_HAVE_SLHDSA_PRIVATE)
    (void)pwCb;
    (void)pwCbArg;
#endif

    if (ok) {
        ctx->selection = selection;
        slhdsa = ctx->newKey(ctx->provCtx);
        if (slhdsa == NULL) {
            ok = 0;
        }
    }

    if (ok) {
        ok = wp_read_der_bio(ctx->provCtx, cBio, &data, &len);
    }
    if (ok) {
        /* The object is not published until dec_send_params below. */
        rc = ctx->decode(data, &idx, (void*)&slhdsa->key, len);
        if ((rc != 0) || (idx != len)) {
#if defined(WP_HAVE_PKCS8_ENC) && defined(WP_HAVE_SLHDSA_PRIVATE)
            /* May be an encrypted PKCS#8 key - decrypt and retry. */
            if ((ctx->format != WP_ENC_FORMAT_PKI) ||
                    (!wp_slhdsa_decode_enc_pki(ctx, slhdsa, data, len, pwCb,
                        pwCbArg))) {
                WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "decode", rc);
                ok = 0;
                decoded = 0;
            }
#else
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "decode", rc);
            ok = 0;
            decoded = 0;
#endif
        }
    }
    /* wc_SlhDsaKey_*Decode overwrites the preset parameter set from the DER's
     * OID rather than rejecting a mismatch, so every per-set decoder would
     * accept any SLH-DSA key and leave this object describing the wrong set.
     * Hand a foreign set back to the chain so the right decoder claims it. */
    if (ok && ((slhdsa->key.params == NULL) ||
            (slhdsa->key.params->param != slhdsa->data->param))) {
        ok = 0;
        decoded = 0;
    }
#ifdef WP_HAVE_SLHDSA_PRIVATE
    if (ok && (ctx->format == WP_ENC_FORMAT_PKI) &&
            (wc_SlhDsaKey_CheckKey(&slhdsa->key) != 0)) {
        ok = 0;
    }
#endif
    if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        slhdsa->hasPub = 1;
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        slhdsa->hasPriv = 1;
        /* The 4n FIPS 205 private key ends with the public key, so a decoded
         * private always carries it; confirm from the key's own flags. */
        slhdsa->hasPub =
            ((slhdsa->key.flags & WC_SLHDSA_FLAG_PUBLIC) != 0) ? 1 : 0;
    }

    OPENSSL_clear_free(data, len);

    if (ok && (!wp_slhdsa_dec_send_params(slhdsa, ctx->dataType, dataCb,
            dataCbArg))) {
        ok = 0;
    }

    if (!ok) {
        wp_slhdsa_free(slhdsa);
        /* Not our OID: report no error so the decoder chain keeps trying. */
        if (!decoded) {
            ok = 1;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the SLH-DSA key.
 *
 * SLH-DSA keys are large so the DER buffer is sized from a query-length call
 * (output == NULL) and then allocated, rather than using a fixed buffer.
 *
 * @param [in]      ctx        SLH-DSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      slhdsa     SLH-DSA key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode. Unused.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_slhdsa_encode(wp_SlhDsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    const wp_SlhDsa* slhdsa, const OSSL_PARAM* params, int selection,
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
    unsigned char* encData = NULL;
    size_t encLen = 0;
    unsigned char* srcData;
    size_t srcLen;
    unsigned char* pemData = NULL;
    size_t pemAllocLen = 0;
    int pemType = (ctx->format == WP_ENC_FORMAT_SPKI) ? PUBLICKEY_TYPE :
                                                        PKCS8_PRIVATEKEY_TYPE;
    int private = (ctx->format == WP_ENC_FORMAT_PKI) ||
                  (ctx->format == WP_ENC_FORMAT_EPKI);
    int locked = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PQC, "wp_slhdsa_encode");

    (void)params;
    (void)selection;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (out == NULL)) {
        ok = 0;
    }
    if (ok && (slhdsa == NULL)) {
        ok = 0;
    }
    if (ok && (wp_lock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa)) != 1)) {
        ok = 0;
    }
    else if (ok) {
        locked = 1;
    }

    if (ok && ((private && !slhdsa->hasPriv) ||
            (!private && !slhdsa->hasPub))) {
        ok = 0;
    }
    if (ok) {
        rc = ctx->encode((void*)&slhdsa->key, NULL, 0);
        if (rc <= 0) {
            ok = 0;
        }
        else {
            /* Buffer holds the plaintext PKCS #8 encoding; EPKI encrypts into
             * a separate buffer allocated later. */
            derAllocLen = (word32)rc + WP_SLHDSA_DER_SLACK;
        }
    }
    if (ok) {
        derData = (unsigned char*)OPENSSL_malloc(derAllocLen);
        if (derData == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        rc = ctx->encode((void*)&slhdsa->key, derData, derAllocLen);
        if (rc <= 0) {
            ok = 0;
        }
        else {
            derLen = (size_t)rc;
        }
    }
    if (locked) {
        wp_unlock(wp_slhdsa_get_mutex((wp_SlhDsa*)slhdsa));
        locked = 0;
    }
    /* By default the plaintext DER is the source for the output encoding. */
    srcData = derData;
    srcLen = derLen;
    /* A cipher on a PrivateKeyInfo encoder selects the encrypted form. */
    if (ok && ((ctx->format == WP_ENC_FORMAT_EPKI)
#ifdef WP_HAVE_PKCS8_ENC
            || ((ctx->format == WP_ENC_FORMAT_PKI) &&
                (ctx->cipherName != NULL))
#endif
            )) {
        pemType = PKCS8_ENC_PRIVATEKEY_TYPE;
        /* The PBES2 output is larger than the plaintext and must use a
         * separate buffer, so size it and encrypt into fresh memory. */
        if (!wp_encrypt_key_pkcs8_size(ctx->provCtx, ctx->cipher,
                (word32)derLen, &encLen)) {
            ok = 0;
        }
        if (ok) {
            encData = (unsigned char*)OPENSSL_malloc(encLen);
            if (encData == NULL) {
                ok = 0;
            }
        }
        if (ok && ((pwCb == NULL) ||
                !wp_encrypt_key_pkcs8(ctx->provCtx, ctx->cipher, derData,
                    (word32)derLen, encData, &encLen, pwCb, pwCbArg))) {
            ok = 0;
        }
        if (ok) {
            srcData = encData;
            srcLen = encLen;
        }
    }

    if (ok && (ctx->encoding == WP_FORMAT_DER)) {
        keyData = srcData;
        keyLen = srcLen;
    }
    else if (ok && (ctx->encoding == WP_FORMAT_PEM)) {
        rc = wc_DerToPemEx(srcData, (word32)srcLen, NULL, 0, NULL, pemType);
        if (rc <= 0) {
            ok = 0;
        }
        if (ok) {
            pemAllocLen = (size_t)rc;
            pemData = (unsigned char*)OPENSSL_malloc(pemAllocLen);
            if (pemData == NULL) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_DerToPemEx(srcData, (word32)srcLen, pemData,
                (word32)pemAllocLen, NULL, pemType);
            if (rc <= 0) {
                ok = 0;
            }
        }
        if (ok) {
            keyLen = (size_t)rc;
            keyData = pemData;
        }
    }
    if (ok) {
        rc = BIO_write(out, keyData, (int)keyLen);
        if (rc != (int)keyLen) {
            ok = 0;
        }
    }

    if (private) {
        if (derData != NULL) {
            OPENSSL_clear_free(derData, derAllocLen);
        }
        OPENSSL_clear_free(pemData, pemAllocLen);
    }
    else {
        OPENSSL_free(derData);
        OPENSSL_free(pemData);
    }
    OPENSSL_clear_free(encData, encLen);
    BIO_free(out);
    WOLFPROV_LEAVE(WP_LOG_COMP_PQC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the SLH-DSA key object.
 *
 * @param [in] ctx          SLH-DSA encoder/decoder context object.
 * @param [in] slhdsa       SLH-DSA key object.
 * @param [in] size         Size of key object.
 * @param [in] exportCb     Callback to export key.
 * @param [in] exportCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_slhdsa_export_object(wp_SlhDsaEncDecCtx* ctx,
    const void* reference, size_t size, OSSL_CALLBACK* exportCb,
    void* exportCbArg)
{
    wp_SlhDsa* slhdsa;
    int selection;
    int ok;

    if ((ctx == NULL) || (reference == NULL) ||
            (size != sizeof(slhdsa))) {
        return 0;
    }
    slhdsa = *(wp_SlhDsa* const*)reference;
    if (slhdsa == NULL) {
        return 0;
    }
    selection = ctx->selection;
    if (selection == 0) {
        selection = OSSL_KEYMGMT_SELECT_ALL;
    }
    if (!wp_slhdsa_up_ref(slhdsa)) {
        return 0;
    }
    ok = wp_slhdsa_export(slhdsa, selection, exportCb, exportCbArg);
    wp_slhdsa_free(slhdsa);
    return ok;
}

/**
 * Return whether the SPKI decoder/encoder handles this part of the key.
 *
 * @param [in] provCtx    Provider context. Unused.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported, 0 when not.
 */
static int wp_slhdsa_spki_does_selection(WOLFPROV_CTX* provCtx, int selection)
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
 * Decode a public SLH-DSA key from SPKI DER.
 *
 * @param [in]      input     Buffer holding SPKI DER data.
 * @param [in, out] inOutIdx  On in, index into buffer. On out, index after.
 * @param [in, out] key       SLH-DSA key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success, negative on error.
 */
static int wp_slhdsa_pub_decode(const byte* input, word32* inOutIdx, void* key,
    word32 inSz)
{
    SlhDsaKey* slhdsa = (SlhDsaKey*)key;

    if ((input == NULL) || (inOutIdx == NULL) || (slhdsa == NULL) ||
            (slhdsa->params == NULL) || (*inOutIdx > inSz)) {
        return BAD_FUNC_ARG;
    }

    /* The backend first accepts a window of exactly 2n bytes as a raw public
     * key. This decoder advertises SubjectPublicKeyInfo, whose DER wrapper
     * necessarily makes it larger than 2n. Reject the raw-sized window so
     * the backend's normal SPKI parser validates the complete structure and
     * algorithm identifier. */
    if ((inSz - *inOutIdx) == (word32)(2 * slhdsa->params->n)) {
        return ASN_PARSE_E;
    }

    return wc_SlhDsaKey_PublicKeyDecode(input, inOutIdx, slhdsa, inSz);
}

/**
 * Encode the public part of an SLH-DSA key as SubjectPublicKeyInfo DER.
 *
 * Pass NULL for output to query the required length.
 *
 * @param [in]  key     SLH-DSA key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  inLen   Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success, negative on error.
 */
static int wp_slhdsa_pub_encode(void* key, byte* output, word32 inLen)
{
    return wc_SlhDsaKey_PublicKeyToDer((SlhDsaKey*)key, output, inLen, 1);
}

#ifdef WP_HAVE_SLHDSA_PRIVATE
/**
 * Return whether the PKI decoder/encoder handles this part of the key.
 *
 * @param [in] provCtx    Provider context. Unused.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported, 0 when not.
 */
static int wp_slhdsa_pki_does_selection(WOLFPROV_CTX* provCtx, int selection)
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
 * Decode a private SLH-DSA key from PKCS8 PrivateKeyInfo DER.
 *
 * @param [in]      input     Buffer holding PKCS8 DER data.
 * @param [in, out] inOutIdx  On in, index into buffer. On out, index after.
 * @param [in, out] key       SLH-DSA key object.
 * @param [in]      inSz      Length of buffer in bytes.
 * @return  0 on success, negative on error.
 */
static int wp_slhdsa_priv_decode(const byte* input, word32* inOutIdx,
    void* key, word32 inSz)
{
    return wc_SlhDsaKey_PrivateKeyDecode(input, inOutIdx, (SlhDsaKey*)key,
        inSz);
}

/**
 * Encode the private part of an SLH-DSA key as PKCS8 PrivateKeyInfo DER.
 *
 * Pass NULL for output to query the required length.
 *
 * @param [in]  key     SLH-DSA key object.
 * @param [out] output  Buffer to put encoded data in.
 * @param [in]  inLen   Size of buffer in bytes.
 * @return  Size of encoded data in bytes on success, negative on error.
 */
static int wp_slhdsa_priv_encode(void* key, byte* output, word32 inLen)
{
    /* RFC 9909 defines no private-only form for SLH-DSA: the 4n private key
     * already contains the public half, so KeyToDer is the whole encoding. */
    return wc_SlhDsaKey_KeyToDer((SlhDsaKey*)key, output, inLen);
}
#endif /* WP_HAVE_SLHDSA_PRIVATE */

static void* wp_slhdsa_enc_import_object(wp_SlhDsaEncDecCtx* ctx,
    int selection, const OSSL_PARAM params[])
{
    wp_SlhDsa* slhdsa = ctx->newKey(ctx->provCtx);

    if ((slhdsa != NULL) && !wp_slhdsa_import(slhdsa, selection, params)) {
        wp_slhdsa_free(slhdsa);
        slhdsa = NULL;
    }
    return slhdsa;
}

/*
 * Per-parameter-set encoder/decoder context constructors and dispatch tables.
 */

#define IMPLEMENT_SLHDSA_SPKI_DECODER(alg, dataType)                           \
static wp_SlhDsaEncDecCtx* wp_##alg##_spki_dec_new(WOLFPROV_CTX* provCtx)      \
{                                                                              \
    return wp_slhdsa_enc_dec_new(provCtx, wp_##alg##_new, dataType,            \
        WP_ENC_FORMAT_SPKI, 0, wp_slhdsa_pub_decode, NULL);                    \
}                                                                              \
const OSSL_DISPATCH wp_##alg##_spki_decoder_functions[] = {                    \
    { OSSL_FUNC_DECODER_NEWCTX,        (DFUNC)wp_##alg##_spki_dec_new       }, \
    { OSSL_FUNC_DECODER_FREECTX,       (DFUNC)wp_slhdsa_enc_dec_free        }, \
    { OSSL_FUNC_DECODER_DOES_SELECTION,                                        \
                                       (DFUNC)wp_slhdsa_spki_does_selection }, \
    { OSSL_FUNC_DECODER_DECODE,        (DFUNC)wp_slhdsa_decode              }, \
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (DFUNC)wp_slhdsa_export_object       }, \
    { 0, NULL }                                                                \
};

#ifdef WP_HAVE_SLHDSA_PRIVATE
#define IMPLEMENT_SLHDSA_PKI_DECODER(alg, dataType)                            \
static wp_SlhDsaEncDecCtx* wp_##alg##_pki_dec_new(WOLFPROV_CTX* provCtx)       \
{                                                                              \
    return wp_slhdsa_enc_dec_new(provCtx, wp_##alg##_new, dataType,            \
        WP_ENC_FORMAT_PKI, 0, wp_slhdsa_priv_decode, NULL);                    \
}                                                                              \
const OSSL_DISPATCH wp_##alg##_pki_decoder_functions[] = {                     \
    { OSSL_FUNC_DECODER_NEWCTX,        (DFUNC)wp_##alg##_pki_dec_new        }, \
    { OSSL_FUNC_DECODER_FREECTX,       (DFUNC)wp_slhdsa_enc_dec_free        }, \
    { OSSL_FUNC_DECODER_DOES_SELECTION,                                        \
                                       (DFUNC)wp_slhdsa_pki_does_selection  }, \
    { OSSL_FUNC_DECODER_DECODE,        (DFUNC)wp_slhdsa_decode              }, \
    { OSSL_FUNC_DECODER_EXPORT_OBJECT, (DFUNC)wp_slhdsa_export_object       }, \
    { 0, NULL }                                                                \
};
#else
#define IMPLEMENT_SLHDSA_PKI_DECODER(alg, dataType)
#endif

#define IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, fmt, enc, dsel)                    \
static wp_SlhDsaEncDecCtx* wp_##alg##_##fmt##_##enc##_enc_new(                 \
    WOLFPROV_CTX* provCtx)                                                     \
{                                                                              \
    return wp_slhdsa_enc_dec_new(provCtx, wp_##alg##_new, NULL,                \
        WP_ENC_FORMAT_##fmt##_VAL, WP_FORMAT_##enc##_VAL, NULL,                \
        WP_SLHDSA_ENC_##fmt##_ENCODE);                                         \
}                                                                              \
const OSSL_DISPATCH wp_##alg##_##fmt##_##enc##_encoder_functions[] = {         \
    { OSSL_FUNC_ENCODER_NEWCTX,                                                \
        (DFUNC)wp_##alg##_##fmt##_##enc##_enc_new                   },         \
    { OSSL_FUNC_ENCODER_FREECTX,       (DFUNC)wp_slhdsa_enc_dec_free        }, \
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                                   \
                            (DFUNC)wp_slhdsa_enc_dec_settable_ctx_params    }, \
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                        \
                            (DFUNC)wp_slhdsa_enc_dec_set_ctx_params         }, \
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)dsel                        },  \
    { OSSL_FUNC_ENCODER_ENCODE,        (DFUNC)wp_slhdsa_encode              }, \
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                     \
                                (DFUNC)wp_slhdsa_enc_import_object          }, \
    { OSSL_FUNC_ENCODER_FREE_OBJECT,   (DFUNC)wp_slhdsa_free                }, \
    { 0, NULL }                                                                \
};

/* Encode-function selectors for the table macro, mapping the lower-case token
 * pasted into each table name onto its format/encoding enum value. */
#define WP_ENC_FORMAT_spki_VAL      WP_ENC_FORMAT_SPKI
#define WP_ENC_FORMAT_pki_VAL       WP_ENC_FORMAT_PKI
#define WP_ENC_FORMAT_epki_VAL      WP_ENC_FORMAT_EPKI
#define WP_FORMAT_der_VAL           WP_FORMAT_DER
#define WP_FORMAT_pem_VAL           WP_FORMAT_PEM
#define WP_SLHDSA_ENC_spki_ENCODE   wp_slhdsa_pub_encode
#ifdef WP_HAVE_SLHDSA_PRIVATE
#define WP_SLHDSA_ENC_pki_ENCODE    wp_slhdsa_priv_encode
#define WP_SLHDSA_ENC_epki_ENCODE   wp_slhdsa_priv_encode
#endif

#ifdef WP_HAVE_SLHDSA_PRIVATE
#define IMPLEMENT_SLHDSA_PRIVATE_ENCODERS(alg)                                 \
    IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, pki, der,                              \
        wp_slhdsa_pki_does_selection)                                          \
    IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, pki, pem,                              \
        wp_slhdsa_pki_does_selection)                                          \
    IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, epki, der,                             \
        wp_slhdsa_pki_does_selection)                                          \
    IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, epki, pem,                             \
        wp_slhdsa_pki_does_selection)
#else
#define IMPLEMENT_SLHDSA_PRIVATE_ENCODERS(alg)
#endif

#define IMPLEMENT_SLHDSA_ENC_DEC(alg, dataType)                                \
    IMPLEMENT_SLHDSA_SPKI_DECODER(alg, dataType)                               \
    IMPLEMENT_SLHDSA_PKI_DECODER(alg, dataType)                                \
    IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, spki, der,                             \
        wp_slhdsa_spki_does_selection)                                         \
    IMPLEMENT_SLHDSA_ENCODER_TABLE(alg, spki, pem,                             \
        wp_slhdsa_spki_does_selection)                                         \
    IMPLEMENT_SLHDSA_PRIVATE_ENCODERS(alg)

#ifdef WP_HAVE_SLH_DSA_SHAKE_128S
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_shake_128s, "SLH-DSA-SHAKE-128s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_128F
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_shake_128f, "SLH-DSA-SHAKE-128f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192S
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_shake_192s, "SLH-DSA-SHAKE-192s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_192F
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_shake_192f, "SLH-DSA-SHAKE-192f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256S
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_shake_256s, "SLH-DSA-SHAKE-256s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHAKE_256F
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_shake_256f, "SLH-DSA-SHAKE-256f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128S
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_sha2_128s, "SLH-DSA-SHA2-128s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_128F
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_sha2_128f, "SLH-DSA-SHA2-128f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192S
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_sha2_192s, "SLH-DSA-SHA2-192s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_192F
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_sha2_192f, "SLH-DSA-SHA2-192f")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256S
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_sha2_256s, "SLH-DSA-SHA2-256s")
#endif
#ifdef WP_HAVE_SLH_DSA_SHA2_256F
IMPLEMENT_SLHDSA_ENC_DEC(slhdsa_sha2_256f, "SLH-DSA-SHA2-256f")
#endif

#endif /* WP_HAVE_SLHDSA */
