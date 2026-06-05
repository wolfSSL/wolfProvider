/* wp_mlx_kmgmt.c
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
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_MLKEM

#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>

/** Supported selections (key parts) in this key manager. */
#define WP_MLX_POSSIBLE_SELECTIONS                                             \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/** Classical component is X25519. */
#define WP_MLX_CLASSICAL_X25519     0
/** Classical component is an EC (NIST prime) curve. */
#define WP_MLX_CLASSICAL_ECC        1

/**
 * Per-group hybrid variant data.
 *
 * Matches OpenSSL's hybrid_vtable so the concatenated key_share interoperates.
 */
const wp_MlxData mlxX25519Mlkem768Data = {
    WP_MLX_CLASSICAL_X25519,
    0,
    WC_ML_KEM_768,
    WC_ML_KEM_768_PUBLIC_KEY_SIZE,
    WC_ML_KEM_768_PRIVATE_KEY_SIZE,
    WC_ML_KEM_768_CIPHER_TEXT_SIZE,
    CURVE25519_PUB_KEY_SIZE,
    CURVE25519_KEYSIZE,
    CURVE25519_KEYSIZE,
    0,
    192,
    "X25519MLKEM768"
};

const wp_MlxData mlxSecP256r1Mlkem768Data = {
    WP_MLX_CLASSICAL_ECC,
    ECC_SECP256R1,
    WC_ML_KEM_768,
    WC_ML_KEM_768_PUBLIC_KEY_SIZE,
    WC_ML_KEM_768_PRIVATE_KEY_SIZE,
    WC_ML_KEM_768_CIPHER_TEXT_SIZE,
    65,
    32,
    32,
    1,
    192,
    "SecP256r1MLKEM768"
};

const wp_MlxData mlxSecP384r1Mlkem1024Data = {
    WP_MLX_CLASSICAL_ECC,
    ECC_SECP384R1,
    WC_ML_KEM_1024,
    WC_ML_KEM_1024_PUBLIC_KEY_SIZE,
    WC_ML_KEM_1024_PRIVATE_KEY_SIZE,
    WC_ML_KEM_1024_CIPHER_TEXT_SIZE,
    97,
    48,
    48,
    1,
    256,
    "SecP384r1MLKEM1024"
};

/**
 * Hybrid (ML-KEM + classical) key object.
 */
struct wp_Mlx {
    /** wolfSSL ML-KEM key. */
    MlKemKey mlkem;
    /** Classical key (X25519 or ECC, selected by variant). */
    union {
        curve25519_key x25519;
        ecc_key ecc;
    } classical;
    /** Per-group variant data. */
    const wp_MlxData* data;

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
    /** Classical key object has been initialized. */
    unsigned int classicalInit:1;
};

typedef struct wp_Mlx wp_Mlx;

/**
 * Hybrid key generation context.
 */
typedef struct wp_MlxGenCtx {
    /** wolfSSL random number generator. */
    WC_RNG rng;
    /** Per-group variant data. */
    const wp_MlxData* data;
    /** Provider context. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to generate. */
    int selection;
} wp_MlxGenCtx;


/**
 * Get the wolfSSL ML-KEM key from the hybrid object.
 *
 * @param [in] mlx  Hybrid key object.
 * @return  Pointer to wolfSSL MlKemKey, returned as void*.
 */
void* wp_mlx_get_mlkem_key(wp_Mlx* mlx)
{
    return &mlx->mlkem;
}

/**
 * Get the classical (X25519/ECC) wolfSSL key from the hybrid object.
 *
 * @param [in] mlx  Hybrid key object.
 * @return  Pointer to wolfSSL classical key, returned as void*.
 */
void* wp_mlx_get_classical_key(wp_Mlx* mlx)
{
    return &mlx->classical;
}

/**
 * Get the per-group variant data from the hybrid object.
 *
 * @param [in] mlx  Hybrid key object.
 * @return  Pointer to variant data.
 */
const wp_MlxData* wp_mlx_get_data(const wp_Mlx* mlx)
{
    return mlx->data;
}

/**
 * Whether the hybrid key has a usable public key.
 *
 * @param [in] mlx  Hybrid key object.
 * @return  1 when a public key is available, 0 otherwise.
 */
int wp_mlx_has_pub(const wp_Mlx* mlx)
{
    return (mlx != NULL) && mlx->hasPub;
}

/**
 * Whether the hybrid key has a usable private key.
 *
 * @param [in] mlx  Hybrid key object.
 * @return  1 when a private key is available, 0 otherwise.
 */
int wp_mlx_has_priv(const wp_Mlx* mlx)
{
    return (mlx != NULL) && mlx->hasPriv;
}

/**
 * Initialize the classical wolfSSL key object for the variant.
 *
 * @param [in, out] mlx  Hybrid key object.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_classical_init(wp_Mlx* mlx)
{
    int rc;

    if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
        rc = wc_curve25519_init(&mlx->classical.x25519);
    }
    else {
        rc = wc_ecc_init(&mlx->classical.ecc);
    }
    if (rc == 0) {
        mlx->classicalInit = 1;
    }
    return rc;
}

/**
 * Free the classical wolfSSL key object.
 *
 * @param [in, out] mlx  Hybrid key object.
 */
static void wp_mlx_classical_free(wp_Mlx* mlx)
{
    if (mlx->classicalInit) {
        if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
            wc_curve25519_free(&mlx->classical.x25519);
        }
        else {
            wc_ecc_free(&mlx->classical.ecc);
        }
        mlx->classicalInit = 0;
    }
}

/**
 * Increment reference count for key.
 *
 * @param [in, out] mlx  Hybrid key object.
 * @return  1 on success, 0 on failure.
 */
int wp_mlx_up_ref(wp_Mlx* mlx)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&mlx->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        mlx->refCnt++;
        wc_UnLockMutex(&mlx->mutex);
    }
    return ok;
#else
    mlx->refCnt++;
    return 1;
#endif
}

/**
 * Create a new hybrid key object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] data     Per-group variant data.
 * @return  New hybrid key object on success, NULL on failure.
 */
static wp_Mlx* wp_mlx_new(WOLFPROV_CTX* provCtx, const wp_MlxData* data)
{
    wp_Mlx* mlx = NULL;

    if (wolfssl_prov_is_running() && (data != NULL)) {
        mlx = (wp_Mlx*)OPENSSL_zalloc(sizeof(*mlx));
    }
    if (mlx != NULL) {
        int ok = 1;
        int rc;

        rc = wc_MlKemKey_Init(&mlx->mlkem, data->mlkemType, NULL,
            INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            mlx->data = data;
            rc = wp_mlx_classical_init(mlx);
            if (rc != 0) {
                wc_MlKemKey_Free(&mlx->mlkem);
                ok = 0;
            }
        }
    #ifndef WP_SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&mlx->mutex);
            if (rc != 0) {
                wp_mlx_classical_free(mlx);
                wc_MlKemKey_Free(&mlx->mlkem);
                ok = 0;
            }
        }
    #endif
        if (ok) {
            mlx->provCtx = provCtx;
            mlx->refCnt  = 1;
        }
        if (!ok) {
            OPENSSL_free(mlx);
            mlx = NULL;
        }
    }

    return mlx;
}

/**
 * Dispose of hybrid key object.
 *
 * @param [in, out] mlx  Hybrid key object. May be NULL.
 */
void wp_mlx_free(wp_Mlx* mlx)
{
    if (mlx != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&mlx->mutex);
        cnt = --mlx->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&mlx->mutex);
        }
    #else
        cnt = --mlx->refCnt;
    #endif

        if (cnt == 0) {
        #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&mlx->mutex);
        #endif
            wp_mlx_classical_free(mlx);
            wc_MlKemKey_Free(&mlx->mlkem);
            OPENSSL_free(mlx);
        }
    }
}

/**
 * Encode the classical public key into the supplied buffer.
 *
 * X25519 keys are exported little-endian to match OpenSSL; EC keys use the
 * uncompressed X9.63 point encoding.
 *
 * @param [in]      mlx  Hybrid key object.
 * @param [out]     out  Buffer to hold the public key.
 * @param [in, out] len  On in, buffer size; on out, bytes written.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_classical_export_pub(wp_Mlx* mlx, unsigned char* out,
    word32* len)
{
    int rc;

    if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
        rc = wc_curve25519_export_public_ex(&mlx->classical.x25519, out, len,
            EC25519_LITTLE_ENDIAN);
    }
    else {
        rc = wc_ecc_export_x963(&mlx->classical.ecc, out, len);
    }
    return rc;
}

/**
 * Decode the classical public key from the supplied buffer.
 *
 * @param [in, out] mlx  Hybrid key object.
 * @param [in]      in   Encoded public key.
 * @param [in]      len  Length of encoded public key.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_classical_import_pub(wp_Mlx* mlx, const unsigned char* in,
    word32 len)
{
    int rc;

    if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
        rc = wc_curve25519_import_public_ex(in, len, &mlx->classical.x25519,
            EC25519_LITTLE_ENDIAN);
    }
    else {
        rc = wc_ecc_import_x963(in, len, &mlx->classical.ecc);
    }
    return rc;
}

/**
 * Encode the classical private key into the supplied buffer.
 *
 * @param [in]      mlx  Hybrid key object.
 * @param [out]     out  Buffer to hold the private key.
 * @param [in, out] len  On in, buffer size; on out, bytes written.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_classical_export_priv(wp_Mlx* mlx, unsigned char* out,
    word32* len)
{
    int rc;

    if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
        rc = wc_curve25519_export_private_raw_ex(&mlx->classical.x25519, out,
            len, EC25519_LITTLE_ENDIAN);
    }
    else {
        rc = wc_ecc_export_private_only(&mlx->classical.ecc, out, len);
    }
    return rc;
}

/**
 * Duplicate hybrid key object.
 *
 * @param [in] src        Source hybrid key object.
 * @param [in] selection  Parts of key (public/private) to duplicate.
 * @return  New hybrid key object on success, NULL on failure.
 */
static wp_Mlx* wp_mlx_dup(const wp_Mlx* src, int selection)
{
    wp_Mlx* dst = NULL;
    unsigned char* mPubBuf = NULL;
    unsigned char* mPrivBuf = NULL;
    unsigned char* cPubBuf = NULL;
    unsigned char* cPrivBuf = NULL;
    word32 len;
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

    dst = wp_mlx_new(src->provCtx, src->data);
    if (dst == NULL) {
        return NULL;
    }

    if (dupPub) {
        len = src->data->mlkemPubSize;
        mPubBuf = (unsigned char*)OPENSSL_malloc(len);
        cPubBuf = (unsigned char*)OPENSSL_malloc(src->data->classicalPubSize);
        if ((mPubBuf == NULL) || (cPubBuf == NULL)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePublicKey((MlKemKey*)&src->mlkem, mPubBuf,
                len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlKemKey_DecodePublicKey(&dst->mlkem, mPubBuf, len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            len = src->data->classicalPubSize;
            rc = wp_mlx_classical_export_pub((wp_Mlx*)src, cPubBuf, &len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wp_mlx_classical_import_pub(dst, cPubBuf, len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            dst->hasPub = 1;
        }
    }

    if (ok && dupPriv) {
        len = src->data->mlkemPrivSize;
        mPrivBuf = (unsigned char*)OPENSSL_malloc(len);
        cPrivBuf = (unsigned char*)OPENSSL_malloc(src->data->classicalPrivSize);
        if ((mPrivBuf == NULL) || (cPrivBuf == NULL)) {
            ok = 0;
        }
        if (ok) {
            rc = wc_MlKemKey_EncodePrivateKey((MlKemKey*)&src->mlkem, mPrivBuf,
                len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = wc_MlKemKey_DecodePrivateKey(&dst->mlkem, mPrivBuf, len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            len = src->data->classicalPrivSize;
            rc = wp_mlx_classical_export_priv((wp_Mlx*)src, cPrivBuf, &len);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            if (src->data->classicalType == WP_MLX_CLASSICAL_X25519) {
                rc = wc_curve25519_import_private_ex(cPrivBuf, len,
                    &dst->classical.x25519, EC25519_LITTLE_ENDIAN);
            }
            else {
                rc = wc_ecc_import_private_key_ex(cPrivBuf, len, NULL, 0,
                    &dst->classical.ecc, src->data->curveId);
            }
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            dst->hasPriv = 1;
        }
    }

    OPENSSL_free(mPubBuf);
    OPENSSL_free(cPubBuf);
    if (mPrivBuf != NULL) {
        OPENSSL_clear_free(mPrivBuf, src->data->mlkemPrivSize);
    }
    if (cPrivBuf != NULL) {
        OPENSSL_clear_free(cPrivBuf, src->data->classicalPrivSize);
    }

    if (!ok) {
        wp_mlx_free(dst);
        return NULL;
    }
    return dst;
}

/**
 * Load a hybrid key from a reference.
 *
 * @param [in, out] pMlx  Pointer to a hybrid key reference.
 * @param [in]      size  Size of reference object. Unused.
 * @return  Hybrid key object on success.
 */
static const wp_Mlx* wp_mlx_load(const wp_Mlx** pMlx, size_t size)
{
    const wp_Mlx* mlx = *pMlx;
    (void)size;
    *pMlx = NULL;
    return mlx;
}

/**
 * Check hybrid key object has the components required.
 *
 * @param [in] mlx        Hybrid key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_has(const wp_Mlx* mlx, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (mlx == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok &= mlx->hasPub;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= mlx->hasPriv;
    }
    return ok;
}

/**
 * Compare two hybrid keys.
 *
 * @param [in] a          First hybrid key.
 * @param [in] b          Second hybrid key.
 * @param [in] selection  Parts of key to compare.
 * @return  1 if match, 0 otherwise.
 */
static int wp_mlx_match(const wp_Mlx* a, const wp_Mlx* b, int selection)
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
    if (a->data != b->data) {
        return 0;
    }
    /* Compare the public components for either a public- or private-key
     * selection: the public uniquely identifies the key, so this avoids a
     * fail-open where a private-only match would return equal without
     * comparing anything. */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        lenA = a->data->mlkemPubSize + a->data->classicalPubSize;
        bufA = (unsigned char*)OPENSSL_malloc(lenA);
        bufB = (unsigned char*)OPENSSL_malloc(lenA);
        if ((bufA == NULL) || (bufB == NULL)) {
            ok = 0;
        }
        if (ok) {
            lenA = a->data->mlkemPubSize;
            rc = wc_MlKemKey_EncodePublicKey((MlKemKey*)&a->mlkem, bufA, lenA);
            if (rc == 0) {
                rc = wc_MlKemKey_EncodePublicKey((MlKemKey*)&b->mlkem, bufB,
                    lenA);
            }
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok && (XMEMCMP(bufA, bufB, lenA) != 0)) {
            ok = 0;
        }
        if (ok) {
            lenA = a->data->classicalPubSize;
            lenB = b->data->classicalPubSize;
            rc = wp_mlx_classical_export_pub((wp_Mlx*)a, bufA, &lenA);
            if (rc == 0) {
                rc = wp_mlx_classical_export_pub((wp_Mlx*)b, bufB, &lenB);
            }
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
 * Import hybrid key material from the concatenated (slot-order) encoding.
 *
 * @param [in, out] mlx  Hybrid key object.
 * @param [in]      pub  Concatenated public key (or NULL).
 * @param [in]      priv Concatenated private key (or NULL).
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_load_keys(wp_Mlx* mlx, const unsigned char* pub,
    const unsigned char* priv)
{
    int ok = 1;
    int rc;
    size_t mlkemOff;
    size_t classicalOff;
    int slot = mlx->data->mlkemSlot;

    if (priv != NULL) {
        mlkemOff = (size_t)slot * mlx->data->classicalPrivSize;
        classicalOff = (size_t)(1 - slot) * mlx->data->mlkemPrivSize;
        rc = wc_MlKemKey_DecodePrivateKey(&mlx->mlkem, priv + mlkemOff,
            mlx->data->mlkemPrivSize);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
                rc = wc_curve25519_import_private_ex(priv + classicalOff,
                    mlx->data->classicalPrivSize, &mlx->classical.x25519,
                    EC25519_LITTLE_ENDIAN);
            }
            else {
                rc = wc_ecc_import_private_key_ex(priv + classicalOff,
                    mlx->data->classicalPrivSize, NULL, 0, &mlx->classical.ecc,
                    mlx->data->curveId);
                if (rc == 0) {
                    /* A private-only ECC import leaves the key without a
                     * public point; derive it so the hybrid public can be
                     * exported (curve25519 derives its public lazily on
                     * export, so it needs no equivalent step). */
                    rc = wc_ecc_make_pub(&mlx->classical.ecc, NULL);
                }
            }
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            mlx->hasPriv = 1;
            mlx->hasPub = 1;
        }
    }
    else if (pub != NULL) {
        mlkemOff = (size_t)slot * mlx->data->classicalPubSize;
        classicalOff = (size_t)(1 - slot) * mlx->data->mlkemPubSize;
        rc = wc_MlKemKey_DecodePublicKey(&mlx->mlkem, pub + mlkemOff,
            mlx->data->mlkemPubSize);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = wp_mlx_classical_import_pub(mlx, pub + classicalOff,
                mlx->data->classicalPubSize);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            mlx->hasPub = 1;
        }
    }
    else {
        ok = 0;
    }

    if (!ok) {
        mlx->hasPub = 0;
        mlx->hasPriv = 0;
    }
    return ok;
}

/**
 * Import a hybrid key from parameters.
 *
 * @param [in, out] mlx        Hybrid key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_import(wp_Mlx* mlx, int selection, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* privData = NULL;
    unsigned char* pubData = NULL;
    size_t privLen = 0;
    size_t pubLen = 0;

    if (!wolfssl_prov_is_running() || (mlx == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_MLX_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PRIV_KEY,
                &privData, &privLen)) {
            ok = 0;
        }
        if (ok && (privData != NULL) && (privLen !=
                (size_t)mlx->data->mlkemPrivSize +
                mlx->data->classicalPrivSize)) {
            ok = 0;
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        if (!wp_params_get_octet_string_ptr(params, OSSL_PKEY_PARAM_PUB_KEY,
                &pubData, &pubLen)) {
            ok = 0;
        }
        if (ok && (pubData != NULL) && (pubLen !=
                (size_t)mlx->data->mlkemPubSize +
                mlx->data->classicalPubSize)) {
            ok = 0;
        }
    }
    if (ok && (privData == NULL) && (pubData == NULL)) {
        ok = 0;
    }
    if (ok) {
        ok = wp_mlx_load_keys(mlx, pubData, privData);
    }
    return ok;
}

/** Hybrid key parameters for import/export type queries. */
static const OSSL_PARAM wp_mlx_key_params[] = {
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

static const OSSL_PARAM* wp_mlx_key_types(int selection)
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
    return &wp_mlx_key_params[idx];
}

static const OSSL_PARAM* wp_mlx_import_types(int selection)
{
    return wp_mlx_key_types(selection);
}

static const OSSL_PARAM* wp_mlx_export_types(int selection)
{
    return wp_mlx_key_types(selection);
}

/**
 * Build the concatenated (slot-order) public key encoding.
 *
 * @param [in]  mlx  Hybrid key object.
 * @param [out] out  Buffer of mlkemPubSize + classicalPubSize bytes.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_encode_pub(wp_Mlx* mlx, unsigned char* out)
{
    int rc;
    word32 len;
    int slot = mlx->data->mlkemSlot;
    size_t mlkemOff = (size_t)slot * mlx->data->classicalPubSize;
    size_t classicalOff = (size_t)(1 - slot) * mlx->data->mlkemPubSize;

    rc = wc_MlKemKey_EncodePublicKey(&mlx->mlkem, out + mlkemOff,
        mlx->data->mlkemPubSize);
    if (rc == 0) {
        len = mlx->data->classicalPubSize;
        rc = wp_mlx_classical_export_pub(mlx, out + classicalOff, &len);
    }
    return rc;
}

/**
 * Build the concatenated (slot-order) private key encoding.
 *
 * @param [in]  mlx  Hybrid key object.
 * @param [out] out  Buffer of mlkemPrivSize + classicalPrivSize bytes.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_encode_priv(wp_Mlx* mlx, unsigned char* out)
{
    int rc;
    word32 len;
    int slot = mlx->data->mlkemSlot;
    size_t mlkemOff = (size_t)slot * mlx->data->classicalPrivSize;
    size_t classicalOff = (size_t)(1 - slot) * mlx->data->mlkemPrivSize;

    rc = wc_MlKemKey_EncodePrivateKey(&mlx->mlkem, out + mlkemOff,
        mlx->data->mlkemPrivSize);
    if (rc == 0) {
        len = mlx->data->classicalPrivSize;
        rc = wp_mlx_classical_export_priv(mlx, out + classicalOff, &len);
    }
    return rc;
}

/**
 * Export hybrid key data via callback.
 *
 * @param [in] mlx        Hybrid key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Callback to receive constructed parameters.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_export(wp_Mlx* mlx, int selection, OSSL_CALLBACK* paramCb,
    void* cbArg)
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

    if (!wolfssl_prov_is_running() || (mlx == NULL)) {
        ok = 0;
    }
    XMEMSET(params, 0, sizeof(params));

    if (ok && expPub && mlx->hasPub) {
        pubLen = mlx->data->mlkemPubSize + mlx->data->classicalPubSize;
        pubBuf = (unsigned char*)OPENSSL_malloc(pubLen);
        if (pubBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wp_mlx_encode_pub(mlx, pubBuf);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            wp_param_set_octet_string_ptr(&params[paramsSz++],
                OSSL_PKEY_PARAM_PUB_KEY, pubBuf, pubLen);
        }
    }
    if (ok && expPriv && mlx->hasPriv) {
        privLen = mlx->data->mlkemPrivSize + mlx->data->classicalPrivSize;
        privBuf = (unsigned char*)OPENSSL_malloc(privLen);
        if (privBuf == NULL) {
            ok = 0;
        }
        if (ok) {
            rc = wp_mlx_encode_priv(mlx, privBuf);
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
    if (privBuf != NULL) {
        OPENSSL_clear_free(privBuf, privLen);
    }
    return ok;
}

/**
 * Gettable parameters for hybrid key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of supported gettable parameters.
 */
static const OSSL_PARAM* wp_mlx_gettable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlx_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_mlx_supported_gettable_params;
}

/**
 * Fill an octet-string OSSL_PARAM with the concatenated public key.
 *
 * @param [in]      mlx  Hybrid key object.
 * @param [in, out] p    Parameter to populate.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_get_pub_param(wp_Mlx* mlx, OSSL_PARAM* p)
{
    int ok = 1;
    word32 outLen = mlx->data->mlkemPubSize + mlx->data->classicalPubSize;

    if (!mlx->hasPub) {
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
        if (wp_mlx_encode_pub(mlx, (unsigned char*)p->data) != 0) {
            ok = 0;
        }
        else {
            p->return_size = outLen;
        }
    }
    return ok;
}

/**
 * Get hybrid key parameters.
 *
 * @param [in]      mlx     Hybrid key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_get_params(wp_Mlx* mlx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    if (mlx == NULL) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if ((p != NULL) && !OSSL_PARAM_set_int(p,
            (int)(mlx->data->mlkemPubSize + mlx->data->classicalPubSize) * 8)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) &&
                !OSSL_PARAM_set_int(p, mlx->data->securityBits)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if ((p != NULL) && !OSSL_PARAM_set_int(p,
                (int)(mlx->data->mlkemCtSize + mlx->data->classicalPubSize))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            ok = wp_mlx_get_pub_param(mlx, p);
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p != NULL) {
            ok = wp_mlx_get_pub_param(mlx, p);
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            word32 outLen = mlx->data->mlkemPrivSize +
                mlx->data->classicalPrivSize;
            if (!mlx->hasPriv) {
                ok = 0;
            }
            else if (p->data == NULL) {
                p->return_size = outLen;
            }
            else if (p->data_size < outLen) {
                p->return_size = outLen;
                ok = 0;
            }
            else if (wp_mlx_encode_priv(mlx, (unsigned char*)p->data) != 0) {
                ok = 0;
            }
            else {
                p->return_size = outLen;
            }
        }
    }
    return ok;
}

/**
 * Settable parameters for hybrid key.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Settable parameter list.
 */
static const OSSL_PARAM* wp_mlx_settable_params(WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_mlx_supported_settable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_mlx_supported_settable_params;
}

/**
 * Set hybrid key parameters. Supports importing the peer's concatenated
 * key_share via the encoded public key.
 *
 * @param [in] mlx     Hybrid key object.
 * @param [in] params  Array of parameters.
 * @return  1 on success, 0 on failure.
 */
static int wp_mlx_set_params(wp_Mlx* mlx, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* data = NULL;
    size_t len = 0;

    if (mlx == NULL) {
        ok = 0;
    }
    if (ok && !wp_params_get_octet_string_ptr(params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &data, &len)) {
        ok = 0;
    }
    if (ok && (data != NULL)) {
        if (len != (size_t)mlx->data->mlkemPubSize +
                mlx->data->classicalPubSize) {
            ok = 0;
        }
        else {
            ok = wp_mlx_load_keys(mlx, data, NULL);
        }
    }
    return ok;
}

/*
 * Hybrid key generation
 */

/**
 * Create hybrid generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation. Unused.
 * @param [in] data       Per-group variant data.
 * @return  New generation context on success, NULL on failure.
 */
static wp_MlxGenCtx* wp_mlx_gen_init_base(WOLFPROV_CTX* provCtx, int selection,
    const OSSL_PARAM params[], const wp_MlxData* data)
{
    wp_MlxGenCtx* ctx = NULL;

    (void)params;

    if (wolfssl_prov_is_running() &&
            ((selection & WP_MLX_POSSIBLE_SELECTIONS) != 0)) {
        ctx = (wp_MlxGenCtx*)OPENSSL_zalloc(sizeof(*ctx));
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
 * Generate the classical (X25519/ECC) key pair.
 *
 * @param [in, out] mlx  Hybrid key object.
 * @param [in]      rng  RNG to use.
 * @return  0 on success, negative on failure.
 */
static int wp_mlx_classical_make_key(wp_Mlx* mlx, WC_RNG* rng)
{
    int rc;

    if (mlx->data->classicalType == WP_MLX_CLASSICAL_X25519) {
        rc = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE,
            &mlx->classical.x25519);
    }
    else {
        rc = wc_ecc_make_key_ex(rng, 0, &mlx->classical.ecc,
            mlx->data->curveId);
        if (rc == 0) {
            rc = wc_ecc_set_rng(&mlx->classical.ecc, rng);
        }
    }
    return rc;
}

/**
 * Generate a hybrid key pair (both ML-KEM and classical components).
 *
 * @param [in, out] ctx    Generation context.
 * @param [in]      osslcb Progress callback. Unused.
 * @param [in]      cbarg  Argument for callback. Unused.
 * @return  Hybrid key object on success, NULL on failure.
 */
static wp_Mlx* wp_mlx_gen(wp_MlxGenCtx* ctx, OSSL_CALLBACK* osslcb, void* cbarg)
{
    wp_Mlx* mlx;
    int keyPair = (ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;

    (void)osslcb;
    (void)cbarg;

    mlx = wp_mlx_new(ctx->provCtx, ctx->data);
    if ((mlx != NULL) && keyPair) {
        int rc;

        rc = wc_MlKemKey_MakeKey(&mlx->mlkem, &ctx->rng);
        if (rc == 0) {
            rc = wp_mlx_classical_make_key(mlx, &ctx->rng);
        }
        if (rc != 0) {
            wp_mlx_free(mlx);
            mlx = NULL;
        }
        else {
            mlx->hasPub = 1;
            mlx->hasPriv = 1;
        }
    }
    return mlx;
}

/**
 * Free hybrid generation context.
 *
 * @param [in, out] ctx  Generation context.
 */
static void wp_mlx_gen_cleanup(wp_MlxGenCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        OPENSSL_free(ctx);
    }
}

static int wp_mlx_gen_set_params(wp_MlxGenCtx* ctx, const OSSL_PARAM params[])
{
    (void)params;
    return ctx != NULL;
}

static const OSSL_PARAM* wp_mlx_gen_settable_params(wp_MlxGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    static OSSL_PARAM wp_mlx_gen_settable[] = {
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_mlx_gen_settable;
}

/* Map each hybrid key type to its KEM operation name so OpenSSL fetches the
 * matching KEM implementation without relying on fallback lookup. */
static const char* wp_mlx_x25519_query_operation_name(int op)
{
    (void)op;
    return WP_NAMES_X25519MLKEM768;
}

static const char* wp_mlx_p256_query_operation_name(int op)
{
    (void)op;
    return WP_NAMES_SECP256R1MLKEM768;
}

static const char* wp_mlx_p384_query_operation_name(int op)
{
    (void)op;
    return WP_NAMES_SECP384R1MLKEM1024;
}

/* Per-group new() and gen_init() trampolines. */

static wp_Mlx* wp_mlx_x25519_new(WOLFPROV_CTX* provCtx)
{
    return wp_mlx_new(provCtx, &mlxX25519Mlkem768Data);
}

static wp_Mlx* wp_mlx_p256_new(WOLFPROV_CTX* provCtx)
{
    return wp_mlx_new(provCtx, &mlxSecP256r1Mlkem768Data);
}

static wp_Mlx* wp_mlx_p384_new(WOLFPROV_CTX* provCtx)
{
    return wp_mlx_new(provCtx, &mlxSecP384r1Mlkem1024Data);
}

static wp_MlxGenCtx* wp_mlx_x25519_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mlx_gen_init_base(provCtx, selection, params,
        &mlxX25519Mlkem768Data);
}

static wp_MlxGenCtx* wp_mlx_p256_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mlx_gen_init_base(provCtx, selection, params,
        &mlxSecP256r1Mlkem768Data);
}

static wp_MlxGenCtx* wp_mlx_p384_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mlx_gen_init_base(provCtx, selection, params,
        &mlxSecP384r1Mlkem1024Data);
}

/*
 * Dispatch tables
 */

#define IMPLEMENT_MLX_KEYMGMT_DISPATCH(alg)                                    \
const OSSL_DISPATCH wp_mlx_##alg##_keymgmt_functions[] = {                     \
    { OSSL_FUNC_KEYMGMT_NEW,             (DFUNC)wp_mlx_##alg##_new        },    \
    { OSSL_FUNC_KEYMGMT_FREE,            (DFUNC)wp_mlx_free               },    \
    { OSSL_FUNC_KEYMGMT_DUP,             (DFUNC)wp_mlx_dup                },    \
    { OSSL_FUNC_KEYMGMT_GEN_INIT,        (DFUNC)wp_mlx_##alg##_gen_init   },    \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,  (DFUNC)wp_mlx_gen_set_params     },    \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                   \
        (DFUNC)wp_mlx_gen_settable_params                                 },    \
    { OSSL_FUNC_KEYMGMT_GEN,             (DFUNC)wp_mlx_gen                },    \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,     (DFUNC)wp_mlx_gen_cleanup        },    \
    { OSSL_FUNC_KEYMGMT_LOAD,            (DFUNC)wp_mlx_load               },    \
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,      (DFUNC)wp_mlx_get_params         },    \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (DFUNC)wp_mlx_gettable_params    },    \
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,      (DFUNC)wp_mlx_set_params         },    \
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (DFUNC)wp_mlx_settable_params    },    \
    { OSSL_FUNC_KEYMGMT_HAS,             (DFUNC)wp_mlx_has                },    \
    { OSSL_FUNC_KEYMGMT_MATCH,           (DFUNC)wp_mlx_match              },    \
    { OSSL_FUNC_KEYMGMT_IMPORT,          (DFUNC)wp_mlx_import             },    \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,    (DFUNC)wp_mlx_import_types       },    \
    { OSSL_FUNC_KEYMGMT_EXPORT,          (DFUNC)wp_mlx_export             },    \
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,    (DFUNC)wp_mlx_export_types       },    \
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,                                  \
        (DFUNC)wp_mlx_##alg##_query_operation_name                        },    \
    { 0, NULL }                                                                \
};

IMPLEMENT_MLX_KEYMGMT_DISPATCH(x25519)
IMPLEMENT_MLX_KEYMGMT_DISPATCH(p256)
IMPLEMENT_MLX_KEYMGMT_DISPATCH(p384)

#endif /* WP_HAVE_MLKEM */
