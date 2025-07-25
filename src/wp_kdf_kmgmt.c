/* wp_kdf_kmgmt.c
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

#include <wolfprovider/alg_funcs.h>


/**
 * Key Derivation Function (KDF) key.
 *
 * Dummy key object. For support of using KDFs with EVP_PKEY_derive().
 */
struct wp_Kdf {
#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;
};

/**
 * Increment reference count for key.
 *
 * Used in key exchange.
 *
 * @param [in, out] ecc  ECC key object.
 * @return  1 on success.
 * @return  0 when multi-threaded and locking fails.
 */
int wp_kdf_up_ref(wp_Kdf* kdf)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&kdf->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        kdf->refCnt++;
        wc_UnLockMutex(&kdf->mutex);
    }

    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    kdf->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Create a new KDF key object.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  New ECC key object on success.
 * @return  NULL on failure.
 */
static wp_Kdf* wp_kdf_new(WOLFPROV_CTX *provCtx)
{
    wp_Kdf* kdf = NULL;

    (void)provCtx;

    if (wolfssl_prov_is_running()) {
        kdf = (wp_Kdf*)OPENSSL_zalloc(sizeof(*kdf));
    }
    if (kdf != NULL) {
    #ifndef SINGLE_THREADED
        int rc = wc_InitMutex(&kdf->mutex);
        if (rc != 0) {
            OPENSSL_free(kdf);
            kdf = NULL;
        }
        else
    #endif
        {
            kdf->refCnt = 1;
        }
    }

    return kdf;
}

/**
 * Dispose of KDF key object.
 *
 * @param [in, out] kdf  KDF key object.
 */
void wp_kdf_free(wp_Kdf* kdf)
{
    if (kdf != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&kdf->mutex);
        cnt = --kdf->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&kdf->mutex);
        }
    #else
        cnt = --kdf->refCnt;
    #endif

        if (cnt == 0) {
    #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&kdf->mutex);
    #endif
            OPENSSL_free(kdf);
        }
    }
}

/**
 * Check KDF key object has the components required.
 *
 * Dummy key so always true.
 *
 * @param [in] kdf        KDF key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success.
 */
static int wp_kdf_has(const wp_Kdf* kdf, int selection)
{
    (void)kdf;
    (void)selection;
    WOLFPROV_LEAVE(WP_LOG_KDF, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/** Dispatch table for KDF key management. */
const OSSL_DISPATCH wp_kdf_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,  (DFUNC)wp_kdf_new  },
    { OSSL_FUNC_KEYMGMT_FREE, (DFUNC)wp_kdf_free },
    { OSSL_FUNC_KEYMGMT_HAS,  (DFUNC)wp_kdf_has  },
    { 0, NULL }
};

