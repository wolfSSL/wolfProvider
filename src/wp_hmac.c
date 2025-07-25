/* wp_hmac.c
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


#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_HMAC

/**
 * HMAC context structure when using wolfSSL for implementation.
 */
typedef struct wp_HmacCtx {
    /** wolfSSL HMAC object. */
    Hmac hmac;
    /** wolfSSL digest type. */
    enum wc_HashType type;
    /** Output size of digest in bytes. */
    size_t size;

    /** Provider context object. Used when getting digest type from name. */
    WOLFPROV_CTX* provCtx;

    /** Private key HMAC was initialized with. */
    unsigned char* key;
    /** Length of private key in bytes. */
    size_t keyLen;
} wp_HmacCtx;


/* wp_hmac_init calls this function. */
static int wp_hmac_set_ctx_params(wp_HmacCtx* macCtx,
    const OSSL_PARAM params[]);


/**
 * Create a new HMAC context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New object on success.
 * @return  NULL on failure.
 */
static wp_HmacCtx* wp_hmac_new(WOLFPROV_CTX* provCtx)
{
    wp_HmacCtx* macCtx = NULL;
    int rc;

    if (wolfssl_prov_is_running()) {
        macCtx = OPENSSL_zalloc(sizeof(*macCtx));
    }
    if (macCtx != NULL) {
        rc = wc_HmacInit(&macCtx->hmac, NULL, INVALID_DEVID);
        if (rc != 0) {
            OPENSSL_free(macCtx);
            macCtx = NULL;
        }
    }
    if (macCtx != NULL) {
        macCtx->provCtx = provCtx;
    }

    return macCtx;
}

/**
 * Free the HMAC context object.
 *
 * Calls wolfSSL free function and disposes of the memory.
 * Zeroizes the key.
 *
 * @param [in] macCtx  HMAC context object.
 */
static void wp_hmac_free(wp_HmacCtx* macCtx)
{
    if (macCtx != NULL) {
        wc_HmacFree(&macCtx->hmac);
        OPENSSL_secure_clear_free(macCtx->key, macCtx->keyLen);
        OPENSSL_free(macCtx);
    }
}

/**
 * Set and cache the key into HMAC context object.
 *
 * Allocates space for the key in the wolfSSL HMAC object.
 *
 * @param [in, out] macCtx   HMAC context object.
 * @param [in]      key      Key data to set.
 * @param [in]      keyLen   Length of key data in bytes.
 * @param [in]      restart  Restart HMAC calculation.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hmac_set_key(wp_HmacCtx* macCtx, const unsigned char* key,
    size_t keyLen, int restart)
{
    int ok = 1;
    word32 blockSize = wc_HashGetBlockSize(macCtx->type);

    if (macCtx->keyLen > 0) {
        OPENSSL_secure_clear_free(macCtx->key, macCtx->keyLen);
    }

    if (keyLen < blockSize) {
        /* wolfSSL FIPS needs a key that is at least block size in length with
         * the unused parts zeroed out.
         */
        macCtx->key = OPENSSL_secure_malloc(blockSize);
        if (macCtx->key != NULL) {
            XMEMSET(macCtx->key + keyLen, 0, blockSize - keyLen);
            macCtx->keyLen = blockSize;
        }
        else {
            ok = 0;
        }
    }
    else {
        macCtx->keyLen = keyLen;
        macCtx->key = OPENSSL_secure_malloc(keyLen);
        if (macCtx->key == NULL) {
            ok = 0;
        }
    }

    if (ok) {
        XMEMCPY(macCtx->key, key, keyLen);
        if (restart) {
            int rc = wc_HmacSetKey(&macCtx->hmac, macCtx->type, macCtx->key,
                (word32)macCtx->keyLen);
            if (rc != 0) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Duplicates an HMAC context object.
 *
 * Creates a new object and copies fields.
 * New memory is allocated for key.
 *
 * @param [in] src  HMAC context object to copy.
 * @return  New object on success.
 * @return  NULL on failure.
 */
static wp_HmacCtx* wp_hmac_dup(wp_HmacCtx* src)
{
    wp_HmacCtx* dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = wp_hmac_new(src->provCtx);
    }
    if (dst != NULL) {
        *dst = *src;
        dst->key = NULL;
        dst->keyLen = 0;

        if ((src->key != NULL) &&
            (!wp_hmac_set_key(dst, src->key, src->keyLen, 0))) {
            wp_hmac_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Initializes an HMAC context object with a key and parameters.
 *
 * @param [in, out] macCtx  HMAC context object to initialize.
 * @param [in]      key     Key data to set.
 * @param [in]      keyLen  Length of key data in bytes.
 * @param [in]      params  Extra parameters to set.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hmac_init(wp_HmacCtx* macCtx, const unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_hmac_set_ctx_params(macCtx, params))) {
        ok = 0;
    }
    if (ok) {
        macCtx->size = wc_HmacSizeByType(macCtx->type);
        if ((key != NULL) && (!wp_hmac_set_key(macCtx, key, keyLen, 1))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Update the MAC state with data.
 *
 * @param [in, out] macCtx   HMAC context object to update.
 * @param [in]      data     Data to be MACed.
 * @param [in]      dataLen  Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hmac_update(wp_HmacCtx* macCtx, const unsigned char* data,
    size_t dataLen)
{
    int ok = 1;
    int rc;

    rc = wc_HmacUpdate(&macCtx->hmac, data, (word32)dataLen);
    if (rc != 0) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the MAC value.
 *
 * @param [in, out] macCtx   HMAC context object to update.
 * @param [out]     out      Buffer to place MAC value into.
 * @param [out]     outl     Length of MAC, in bytes, placed in buffer.
 * @param [in]      outSize  Length of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hmac_final(wp_HmacCtx* macCtx, unsigned char* out, size_t* outl,
    size_t outSize)
{
    int ok = 1;
    int rc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < macCtx->size)) {
        ok = 0;
    }

    if (ok) {
        rc = wc_HmacFinal(&macCtx->hmac, out);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *outl = macCtx->size;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return the parameters that can be retrieved.
 *
 * @param [in] macCtx   HMAC context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_hmac_gettable_ctx_params(wp_HmacCtx* macCtx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported parameters for which values can be retrieved.
     */
    static const OSSL_PARAM wp_hmac_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)macCtx;
    (void)provCtx;
    return wp_hmac_supported_gettable_ctx_params;
}

/**
 * Get values from HMAC context object for the parameters in the array.
 *
 * @param [in]      macCtx  HMAC context object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hmac_get_ctx_params(wp_HmacCtx* macCtx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, macCtx->size))) {
        ok = 0;
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if ((p != NULL) &&
            (!OSSL_PARAM_set_int(p, wc_HashGetBlockSize(macCtx->type)))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return the parameters that can be set.
 *
 * @param [in] macCtx   HMAC context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_hmac_settable_ctx_params(wp_HmacCtx* macCtx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported parameters for which values can be set.
     */
    static const OSSL_PARAM wp_hmac_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)macCtx;
    (void)provCtx;
    return wp_hmac_supported_settable_ctx_params;
}

/**
 * Set values into HMAC context object for the parameters in the array.
 *
 * @param [in, out] macCtx  HMAC context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_hmac_set_ctx_params(wp_HmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {

        if (!wp_params_get_digest(params, NULL, macCtx->provCtx->libCtx,
                &macCtx->type, &macCtx->size)) {
            ok = 0;
        }

        if (ok) {
            unsigned char* keyData = NULL;
            size_t keyLen;

            if (!wp_params_get_octet_string_ptr(params, OSSL_MAC_PARAM_KEY,
                    &keyData, &keyLen)) {
                ok = 0;
            }
            if (ok && (keyData != NULL) && (!wp_hmac_set_key(macCtx, keyData,
                    keyLen, 1))) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table of HMAC functions implemented with wolfSSL.
 */
const OSSL_DISPATCH wp_hmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX,              (DFUNC)wp_hmac_new                 },
    { OSSL_FUNC_MAC_DUPCTX,              (DFUNC)wp_hmac_dup                 },
    { OSSL_FUNC_MAC_FREECTX,             (DFUNC)wp_hmac_free                },
    { OSSL_FUNC_MAC_INIT,                (DFUNC)wp_hmac_init                },
    { OSSL_FUNC_MAC_UPDATE,              (DFUNC)wp_hmac_update              },
    { OSSL_FUNC_MAC_FINAL,               (DFUNC)wp_hmac_final               },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (DFUNC)wp_hmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (DFUNC)wp_hmac_get_ctx_params      },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (DFUNC)wp_hmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (DFUNC)wp_hmac_set_ctx_params      },
    { 0, NULL }
};

#endif /* WP_HAVE_HMAC */
