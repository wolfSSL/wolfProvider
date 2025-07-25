/* wp_gmac.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_AESGCM

/**
 * GMAC context structure when using wolfSSL for implementation.
 */
typedef struct wp_GmacCtx {
    /** wolfSSL GMAC object. */
    Gmac gmac;
    /** Cached data to GMAC. */
    unsigned char* data;
    /** Length of cached data. */
    size_t dataLen;

    /** Expected key size in bytes. */
    size_t expKeySize;

    /** IV to use. */
    unsigned char iv[AES_BLOCK_SIZE];
    /** Length of IV data. */
    size_t ivLen;
    /** Private key GMAC was initialized with. */
    unsigned char key[AES_256_KEY_SIZE];
    /** Length of private key in bytes. */
    size_t keyLen;
} wp_GmacCtx;


/* wp_gmac_init calls this function. */
static int wp_gmac_set_ctx_params(wp_GmacCtx* macCtx,
    const OSSL_PARAM params[]);


/**
 * Create a new GMAC context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New object on success.
 * @return  NULL on failure.
 */
static wp_GmacCtx* wp_gmac_new(WOLFPROV_CTX* provCtx)
{
    wp_GmacCtx *macCtx = NULL;

    (void)provCtx;

    if (wolfssl_prov_is_running()) {
        macCtx = OPENSSL_zalloc(sizeof(*macCtx));
    }

    return macCtx;
}

/**
 * Free the GMAC context object.
 *
 * Calls wolfSSL free function and disposes of the memory.
 * Zeroizes the key.
 *
 * @param [in] macCtx  GMAC context object.
 */
static void wp_gmac_free(wp_GmacCtx* macCtx)
{
    if (macCtx != NULL) {
        OPENSSL_cleanse(macCtx->key, macCtx->keyLen);
        OPENSSL_clear_free(macCtx->data, macCtx->dataLen);
        OPENSSL_free(macCtx);
    }
}

/**
 * Set and cache the key into GMAC context object.
 *
 * Allocates space for the key in the wolfSSL GMAC object.
 *
 * @param [in, out] macCtx   GMAC context object.
 * @param [in]      key      Key data to set.
 * @param [in]      keyLen   Length of key data in bytes.
 * @param [in]      restart  Restart GMAC calculation.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_set_key(wp_GmacCtx* macCtx, const unsigned char *key,
    size_t keyLen, int restart)
{
    int ok = 1;

    if (keyLen > AES_256_KEY_SIZE) {
        ok = 0;
    }
    if (ok) {
        if (macCtx->keyLen > 0) {
            OPENSSL_cleanse(macCtx->key, macCtx->keyLen);
        }
        macCtx->keyLen = keyLen;
        XMEMCPY(macCtx->key, key, keyLen);

        if (restart) {
            int rc = wc_GmacSetKey(&macCtx->gmac, macCtx->key,
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
 * Duplicates an GMAC context object.
 *
 * Creates a new object and copies fields.
 * New memory is allocated for key.
 *
 * @param [in] src  GMAC context object to copy.
 * @return  New object on success.
 * @return  NULL on failure.
 */
static wp_GmacCtx* wp_gmac_dup(wp_GmacCtx* src)
{
    wp_GmacCtx *dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = wp_gmac_new(NULL);
    }
    if (dst != NULL) {
        *dst = *src;
        dst->keyLen = 0;
        dst->ivLen = 0;

        if (src->ivLen != 0) {
            XMEMCPY(dst->iv, src->iv, src->ivLen);
            dst->ivLen = src->ivLen;
        }
        if ((src->keyLen != 0) &&
            (!wp_gmac_set_key(dst, src->key, src->keyLen, 0))) {
            wp_gmac_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Initializes an GMAC context object with a key and parameters.
 *
 * @param [in, out] macCtx  GMAC context object to initialize.
 * @param [in]      key     Key data to set.
 * @param [in]      keyLen  Length of key data in bytes.
 * @param [in]      params  Extra parameters to set.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_init(wp_GmacCtx* macCtx, const unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (params != NULL) && (!wp_gmac_set_ctx_params(macCtx, params))) {
        ok = 0;
    }
    if (ok && ((key != NULL) && (!wp_gmac_set_key(macCtx, key, keyLen, 1)))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Update the MAC state with data.
 *
 * @param [in, out] macCtx   GMAC context object to update.
 * @param [in]      data     Data to be MACed.
 * @param [in]      dataLen  Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_update(wp_GmacCtx* macCtx, const unsigned char* data,
    size_t dataLen)
{
    int ok = 1;
    unsigned char* p;

    /* Data cached as wolfSSL doesn't have a streaming API. */
    p = OPENSSL_realloc(macCtx->data, macCtx->dataLen + dataLen);
    if (p == NULL) {
        ok = 0;
    }
    if (ok) {
        macCtx->data = p;
        XMEMCPY(macCtx->data + macCtx->dataLen, data, dataLen);
        macCtx->dataLen += dataLen;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the MAC value.
 *
 * @param [in, out] macCtx   GMAC context object to update.
 * @param [out]     out      Buffer to place MAC value into.
 * @param [out]     outl     Length of MAC, in bytes, placed in buffer.
 * @param [in]      outSize  Length of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_final(wp_GmacCtx* macCtx, unsigned char* out, size_t* outl,
    size_t outSize)
{
    int ok = 1;
    int rc;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < AES_BLOCK_SIZE)) {
        ok = 0;
    }

    if (ok) {
        /* One-shot API for creating GMAC. */
        rc = wc_GmacUpdate(&macCtx->gmac, macCtx->iv, (word32)macCtx->ivLen,
            macCtx->data, (word32)macCtx->dataLen, out, (word32)outSize);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *outl = AES_BLOCK_SIZE;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return the parameters that can be retrieved for the algorithm.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_gmac_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported parameters for which values can be retrieved.
     */
    static const OSSL_PARAM wp_gmac_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_gmac_supported_gettable_ctx_params;
}

/**
 * Get values about GMAC algorithm for the parameters in the array.
 *
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_get_params(OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, AES_BLOCK_SIZE))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return the parameters that can be set.
 *
 * @param [in] macCtx   GMAC context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_gmac_settable_ctx_params(void *macCtx,
    void *provCtx)
{
    /**
     * Supported parameters for which values can be set.
     */
    static const OSSL_PARAM wp_gmac_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_IV, NULL, 0),
        OSSL_PARAM_END
    };
    (void)macCtx;
    (void)provCtx;
    return wp_gmac_supported_settable_ctx_params;
}

/** Mapping of supported ciphers to key size. */
typedef struct wp_gmac_cipher {
    /** Name of cipher. */
    const char* name;
    /** Key size for cipher. */
    size_t keySize;
} wp_gmac_cipher;

/** wolfSSL GMAC compatible cipher names and key sizes. */
static const wp_gmac_cipher wp_gmac_cipher_names[] = {
    { "AES-128-GCM", AES_128_KEY_SIZE },
    { "AES-192-GCM", AES_192_KEY_SIZE },
    { "AES-256-GCM", AES_256_KEY_SIZE },
    { "aes-128-gcm", AES_128_KEY_SIZE },
    { "aes-192-gcm", AES_192_KEY_SIZE },
    { "aes-256-gcm", AES_256_KEY_SIZE },
};

/** Number of GMAC compatible cipher names in table.  */
#define WP_GMAC_CIPHER_NAMES_LEN    \
    (sizeof(wp_gmac_cipher_names) / sizeof(*wp_gmac_cipher_names))

/**
 * Setup the cipher based on the parameters in the array.
 *
 * A parameter with the name of the cipher may not be in the array.
 *
 * @param [in, out] macCtx   GMAC context object.
 * @param [in]      params   Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_setup_cipher(wp_GmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ok = 0;
        }
        if (ok) {
            size_t i;

            for (i = 0; i < WP_GMAC_CIPHER_NAMES_LEN; i++) {
                if (XSTRNCMP(p->data, wp_gmac_cipher_names[i].name,
                        p->data_size) == 0) {
                    macCtx->expKeySize = wp_gmac_cipher_names[i].keySize;
                    break;
                }
            }
            if (i == WP_GMAC_CIPHER_NAMES_LEN) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the key from the parameters.
 *
 * @param [in, out] macCtx  GMAC context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_set_param_key(wp_GmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* data = NULL;
    size_t len;

    if (!wp_params_get_octet_string_ptr(params, OSSL_MAC_PARAM_KEY, &data,
            &len)) {
        ok = 0;
    }
    if (ok && (data != NULL) && !wp_gmac_set_key(macCtx, data, len, 1)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the IV from the parameters.
 *
 * @param [in, out] macCtx  GMAC context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_set_param_iv(wp_GmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* data = NULL;
    size_t len;

    if (!wp_params_get_octet_string_ptr(params, OSSL_MAC_PARAM_IV, &data,
             &len)) {
        ok = 0;
    }
    if (ok && (data != NULL)) {
        if (len > AES_BLOCK_SIZE) {
            ok = 0;
        }
        if (ok) {
            XMEMCPY(macCtx->iv, data, len);
            macCtx->ivLen = len;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set values into GMAC context object for the parameters in the array.
 *
 * @param [in, out] macCtx  GMAC context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_gmac_set_ctx_params(wp_GmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {

        if (!wp_gmac_setup_cipher(macCtx, params)) {
            ok = 0;
        }
        if (ok && (!wp_gmac_set_param_key(macCtx, params))) {
            ok = 0;
        }
        if (ok && (!wp_gmac_set_param_iv(macCtx, params))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table of GMAC functions implemented with wolfSSL.
 */
const OSSL_DISPATCH wp_gmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX,              (DFUNC)wp_gmac_new                 },
    { OSSL_FUNC_MAC_DUPCTX,              (DFUNC)wp_gmac_dup                 },
    { OSSL_FUNC_MAC_FREECTX,             (DFUNC)wp_gmac_free                },
    { OSSL_FUNC_MAC_INIT,                (DFUNC)wp_gmac_init                },
    { OSSL_FUNC_MAC_UPDATE,              (DFUNC)wp_gmac_update              },
    { OSSL_FUNC_MAC_FINAL,               (DFUNC)wp_gmac_final               },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS,     (DFUNC)wp_gmac_gettable_params     },
    { OSSL_FUNC_MAC_GET_PARAMS,          (DFUNC)wp_gmac_get_params          },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (DFUNC)wp_gmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (DFUNC)wp_gmac_set_ctx_params      },
    { 0, NULL }
};

#endif /* WP_HAVE_AESGCM */

