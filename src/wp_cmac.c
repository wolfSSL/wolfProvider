/* wp_cmac.c
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
#include <openssl/cmac.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/internal.h>

#ifdef WP_HAVE_CMAC

/**
 * CMAC context structure when using wolfSSL for implementation.
 */
typedef struct wp_CmacCtx {
    /** wolfSSL CMAC object. */
    Cmac cmac;
    /** wolfSSL CMAC and cipher type. */
    enum CmacType type;

    /** Output size of MAC in bytes. */
    size_t size;
    /** Expected key size in bytes. */
    size_t expKeySize;

    /** Private key CMAC was initialized with. */
    unsigned char key[AES_256_KEY_SIZE];
    /** Length of private key in bytes. */
    size_t keyLen;
} wp_CmacCtx;


/* wp_cmac_init calls this function. */
static int wp_cmac_set_ctx_params(wp_CmacCtx* macCtx,
    const OSSL_PARAM params[]);


/**
 * Create a new CMAC context object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New object on success.
 * @return  NULL on failure.
 */
static wp_CmacCtx* wp_cmac_new(WOLFPROV_CTX* provCtx)
{
    wp_CmacCtx* macCtx = NULL;

    (void)provCtx;

    if (wolfssl_prov_is_running()) {
        macCtx = OPENSSL_zalloc(sizeof(*macCtx));
    }

    return macCtx;
}

/**
 * Free the CMAC context object.
 *
 * Calls wolfSSL free function and disposes of the memory.
 * Zeroizes the key.
 *
 * @param [in] macCtx  CMAC context object.
 */
static void wp_cmac_free(wp_CmacCtx* macCtx)
{
    if (macCtx != NULL) {
        OPENSSL_cleanse(macCtx->key, macCtx->keyLen);
        OPENSSL_free(macCtx);
    }
}

/**
 * Set and cache the key into CMAC context object.
 *
 * Allocates space for the key in the wolfSSL CMAC object.
 *
 * @param [in, out] macCtx   CMAC context object.
 * @param [in]      key      Key data to set.
 * @param [in]      keyLen   Length of key data in bytes.
 * @param [in]      restart  Restart CMAC calculation.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_set_key(wp_CmacCtx* macCtx, const unsigned char* key,
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
        #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
            int rc = wc_InitCmac_ex(&macCtx->cmac, macCtx->key,
                (word32)macCtx->keyLen, macCtx->type, NULL, NULL,
                INVALID_DEVID);
        #else
            int rc = wc_InitCmac(&macCtx->cmac, macCtx->key,
                (word32)macCtx->keyLen, macCtx->type, NULL);
        #endif
            if (rc != 0) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Duplicates an CMAC context object.
 *
 * Creates a new object and copies fields.
 * New memory is allocated for key.
 *
 * @param [in] src  CMAC context object to copy.
 * @return  New object on success.
 * @return  NULL on failure.
 */
static wp_CmacCtx* wp_cmac_dup(wp_CmacCtx* src)
{
    wp_CmacCtx* dst = NULL;

    if (wolfssl_prov_is_running()) {
        dst = wp_cmac_new(NULL);
    }
    if (dst != NULL) {
        *dst = *src;
        dst->keyLen = 0;

        if ((src->keyLen != 0) &&
            (!wp_cmac_set_key(dst, src->key, src->keyLen, 0))) {
            wp_cmac_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Initializes an CMAC context object with a key and parameters.
 *
 * @param [in, out] macCtx  CMAC context object to initialize.
 * @param [in]      key     Key data to set.
 * @param [in]      keyLen  Length of key data in bytes.
 * @param [in]      params  Extra parameters to set.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_init(wp_CmacCtx* macCtx, const unsigned char* key,
    size_t keyLen, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (!wp_cmac_set_ctx_params(macCtx, params))) {
        ok = 0;
    }
    if (ok) {
        macCtx->size = AES_BLOCK_SIZE;
        if ((key != NULL) && (!wp_cmac_set_key(macCtx, key, keyLen, 1))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Update the MAC state with data.
 *
 * @param [in, out] macCtx   CMAC context object to update.
 * @param [in]      data     Data to be MACed.
 * @param [in]      dataLen  Length of data in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_update(wp_CmacCtx* macCtx, const unsigned char* data,
    size_t dataLen)
{
    int ok = 1;
    int rc;

    rc = wc_CmacUpdate(&macCtx->cmac, data, (word32)dataLen);
    if (rc != 0) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Finalize the MAC value.
 *
 * @param [in, out] macCtx   CMAC context object to update.
 * @param [out]     out      Buffer to place MAC value into.
 * @param [out]     outl     Length of MAC, in bytes, placed in buffer.
 * @param [in]      outSize  Length of buffer in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_final(wp_CmacCtx* macCtx, unsigned char* out, size_t* outl,
    size_t outSize)
{
    int ok = 1;
    int rc;
    word32 outSz;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (outSize < macCtx->size)) {
        ok = 0;
    }

    if (ok) {
        outSz = (word32)outSize;
        rc = wc_CmacFinal(&macCtx->cmac, out, &outSz);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *outl = outSz;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return the parameters that can be retrieved.
 *
 * @param [in] macCtx   CMAC context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cmac_gettable_ctx_params(wp_CmacCtx* macCtx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported parameters for which values can be retrieved.
     */
    static const OSSL_PARAM wp_cmac_supported_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)macCtx;
    (void)provCtx;
    return wp_cmac_supported_gettable_ctx_params;
}

/**
 * Get values from CMAC context object for the parameters in the array.
 *
 * @param [in]      macCtx  CMAC context object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_get_ctx_params(wp_CmacCtx* macCtx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
    if ((p != NULL) && (!OSSL_PARAM_set_size_t(p, macCtx->size))) {
        ok = 0;
    }

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p, AES_BLOCK_SIZE))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return the parameters that can be set.
 *
 * @param [in] macCtx   CMAC context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters.
 */
static const OSSL_PARAM* wp_cmac_settable_ctx_params(wp_CmacCtx* macCtx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported parameters for which values can be set.
     */
    static const OSSL_PARAM wp_cmac_supported_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)macCtx;
    (void)provCtx;
    return wp_cmac_supported_settable_ctx_params;
}

/** Mapping of supported ciphers to key size. */
typedef struct wp_cmac_cipher {
    /** Name of cipher. */
    const char* name;
    /** Key size for cipher. */
    size_t keySize;
} wp_cmac_cipher;

/** wolfSSL CMAC compatible cipher names and key sizes. */
static const wp_cmac_cipher wp_cmac_cipher_names[] = {
    { "AES-128-CBC", AES_128_KEY_SIZE },
    { "AES-192-CBC", AES_192_KEY_SIZE },
    { "AES-256-CBC", AES_256_KEY_SIZE },
    { "aes-128-cbc", AES_128_KEY_SIZE },
    { "aes-192-cbc", AES_192_KEY_SIZE },
    { "aes-256-cbc", AES_256_KEY_SIZE },
};

/** Number of CMAC compatible cipher names in table.  */
#define WP_CMAC_CIPHER_NAMES_LEN    \
    (sizeof(wp_cmac_cipher_names) / sizeof(*wp_cmac_cipher_names))

/**
 * Setup the cipher based on the parameters in the array.
 *
 * A parameter with the name of the cipher may not be in the array.
 *
 * @param [in, out] macCtx   CMAC context object.
 * @param [in]      params   Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_setup_cipher(wp_CmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ok = 0;
        }
        if (ok) {
            size_t i;

            macCtx->type = WC_CMAC_AES;
            macCtx->size = AES_BLOCK_SIZE;

            for (i = 0; i < WP_CMAC_CIPHER_NAMES_LEN; i++) {
                if (XSTRNCMP(p->data, wp_cmac_cipher_names[i].name,
                        p->data_size) == 0) {
                    macCtx->expKeySize = wp_cmac_cipher_names[i].keySize;
                    break;
                }
            }
            if (i == WP_CMAC_CIPHER_NAMES_LEN) {
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
 * @param [in, out] macCtx  CMAC context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_set_param_key(wp_CmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;
    unsigned char* data = NULL;
    size_t len;

    if (!wp_params_get_octet_string_ptr(params, OSSL_MAC_PARAM_KEY, &data,
            &len)) {
        ok = 0;
    }
    if (ok && (data != NULL) && !wp_cmac_set_key(macCtx, data, len, 1)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set values into CMAC context object for the parameters in the array.
 *
 * @param [in, out] macCtx  CMAC context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_cmac_set_ctx_params(wp_CmacCtx* macCtx, const OSSL_PARAM params[])
{
    int ok = 1;

    if (params != NULL) {
        if (!wp_cmac_setup_cipher(macCtx, params)) {
            ok = 0;
        }
        if (ok && (!wp_cmac_set_param_key(macCtx, params))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table of CMAC functions implemented with wolfSSL.
 */
const OSSL_DISPATCH wp_cmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX,              (DFUNC)wp_cmac_new                 },
    { OSSL_FUNC_MAC_DUPCTX,              (DFUNC)wp_cmac_dup                 },
    { OSSL_FUNC_MAC_FREECTX,             (DFUNC)wp_cmac_free                },
    { OSSL_FUNC_MAC_INIT,                (DFUNC)wp_cmac_init                },
    { OSSL_FUNC_MAC_UPDATE,              (DFUNC)wp_cmac_update              },
    { OSSL_FUNC_MAC_FINAL,               (DFUNC)wp_cmac_final               },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (DFUNC)wp_cmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS,      (DFUNC)wp_cmac_get_ctx_params      },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (DFUNC)wp_cmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS,      (DFUNC)wp_cmac_set_ctx_params      },
    { 0, NULL }
};

#endif /* WP_HAVE_CMAC */

