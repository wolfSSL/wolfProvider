/* wp_mac_kmgmt.c
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

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#if defined(WP_HAVE_HMAC) || defined(WP_HAVE_CMAC)

/**
 * MAC key object. Used for HMAC and CMAC.
 */
struct wp_Mac {
    /** Key data. */
    unsigned char* key;
    /** Length of key. */
    size_t keyLen;
#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;

    /** Provider context - used to create a new key.  */
    WOLFPROV_CTX* provCtx;

    /** Type of key. */
    int type;
    /** CMAC: Name of cipher used. */
    char cipher[WP_MAX_CIPH_NAME_SIZE];
    /** Properties for cipher/digest. */
    char* properties;
};


typedef struct wp_MacGenCtx {
    /** Generated key - actually passed in. */
    unsigned char* key;
    /** Length of generated key in bytes. */
    size_t keyLen;

    /** Provider context - used to create a new key.  */
    WOLFPROV_CTX* provCtx;
    /** Which parts of the key to generate. */
    int selection;

    /** Type of key. */
    int type;
    /** CMAC: Name of cipher used. */
    char cipher[WP_MAX_CIPH_NAME_SIZE];
} wp_MacGenCtx;


/* Prototype for generation initialization. */
static int wp_mac_gen_set_params(wp_MacGenCtx* ctx, const OSSL_PARAM params[]);


/**
 * Increment reference count for key.
 *
 * Used in signing.
 *
 * @param [in, out] mac  MAC key object.
 * @return  1 on success.
 * @return  0 when multi-threaded and locking fails.
 */
int wp_mac_up_ref(wp_Mac* mac)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&mac->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        mac->refCnt++;
        wc_UnLockMutex(&mac->mutex);
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    mac->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the key type.
 *
 * @param [in] mac  MAC key object.
 * @return  MAC key type.
 */
int wp_mac_get_type(wp_Mac* mac)
{
    return mac->type;
}

/**
 * Get the private key.
 *
 * @param [in]  mac      MAC key object.
 * @param [out] priv     Private key data.
 * @param [out] privLen  Length of private key in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_mac_get_private_key(wp_Mac* mac, unsigned char** priv, size_t* privLen)
{
    int ok = 0;

    if (mac != NULL) {
        *priv = mac->key;
        *privLen = mac->keyLen;
        ok = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the cipher name for CMAC.
 *
 * @param [in] mac  MAC key object.
 * @return  Cipher name.
 */
char* wp_mac_get_ciphername(wp_Mac* mac)
{
    return mac->cipher;
}

/**
 * Get the properties of digest/cipher.
 *
 * @param [in] mac  MAC key object.
 * @return  Properties string.
 */
char* wp_mac_get_properties(wp_Mac* mac)
{
    return mac->properties;
}

/**
 * Create a new MAC key object.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] type     Type of MAC key.
 * @return  New MAC key object on success.
 * @return  NULL on failure.
 */
static wp_Mac* wp_mac_new(WOLFPROV_CTX *provCtx, int type)
{
    wp_Mac* mac = NULL;

    if (wolfssl_prov_is_running()) {
        mac = (wp_Mac*)OPENSSL_zalloc(sizeof(*mac));
    }
    if (mac != NULL) {
    #ifndef SINGLE_THREADED
        int rc = wc_InitMutex(&mac->mutex);
        if (rc != 0) {
            OPENSSL_free(mac);
            mac = NULL;
        }
        else
    #endif
        {
            mac->provCtx = provCtx;
            mac->type = type;
            mac->refCnt = 1;
            mac->keyLen = MAX_SIZE_T;
        }
    }

    return mac;
}

/**
 * Dispose of MAC key object.
 *
 * @param [in, out] mac  MAC key object.
 */
void wp_mac_free(wp_Mac* mac)
{
    if (mac != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&mac->mutex);
        cnt = --mac->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&mac->mutex);
        }
    #else
        cnt = --mac->refCnt;
    #endif

        if (cnt == 0) {
    #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&mac->mutex);
    #endif
            OPENSSL_free(mac->properties);
            OPENSSL_clear_free(mac->key, mac->keyLen);
            OPENSSL_free(mac);
        }
    }
}

/**
 * Duplicate the MAC key object.
 *
 * @param [in] src        Source MAC key object.
 * @param [in] selection  Parts of key to include.
 * @return  NULL on failure.
 * @return  New MAC key object on success.
 */
static wp_Mac* wp_mac_dup(const wp_Mac *src, int selection)
{
    wp_Mac* dst;

    (void)selection;

    dst = wp_mac_new(src->provCtx, src->type);
    if (dst != NULL) {
        int ok = 1;

        /* Copy key if set. */
        if (src->key != NULL) {
            dst->key = OPENSSL_malloc(src->keyLen);
            if (dst->key == NULL) {
                ok = 0;
            }
            else {
                XMEMCPY(dst->key, src->key, src->keyLen);
            }
        }
        dst->keyLen = src->keyLen;
        /* Copy properties if set. */
        if (src->properties != NULL) {
            size_t propLen = XSTRLEN(src->properties) + 1;
            dst->properties = OPENSSL_malloc(propLen);
            if (dst->properties == NULL) {
                ok = 0;
            }
            else {
                XMEMCPY(dst->properties, src->properties, propLen);
            }
        }
        /* Copy cipher name. */
        if (ok) {
            XMEMCPY(dst->cipher, src->cipher, WP_MAX_CIPH_NAME_SIZE);
        }

        if (!ok) {
            wp_mac_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Check MAC key object has the components required.
 *
 * @param [in] mac        MAC key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_has(const wp_Mac* mac, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
       ok = 0;
    }
    if (mac == NULL) {
       ok = 0;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        ok &= mac->key != NULL;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two MAC key objects match for the components specified.
 *
 * @param [in] mac1       First ECC key object.
 * @param [in] mac2       Second ECC key object.
 * @param [in] selection  Parts of key to match.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_match(const wp_Mac* mac1, const wp_Mac* mac2, int selection)
{
   int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) &&
        (mac1->keyLen != MAX_SIZE_T) && ((mac1->keyLen != mac2->keyLen) ||
        (XMEMCMP(mac1->key, mac2->key, mac1->keyLen) != 0) ||
        (XMEMCMP(mac1->cipher, mac2->cipher, WP_MAX_CIPH_NAME_SIZE) != 0))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key into MAC key object from parameters.
 *
 * @param [in, out] mac        MAC key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_import(wp_Mac *mac, int selection, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    if ((!wolfssl_prov_is_running()) || (mac == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)) {
        ok = 0;
    }
    if (ok && (!wp_params_get_octet_string(params, OSSL_PKEY_PARAM_PRIV_KEY,
            &mac->key, &mac->keyLen, 1))) {
        ok = 0;
    }
    if (ok && (mac->type == WP_MAC_TYPE_CMAC) && (!wp_params_get_utf8_string(
            params, OSSL_PKEY_PARAM_CIPHER, mac->cipher,
            WP_MAX_CIPH_NAME_SIZE))) {
        ok = 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(mac->properties);
        mac->properties = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &mac->properties, 0)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the size of allocated data needed for private key.
 *
 * Called when exporting.
 *
 * @param [in] mac   MAC key object.
 * @return  Size of buffer to hold allocated key pair data.
 */
static size_t wp_mac_export_priv_key_alloc_size(wp_Mac* mac)
{
    /* Private key. */
    size_t len = mac->keyLen;
    if (mac->type == WP_MAC_TYPE_CMAC) {
        len += XSTRLEN(mac->cipher) + 1;
    }
    return len;
}

/**
 * Put the MAC private key and cipher name into the parameter.
 *
 * Assumes data buffer is big enough.
 *
 * @param [in]      mac     MAC key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @param [in, out] data    Data buffer to place group data into.
 * @param [in, out] idx     Pointer to current index into data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_export_priv_key(wp_Mac* mac, OSSL_PARAM* params, int* pIdx,
    unsigned char* data, size_t* idx)
{
    int i = *pIdx;

    if (mac->keyLen != MAX_SIZE_T) {
        XMEMCPY(data + *idx, mac->key, mac->keyLen);
        wp_param_set_octet_string_ptr(&params[i++], OSSL_PKEY_PARAM_PRIV_KEY,
            data + *idx, mac->keyLen);
        *idx += mac->keyLen;
    }
    if (mac->type == WP_MAC_TYPE_CMAC) {
        size_t cipherLen = XSTRLEN(mac->cipher);
        XMEMCPY(data + *idx, mac->cipher, cipherLen + 1);
        wp_param_set_utf8_string_ptr(&params[i++], OSSL_PKEY_PARAM_CIPHER,
            (char*)(data + *idx));
        *idx += cipherLen;
    }

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Export the MAC key.
 *
 * Key data placed in parameters and then passed to callback.
 *
 * @param [in] mac        MAC key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Function to pass constructed parameters to.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_export(wp_Mac *mac, int selection, OSSL_CALLBACK *paramCb,
    void *cbArg)
{
    int ok = 1;
    OSSL_PARAM params[3];
    int paramsSz = 0;
    unsigned char* data = NULL;
    size_t len = 0;

    XMEMSET(params, 0, sizeof(params));

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        size_t idx = 0;

        len = wp_mac_export_priv_key_alloc_size(mac);
        if (len != MAX_SIZE_T) {
            data = OPENSSL_malloc(len + 1);
            if (data == NULL) {
                ok = 0;
            }
        }
        if (ok && !wp_mac_export_priv_key(mac, params, &paramsSz, data, &idx)) {
            ok = 0;
        }
    }
    if (ok) {
        ok = paramCb(params, cbArg);
    }
    OPENSSL_clear_free(data, len);

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/*
 * MAC generation.
 */

/**
 * Create MAC generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @param [in] type       Type of MAC key.
 * @return  New MAC generation context object on success.
 * @return  NULL on failure.
 */
static wp_MacGenCtx* wp_mac_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], int type)
{
    wp_MacGenCtx* ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ctx->provCtx = provCtx;
        ctx->selection = selection;
        ctx->type = type;

        if (!wp_mac_gen_set_params(ctx, params)) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Sets the parameters into the MAC generation context object.
 *
 * @param [in, out] ctx     MAC generation context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_gen_set_params(wp_MacGenCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wp_params_get_octet_string(params, OSSL_PKEY_PARAM_PRIV_KEY,
            &ctx->key, &ctx->keyLen, 1)) {
        ok = 0;
    }
    if (ok && (ctx->type == WP_MAC_TYPE_CMAC) && !wp_params_get_utf8_string(
            params, OSSL_PKEY_PARAM_CIPHER, ctx->cipher,
            WP_MAX_CIPH_NAME_SIZE)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate MAC private key by copying it out of context.
 *
 * @param [in, out] ctx    MAC generation context object.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument to pass to callback. Unused.
 * @return  NULL on failure.
 * @return  MAC key object on success.
 */
static wp_Mac* wp_mac_gen(wp_MacGenCtx *ctx, OSSL_CALLBACK *cb, void *cbArg)
{
    wp_Mac* mac;

    (void)cb;
    (void)cbArg;

    mac = wp_mac_new(ctx->provCtx, ctx->type);
    if (mac != NULL) {
        /* Move key pointer to key object. */
        mac->key = ctx->key;
        mac->keyLen = ctx->keyLen;
        ctx->key = NULL;
        ctx->keyLen = 0;
        /* Copy over any cipher name. */
        XMEMCPY(mac->cipher, ctx->cipher, WP_MAX_CIPH_NAME_SIZE);
    }

    return mac;
}

/**
 * Dispose of the MAC generation context object.
 *
 * @param [in, out] ctx  MAC generation context object.
 */
static void wp_mac_gen_cleanup(wp_MacGenCtx *ctx)
{
    if (ctx != NULL) {
        OPENSSL_clear_free(ctx->key, ctx->keyLen);
        OPENSSL_free(ctx);
    }
}

/**
 * Load the MAC key.
 *
 * Return the MAC key object taken out of the reference.
 *
 * @param [in, out] pMac  Pointer to a MAC key object.
 * @param [in]      size  Size of data structure that is the MAC key object.
 *                        Unused.
 * @return  NULL when no MAC key object at reference.
 * @return  MAC key object from reference on success.
 */
static const wp_Mac* wp_mac_load(const wp_Mac** pMac, size_t size)
{
    const wp_Mac* mac = *pMac;
    (void)size;
    *pMac = NULL;
    return mac;
}

/**
 * Get the MAC key parameters.
 *
 * @param [in]      mac     MAC key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_mac_get_params(wp_Mac* mac, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    if (mac->keyLen != MAX_SIZE_T) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if ((p != NULL) && (!OSSL_PARAM_set_octet_string(p, mac->key,
                mac->keyLen))) {
            ok = 0;
        }
    }
    if (ok && (mac->type == WP_MAC_TYPE_CMAC)) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_CIPHER);
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_string(p, mac->cipher))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_MAC, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/*
 * HMAC
 */

#ifdef WP_HAVE_HMAC

/**
 * Create a new HMAC key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New MAC key object on success.
 * @return  NULL on failure.
 */
static wp_Mac *wp_hmac_new(WOLFPROV_CTX *provCtx)
{
    return wp_mac_new(provCtx, WP_MAC_TYPE_HMAC);
}

/**
 * Return an array of supported gettable parameters for the HMAC key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_hmac_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for HMAC key object.
     */
    static const OSSL_PARAM wp_hmac_supported_gettable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_hmac_supported_gettable_params;
}

/**
 * Return an array of supported settable parameters for the HMAC gen context.
 *
 * @param [in] ctx      MAC generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_hmac_gen_settable_params(wp_MacGenCtx* ctx,
    WOLFPROV_CTX* provCtx)

{
    /**
     * Supported settable parameters for HMAC generation context.
     */
    static const OSSL_PARAM wp_hmac_gen_supported_settable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_hmac_gen_supported_settable_params;
}

/**
 * Get the key parameters for a selection.
 *
 * @param [in] selection  Parts of key to import/export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_hmac_key_types(int selection)
{
    /**
     * Supported HMAC key parameters.
     */
    static const OSSL_PARAM wp_hmac_supported_key_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    const OSSL_PARAM* params = NULL;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        params = wp_hmac_supported_key_params;
    }
    return params;
}
/**
 * Get the key parameters when importing for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM *wp_hmac_import_types(int selection)
{
    return wp_hmac_key_types(selection);
}
/**
 * Get the key parameters when exporting for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM *wp_hmac_export_types(int selection)
{
    return wp_hmac_key_types(selection);
}

/**
 * Create HMAC generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New MAC generation context object on success.
 * @return  NULL on failure.
 */
static wp_MacGenCtx* wp_hmac_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mac_gen_init(provCtx, selection, params, WP_MAC_TYPE_HMAC);
}

/** Dispatch table for HMAC key management. */
const OSSL_DISPATCH wp_hmac_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,               (DFUNC)wp_hmac_new                 },
    { OSSL_FUNC_KEYMGMT_FREE,              (DFUNC)wp_mac_free                 },
    { OSSL_FUNC_KEYMGMT_DUP,               (DFUNC)wp_mac_dup                  },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,          (DFUNC)wp_hmac_gen_init            },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,    (DFUNC)wp_mac_gen_set_params       },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                           (DFUNC)wp_hmac_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,               (DFUNC)wp_mac_gen                  },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,       (DFUNC)wp_mac_gen_cleanup          },
    { OSSL_FUNC_KEYMGMT_LOAD,              (DFUNC)wp_mac_load                 },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,        (DFUNC)wp_mac_get_params           },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,   (DFUNC)wp_hmac_gettable_params     },
    { OSSL_FUNC_KEYMGMT_HAS,               (DFUNC)wp_mac_has                  },
    { OSSL_FUNC_KEYMGMT_MATCH,             (DFUNC)wp_mac_match                },
    { OSSL_FUNC_KEYMGMT_IMPORT,            (DFUNC)wp_mac_import               },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,      (DFUNC)wp_hmac_import_types        },
    { OSSL_FUNC_KEYMGMT_EXPORT,            (DFUNC)wp_mac_export               },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,      (DFUNC)wp_hmac_export_types        },
    { 0, NULL }
};

#endif /* WP_HAVE_HMAC */

/*
 * CMAC
 */

#ifdef WP_HAVE_CMAC

/**
 * Create a new CMAC key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New MAC key object on success.
 * @return  NULL on failure.
 */
static wp_Mac *wp_cmac_new(WOLFPROV_CTX *provCtx)
{
    return wp_mac_new(provCtx, WP_MAC_TYPE_CMAC);
}

/**
 * Return an array of supported gettable parameters for the CMAC key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_cmac_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for CMAC key object.
     */
    static const OSSL_PARAM wp_cmac_supported_gettable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_cmac_supported_gettable_params;
}

/**
 * Return an array of supported settable parameters for the CMAC gen context.
 *
 * @param [in] ctx      MAC generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_cmac_gen_settable_params(wp_MacGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for HMAC generation context.
     */
    static const OSSL_PARAM wp_cmac_gen_supported_settable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_cmac_gen_supported_settable_params;
}

/**
 * Get the key parameters for a selection.
 *
 * @param [in] selection  Parts of key to import/export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_cmac_key_types(int selection)
{
    /**
     * Supported HMAC key parameters.
     */
    static const OSSL_PARAM wp_cmac_key_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    const OSSL_PARAM* params = NULL;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        params = wp_cmac_key_params;
    }
    return params;
}
/**
 * Get the key parameters when importing for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM *wp_cmac_import_types(int selection)
{
    return wp_cmac_key_types(selection);
}
/**
 * Get the key parameters when exporting for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM *wp_cmac_export_types(int selection)
{
    return wp_cmac_key_types(selection);
}

/**
 * Create CMAC generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New MAC generation context object on success.
 * @return  NULL on failure.
 */
static wp_MacGenCtx* wp_cmac_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    return wp_mac_gen_init(provCtx, selection, params, WP_MAC_TYPE_CMAC);
}

/** Dispatch table for CMAC key management. */
const OSSL_DISPATCH wp_cmac_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,               (DFUNC)wp_cmac_new                 },
    { OSSL_FUNC_KEYMGMT_FREE,              (DFUNC)wp_mac_free                 },
    { OSSL_FUNC_KEYMGMT_DUP,               (DFUNC)wp_mac_dup                  },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,          (DFUNC)wp_cmac_gen_init            },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,    (DFUNC)wp_mac_gen_set_params       },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                           (DFUNC)wp_cmac_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,               (DFUNC)wp_mac_gen                  },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,       (DFUNC)wp_mac_gen_cleanup          },
    { OSSL_FUNC_KEYMGMT_LOAD,              (DFUNC)wp_mac_load                 },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,        (DFUNC)wp_mac_get_params           },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,   (DFUNC)wp_cmac_gettable_params     },
    { OSSL_FUNC_KEYMGMT_HAS,               (DFUNC)wp_mac_has                  },
    { OSSL_FUNC_KEYMGMT_MATCH,             (DFUNC)wp_mac_match                },
    { OSSL_FUNC_KEYMGMT_IMPORT,            (DFUNC)wp_mac_import               },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,      (DFUNC)wp_cmac_import_types        },
    { OSSL_FUNC_KEYMGMT_EXPORT,            (DFUNC)wp_mac_export               },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,      (DFUNC)wp_cmac_export_types        },
    { 0, NULL }
};

#endif /* WP_HAVE_CMAC */

#endif /* WP_HAVE_HMAC || WP_HAVE_CMAC */

