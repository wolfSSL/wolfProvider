/* wp_dh_kmgmt.c
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
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>

#ifdef WP_HAVE_DH

/** Supported selections (key parts) in this key manager for DH. */
#define WP_DH_POSSIBLE_SELECTIONS                                              \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS)

/** Maximum size of the group name string. */
#define WP_MAX_DH_GROUP_NAME_SZ     10


/**
 * DH key.
 */
struct wp_Dh {
    /** wolfSSL DH key object. */
    DhKey key;
    /** Private key as a big-endian byte array. */
    unsigned char* priv;
    /** Length of private key data in bytes. */
    size_t privSz;
    /** Public key as a big-endian byte array. */
    unsigned char* pub;
    /** Length of public key data in bytes. */
    size_t pubSz;

#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;

    /** Provider context - useful when duplicating. */
    WOLFPROV_CTX* provCtx;

    /** wolfSSL id of parameter group. */
    int id;
    /** Number of bits in prime. */
    int bits;
};

typedef struct wp_DhGenCtx {
    /** Provider context - used when creating a DH key. */
    WOLFPROV_CTX* provCtx;
    /** The parts of a DH key to generate. */
    int selection;

    /** wolfSSL random number generator for signing. */
    WC_RNG rng;

    /** Template for DH key generation. */
    wp_Dh* dh;

    /** Name of group to representing the parameters. */
    char name[WP_MAX_DH_GROUP_NAME_SZ];
    /** Number of bits in prime. */
    int bits;
    /** Length of private key to generate - value ignored. */
    int privLen;
    /** DH generator parameter to use in generation - value ignored. */
    int generator;
} wp_DhGenCtx;

/**
 * Mapping of DH groups to wolfSSL data.
 */
typedef struct wp_DhGroupMap {
    /** Name of group to representing the parameters. */
    const char* name;
    /** wolfSSL id of DH group.  */
    int id;
    /** Number of bits in prime. */
    int bits;
#ifdef HAVE_PUBLIC_FFDHE
    /** Function to get group parameters from wolfSSL. */
    const DhParams*(*get)(void);
#else
    /** Name to use with wolfCrypt to get parameters. */
    int wcName;
#endif
} wp_DhGroupMap;


/* Prototype for generation initialization. */
static int wp_dh_gen_set_params(wp_DhGenCtx* ctx, const OSSL_PARAM params[]);

/*
 * DH group mapping.
 */

#ifdef HAVE_PUBLIC_FFDHE
    /* wolfCrypt Get function for each supported DH group. */
    #define WC_FFDHE2048    wc_Dh_ffdhe2048_Get
    #define WC_FFDHE3072    wc_Dh_ffdhe3072_Get
    #define WC_FFDHE4096    wc_Dh_ffdhe4096_Get
    #define WC_FFDHE6144    wc_Dh_ffdhe6144_Get
    #define WC_FFDHE8192    wc_Dh_ffdhe8192_Get
#else
    /* wolfCrypt Name for each supported DH group. */
    #define WC_FFDHE2048    WC_FFDHE_2048
    #define WC_FFDHE3072    WC_FFDHE_3072
    #define WC_FFDHE4096    WC_FFDHE_4096
    #define WC_FFDHE6144    WC_FFDHE_6144
    #define WC_FFDHE8192    WC_FFDHE_8192
#endif

/** Mapping of OpenSSL string to wolfSSL DH group information. */
static const wp_DhGroupMap wp_dh_group_map[] = {
#ifdef HAVE_FFDHE_2048
    { SN_ffdhe2048, WOLFSSL_FFDHE_2048, 2048, WC_FFDHE2048 },
#endif
#ifdef HAVE_FFDHE_3072
    { SN_ffdhe3072, WOLFSSL_FFDHE_3072, 3072, WC_FFDHE3072 },
#endif
#ifdef HAVE_FFDHE_4096
    { SN_ffdhe4096, WOLFSSL_FFDHE_4096, 4096, WC_FFDHE4096 },
#endif
#ifdef HAVE_FFDHE_6144
    { SN_ffdhe6144, WOLFSSL_FFDHE_6144, 6144, WC_FFDHE6144 },
#endif
#ifdef HAVE_FFDHE_8192
    { SN_ffdhe8192, WOLFSSL_FFDHE_8192, 8192, WC_FFDHE8192 },
#endif
};

/** Number of entries in DH group mapping. */
#define WP_DH_GROUP_MAP_SZ  \
    (sizeof(wp_dh_group_map) / sizeof(*wp_dh_group_map))


/**
 * Set the parameters into the DH key object based on group name.
 *
 * @param [in, out] dh    DH key object.
 * @param [in]      name  OpenSSL string name for DH group.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_map_group_name(wp_Dh* dh, const char* name)
{
    int ok = 1;
    size_t i;

    for (i = 0; i < WP_DH_GROUP_MAP_SZ; i++) {
        if (strcasecmp(wp_dh_group_map[i].name, name) == 0) {
    #ifdef HAVE_PUBLIC_FFDHE
            const DhParams* params;
    #endif
            int rc;

            dh->id   = wp_dh_group_map[i].id;
            dh->bits = wp_dh_group_map[i].bits;
    #ifdef HAVE_PUBLIC_FFDHE
            params = wp_dh_group_map[i].get();
            rc = mp_read_unsigned_bin(&dh->key.p, params->p, params->p_len);
            if (rc != 0) {
                ok = 0;
            }
            if (ok) {
                rc = mp_read_unsigned_bin(&dh->key.g, params->g, params->g_len);
                if (rc != 0) {
                    ok = 0;
                }
            }
        #ifdef HAVE_FFDHE_Q
            if (ok) {
                rc = mp_read_unsigned_bin(&dh->key.q, params->q, params->q_len);
                if (rc != 0) {
                    ok = 0;
                }
            }
        #endif
    #else
            rc = wc_DhSetNamedKey(&dh->key, wp_dh_group_map[i].wcName);
            if (rc != 0) {
                ok = 0;
            }
    #endif
            break;
        }
    }
    /* Index at size means it didn't find any match. */
    if (i == WP_DH_GROUP_MAP_SZ) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the OpenSSL string for the parameter group set in the DH key object.
 *
 * @param [in] dh  DH key object.
 * @return  NULL on failure.
 * @return  OpenSSL DH group name string.
 */
static const char* wp_dh_get_group_name(wp_Dh* dh)
{
    const char* name = NULL;
    size_t i;

    for (i = 0; i < WP_DH_GROUP_MAP_SZ; i++) {
        if (dh->id == wp_dh_group_map[i].id) {
            name = wp_dh_group_map[i].name;
            break;
        }
    }

    return name;
}


/*
 * DH key object functions.
 */

/**
 * Increment reference count for key.
 *
 * Used in key generation and key exchange.
 *
 * @param [in, out] dh  DH key object.
 * @return  1 on success.
 * @return  0 when multi-threaded and locking fails.
 */
int wp_dh_up_ref(wp_Dh* dh)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&dh->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        dh->refCnt++;
        wc_UnLockMutex(&dh->mutex);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    dh->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the wolfSSL DH object from the DH key object.
 *
 * @param [in] dh  DH key object.
 * @return  Pointer to wolfSSL DH object.
 */
DhKey* wp_dh_get_key(wp_Dh* dh)
{
    return &dh->key;
}

/**
 * Get the maximum size of a secret in bytes.
 *
 * @param [in] dh  DH key object.
 * @return  Maximum number of bytes in a secret.
 */
int wp_dh_get_size(const wp_Dh* dh)
{
    return (dh->bits + 7) / 8;
}

/**
 * Get the private key from the DH key object.
 *
 * wolfSSL requires the private key for key exchange to be passed in as a byte
 * array.
 *
 * @param [in]  dh      DH key object.
 * @param [out] priv    Private key data.
 * @param [out] privSz  Number of bytes in private key data.
 * @return  1 on success.
 * @return  0 when private key not set.
 */
int wp_dh_get_priv(wp_Dh* dh, unsigned char** priv, word32* privSz)
{
    int ok = 1;

    if (privSz == 0) {
        ok = 0;
    }
    else {
        *priv   = dh->priv;
        *privSz = (word32)dh->privSz;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the public key from the DH key object.
 *
 * wolfSSL requires the public key for key exchange to be passed in as a byte
 * array.
 *
 * @param [in]  dh     DH key object.
 * @param [out] pub    Public key data.
 * @param [out] pubSz  Number of bytes in public key data.
 * @return  1 on success.
 * @return  0 when public key not set.
 */
int wp_dh_get_pub(wp_Dh* dh, unsigned char** pub, word32* pubSz)
{
    int ok = 1;

    if (pubSz == 0) {
        ok = 0;
    }
    else {
        *pub   = dh->pub;
        *pubSz = (word32)dh->pubSz;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Create a new DH key object.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH key object on success.
 * @return  NULL on failure.
 */
static wp_Dh* wp_dh_new(WOLFPROV_CTX *provCtx)
{
    wp_Dh* dh = NULL;

    if (wolfssl_prov_is_running()) {
        dh = (wp_Dh*)OPENSSL_zalloc(sizeof(*dh));
    }
    if (dh != NULL) {
        int ok = 1;
        int rc;

        rc = wc_InitDhKey_ex(&dh->key, NULL, INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }
    #ifndef SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&dh->mutex);
            if (rc != 0) {
                wc_FreeDhKey(&dh->key);
                ok = 0;
            }
        }
    #endif
        if (ok) {
            dh->refCnt = 1;
            dh->provCtx = provCtx;
        }

        if (!ok) {
            /* wolfSSL DH object freed when mutext initialization fails. */
            OPENSSL_free(dh);
            dh = NULL;
        }
    }

    return dh;
}

/**
 * Dispose of DH key object.
 *
 * @param [in, out] dh  DH key object.
 */
void wp_dh_free(wp_Dh* dh)
{
    if (dh != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&dh->mutex);
        cnt = --dh->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&dh->mutex);
        }
    #else
        cnt = --dh->refCnt;
    #endif

        if (cnt == 0) {
            /* No more references to this object. */
            OPENSSL_free(dh->pub);
            OPENSSL_free(dh->priv);
    #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&dh->mutex);
    #endif
            wc_FreeDhKey(&dh->key);
            OPENSSL_free(dh);
        }
    }
}

/**
 * Copy the parameters from one DH key object into another.
 *
 * @param [in]      src  Source DH key object.
 * @param [in, out] dst  Destinate DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_copy_params(const wp_Dh *src, wp_Dh *dst)
{
    int ok = 1;
    int rc;

    /* Copy prime in wolfSSL object. */
    rc = mp_copy((mp_int*)&src->key.p, &dst->key.p);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        /* Copy generator in wolfSSL object. */
        rc = mp_copy((mp_int*)&src->key.g, &dst->key.g);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        /* Copy the small prime in wolfSSL object. */
        rc = mp_copy((mp_int*)&src->key.q, &dst->key.q);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        dst->id   = src->id;
        dst->bits = src->bits;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Duplicate specific parts of a DH key object.
 *
 * @param [in] src        Source DH key object.
 * @param [in] selection  Parts of key to include.
 * @return  NULL on failure.
 * @return  New DH key object on success.
 */
static wp_Dh* wp_dh_dup(const wp_Dh *src, int selection)
{
    wp_Dh* dst;

    /* Create a new DH key object to return. */
    dst = wp_dh_new(src->provCtx);
    if (dst != NULL) {
        int ok = 1;

        /* Copy the parameters when required. */
        if (((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) &&
            (!wp_dh_copy_params(src, dst))) {
            ok = 0;
        }
        /* Copy the public key parameters when required. */
        if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
            /* Must be copying parameters as well. */
            if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0) {
                ok = 0;
            }
            /* Must have public key! */
            if (ok && (src->pub == NULL)) {
                ok = 0;
            }
            /* Duplicates the public key data. */
            if (ok) {
                dst->pub = OPENSSL_memdup(src->pub, src->pubSz);
                if (dst->pub == NULL) {
                    ok = 0;
                }
            }
            if (ok) {
                dst->pubSz = src->pubSz;
            }
        }
        if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
            /* Must be copying parameters as well. */
            if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0) {
                ok = 0;
            }
            /* Must have private key! */
            if (ok && (src->priv == NULL)) {
                ok = 0;
            }
            /* Duplicates the private key data. */
            if (ok) {
                dst->priv = OPENSSL_memdup(src->priv, src->privSz);
                if (dst->priv == NULL) {
                    ok = 0;
                }
            }
            if (ok) {
                dst->privSz = src->privSz;
            }
        }

        /* Dispose of key object on error. */
        if (!ok) {
            wp_dh_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Load the DH key.
 *
 * Return the DH key object taken out of the reference.
 *
 * @param [in, out] pDh   Pointer to a DH key object.
 * @param [in]      size  Size of data structure that is the DH key object.
 *                        Unused.
 * @return  NULL when no DH key object at reference.
 * @return  DH key object from reference on success.
 */
static const wp_Dh* wp_dh_load(const wp_Dh** pDh, size_t size)
{
    const wp_Dh* dh = *pDh;
    /* TODO: validate the object is a wp_Dh? */
    (void)size;
    *pDh = NULL;
    return dh;
}

/**
 * Return an array of supported settable parameters for the DH key.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_dh_settable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for DH key.
     */
    static const OSSL_PARAM wp_dh_supported_settable_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_dh_supported_settable_params;
}

/**
 * Set the DH key parameters.
 *
 * @param [in, out] dh      DH key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_set_params(wp_Dh *dh, const OSSL_PARAM params[])
{
    int ok = 1;

    /* Encoded public key is a big-endian byte array of the number. */
    if ((params != NULL) && (!wp_params_get_octet_string(params,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, &dh->pub, &dh->pubSz, 0))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Return an array of supported gettable parameters for the DH key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM *wp_dh_gettable_params(WOLFPROV_CTX* provCtx)
{
    /**
     * Supported gettable parameters for DH key.
     */
    static const OSSL_PARAM wp_dh_supported_gettable_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provCtx;
    return wp_dh_supported_gettable_params;
}

/**
 * Get the security bits for a DH key.
 *
 * @param [in] dh  DH key object.
 * @return  Security bits on success.
 * @return  0 on failure.
 */
static int wp_dh_get_security_bits(wp_Dh* dh)
{
    int bits = 0;

    if (dh->bits >= 8192) {
        bits = 192;
    }
    else if (dh->bits >= 3072) {
        bits = 128;
    }
    else if (dh->bits >= 2048) {
        bits = 112;
    }
    else if (dh->bits >= 1024) {
        bits = 80;
    }

    return bits;
}

/**
 * Get the encoded public key into parameters.
 *
 * @param [in]      dh      DH key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_get_params_encoded_public_key(wp_Dh* dh, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ok = 0;
        }
        if (ok) {
            size_t outLen = mp_unsigned_bin_size(&dh->key.p);

            if (p->data != NULL) {
                if (p->data_size < outLen) {
                    ok = 0;
                }
                if (ok) {
                    unsigned char* data = p->data;
                    size_t padSz = outLen - dh->pubSz;
                    /* Front pad with zeros. */
                    XMEMSET(data, 0, padSz);
                    XMEMCPY(data + padSz, dh->pub, dh->pubSz);
                }
            }
            p->return_size = outLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the DH key parameters.
 *
 * @param [in]      dh      DH key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_get_params(wp_Dh* dh, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
        if (p != NULL) {
            if (!OSSL_PARAM_set_uint(p, mp_unsigned_bin_size(&dh->key.p))) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if (p != NULL) {
            if (!OSSL_PARAM_set_int(p, dh->bits)) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if (p != NULL) {
            if (!OSSL_PARAM_set_int(p, wp_dh_get_security_bits(dh))) {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_P);
        if (p != NULL) {
            /* When buffer is NULL, return the size irrespective of type */
            if (p->data == NULL) {
                ok = wp_params_set_mp(params, OSSL_PKEY_PARAM_FFC_P, &dh->key.g, 1);
            }
            /* When buffer is non-NULL, type must be int or uint */
            else 
            if (p->data_type == OSSL_PARAM_INTEGER || 
                     p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
                    ok = wp_params_set_mp(params, OSSL_PKEY_PARAM_FFC_P, &dh->key.p, 1);
            }
            else {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_G);
        if (p != NULL) {
            /* When buffer is NULL, return the size irrespective of type */
            if (p->data == NULL) {
                ok = wp_params_set_mp(params, OSSL_PKEY_PARAM_FFC_G, &dh->key.g, 1);
            }
            /* When buffer is non-NULL, type must be int or uint */
            else if (p->data_type == OSSL_PARAM_INTEGER || 
                     p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
                    ok = wp_params_set_mp(params, OSSL_PKEY_PARAM_FFC_G, &dh->key.g, 1);
            }
            else {
                ok = 0;
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FFC_Q);
        if (p != NULL) {
            /* OSSL does not check the type */
            ok = wp_params_set_mp(params, OSSL_PKEY_PARAM_FFC_Q, &dh->key.q, 1);
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            if (p->data == NULL) {
                p->return_size = dh->pubSz;
            }
            else { 
                /* return_size is set within this function */
                ok = wp_params_set_octet_string_be(params, OSSL_PKEY_PARAM_PUB_KEY,
                    dh->pub, dh->pubSz);
            }
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL) {
            if (p->data == NULL) {
                p->return_size = dh->pubSz;
            }
            else if (p->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
                if (p->data_size < dh->privSz) {
                    ok = 0;
                }
                else {
                    /* OSSL returns a BIGNUM, but we copy raw bytes*/
                    XMEMCPY(p->data, dh->priv, dh->privSz);
                    p->return_size = dh->privSz;
                }
            }
            else { 
                /* return_size is set within this function */
                ok = wp_params_set_octet_string_be(params, OSSL_PKEY_PARAM_PRIV_KEY,
                    dh->priv, dh->privSz);
            }
        }
    }
    if (ok && (!wp_params_set_octet_string_be(params, OSSL_PKEY_PARAM_PRIV_KEY,
            dh->priv, dh->privSz))) {
        ok = 0;
    }
    if (ok && (!wp_dh_get_params_encoded_public_key(dh, params))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check DH key object has the components required.
 *
 * @param [in] dh         DH key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_has(const wp_Dh* dh, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (dh == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        ok &= dh->pubSz > 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        ok &= dh->privSz > 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)) {
        ok &= (dh->id != 0) || (!mp_iszero((mp_int*)&dh->key.p));
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two DH key objects match for the components specified.
 *
 * @param [in] dh1        First DH key object.
 * @param [in] dh2        Second DH key object.
 * @param [in] selection  Parts of key to match.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_dh_match(const wp_Dh* dh1, const wp_Dh* dh2, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
        /* Compare public key buffers. */
        ok &= dh1->pubSz == dh2->pubSz;
        if (ok) {
            ok &= XMEMCMP(dh1->pub, dh2->pub, dh1->pubSz) == 0;
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        /* Compare private key buffers. */
        ok &= dh1->privSz == dh2->privSz;
        if (ok) {
            ok &= XMEMCMP(dh1->priv, dh2->priv, dh1->privSz) == 0;
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)) {
        /* Check id is the same. */
        ok &= dh1->id == dh2->id;
        if (ok && (dh1->id == 0)) {
            ok &= (mp_cmp((mp_int*)&dh1->key.p, (mp_int*)&dh2->key.p) == MP_EQ);
            ok &= (mp_cmp((mp_int*)&dh1->key.g, (mp_int*)&dh2->key.g) == MP_EQ);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
/**
 * Quickly validate the public part of DH key.
 *
 * @param [in] dh         DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_validate_pub_key_quick(const wp_Dh* dh)
{
    int ok = 1;
    int rc;
    word32 primeSz = mp_unsigned_bin_size((mp_int*)&dh->key.p);
    unsigned char* prime;

    prime = OPENSSL_malloc(primeSz);
    if (prime == NULL) {
        ok = 0;
    }
    if (ok) {
        rc = mp_to_unsigned_bin((mp_int*)&dh->key.p, prime);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        rc = wc_DhCheckPubValue(prime, primeSz, dh->pub, (word32)dh->pubSz);
        if (rc != 0) {
            ok = 0;
        }
    }
    OPENSSL_free(prime);

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Validate the DH key.
 *
 * @param [in] dh         DH key object.
 * @param [in] selection  Parts of key to validate.
 * @param [in] checkType  How thorough to check key. Values:
 *                          OSSL_KEYMGMT_VALIDATE_FULL_CHECK or
 *                          OSSL_KEYMGMT_VALIDATE_QUICK_CHECK.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_validate(const wp_Dh* dh, int selection, int checkType)
{
    int ok = 1;
    int rc;

    if (((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) &&
        (dh->id == 0)) {
        /* TODO: check explicit parameters. */
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)) {
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        /* TODO: quick check for older versions? */
        if (checkType == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK) {
            ok = wp_dh_validate_pub_key_quick(dh);
        }
        else
    #else
        (void)checkType;
    #endif
        {
            rc = wc_DhCheckPubKey((DhKey*)&dh->key, dh->pub, (word32)dh->pubSz);
            if (rc != 0) {
                ok = 0;
            }
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)) {
        rc = wc_DhCheckPrivKey((DhKey*)&dh->key, dh->priv, (word32)dh->privSz);
        if (rc != 0) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the group into DH key object from parameters.
 *
 * @param [in, out] dh      DH key object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_import_group(wp_Dh* dh, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;
    const char* name = NULL;

    /* Look for the group name first. */
    if (!wp_params_get_utf8_string_ptr(params, OSSL_PKEY_PARAM_GROUP_NAME,
            &name)) {
        ok = 0;
    }
    /* When name was found, set the parameters based on the mapping. */
    if (ok && (name != NULL) && (!wp_dh_map_group_name(dh, name))) {
        ok = 0;
    }
    if (ok && (name == NULL)) {
        /* Set the explicit parameters instead. */
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
        if ((p != NULL) && (!wp_mp_read_unsigned_bin_le(&dh->key.p, p->data,
                p->data_size))) {
            ok = 0;
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);
            if ((p != NULL) && (!wp_mp_read_unsigned_bin_le(&dh->key.g, p->data,
                    p->data_size))) {
                ok = 0;
            }
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
            if ((p != NULL) && (!wp_mp_read_unsigned_bin_le(&dh->key.q, p->data,
                    p->data_size))) {
                ok = 0;
            }
        }
        if (ok) {
            dh->bits = mp_count_bits(&dh->key.p);
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key pair into DH key object from parameters.
 *
 * @param [in, out] dh      DH key object.
 * @param [in]      params  Array of parameters and values.
 * @param [in]      priv    Private key is to be imported.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_import_keypair(wp_Dh* dh, const OSSL_PARAM params[],
    int priv)
{
    int ok = 1;

    if (!wp_params_get_bn_be(params, OSSL_PKEY_PARAM_PUB_KEY, &dh->pub,
            &dh->pubSz, 0)) {
        ok = 0;
    }
    if (ok && priv && (!wp_params_get_bn_be(params, OSSL_PKEY_PARAM_PRIV_KEY,
            &dh->priv, &dh->privSz, 1))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key into DH key object from parameters.
 *
 * @param [in, out] dh         DH key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_import(wp_Dh* dh, int selection, const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (dh == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_DH_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0) &&
        (!wp_dh_import_group(dh, params))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) &&
        (!wp_dh_import_keypair(dh, params,
           (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** DH private key parameters. */
#define WP_DH_PRIVATE_KEY_PARAMS                                               \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
/** DH public key parameters. */
#define WP_DH_PUBLIC_KEY_PARAMS                                                \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
/** DH domain parameters - with FFC_Q. */
#define WP_DH_DOMAIN_PARAMS                                                    \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0),                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),                             \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0)

/**
 * Table of key parameters for difference selections.
 */
static const OSSL_PARAM wp_dh_key_params[] = {
    /* 0 */
    OSSL_PARAM_END,

    /* 1 */
    WP_DH_PRIVATE_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 3 */
    WP_DH_PUBLIC_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 5 */
    WP_DH_PRIVATE_KEY_PARAMS,
    WP_DH_PUBLIC_KEY_PARAMS,
    OSSL_PARAM_END,

    /* 8 */
    WP_DH_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 12/13 */
    WP_DH_PRIVATE_KEY_PARAMS,
    WP_DH_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 17/19 */
    WP_DH_PUBLIC_KEY_PARAMS,
    WP_DH_DOMAIN_PARAMS,
    OSSL_PARAM_END,

    /* 22/25 */
    WP_DH_PUBLIC_KEY_PARAMS,
    WP_DH_PRIVATE_KEY_PARAMS,
    WP_DH_DOMAIN_PARAMS,
    OSSL_PARAM_END,
};

/**
 * Get the key parameters for a selection.
 *
 * @param [in] selection  Parts of key to import/export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_dh_key_types(int selection)
{
    int idx = 0;
    int extra = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        idx += 8;
        extra += 4;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        idx += 3 + 2 * extra;
        extra++;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        idx += 1 + extra;
    }

    return &wp_dh_key_params[idx];
}

/**
 * Get the key parameters when importing for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_dh_import_types(int selection)
{
    return wp_dh_key_types(selection);
}


/**
 * Get the size of allocated data needed for group.
 *
 * Called when exporting.
 *
 * @param [in] dh  DH key object.
 * @return  Size of buffer to hold allocated group data.
 */
static size_t wp_dh_export_group_alloc_size(wp_Dh* dh)
{
    size_t sz = 0;
    const char* name;

    name = wp_dh_get_group_name(dh);
    if (name == NULL) {
        sz  = mp_unsigned_bin_size(&dh->key.p) +
              mp_unsigned_bin_size(&dh->key.g) +
              mp_unsigned_bin_size(&dh->key.q);
    }

    return sz;
}

/**
 * Put the DH key's group data into the parameters.
 *
 * Assumes data buffer is big enough.
 *
 * @param [in]      dh      DH key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @param [in, out] data    Data buffer to place group data into.
 * @param [in, out] idx     Pointer to current index into data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_export_group(wp_Dh* dh, OSSL_PARAM params[], int* pIdx,
    unsigned char* data, size_t* idx)
{
    int ok = 1;
    const char* name;
    int i = *pIdx;

    name = wp_dh_get_group_name(dh);
    if (name != NULL) {
        wp_param_set_utf8_string_ptr(&params[i++], OSSL_PKEY_PARAM_GROUP_NAME,
            name);
    }
    else {
        if (!wp_param_set_mp(&params[i++], OSSL_PKEY_PARAM_FFC_P, &dh->key.p,
                data, idx)) {
            ok = 0;
        }
        if (ok && (!wp_param_set_mp(&params[i++], OSSL_PKEY_PARAM_FFC_G,
                &dh->key.g, data, idx))) {
            ok = 0;
        }
        if (ok && (!wp_param_set_mp(&params[i++], OSSL_PKEY_PARAM_FFC_Q,
                &dh->key.q, data, idx))) {
            ok = 0;
        }
    }

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the size of allocated data needed for key pair.
 *
 * Called when exporting.
 *
 * @param [in] dh  DH key object.
 * @return  Size of buffer to hold allocated key pair data.
 */
static size_t wp_dh_export_keypair_alloc_size(wp_Dh* dh)
{
    return dh->pubSz + dh->privSz;
}

/**
 * Put the DH key pair data into the parameter.
 *
 * Assumes data buffer is big enough.
 *
 * @param [in]      dh      DH key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @param [in, out] data    Data buffer to place group data into.
 * @param [in, out] idx     Pointer to current index into data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_export_keypair(wp_Dh* dh, OSSL_PARAM params[], int* pIdx,
    unsigned char* data, size_t* idx)
{
    int ok = 1;
    int i = *pIdx;

    if (dh->pubSz > 0) {
        wp_param_set_mp_buf(&params[i++], OSSL_PKEY_PARAM_PUB_KEY, dh->pub,
            dh->pubSz, data, idx);
    }
    if (dh->privSz > 0) {
        wp_param_set_mp_buf(&params[i++], OSSL_PKEY_PARAM_PRIV_KEY, dh->priv,
            dh->privSz, data, idx);
    }

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the DH key.
 *
 * Key data placed in parameters and then passed to callback.
 *
 * @param [in] dh         DH key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Function to pass constructed parameters to.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_export(wp_Dh *dh, int selection, OSSL_CALLBACK *paramCb,
    void *cbArg)
{
    int ok = 1;
    OSSL_PARAM params[6];
    int paramsSz = 0;
    unsigned char* data = NULL;
    size_t sz = 0;
    size_t idx = 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && (dh == NULL)) {
        ok = 0;
    }
    if (ok) {
        XMEMSET(params, 0, sizeof(params));

        sz = wp_dh_export_keypair_alloc_size(dh);
        if (((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)) {
            sz += wp_dh_export_group_alloc_size(dh);
        }

        data = OPENSSL_secure_malloc(sz);
        if (data == NULL) {
            ok = 0;
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)) {
        ok &= wp_dh_export_group(dh, params, &paramsSz, data, &idx);
    }
    if (ok && (!wp_dh_export_keypair(dh, params, &paramsSz, data, &idx))) {
        ok = 0;
    }
    if (ok && (!(*paramCb)(params, cbArg))) {
        ok = 0;
    }
    OPENSSL_secure_clear_free(data, sz);

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the key parameters when exporting for a selection.
 *
 * @param [in] selection  Parts of key to export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM *wp_dh_export_types(int selection)
{
    return wp_dh_key_types(selection);
}

/**
 * Return the operation name as a string.
 *
 * @param [in] op  Operationn type being performed. Unused.
 * @return  Name of DH operation.
 */
static const char* wp_dh_query_operation_name(int op)
{
    (void)op;
    return "DH";
}

/*
 * DH parameter/key generation functions.
 */

/**
 * Create DH generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New DH generation context object on success.
 * @return  NULL on failure.
 */
static wp_DhGenCtx* wp_dh_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[])
{
    wp_DhGenCtx* ctx = NULL;

    if (wolfssl_prov_is_running() &&
        ((selection & WP_DH_POSSIBLE_SELECTIONS) != 0)) {
        ctx = OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int rc;
        int ok = 1;

        rc = wc_InitRng(&ctx->rng);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            if (!wp_dh_gen_set_params(ctx, params)) {
                wc_FreeRng(&ctx->rng);
                ok = 0;
            }
        }
        if (ok) {
            ctx->provCtx   = provCtx;
            ctx->selection = selection;
            ctx->bits      = 2048;
            ctx->generator = 2;
        }

        if (!ok) {
            /* Rng freed when parameters fail to set. */
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/**
 * Set a template key.
 *
 * Copies the parameters into a new DH object that is stored in the DH
 * generation context object.
 *
 * @param [in, out] ctx  DH generation context object.
 * @param [in]      dh   DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_gen_set_template(wp_DhGenCtx* ctx, const wp_Dh* dh)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }

    if (ok && (ctx->dh != dh)) {
        wp_Dh* dupDh = wp_dh_dup(dh, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS);
        if (dupDh == NULL) {
            ok = 0;
        }
        else {
            wp_dh_free(ctx->dh);
            ctx->dh = dupDh;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Sets the parameters into the DH generation context object.
 *
 * @param [in, out] ctx     DH generation context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_gen_set_params(wp_DhGenCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PBITS);
    if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ctx->bits))) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
        if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ctx->privLen))) {
            return 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_GENERATOR);
        if ((p != NULL) && (!OSSL_PARAM_get_int(p, &ctx->generator))) {
            ok = 0;
        }
    }
    if (ok && (!wp_params_get_utf8_string(params, OSSL_PKEY_PARAM_GROUP_NAME,
            ctx->name, sizeof(ctx->name)))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate DH group parameters using wolfSSL.
 *
 * @param [in, out] ctx  DH generation context object.
 * @param [in, out] dh   DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_gen_parameters(wp_DhGenCtx *ctx, wp_Dh* dh)
{
    int ok = 1;
    int rc;

    rc = wc_DhGenerateParams(&ctx->rng, ctx->bits, &dh->key);
    if (rc != 0) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Copy the group parameters into the DH key object.
 *
 * Use the template key if available. Otherwise use the group name.
 *
 * @param [in]      ctx  DH generation context object.
 * @param [in, out] dh   DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_gen_copy_parameters(wp_DhGenCtx *ctx, wp_Dh* dh)
{
    int ok = 1;

    if (ctx->dh != NULL) {
        int rc;

        rc = mp_copy(&ctx->dh->key.p, &dh->key.p);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            rc = mp_copy(&ctx->dh->key.g, &dh->key.g);
            if (rc != 0) {
                ok = 0;
            }
        }
        if (ok) {
            rc = mp_copy(&ctx->dh->key.q, &dh->key.q);
            if (rc != 0) {
                ok = 0;
            }
        }
        dh->bits = mp_count_bits(&dh->key.p);
    }
    else if (ctx->name[0] != '\0') {
        if (!wp_dh_map_group_name(dh, ctx->name)) {
            ok = 0;
        }
    }
    else {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate DH key pair using wolfSSL.
 *
 * @param [in, out] ctx  DH generation context object.
 * @param [in, out] dh   DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_gen_keypair(wp_DhGenCtx *ctx, wp_Dh* dh)
{
    int ok = 1;
    int rc;
    unsigned char* p = NULL;
    word32 sz;
    word32 pubSz;
    word32 privSz;

    /* The size of the generated private key will be the size of the small
     * prime 'q'. When not available, just use the size of the prime 'p'.
     */
    if (!mp_iszero(&dh->key.q)) {
        sz = mp_unsigned_bin_size(&dh->key.q);
    }
    else
    {
        sz = mp_unsigned_bin_size(&dh->key.p);
    }
    /* Allocate space for generated private key data. */
    if (sz > dh->privSz) {
        p = OPENSSL_realloc(dh->priv, sz);
        if (p == NULL) {
            ok = 0;
        }
        else {
            dh->priv = p;
            dh->privSz = sz;
            p = NULL;
        }
    }
    if (ok) {
        /* Allocate space for generated public key data. */
        sz = mp_unsigned_bin_size(&dh->key.p);
        if (sz > dh->pubSz) {
            p = OPENSSL_realloc(dh->pub, sz);
            if (p == NULL) {
                ok = 0;
            }
            else {
                dh->pub = p;
                dh->pubSz = sz;
            }
        }
    }
    if (ok) {
        /* Use wolfSSL to generate key pair. */
        pubSz = (word32)dh->pubSz;
        privSz = (word32)dh->privSz;
    #if LIBWOLFSSL_VERSION_HEX >= 0x05000000
        /* TODO: don't want to check parameters in older versions! */
        dh->key.trustedGroup = 1;
    #endif
        PRIVATE_KEY_UNLOCK();
        rc = wc_DhGenerateKeyPair(&dh->key, &ctx->rng, dh->priv, &privSz,
            dh->pub, &pubSz);
        PRIVATE_KEY_LOCK();
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        dh->pubSz = pubSz;
        dh->privSz = privSz;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Validate the DH parameters.
 *
 * @param [in] dh  DH key object.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_params_validate(wp_Dh* dh)
{
    int ok = 1;
    int rc;
    word32 sz;
    mp_int t;
    mp_int one;

    rc = mp_init_multi(&t, &one, NULL, NULL, NULL, NULL);
    if (rc != 0) {
        ok = 0;
    }

    if (ok) {
        /* Ensure p is a minimum size. */
        sz = mp_count_bits(&dh->key.p);
        if (sz < 1024) {
            ok = 0;
        }

        if (ok && (mp_set(&one, 1) != 0)) {
            ok = 0;
        }

        /* Check generator is not 1 or less. */
        if (ok && (mp_cmp(&dh->key.g, &one) != MP_GT)) {
            ok = 0;
        }
        /* Check generator is less than prime. */
        if (ok && (mp_cmp(&dh->key.g, &dh->key.p) != MP_LT)) {
            ok = 0;
        }
        /* Ensure generator works. */
        if (ok && (mp_exptmod(&dh->key.g, &dh->key.q, &dh->key.p, &t) != 0)) {
            ok = 0;
        }
        if (ok && (!mp_isone(&t))) {
            ok = 0;
        }

        mp_clear(&one);
        mp_clear(&t);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Generate group parameters/key pair.
 *
 * @param [in, out] ctx    DH generation context object.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument to pass to callback. Unused.
 * @return  NULL on failure.
 * @return  New DH key object on success.
 */
static wp_Dh* wp_dh_gen(wp_DhGenCtx *ctx, OSSL_CALLBACK *cb, void *cbArg)
{
    wp_Dh* dh = NULL;

    (void)cb;
    (void)cbArg;

    /* Create a new DH key object to hold generated data. */
    dh = wp_dh_new(ctx->provCtx);
    if (dh != NULL) {
        int ok = 1;

        /* Either generate parameters or copy. */
        if (ok && ((ctx->selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) !=
                0)) {
            if (!wp_dh_gen_parameters(ctx, dh)) {
                ok = 0;
            }
        }
        else if (!wp_dh_gen_copy_parameters(ctx, dh)) {
            ok = 0;
        }
        /* Generate key pair if requested. */
        if (ok && ((ctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)) {
            if (!wp_dh_params_validate(dh)) {
                ok = 0;
            }
            if (ok && (!wp_dh_gen_keypair(ctx, dh))) {
                ok = 0;
            }
        }

        if (!ok) {
            wp_dh_free(dh);
            dh = NULL;
        }
    }

    return dh;
}

/**
 * Dispose of the DH generation context object.
 *
 * @param [in, out] ctx  DH generation context object.
 */
static void wp_dh_gen_cleanup(wp_DhGenCtx *ctx)
{
    wp_dh_free(ctx->dh);
    wc_FreeRng(&ctx->rng);
    OPENSSL_free(ctx);
}

/**
 * Return an array of supported settable parameters for the DH gen context.
 *
 * @param [in] ctx      DH generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_dh_gen_settable_params(wp_DhGenCtx* ctx,
    WOLFPROV_CTX* provCtx)
{
    /**
     * Supported settable parameters for DH generation context.
     */
    static OSSL_PARAM wp_dh_gen_supported_settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_PRIV_LEN, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_FFC_PBITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_DH_GENERATOR, NULL),
        OSSL_PARAM_END
    };
    (void)ctx;
    (void)provCtx;
    return wp_dh_gen_supported_settable;
}


/**
 * Dispatch table for DH/DHX key management.
 */
const OSSL_DISPATCH wp_dh_keymgmt_functions[] = {
    /* DH key. */
    { OSSL_FUNC_KEYMGMT_NEW,                (DFUNC)wp_dh_new                  },
    { OSSL_FUNC_KEYMGMT_FREE,               (DFUNC)wp_dh_free                 },
    { OSSL_FUNC_KEYMGMT_DUP,                (DFUNC)wp_dh_dup                  },
    { OSSL_FUNC_KEYMGMT_LOAD,               (DFUNC)wp_dh_load                 },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,         (DFUNC)wp_dh_get_params           },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,    (DFUNC)wp_dh_gettable_params      },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS,         (DFUNC)wp_dh_set_params           },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,    (DFUNC)wp_dh_settable_params      },
    { OSSL_FUNC_KEYMGMT_HAS,                (DFUNC)wp_dh_has                  },
    { OSSL_FUNC_KEYMGMT_MATCH,              (DFUNC)wp_dh_match                },
    { OSSL_FUNC_KEYMGMT_VALIDATE,           (DFUNC)wp_dh_validate             },
    { OSSL_FUNC_KEYMGMT_IMPORT,             (DFUNC)wp_dh_import               },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,       (DFUNC)wp_dh_import_types         },
    { OSSL_FUNC_KEYMGMT_EXPORT,             (DFUNC)wp_dh_export               },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,       (DFUNC)wp_dh_export_types         },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
                                            (DFUNC)wp_dh_query_operation_name },
    /* DH generation. */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,           (DFUNC)wp_dh_gen_init             },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,     (DFUNC)wp_dh_gen_set_params       },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                            (DFUNC)wp_dh_gen_settable_params  },
    { OSSL_FUNC_KEYMGMT_GEN,                (DFUNC)wp_dh_gen                  },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,        (DFUNC)wp_dh_gen_cleanup          },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,   (DFUNC)wp_dh_gen_set_template     },
    { 0, NULL }
};

/*
 * DH encoding/decoding.
 */

/* TODO: encode public/private key. */
/* TODO: support PKCS#8 formatted private key. */
/* TODO: support encrypted PKCS#8 formatted private key. */


/**
 * Encode/decode DH public/private key.
 */
typedef struct wp_DhEncDecCtx {
    /** Provider context - used when creating DH key. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to export. */
    int selection;

    /** Supported format. */
    int format;
    /** Data format: DER or PEM. */
    int encoding;

    /** Cipher to use when encoding EncryptedPrivateKeyInfo. */
    int cipher;
    /** Name of cipher to use when encoding EncryptedPrivateKeyInfo. */
    const char* cipherName;
} wp_DhEncDecCtx;


/**
 * Create a new DH encoder/decoder context.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] format    Supported format.
 * @param [in] encoding  Data format.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_enc_dec_new(WOLFPROV_CTX* provCtx, int format,
    int encoding)
{
    wp_DhEncDecCtx *ctx = NULL;
    if (wolfssl_prov_is_running()) {
        ctx = (wp_DhEncDecCtx*)OPENSSL_zalloc(sizeof(wp_DhEncDecCtx));
    }
    if (ctx != NULL) {
        ctx->provCtx  = provCtx;
        ctx->format   = format;
        ctx->encoding = encoding;
    }
    return ctx;
}

/**
 * Dispose of DH encoder/decoder context object.
 *
 * @param [in, out] ctx  DH encoder/decoder context object.
 */
static void wp_dh_enc_dec_free(wp_DhEncDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return the settable parameters for the DH encoder/decoder context.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_dh_enc_dec_settable_ctx_params(
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_dh_enc_dec_supported_settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    (void)provCtx;
    return wp_dh_enc_dec_supported_settables;
}

/**
 * Set the DH encoder/decoder context parameters.
 *
 * @param [in, out] ctx     DH encoder/decoder context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_enc_dec_set_ctx_params(wp_DhEncDecCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wp_cipher_from_params(params, &ctx->cipher, &ctx->cipherName)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if (LIBWOLFSSL_VERSION_HEX >= 0x05000000 && defined(WOLFSSL_DH_EXTRA))
extern int wc_DhPublicKeyDecode(const byte* input, word32* inOutIdx, DhKey* key,
    word32 inSz);

/**
 * Decode the SubjectPublicInfo DER encoded DH key into the DH key object.
 *
 * @param [in, out] dh    DH key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_decode_spki(wp_Dh* dh, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;

    rc = wc_DhPublicKeyDecode(data, &idx, &dh->key, len);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        dh->pubSz = mp_unsigned_bin_size(&dh->key.pub);
        dh->pub = OPENSSL_malloc(dh->pubSz);
        if (dh->pub == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        rc = mp_to_unsigned_bin(&dh->key.pub, dh->pub);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        dh->bits = mp_count_bits(&dh->key.p);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#else
/**
 * Decode the SubjectPublicInfo DER encoded DH key into the DH key object.
 *
 * @param [in, out] dh    DH key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_decode_spki(wp_Dh* dh, unsigned char* data, word32 len)
{
    (void)dh;
    (void)data;
    (void)len;
    return 0;
}
#endif

#ifdef WOLFSSL_DH_EXTRA
/**
 * Decode the PrivateKeyInfo DER encoded DH key into the DH key object.
 *
 * @param [in, out] dh    DH key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_decode_pki(wp_Dh* dh, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;
    unsigned char* base = NULL;

    rc = wc_DhKeyDecode(data, &idx, &dh->key, len);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        dh->privSz = mp_unsigned_bin_size(&dh->key.priv);
        dh->priv = OPENSSL_malloc(dh->privSz);
        if (dh->priv == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        rc = mp_to_unsigned_bin(&dh->key.priv, dh->priv);
        if (rc != 0) {
            ok = 0;
        }
    }
    /* Calculate the public key. base ^ priv using key agree. */
    if (ok) {
        base = OPENSSL_malloc(mp_unsigned_bin_size(&dh->key.g));
        if (base == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        rc = mp_to_unsigned_bin(&dh->key.g, base);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        dh->pub = OPENSSL_malloc(mp_unsigned_bin_size(&dh->key.p));
        if (dh->pub == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        rc = wc_DhAgree(&dh->key, dh->pub, &idx, dh->priv, (word32)dh->privSz,
            base, 1);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        dh->pubSz = idx;
        dh->bits = mp_count_bits(&dh->key.p);
    }

    OPENSSL_free(base);
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#else
/**
 * Decode the PrivateKeyInfo DER encoded DH key into the DH key object.
 *
 * @param [in, out] dh    DH key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_decode_pki(wp_Dh* dh, unsigned char* data, word32 len)
{
    (void)dh;
    (void)data;
    (void)len;
    return 0;
}
#endif

/**
 * Decode the DER encoded DH parameters into the DH key object.
 *
 * @param [in, out] dh    DH key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_decode_params(wp_Dh* dh, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;

    rc = wc_DhKeyDecode(data, &idx, &dh->key, len);
    if (rc != 0) {
        ok = 0;
    }
    if (ok) {
        dh->bits = mp_count_bits(&dh->key.p);
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Construct parameters from DH key and pass off to callback.
 *
 * @param [in] dh        DH key object.
 * @param [in] dataCb     Callback to pass DH key in parameters to.
 * @param [in] dataCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_dec_send_params(wp_Dh* dh, OSSL_CALLBACK *dataCb,
    void *dataCbArg)
{
    int ok = 1;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (char*)"DH", 0);
    /* The address of the key object becomes the octet string pointer. */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &dh, sizeof(dh));
    params[3] = OSSL_PARAM_construct_end();

    /* Callback to do something with DH key object. */
    if (!dataCb(params, dataCbArg)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the data in the core BIO.
 *
 * The format of the key must be the same as the decoder's format.
 *
 * @param [in, out] ctx        DH encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to read data from.
 * @param [in]      selection  Parts of key to export.
 * @param [in]      dataCb     Callback to pass DH key in parameters to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_decode(wp_DhEncDecCtx* ctx, OSSL_CORE_BIO *cBio,
    int selection, OSSL_CALLBACK *dataCb, void *dataCbArg,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    int ok = 1;
    int decoded = 1;
    wp_Dh* dh = NULL;
    unsigned char* data = NULL;
    word32 len = 0;

    (void)pwCb;
    (void)pwCbArg;

    ctx->selection = selection;

    dh = wp_dh_new(ctx->provCtx);
    if (dh == NULL) {
        ok = 0;
    }
    if (ok && (!wp_read_der_bio(ctx->provCtx, cBio, &data, &len))) {
        ok = 0;
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC)) {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0){
            if (!wp_dh_decode_pki(dh, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
        else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            if (!wp_dh_decode_spki(dh, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
        else {
            if (!wp_dh_decode_params(dh, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        if (!wp_dh_decode_spki(dh, data, len)) {
            ok = 0;
            decoded = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        if (!wp_dh_decode_pki(dh, data, len)) {
            ok = 0;
            decoded = 0;
        }
    }

    OPENSSL_clear_free(data, len);

    if (ok && (!wp_dh_dec_send_params(dh, dataCb, dataCbArg))) {
        ok = 0;
    }

    if (!ok) {
        /* Callback takes key. */
        wp_dh_free(dh);
        if (!decoded) {
            ok = 1;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#if (LIBWOLFSSL_VERSION_HEX >= 0x05000000 && defined(WOLFSSL_DH_EXTRA))
/**
 * Get the Parameters encoding size for the key.
 *
 * @param [in]  dh      DH key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_params_size(const wp_Dh *dh, size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len;

    ret = wc_DhParamsToDer((DhKey*)&dh->key, NULL, &len);
    if (ret != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the DH key in a Parameters format.
 *
 * @param [in]      dh       DH key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_params(const wp_Dh *dh, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len = (word32)*keyLen;

    ret = wc_DhParamsToDer((DhKey*)&dh->key, keyData, &len);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the SubjectPublicKeyInfo encoding size for the key.
 *
 * @param [in]  dh      DH key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_spki_size(const wp_Dh *dh, size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len;

    /* If we have a generated public key that is not set in the inner key,
     * set it now */
    if (mp_bitsused(&dh->key.pub) == 0 && dh->pub != NULL && dh->pubSz > 0) {
        ret = wc_DhImportKeyPair((DhKey*)&dh->key, NULL, 0,
            dh->pub, (word32)dh->pubSz);
        if (ret != 0) {
            ok = 0;
        }
    }

    ret = wc_DhPubKeyToDer((DhKey*)&dh->key, NULL, &len);
    if (ret != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the DH key in a SubjectPublicKeyInfo format.
 *
 * @param [in]      dh       DH key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_spki(const wp_Dh *dh, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len = (word32)*keyLen;

    ret = wc_DhPubKeyToDer((DhKey*)&dh->key, keyData, &len);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
        /* wolfSSL calculating it wrong. */
        if (keyData[1] == 0x81) {
            keyData[2] = len - 3;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the PKCS#8 encoding size for the key.
 *
 * @param [in]  dh      DH key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_pki_size(const wp_Dh *dh, size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len;

    /* If we have a generated private key that is not set in the inner key,
     * set it now */
    if (mp_bitsused(&dh->key.priv) == 0 && dh->priv != NULL && dh->privSz > 0) {
        ret = wc_DhImportKeyPair((DhKey*)&dh->key, dh->priv, (word32)dh->privSz,
            dh->pub, (word32)dh->pubSz);
        if (ret != 0) {
            ok = 0;
        }
    }

    ret = wc_DhPrivKeyToDer((DhKey*)&dh->key, NULL, &len);
    if (ret != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the DH key in a PKCS#8 format.
 *
 * @param [in]      dh       DH key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_pki(const wp_Dh *dh, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len = (word32)*keyLen;

    ret = wc_DhPrivKeyToDer((DhKey*)&dh->key, keyData, &len);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = len;
        /* wolfSSL calculating it wrong. */
        if (keyData[1] == 0x81) {
            keyData[2] = len - 3;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS
/**
 * Get the Encrypted PKCS#8 encoding size for the key.
 *
 * @param [in]  ctx     DH encoder/decoder context object.
 * @param [in]  dh      DH key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_epki_size(const wp_Dh *dh, size_t* keyLen)
{
    int ok = 1;
    int ret;
    word32 len;

    ret = wc_DhPrivKeyToDer((DhKey*)&dh->key, NULL, &len);
    if (ret != LENGTH_ONLY_E) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ((len + 15) / 16) * 16;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the DH key in an Encrypted PKCS#8 format.
 *
 * @param [in]      ctx         DH encoder/decoder context object.
 * @param [in]      dh          DH key object.
 * @param [out]     keyData     Buffer to hold encoded data.
 * @param [in, out] keyLen      On in, length of buffer in bytes.
 *                              On out, length of encoding in bytes.
 * @param [in]      pwCb        Password callback.
 * @param [in]      pwCbArg     Argument to pass to password callback.
 * @param [out]     cipherInfo  Information about encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode_epki(const wp_DhEncDecCtx* ctx, const wp_Dh *dh,
    unsigned char* keyData, size_t* keyLen, OSSL_PASSPHRASE_CALLBACK *pwCb,
    void *pwCbArg, byte** cipherInfo)
{
    int ok = 1;
    int rc;
    word32 pkcs8Len = (word32)*keyLen;

    /* Encode key. */
    rc = wc_DhPrivKeyToDer((DhKey*)&dh->key, keyData, &pkcs8Len);
    if (rc <= 0) {
        ok = 0;
    }
    if (ok && (!wp_encrypt_key(ctx->provCtx, ctx->cipherName, keyData, keyLen,
            pkcs8Len, pwCb, pwCbArg, cipherInfo))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif
#endif

/**
 * Encode the DH key.
 *
 * @param [in]      ctx        DH encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      key        DH key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode. Unused.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_encode(wp_DhEncDecCtx* ctx, OSSL_CORE_BIO *cBio,
    const wp_Dh *key, const OSSL_PARAM* params, int selection,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg)
{
    int ok = 1;
#if (LIBWOLFSSL_VERSION_HEX >= 0x05000000 && defined(WOLFSSL_DH_EXTRA))
    int rc;
    BIO* out = wp_corebio_get_bio(ctx->provCtx, cBio);
    unsigned char* keyData = NULL;
    size_t keyLen;
    unsigned char* derData = NULL;
    size_t derLen = 0;
    unsigned char* pemData = NULL;
    size_t pemLen = 0;
    int pemType = DH_PRIVATEKEY_TYPE;
    int private = 0;
    byte* cipherInfo = NULL;

    if (out == NULL) {
        ok = 0;
    }

    (void)params;
    (void)selection;
    (void)pwCb;
    (void)pwCbArg;

    if (ok && (ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC)) {
        private = 1;
        if (!wp_dh_encode_params_size(key, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        if (!wp_dh_encode_spki_size(key, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        private = 1;
        if (!wp_dh_encode_pki_size(key, &derLen)) {
            ok = 0;
        }
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        private = 1;
        if (!wp_dh_encode_epki_size(key, &derLen)) {
            ok = 0;
        }
    }
#endif

    if (ok) {
        keyLen = derLen;
        keyData = derData = OPENSSL_malloc(derLen);
        if (derData == NULL) {
            ok = 0;
        }
    }

    if (ok && (ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC)) {
        pemType = DH_PARAM_TYPE;
        if (!wp_dh_encode_params(key, derData, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        pemType = PUBLICKEY_TYPE;
        if (!wp_dh_encode_spki(key, derData, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        private = 1;
        if (!wp_dh_encode_pki(key, derData, &derLen)) {
            ok = 0;
        }
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        private = 1;
        if (!wp_dh_encode_epki(ctx, key, derData, &derLen, pwCb, pwCbArg,
                (ctx->encoding == WP_FORMAT_PEM) ? &cipherInfo : NULL)) {
            ok = 0;
        }
    }
#endif

    if (ok && (ctx->encoding == WP_FORMAT_DER)) {
        keyLen = derLen;
    }
    else if (ok && (ctx->encoding == WP_FORMAT_PEM)) {
        rc = wc_DerToPemEx(derData, (word32)derLen, NULL, 0, cipherInfo,
            pemType);
        if (rc <= 0) {
            ok = 0;
        }
        if (ok) {
            pemLen = rc;
            pemData = OPENSSL_malloc(pemLen);
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
            keyLen = pemLen = rc;
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
        OPENSSL_clear_free(derData, derLen);
        OPENSSL_clear_free(pemData, pemLen);
    }
    else {
        OPENSSL_free(derData);
        OPENSSL_free(pemData);
    }
    OPENSSL_free(cipherInfo);

    BIO_free(out);
#else
    (void)ctx;
    (void)cBio;
    (void)key;
    (void)params;
    (void)selection;
    (void)pwCb;
    (void)pwCbArg;
#endif

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the DH key object.
 *
 * @param [in] ctx          DH encoder/decoder context object.
 * @param [in] dh           DH key object.
 * @param [in] size         Size of key object.
 * @param [in] exportCb     Callback to export key.
 * @param [in] exportCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_dh_export_object(wp_DhEncDecCtx* ctx, wp_Dh* dh, size_t size,
    OSSL_CALLBACK *exportCb, void *exportCbArg)
{
    /* TODO: check size to ensure it really is a wc_Dh object.  */
    (void)size;
    return wp_dh_export(dh, ctx->selection, exportCb, exportCbArg);
}

/*
 * DH Parameters
 */

/**
 * Create a new DH encoder/decoder context that handles decoding parameters.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_type_specific_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_TYPE_SPECIFIC,
        WP_FORMAT_DER);
}

/**
 * Return whether the params decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        DH encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_dh_type_specific_does_selection(WOLFPROV_CTX* provCtx,
    int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for type-specific decoder.
 */
const OSSL_DISPATCH wp_dh_type_specific_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_dh_type_specific_dec_new   },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
                                   (DFUNC)wp_dh_type_specific_does_selection },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_dh_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_dh_export_object           },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding t-s in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_type_specific_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_TYPE_SPECIFIC,
        WP_FORMAT_DER);
}

/**
 * Dispatch table for type-specific to DER encoder.
 */
const OSSL_DISPATCH wp_dh_type_specific_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,    (DFUNC)wp_dh_type_specific_der_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                   (DFUNC)wp_dh_enc_dec_settable_ctx_params  },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
                                   (DFUNC)wp_dh_type_specific_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding t-s in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_type_specific_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_TYPE_SPECIFIC,
        WP_FORMAT_PEM);
}

/**
 * Dispatch table for type-specific to PEM encoder.
 */
const OSSL_DISPATCH wp_dh_type_specific_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,    (DFUNC)wp_dh_type_specific_pem_enc_new    },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                   (DFUNC)wp_dh_enc_dec_settable_ctx_params  },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
                                   (DFUNC)wp_dh_type_specific_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/*
 * DH SubkectPublicKeyInfo
 */

/**
 * Create a new DH encoder/decoder context that handles decoding SPKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_SPKI, WP_FORMAT_DER);
}

/**
 * Return whether the SPKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        DH encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_dh_spki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for SPKI decoder.
 */
const OSSL_DISPATCH wp_dh_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_dh_spki_dec_new            },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_dh_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_dh_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_dh_export_object           },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding SPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_SPKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_dh_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_dh_spki_der_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_dh_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_dh_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding SPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_SPKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for SPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_dh_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_dh_spki_pem_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_dh_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_dh_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/*
 * DH PrivateKeyInfo
 */

/**
 * Create a new DH encoder/decoder context that handles decoding PKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_PKI, WP_FORMAT_DER);
}

/**
 * Return whether the PKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        DH encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_dh_pki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_KE, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for PKI decoder.
 */
const OSSL_DISPATCH wp_dh_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_dh_pki_dec_new             },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_dh_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_dh_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_dh_export_object           },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_PKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_dh_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_dh_pki_der_enc_new         },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_dh_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_dh_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_PKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_dh_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_dh_pki_pem_enc_new         },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_dh_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_dh_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/*
 * DH EncryptedPrivateKeyInfo
 */

/**
 * Create a new DH encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_EPKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for EPKI to DER encoder.
 */
const OSSL_DISPATCH wp_dh_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_dh_epki_der_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_dh_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_dh_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

/**
 * Create a new DH encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New DH encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_DhEncDecCtx* wp_dh_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_dh_enc_dec_new(provCtx, WP_ENC_FORMAT_EPKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for EPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_dh_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_dh_epki_pem_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_dh_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_dh_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_dh_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_dh_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_dh_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_dh_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_dh_free                    },
    { 0, NULL }
};

#endif /* WP_HAVE_DH */
