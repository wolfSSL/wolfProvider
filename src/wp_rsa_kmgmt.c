/* wp_rsa_kmgmt.c
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
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/alg_funcs.h>
#include <wolfprovider/wp_fips.h>

#include <wolfssl/wolfcrypt/asn.h>

#ifdef WP_HAVE_RSA

/** Supported selections (key parts) in this key manager for RSA. */
#define WP_RSA_POSSIBLE_SELECTIONS                                             \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

/** RSA number related parameters. */
#define WP_RSA_NUM_PARAMS                                                      \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),                                 \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0),                           \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0),                         \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0)

/** RSA PSS specific parameters. */
#define WP_RSA_PSS_PARAMS                                                      \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),               \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),          \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),          \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL)


/** Count of RSA numbers that are in parameters. */
#define WP_RSA_PARAM_NUMS_CNT       8
/** Count of public RSA numbers that are in parameters. */
#define WP_RSA_PARAM_PUB_NUMS_CNT   2

/** Default RSA digest */
#define WP_RSA_DEFAULT_MD          "SHA256"

/** Default RSA PSS digest. */
#define WP_RSA_PSS_DIGEST_DEF       WC_HASH_TYPE_SHA
/** Default MGF algorithm */
#define WP_RSA_PSS_MGF_DEF          WC_MGF1SHA1


#ifndef OFFSETOF
    #define OFFSETOF(type, field) ((size_t)&(((type *)0)->field))
#endif

#ifndef ARRAY_SIZE
    #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/** SHA-256 Algorithm ID DER encoding in PSS parameters. */
static const byte sha256AlgId[] = {
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
/** SHA-256 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte sha256AlgIdNull[] = {
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00
};
/** SHA-384 Algorithm ID DER encoding in PSS parameters. */
static const byte sha384AlgId[] = {
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
/** SHA-384 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte sha384AlgIdNull[] = {
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00
};
/** SHA-512 Algorithm ID DER encoding in PSS parameters. */
static const byte sha512AlgId[] = {
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};
/** SHA-512 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte sha512AlgIdNull[] = {
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00
};

/** MGF1 SHA-256 Algorithm ID DER encoding in PSS parameters. */
static const byte mgf1Sha256AlgId[] = {
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01
};
/** MGF1 SHA-256 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte mgf1Sha256AlgIdNull[] = {
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00
};
/** MGF1 SHA-384 Algorithm ID DER encoding in PSS parameters. */
static const byte mgf1Sha384AlgId[] = {
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02
};
/** MGF1 SHA-384 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte mgf1Sha384AlgIdNull[] = {
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x02, 0x05, 0x00
};
/** MGF1 SHA-512 Algorithm ID DER encoding in PSS parameters. */
static const byte mgf1Sha512AlgId[] = {
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x03
};
/** MGF1 SHA-512 Algorithm ID with NULL DER encoding in PSS parameters. */
static const byte mgf1Sha512AlgIdNull[] = {
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x03, 0x05, 0x00
};

/** Salt length DER encoding in PSS parameters. */
static const byte saltLenDer[] = {
    0xa2, 0x03, 0x02, 0x01
};
/** Salt length as 2 bytes DER encoding in PSS parameters. */
static const byte saltLenDer2[] = {
    0xa2, 0x04, 0x02, 0x02
};

/** Table of offsets into RsaKey structure of various fields. */
static const size_t wp_rsa_offset[WP_RSA_PARAM_NUMS_CNT] = {
    OFFSETOF(RsaKey, n),
    OFFSETOF(RsaKey, e),
    OFFSETOF(RsaKey, d),
    OFFSETOF(RsaKey, p),
    OFFSETOF(RsaKey, q),
    OFFSETOF(RsaKey, dP),
    OFFSETOF(RsaKey, dQ),
    OFFSETOF(RsaKey, u)
};
/** Table of parameter keys for RSA numbers. */
static const char* wp_rsa_param_key[WP_RSA_PARAM_NUMS_CNT] = {
    OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_D,
    OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2,
    OSSL_PKEY_PARAM_RSA_EXPONENT1, OSSL_PKEY_PARAM_RSA_EXPONENT2,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT1
};

/**
 * RSA PSS parameters.
 */
typedef struct wp_RsaPssParams {
    /** wolfSSL hash type to use when digesting message. */
    enum wc_HashType hashType;
    /** wolfSSL MGF to use when performing PSS padding. */
    int mgf;
    /** Name of hash to use for digesting message. */
    char mdName[WP_MAX_MD_NAME_SIZE];
    /** Name of hash to use with MGF when performing PSS padding. */
    char mgfMdName[WP_MAX_MD_NAME_SIZE];
    /** Length of salt. */
    int saltLen;
    /** Trailer field value for PSS DER. Id for last padding byte. */
    int derTrailer;
} wp_RsaPssParams;

/**
 * RSA key.
 */
struct wp_Rsa {
    /** wolfSSL RSA key object. */
    RsaKey key;

#ifndef WP_SINGLE_THREADED
    /** Mutex for reference count updating. */
    wolfSSL_Mutex mutex;
#endif
    /** Count of references to this object. */
    int refCnt;

    /** Provider context - useful when duplicating. */
    WOLFPROV_CTX* provCtx;

    /** Type of RSA key: PKCS#1.5 or PSS. */
    int type;
    /** Number of bits in key. */
    int bits;
    /** Public key available. */
    unsigned int hasPub:1;
    /** Private key available. */
    unsigned int hasPriv:1;

    /** Extra PSS parameters. */
    wp_RsaPssParams pssParams;
    /** PSS parameters set. */
    int pssDefSet;
};

/**
 * RSA generation context.
 */
typedef struct wp_RsaGenCtx {
    /** wolfSSL random number generator object. */
    WC_RNG rng;

    /** Provider context - used when creating an RSA key. */
    WOLFPROV_CTX* provCtx;

    /** Type of RSA key to create: PKCS#1.5 or PSS. */
    int type;
    /** Number of bits to generate key with. */
    size_t bits;
    /** Public exponent to generate key with. */
    size_t e;

    /** Extra PSS parameters to set. */
    wp_RsaPssParams pssParams;
    /** Default PSS parameters have been set. */
    int pssDefSet;
} wp_RsaGenCtx;


/* Prototype for generation initialization. */
static int wp_rsa_gen_set_params(wp_RsaGenCtx* ctx, const OSSL_PARAM params[]);

/**
 * Increment reference count for key.
 *
 * Used in key generation, signing/verify and key exchange.
 *
 * @param [in, out] rsa  RSA key object.
 * @return  1 on success.
 * @return  0 when multi-threaded and locking fails.
 */
int wp_rsa_up_ref(wp_Rsa* rsa)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    rc = wc_LockMutex(&rsa->mutex);
    if (rc < 0) {
        ok = 0;
    }
    if (ok) {
        rsa->refCnt++;
        wc_UnLockMutex(&rsa->mutex);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    rsa->refCnt++;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Get the type of RSA key.
 *
 * @param [in] rsa  RSA key object.
 * @return  RSA_FLAG_TYPE_RSA for PKCS#1.5 RSA.
 * @return  RSA_FLAG_TYPE_RSASSAPSS for PSS RSA.
 */
int wp_rsa_get_type(wp_Rsa* rsa)
{
    return rsa->type;
}

/**
 * Get the wolfSSL key object.
 *
 * @param [in] rsa  RSA key object.
 * @return  Pointer to wolfSSL RSA key object.
 */
RsaKey* wp_rsa_get_key(wp_Rsa* rsa)
{
    return &rsa->key;
}

/**
 * Get the number of bits to RSA key.
 *
 * @param [in] rsa  RSA key object.
 * @return  Number of bits in key.
 */
int wp_rsa_get_bits(wp_Rsa* rsa)
{
    return rsa->bits;
}

/**
 * Get the mutex object from the RSA key object.
 *
 * @param [in] rsa  RSA key object.
 * @return  Pointer to wolfSSL mutex object.
 */
wolfSSL_Mutex* wp_rsa_get_mutex(wp_Rsa* rsa)
{
    return &rsa->mutex;
}

/**
 * Check the RSA key size is valid.
 *
 * @param [in] keySize    RSA key size in bits.
 * @param [in] allow1024  Whether to allow 1024-bit RSA keys.
 * @return  1 when valid.
 * @return  0 when not valid.
 */
static int wp_rsa_check_key_size_int(int keySize, int allow1024)
{
    int ok = 1;

    if ((keySize < RSA_MIN_SIZE) || (keySize > RSA_MAX_SIZE)) {
        WOLFPROV_MSG(WP_LOG_PK, "RSA key size invalid: %d\n", keySize);
        ok = 0;
    }
#ifdef HAVE_FIPS
    if (!allow1024 && keySize < 2048) {
        ok = 0;
    }
    else if (keySize > 4096) {
        ok = 0;
    }
#else
    (void)allow1024;
#endif

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check the RSA key size is valid.
 *
 * @param [in] rsa        RSA key object.
 * @param [in] allow1024  Whether to allow 1024-bit RSA keys.
 * @return  1 when valid.
 * @return  0 when not valid.
 */
int wp_rsa_check_key_size(wp_Rsa* rsa, int allow1024)
{
    return wp_rsa_check_key_size_int(rsa->bits, allow1024);
}

/**
 * Check the RSA key size is valid.
 *
 * @param [in] rsagen     RSA generation context object.
 * @return  1 when valid.
 * @return  0 when not valid.
 */
static int wp_rsagen_check_key_size(wp_RsaGenCtx* rsagen)
{
    return wp_rsa_check_key_size_int((int)rsagen->bits, 0);
}

/**
 * Get the PSS digests.
 *
 * @param [in] rsa  RSA key object.
 * @return  Pointer to wolfSSL RSA key object.
 */
void wp_rsa_get_pss_mds(wp_Rsa* rsa, char** mdName, char** mgfMdName)
{
    *mdName = rsa->pssParams.mdName;
    *mgfMdName = rsa->pssParams.mgfMdName;
}

/**
 * Get the PSS salt length set from parameters.
 *
 * @param [in] rsa  RSA key object.
 * @return  Length in bytes of salt.
 */
int wp_rsa_get_pss_salt_len(wp_Rsa* rsa)
{
    return rsa->pssParams.saltLen;
}

/**
 * Get whether PSS parameters set.
 *
 * @param [in] rsa  RSA key object.
 * @return  PSS parameters set.
 */
int wp_rsa_get_pss_params_set(wp_Rsa* rsa)
{
    return rsa->pssDefSet;
}

/**
 * Create a new RSA key. Base function.
 *
 * @param [in] provCtx  Provider context.
 * @param [in] type     Type of RSA key: PKCS#1.5 or PSS.
 * @return  NULL on failure.
 * @return  New RSA key object on success.
 */
static wp_Rsa* wp_rsa_base_new(WOLFPROV_CTX* provCtx, int type)
{
    wp_Rsa* rsa = NULL;

    if (wolfssl_prov_is_running()) {
        rsa = (wp_Rsa*)OPENSSL_zalloc(sizeof(*rsa));
    }
    if (rsa != NULL) {
        int ok = 1;
        int rc;

        rc = wc_InitRsaKey(&rsa->key, NULL);
        if (rc != 0) {
            ok = 0;
        }

    #ifndef SINGLE_THREADED
        if (ok) {
            rc = wc_InitMutex(&rsa->mutex);
            if (rc != 0) {
                wc_FreeRsaKey(&rsa->key);
                ok = 0;
            }
        }
    #endif

        if (ok) {
            rsa->provCtx = provCtx;
            rsa->type = type;
            rsa->refCnt = 1;
        }

        if (!ok) {
            OPENSSL_free(rsa);
            rsa = NULL;
        }
    }

    return rsa;
}

/**
 * Dispose of RSA key object.
 *
 * @param [in, out] rsa  RSA key object.
 */
void wp_rsa_free(wp_Rsa* rsa)
{
    if (rsa != NULL) {
        int cnt;
    #ifndef WP_SINGLE_THREADED
        int rc;

        rc = wc_LockMutex(&rsa->mutex);
        cnt = --rsa->refCnt;
        if (rc == 0) {
            wc_UnLockMutex(&rsa->mutex);
        }
    #else
        cnt = --rsa->refCnt;
    #endif

        if (cnt == 0) {
    #ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&rsa->mutex);
    #endif
            wc_FreeRsaKey(&rsa->key);
            OPENSSL_free(rsa);
        }
    }
}

/**
 * Duplicate specific parts of an RSA key object.
 *
 * @param [in] src        Source RSA key object.
 * @param [in] selection  Parts of key to include.
 * @return  NULL on failure.
 * @return  New RSA key object on success.
 */
static wp_Rsa* wp_rsa_dup(const wp_Rsa* src, int selection)
{
    wp_Rsa* dst = NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        dst = wp_rsa_base_new(src->provCtx, src->type);
    }
    if (dst != NULL) {
        int ok = 1;
        int rc;
        int i;
        int cnt;
        int copyPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

        /* Determine number of multi-precision numbers to copy. */
        if (copyPriv) {
            cnt = WP_RSA_PARAM_NUMS_CNT;
        }
        else {
            cnt = WP_RSA_PARAM_PUB_NUMS_CNT;
        }

        for (i = 0; ok && (i < cnt); i++) {
            mp_int* src_mp = (mp_int*)(((byte*)&src->key) + wp_rsa_offset[i]);
            mp_int* dst_mp = (mp_int*)(((byte*)&dst->key) + wp_rsa_offset[i]);

            rc = mp_copy(src_mp, dst_mp);
            if (rc != 0) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            dst->bits      = src->bits;
            dst->hasPub    = 1;
            dst->hasPriv   = copyPriv;
            dst->pssParams = src->pssParams;
            dst->pssDefSet = src->pssDefSet;
        }

        if (!ok) {
            wp_rsa_free(dst);
            dst = NULL;
        }
    }

    return dst;
}

/**
 * Set the PSS defaults.
 *
 * @param [in, out] pss  PSS parameters object.
 * @return  1 on success.
 */
static int wp_rsa_pss_params_set_pss_defaults(wp_RsaPssParams* pss)
{
    pss->hashType = WP_RSA_PSS_DIGEST_DEF;
    pss->mgf = WP_RSA_PSS_MGF_DEF;
    XSTRNCPY(pss->mdName, "SHA-1", sizeof(pss->mdName));
    XSTRNCPY(pss->mgfMdName, "SHA-1", sizeof(pss->mdName));
    pss->saltLen = WP_RSA_DEFAULT_SALT_LEN;
    pss->derTrailer = 1; /* Default: RFC8017 A.2.3 */

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Setup the MGF1 digest algorithm based on name and properties.
 *
 * @param [in, out] pss      RSA PSS parameters object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @param [in]      libCtx   Library context.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_params_setup_mgf1_md(wp_RsaPssParams* pss,
    const char* mdName, const char* mdProps, OSSL_LIB_CTX* libCtx)
{
    int ok = 1;

    OPENSSL_strlcpy(pss->mgfMdName, mdName, sizeof(pss->mgfMdName));
    pss->mgf = wp_name_to_wc_mgf(libCtx, mdName, mdProps);
    if (pss->mgf == WC_MGF1NONE) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Setup the digest based on name and properties.
 *
 * @param [in, out] pss      RSA PSS parameters object.
 * @param [in]      mdName   Name of digest.
 * @param [in]      mdProps  Digest properties.
 * @param [in]      libCtx   Library context.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_params_setup_md(wp_RsaPssParams* pss, const char* mdName,
    const char* mdProps, OSSL_LIB_CTX* libCtx)
{
    int ok = 1;

    pss->hashType = wp_name_to_wc_hash_type(libCtx, mdName, mdProps);
    if ((pss->hashType == WC_HASH_TYPE_NONE) ||
        (pss->hashType == WC_HASH_TYPE_MD5)) {
        ok = 0;
    }

    if (ok) {
        OPENSSL_strlcpy(pss->mdName, mdName, sizeof(pss->mdName));

        if (!wp_rsa_pss_params_setup_mgf1_md(pss, mdName, mdProps, libCtx)) {
             ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the digest to use into RSA PSS parameters object.
 *
 * @param [in, out] pss         RSA PSS parameters object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @param [in]      libCtx      Library context.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_params_set_digest(wp_RsaPssParams* pss,
    const OSSL_PARAM* p, const OSSL_PARAM* propsParam, OSSL_LIB_CTX* libCtx)
{
    int ok = 1;
    char mdName[WP_MAX_MD_NAME_SIZE] = "";
    char* pMdName = mdName;
    char mdProps[WP_MAX_MD_NAME_SIZE] = "";
    char* pMdProps = NULL;

    if (!OSSL_PARAM_get_utf8_string(p, &pMdName, sizeof(mdName))) {
        ok = 0;
    }
    if (ok && propsParam != NULL) {
        pMdProps = mdProps;
        if (!OSSL_PARAM_get_utf8_string(propsParam, &pMdProps,
                sizeof(mdProps))) {
            ok = 0;
        }
    }
    if (ok) {
        ok = wp_rsa_pss_params_setup_md(pss, mdName, mdProps, libCtx);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set the digest to use into RSA PSS parameters object.
 *
 * @param [in, out] pss         RSA PSS parameters object.
 * @param [in]      p           Parameter object.
 * @param [in]      propsParam  Parameter containing properties.
 * @param [in]      libCtx      Library context.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_params_set_mgf1_digest(wp_RsaPssParams* pss,
    const OSSL_PARAM* p, const OSSL_PARAM* propsParam, OSSL_LIB_CTX* libCtx)
{
    int ok = 1;
    char mdName[WP_MAX_MD_NAME_SIZE] = "";
    char* pMdName = mdName;
    char mdProps[WP_MAX_MD_NAME_SIZE] = "";
    char* pMdProps = NULL;

    if (!OSSL_PARAM_get_utf8_string(p, &pMdName, sizeof(mdName))) {
        ok = 0;
    }
    if (ok && propsParam != NULL) {
        pMdProps = mdProps;
        if (!OSSL_PARAM_get_utf8_string(propsParam, &pMdProps,
                sizeof(mdProps))) {
            ok = 0;
        }
    }
    if (ok) {
        ok = wp_rsa_pss_params_setup_mgf1_md(pss, mdName, mdProps, libCtx);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Set PSS parameters from the parameter array.
 *
 * @param [in, out] pss          RSA PSS parameters object.
 * @param [in, out] defaultsSet  Whether default PSS parameters have been set.
 * @param [in]      params       Array of parameters and values.
 * @param [in]      libCtx       Library context.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_params_set_params(wp_RsaPssParams* pss,
    int* defaultsSet, const OSSL_PARAM params[], OSSL_LIB_CTX* libCtx)
{
    int ok = 1;
    const OSSL_PARAM* p;
    const OSSL_PARAM* propsParam = NULL;

    if (!defaultsSet) {
        if (!wp_rsa_pss_params_set_pss_defaults(pss)) {
            ok = 0;
        }
        else {
            *defaultsSet = 1;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
    if (p != NULL) {
        propsParam = OSSL_PARAM_locate_const(params,
            OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
        if (!wp_rsa_pss_params_set_digest(pss, p, propsParam, libCtx)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MASKGENFUNC);
        if ((p != NULL) && (p->data_type != OSSL_PARAM_UTF8_STRING)) {
            ok = 0;
        }
        if ((p != NULL) && ok && (XSTRNCASECMP(p->data, SN_mgf1,
                p->data_size) != 0)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
        if ((p != NULL) && (propsParam == NULL)) {
            propsParam = OSSL_PARAM_locate_const(params,
                OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
        }
        if ((p != NULL) && !wp_rsa_pss_params_set_mgf1_digest(pss, p,
                propsParam, libCtx)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
        if ((p != NULL) && (!OSSL_PARAM_get_int(p, &pss->saltLen))) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Load the RSA key.
 *
 * Return the RSA key object taken out of the reference.
 *
 * @param [in, out] pRsa  Pointer to a RSA key object.
 * @param [in]      size  Size of data structure that is the RSA key object.
 *                        Unused.
 * @param [in]      type  Expected RSA type: PKCS#1.5 or PSS.
 * @return  NULL when no RSA key object at reference or not matching type.
 * @return  RSA key object from reference on success.
 */
static const wp_Rsa* wp_rsa_base_load(const wp_Rsa** pRsa, size_t size,
    int type)
{
    const wp_Rsa* rsa = *pRsa;

    /* TODO: validate the object is a wp_Rsa? */
    (void)size;

    if (rsa->type != type) {
        rsa = NULL;
    }
    else {
        *pRsa = NULL;
    }

    return rsa;
}

/**
 * Get the security bits for an RSA key.
 *
 * @param [in] rsa  RSA key object.
 * @return  Security bits on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_security_bits(wp_Rsa* rsa)
{
    int bits = 0;

    if (rsa->bits >= 8192) {
        bits = 192;
    }
    else if (rsa->bits >= 3072) {
        bits = 128;
    }
    else if (rsa->bits >= 2048) {
        bits = 112;
    }
    else if (rsa->bits >= 1024) {
        bits = 80;
    }

    return bits;
}

/**
 * Get the key data into the parameters.
 *
 * @param [in]      rsa     RSA key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_params_key_data(wp_Rsa* rsa,  OSSL_PARAM params[])
{
    int ok = 1;
    int i;

    for (i = 0; ok && (i < WP_RSA_PARAM_NUMS_CNT); i++) {
        OSSL_PARAM* p = OSSL_PARAM_locate(params, wp_rsa_param_key[i]);
        if (p != NULL) {
            size_t oLen;
            mp_int* mp = (mp_int*)(((byte*)&rsa->key) + wp_rsa_offset[i]);
            oLen = mp_unsigned_bin_size(mp);
            if (oLen > p->data_size) {
                ok = 0;
            }
            if (ok && (p->data != NULL) &&
                      (!wp_mp_to_unsigned_bin_le(mp, p->data, oLen))) {
                ok = 0;
            }
            p->return_size = oLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the PSS parameters into the parameters array.
 *
 * @param [in]      pss     PSS object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_params_pss(wp_RsaPssParams* pss,  OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    if (pss->hashType != WP_RSA_PSS_DIGEST_DEF) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, pss->mdName)) {
            ok = 0;
        }
    }
    /* MGF is default so don't set. */
    if (ok && (pss->mgf != WP_RSA_PSS_MGF_DEF)) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
        if ((p != NULL) && !OSSL_PARAM_set_utf8_string(p, pss->mgfMdName)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, pss->saltLen)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the RSA key parameters.
 *
 * @param [in]      rsa     RSA key object.
 * @param [in, out] params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_get_params(wp_Rsa* rsa, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if ((p != NULL) && !OSSL_PARAM_set_int(p, (rsa->bits + 7) / 8)) {
        ok = 0;
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
        if ((p != NULL) && !OSSL_PARAM_set_int(p, rsa->bits)) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
        if ((p != NULL) && (!OSSL_PARAM_set_int(p,
                wp_rsa_get_security_bits(rsa)))) {
            ok = 0;
        }
    }
    if (ok) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST);
        if ((p != NULL) && ((rsa->type != RSA_FLAG_TYPE_RSASSAPSS) ||
            (!rsa->pssDefSet)) && (!OSSL_PARAM_set_utf8_string(p,
                WP_RSA_DEFAULT_MD))) {
            ok = 0;
        }
    }
    if (ok && (!wp_rsa_get_params_key_data(rsa, params))) {
        ok = 0;
    }
    if (ok && (rsa->type == RSA_FLAG_TYPE_RSASSAPSS) && rsa->pssDefSet &&
        (!wp_rsa_get_params_pss(&rsa->pssParams, params))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check RSA key object has the components required.
 *
 * @param [in] rsa        RSA key object.
 * @param [in] selection  Parts of key required.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_has(const wp_Rsa* rsa, int selection)
{
    int ok = 1;

    if (!wolfssl_prov_is_running()) {
       ok = 0;
    }
    if (rsa == NULL) {
       ok = 0;
    }
    if (ok && ((selection & WP_RSA_POSSIBLE_SELECTIONS) != 0)) {
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok &= rsa->hasPub;
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok &= rsa->hasPriv;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Check that two RSA key objects match for the components specified.
 *
 * @param [in] rsa1       First RSA key object.
 * @param [in] rsa2       Second RSA key object.
 * @param [in] selection  Parts of key to match.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_match(const wp_Rsa* rsa1, const wp_Rsa* rsa2, int selection)
{
    int ok = 1;
    int checked = 0;

    if (ok && mp_cmp((mp_int*)&rsa1->key.e, (mp_int*)&rsa2->key.e) != MP_EQ) {
        ok = 0;
    }
    if (ok && (((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0))) {
        if (ok && (((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0))) {
            if (mp_cmp((mp_int*)&rsa1->key.n, (mp_int*)&rsa2->key.n) != MP_EQ) {
                ok = 0;
            }
            else {
                checked = 1;
            }
        }
        if (ok && checked == 0 &&
                (((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))) {
            if (mp_cmp((mp_int*)&rsa1->key.d, (mp_int*)&rsa2->key.d) != MP_EQ) {
                ok = 0;
            } else {
                checked = 1;
            }
        }
        ok = ok && checked;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Validate the RSA key.
 *
 * @param [in] rsa        RSA key object.
 * @param [in] selection  Parts of key to validate.
 * @param [in] checkType  How thorough to check key. Values:
 *                          OSSL_KEYMGMT_VALIDATE_FULL_CHECK or
 *                          OSSL_KEYMGMT_VALIDATE_QUICK_CHECK.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_validate(const wp_Rsa* rsa, int selection, int checkType)
{
    int ok = 1;
    int checkPub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    int checkPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    (void)checkType;

#ifdef WOLFSSL_RSA_KEY_CHECK
    if (checkPub && checkPriv) {
        int rc = wc_CheckRsaKey((RsaKey*)&rsa->key);
        if (rc != 0) {
            ok = 0;
        }
    }
    else
#endif
    if (checkPriv) {
        if (mp_isone(&rsa->key.d) || mp_iszero((mp_int*)&rsa->key.d) ||
            (mp_cmp((mp_int*)&rsa->key.d, (mp_int*)&rsa->key.n) != MP_LT)) {
            ok = 0;
        }
    }
    else if (checkPub) {
        if (mp_iseven(&rsa->key.e) || mp_iszero((mp_int*)&rsa->key.e) ||
            mp_isone(&rsa->key.e)) {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key data into RSA key object from parameters.
 *
 * @param [in, out] rsa        RSA key object.
 * @param [in]      params     Array of parameters and values.
 * @param [in]      priv       Import the private key values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_import_key_data(wp_Rsa* rsa, const OSSL_PARAM params[],
    int priv)
{
    int ok = 1;
    int i, j, index = -1;
    int cnt = 0;
    mp_int* mp = NULL;
    const OSSL_PARAM* p = NULL;

    /* N and E params are the only ones required by OSSL, so match that.
     * See ossl_rsa_fromdata() and RSA_set0_key() in OpenSSL. */
    if (OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N) == NULL || 
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E) == NULL) {
        WOLFPROV_MSG(WP_LOG_PK, "Param N or E is missing");
        ok = 0;
    }

    if (ok) {
        cnt = wp_params_count(params);
        rsa->key.type = priv ? RSA_PRIVATE : RSA_PUBLIC;

        for (i = 0; i < cnt; i++) {
            /* Use the table to look up the offset in the rsa struct */
            p = &params[i];
            index = -1;
            for (j = 0; j < (int)ARRAY_SIZE(wp_rsa_param_key); j++) {
                if (XSTRNCMP(p->key, wp_rsa_param_key[j], XSTRLEN(p->key)) == 0) {
                    index = j; 
                    break;
                }
            }
            if (index < 0) {
                /* Follow OSSL implementation and ignore irrelevant fields. */
                WOLFPROV_MSG(WP_LOG_PK, "Unexpected param %s, skipping.", 
                    p->key);
                continue;
            }

            /* Read the value into the rsa struct */
            if (ok) {
                mp = (mp_int*)(((byte*)&rsa->key) + wp_rsa_offset[index]);
                if (!wp_mp_read_unsigned_bin_le(mp, p->data, p->data_size)) {
                    WOLFPROV_MSG(WP_LOG_PK,
                        "Failed to read %s from parameters", p->key);
                    ok = 0;
                }
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Import the key into RSA key object from parameters.
 *
 * @param [in, out] rsa        RSA key object.
 * @param [in]      selection  Parts of key to import.
 * @param [in]      params     Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_import(wp_Rsa* rsa, int selection, const OSSL_PARAM params[])
{
    int ok = 1;
    int importPriv =  (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int importPub =  (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;

    if ((!wolfssl_prov_is_running()) || (rsa == NULL)) {
        ok = 0;
    }
    if (ok && ((selection & WP_RSA_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok && (importPriv || importPub) && (!wp_rsa_import_key_data(rsa, params,
            importPriv))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) &&
        (rsa->type == RSA_FLAG_TYPE_RSASSAPSS) &&
        (!wp_rsa_pss_params_set_params(&rsa->pssParams, &rsa->pssDefSet, params,
         rsa->provCtx->libCtx))) {
        ok = 0;
    }
    if (ok) {
        rsa->bits    = mp_count_bits(&rsa->key.n);
        rsa->hasPub  = importPub;
        rsa->hasPriv = importPriv;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the key parameters for a selection.
 *
 * @param [in] selection  Parts of key to import/export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_rsa_key_types(int selection)
{
    /** TODO: OpenSSL doesn't have PSS parameters for PSS. */
    static const OSSL_PARAM wp_rsa_key_params[] = {
        WP_RSA_NUM_PARAMS,
        OSSL_PARAM_END
    };
    const OSSL_PARAM* params = NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        params = wp_rsa_key_params;
    }

    return params;
}

/**
 * Get the key parameters when importing for a selection.
 *
 * @param [in] selection  Parts of key to import.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_rsa_import_types(int selection)
{
    return wp_rsa_key_types(selection);
}

/**
 * Put the RSA PSS parameters into the parameters array.
 *
 * @param [in]      pss     PSS parameters object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_params_export(wp_RsaPssParams* pss, OSSL_PARAM* params,
    int* idx)
{
    int i = *idx;

    wp_param_set_utf8_string_ptr(&params[i++], OSSL_PKEY_PARAM_RSA_DIGEST,
        pss->mdName);
    wp_param_set_utf8_string_ptr(&params[i++], OSSL_PKEY_PARAM_MGF1_DIGEST,
        pss->mgfMdName);
    wp_param_set_utf8_string_ptr(&params[i++], OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
        SN_mgf1);
    wp_param_set_int(&params[i++], OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
        &pss->saltLen);

    *idx = i;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/**
 * Get the size of allocated data needed for key pair.
 *
 * Called when exporting.
 *
 * @param [in] rsa   RSA key object.
 * @param [in] priv  Private key is being exported.
 * @return  Size of buffer to hold allocated key pair data.
 */
static size_t wp_rsa_export_keypair_alloc_size(wp_Rsa* rsa, int priv)
{
    int i;
    size_t len = 0;
    int cnt;

    if (priv) {
        cnt = WP_RSA_PARAM_NUMS_CNT;
    }
    else {
        cnt = WP_RSA_PARAM_PUB_NUMS_CNT;
    }

    for (i = 0; i < cnt; i++) {
         mp_int* mp = (mp_int*)(((byte*)&rsa->key) + wp_rsa_offset[i]);
         if (!mp_iszero(mp)) {
             len += mp_unsigned_bin_size(mp);
         }
    }

    return len;
}

/**
 * Put the RSA key pair data into the parameter.
 *
 * Assumes data buffer is big enough.
 *
 * @param [in]      rsa     RSA key object.
 * @param [in, out] params  Array of parameters and values.
 * @param [in, out] pIdx    Current index into parameters array.
 * @param [in, out] data    Data buffer to place group data into.
 * @param [in, out] idx     Pointer to current index into data.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_export_keypair(wp_Rsa* rsa, OSSL_PARAM* params, int* pIdx,
    unsigned char* data, size_t* idx, int priv)
{
    int ok = 1;
    int i = *pIdx;
    int j;
    int cnt;

    if (priv) {
        cnt = WP_RSA_PARAM_NUMS_CNT;
    }
    else {
        cnt = WP_RSA_PARAM_PUB_NUMS_CNT;
    }

    for (j = 0; ok && (j < cnt); j++) {
         mp_int* mp = (mp_int*)(((byte*)&rsa->key) + wp_rsa_offset[j]);
         if (!mp_iszero(mp) && (!wp_param_set_mp(&params[i++],
                 wp_rsa_param_key[j], mp, data, idx))) {
             ok = 0;
        }
    }

    *pIdx = i;
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the RSA key.
 *
 * Key data placed in parameters and then passed to callback.
 *
 * @param [in] rsa        RSA key object.
 * @param [in] selection  Parts of key to export.
 * @param [in] paramCb    Function to pass constructed parameters to.
 * @param [in] cbArg      Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_export(wp_Rsa* rsa, int selection, OSSL_CALLBACK* paramCb,
    void* cbArg)
{
    int ok = 1;
    OSSL_PARAM params[13];
    int paramSz = 0;
    unsigned char* data = NULL;
    size_t len = 0;
    int expPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    if (!wolfssl_prov_is_running()) {
        ok = 0;
    }
    if (ok && ((selection & WP_RSA_POSSIBLE_SELECTIONS) == 0)) {
        ok = 0;
    }
    if (ok) {
        XMEMSET(params, 0, sizeof(params));
        data = OPENSSL_malloc(wp_rsa_export_keypair_alloc_size(rsa, expPriv));
        if (data == NULL) {
            ok = 0;
        }
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) &&
        (rsa->type == RSA_FLAG_TYPE_RSASSAPSS) && rsa->pssDefSet &&
        (!wp_rsa_pss_params_export(&rsa->pssParams, params, &paramSz))) {
        ok = 0;
    }
    if (ok && ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) &&
        (!wp_rsa_export_keypair(rsa, params, &paramSz, data, &len, expPriv))) {
        ok = 0;
    }

    if (ok && (!paramCb(params, cbArg))) {
        ok = 0;
    }

    (void)paramSz;
    OPENSSL_clear_free(data, len);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the key parameters when exporting for a selection.
 *
 * @param [in] selection  Parts of key to export.
 * @return  Terminated array of parameters.
 */
static const OSSL_PARAM* wp_rsa_export_types(int selection)
{
    return wp_rsa_key_types(selection);
}

/*
 * RSA generation
 */

/**
 * Create RSA generation context object. Base function.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New RSA generation context object on success.
 * @return  NULL on failure.
 */
static wp_RsaGenCtx* wp_rsa_base_gen_init(WOLFPROV_CTX* provCtx,
    int selection, const OSSL_PARAM params[], int type)
{
    wp_RsaGenCtx* ctx = NULL;

    if (wolfssl_prov_is_running() &&
        ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)) {
        ctx = (wp_RsaGenCtx*)OPENSSL_zalloc(sizeof(*ctx));
    }
    if (ctx != NULL) {
        int ok = 1;
        int rc;

        rc = wc_InitRng_ex(&ctx->rng, NULL, INVALID_DEVID);
        if (rc != 0) {
            ok = 0;
        }
        if (ok) {
            ctx->provCtx = provCtx;
            ctx->type    = type;
            /* Set defaults. */
            ctx->bits    = 2048;
            ctx->e       = WC_RSA_EXPONENT;

            if (!wp_rsa_gen_set_params(ctx, params)) {
                wc_FreeRng(&ctx->rng);
                ok = 0;
            }
        }

        if (!ok) {
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

#ifndef WP_RSA_KEYGEN_MAX_RETRY_CNT
#define WP_RSA_KEYGEN_MAX_RETRY_CNT 10
#endif

/**
 * Generate RSA key pair using wolfSSL.
 *
 * @param [in, out] ctx    RSA generation context object.
 * @param [in]      cb     Progress callback. Unused.
 * @param [in]      cbArg  Argument to pass to callback. Unused.
 * @return  NULL on failure.
 * @return  RSA key object on success.
 */
static wp_Rsa* wp_rsa_gen(wp_RsaGenCtx* ctx, OSSL_CALLBACK* cb, void* cbArg)
{
    wp_Rsa* rsa = NULL;
    int rc = -1;
    int i = 0;

    (void)cb;
    (void)cbArg;

    if (wolfssl_prov_is_running() && wp_rsagen_check_key_size(ctx)) {
        rsa = wp_rsa_base_new(ctx->provCtx, ctx->type);
        if (rsa != NULL) {
            /* wolfCrypt FIPS RSA keygen has a small chance it simply will not
             * find RSA primes within the failCount. Account for this by
             * retrying here. For simplicity we will always use this flow
             * even for non-FIPS case. */
            for (i = 0; i < WP_RSA_KEYGEN_MAX_RETRY_CNT; i++) {
                rc = wc_MakeRsaKey(&rsa->key, (int)ctx->bits, ctx->e,
                    &ctx->rng);
                if (rc == PRIME_GEN_E) {
                    /* retry */
                }
                else if (rc != 0) {
                    wp_rsa_free(rsa);
                    rsa = NULL;
                    break;
                }
                else {
                    rsa->type      = ctx->type;
                    rsa->bits      = (int)ctx->bits;
                    rsa->hasPub    = 1;
                    rsa->hasPriv   = 1;
                    rsa->pssParams = ctx->pssParams;
                    break;
                }
            }
        }
    }

    if (i == WP_RSA_KEYGEN_MAX_RETRY_CNT) {
        wp_rsa_free(rsa);
        rsa = NULL;
    }

    return rsa;
}

/**
 * Dispose of the RSA generation context object.
 *
 * @param [in, out] ctx  RSA generation context object.
 */
static void wp_rsa_gen_cleanup(wp_RsaGenCtx* ctx)
{
    if (ctx != NULL) {
        wc_FreeRng(&ctx->rng);
        OPENSSL_free(ctx);
    }
}

/**
 * Sets the parameters into the RSA generation context object.
 *
 * @param [in, out] ctx     RSA generation context object.
 * @param [in]      params  Array of parameters and values.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_gen_set_params(wp_RsaGenCtx* ctx, const OSSL_PARAM params[])
{
    int ok = 1;
    const OSSL_PARAM* p;

    if (params) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
        if (p != NULL) {
            if (!OSSL_PARAM_get_size_t(p, &ctx->bits)) {
                ok = 0;
            }
            else if (!wp_rsagen_check_key_size(ctx)) {
                ok = 0;
            }
            else if ((ctx->bits < RSA_MIN_SIZE) || (ctx->bits > RSA_MAX_SIZE)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
                ok = 0;
            }
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES);
            if (p != NULL) {
                size_t primes;

                if (!OSSL_PARAM_get_size_t(p, &primes)) {
                    ok = 0;
                }
                else if (primes != 2) {
                    ok = 0;
                }
            }
        }
        if (ok) {
            p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
            if ((p != NULL) && (!OSSL_PARAM_get_size_t(p, &ctx->e))) {
                ok = 0;
            }
        }
        if (ok && (ctx->type == RSA_FLAG_TYPE_RSASSAPSS)) {
            if (!wp_rsa_pss_params_set_params(&ctx->pssParams, &ctx->pssDefSet,
                   params, ctx->provCtx->libCtx)) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/*
 * RSA PKCS #1.5
 */

/**
 * Create a new RSA PKCS#1.5 key.
 *
 * @param [in] provCtx  Provider context.
 * @return  NULL on failure.
 * @return  New RSA key object on success.
 */
static wp_Rsa* wp_rsa_new(WOLFPROV_CTX* provctx)
{
    return wp_rsa_base_new(provctx, RSA_FLAG_TYPE_RSA);
}

/**
 * Return an array of supported gettable parameters for the RSA key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_rsa_gettable_params(WOLFPROV_CTX* provctx)
{
    static const OSSL_PARAM wp_rsa_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        WP_RSA_NUM_PARAMS,
        OSSL_PARAM_END
    };
    (void)provctx;
    return wp_rsa_params;
}

/**
 * Create RSA generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New RSA generation context object on success.
 * @return  NULL on failure.
 */
static wp_RsaGenCtx* wp_rsa_gen_init(WOLFPROV_CTX* provctx, int selection,
    const OSSL_PARAM params[])
{
    return wp_rsa_base_gen_init(provctx, selection, params, RSA_FLAG_TYPE_RSA);
}

/**
 * Return an array of supported settable parameters for the RSA gen context.
 *
 * @param [in] ctx      RSA generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_rsa_gen_settable_params(wp_RsaGenCtx* gctx,
    WOLFPROV_CTX* provctx)
{
    /**
     * Supported settable parameters for RSA generation context.
     */
    static OSSL_PARAM wp_rsa_gen_settable[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    (void)gctx;
    (void)provctx;
    return wp_rsa_gen_settable;
}

/**
 * Load the RSA key.
 *
 * Return the RSA key object taken out of the reference.
 *
 * @param [in, out] pRsa  Pointer to a RSA key object.
 * @param [in]      size  Size of data structure that is the RSA key object.
 *                        Unused.
 * @return  NULL when no RSA key object at reference or not RSA PKCS#1.5 type.
 * @return  RSA key object from reference on success.
 */
static const wp_Rsa* wp_rsa_load(const wp_Rsa** prsa, size_t size)
{
    return wp_rsa_base_load(prsa, size, RSA_FLAG_TYPE_RSA);
}

/** Dispatch table for RSA key management. */
const OSSL_DISPATCH wp_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,               (DFUNC)wp_rsa_new                  },
    { OSSL_FUNC_KEYMGMT_FREE,              (DFUNC)wp_rsa_free                 },
    { OSSL_FUNC_KEYMGMT_DUP,               (DFUNC)wp_rsa_dup                  },
    { OSSL_FUNC_KEYMGMT_LOAD,              (DFUNC)wp_rsa_load                 },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,        (DFUNC)wp_rsa_get_params           },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,   (DFUNC)wp_rsa_gettable_params      },
    { OSSL_FUNC_KEYMGMT_HAS,               (DFUNC)wp_rsa_has                  },
    { OSSL_FUNC_KEYMGMT_MATCH,             (DFUNC)wp_rsa_match                },
    { OSSL_FUNC_KEYMGMT_VALIDATE,          (DFUNC)wp_rsa_validate             },
    { OSSL_FUNC_KEYMGMT_IMPORT,            (DFUNC)wp_rsa_import               },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,      (DFUNC)wp_rsa_import_types         },
    { OSSL_FUNC_KEYMGMT_EXPORT,            (DFUNC)wp_rsa_export               },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,      (DFUNC)wp_rsa_export_types         },
    /* RSA PKCS#1.5 generation */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,          (DFUNC)wp_rsa_gen_init             },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,    (DFUNC)wp_rsa_gen_set_params       },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                           (DFUNC)wp_rsa_gen_settable_params  },
    { OSSL_FUNC_KEYMGMT_GEN,               (DFUNC)wp_rsa_gen                  },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,       (DFUNC)wp_rsa_gen_cleanup          },
    { 0, NULL }
};

/*
 * RSA PSS
 */

/**
 * Create a new RSA PSS key.
 *
 * @param [in] provCtx  Provider context.
 * @return  NULL on failure.
 * @return  New RSA key object on success.
 */
static wp_Rsa* wp_rsapss_new(WOLFPROV_CTX* provctx)
{
    return wp_rsa_base_new(provctx, RSA_FLAG_TYPE_RSASSAPSS);
}

/**
 * Load the RSA key.
 *
 * Return the RSA key object taken out of the reference.
 *
 * @param [in, out] pRsa  Pointer to a RSA key object.
 * @param [in]      size  Size of data structure that is the RSA key object.
 *                        Unused.
 * @return  NULL when no RSA key object at reference or not RSA PSS type.
 * @return  RSA key object from reference on success.
 */
static const wp_Rsa* wp_rsapss_load(const wp_Rsa** prsa, size_t size)
{
    return wp_rsa_base_load(prsa, size, RSA_FLAG_TYPE_RSASSAPSS);
}

/**
 * Return an array of supported gettable parameters for the RSA PSS key object.
 *
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_rsapss_gettable_params(WOLFPROV_CTX* provctx)
{
    static const OSSL_PARAM wp_rsa_params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
        WP_RSA_NUM_PARAMS,
        /* TODO: OpenSSL doesn't include these. */
        WP_RSA_PSS_PARAMS,
        OSSL_PARAM_END
    };
    (void)provctx;
    return wp_rsa_params;
}

/**
 * Return the operation name as a string.
 *
 * Name is "RSA-PSS" which doesn't match operation name: "RSA"
 *
 * @param [in] op  Operationn type being performed. Unused.
 * @return  Name of operation.
 */
static const char* wp_rsa_query_operation_name(int operation_id)
{
    (void)operation_id;
    return "RSA";
}

/**
 * Create RSA PSS generation context object.
 *
 * @param [in] provCtx    Provider context.
 * @param [in] selection  Parts of the key to generate.
 * @param [in] params     Parameters to set for generation.
 * @return  New RSA generation context object on success.
 * @return  NULL on failure.
 */
static wp_RsaGenCtx* wp_rsapss_gen_init(WOLFPROV_CTX* provctx, int selection,
    const OSSL_PARAM params[])
{
    return wp_rsa_base_gen_init(provctx, selection, params,
        RSA_FLAG_TYPE_RSASSAPSS);
}

/**
 * Return an array of supported settable parameters for the RSA PSS gen context.
 *
 * @param [in] ctx      RSA generation context object. Unused.
 * @param [in] provCtx  Provider context object. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_rsapss_gen_settable_params(wp_RsaGenCtx* gctx,
    WOLFPROV_CTX* provctx)
{
    /**
     * Supported settable parameters for RSA PSS generation context.
     */
    static OSSL_PARAM wp_rsapss_gen_settable[] = {
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),
        WP_RSA_PSS_PARAMS,
        OSSL_PARAM_END
    };
    (void)gctx;
    (void)provctx;
    return wp_rsapss_gen_settable;
}

/** Dispatch table for RSA PSS key management. */
const OSSL_DISPATCH wp_rsapss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,               (DFUNC)wp_rsapss_new               },
    { OSSL_FUNC_KEYMGMT_FREE,              (DFUNC)wp_rsa_free                 },
    { OSSL_FUNC_KEYMGMT_DUP,               (DFUNC)wp_rsa_dup                  },
    { OSSL_FUNC_KEYMGMT_LOAD,              (DFUNC)wp_rsapss_load              },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS,        (DFUNC)wp_rsa_get_params           },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,   (DFUNC)wp_rsapss_gettable_params   },
    { OSSL_FUNC_KEYMGMT_HAS,               (DFUNC)wp_rsa_has                  },
    { OSSL_FUNC_KEYMGMT_MATCH,             (DFUNC)wp_rsa_match                },
    { OSSL_FUNC_KEYMGMT_VALIDATE,          (DFUNC)wp_rsa_validate             },
    { OSSL_FUNC_KEYMGMT_IMPORT,            (DFUNC)wp_rsa_import               },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,      (DFUNC)wp_rsa_import_types         },
    { OSSL_FUNC_KEYMGMT_EXPORT,            (DFUNC)wp_rsa_export               },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,      (DFUNC)wp_rsa_export_types         },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
                                         (DFUNC)wp_rsa_query_operation_name   },
    /* RSAPSS generation */
    { OSSL_FUNC_KEYMGMT_GEN_INIT,          (DFUNC)wp_rsapss_gen_init          },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,    (DFUNC)wp_rsa_gen_set_params       },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
                                         (DFUNC)wp_rsapss_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN,               (DFUNC)wp_rsa_gen                  },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,       (DFUNC)wp_rsa_gen_cleanup          },
    { 0, NULL }
};

/* TODO: support encrypted PKCS#8 formatted private key. */

/**
 * RSA encode/decode context.
 */
typedef struct wp_RsaEncDecCtx {
    /** Provider context - used when creating RSA key. */
    WOLFPROV_CTX* provCtx;
    /** Parts of key to export. */
    int selection;

    /** Type of RSA key: PKCS#1.5 or PSS. */
    int type;
    /** Supported key format. */
    int format;
    /** Data format: DER or PEM. */
    int encoding;

    /** Cipher to use when encoding EncryptedPrivateKeyInfo. */
    int cipher;
    /** Name of cipher to use when encoding EncryptedPrivateKeyInfo. */
    const char* cipherName;
} wp_RsaEncDecCtx;


/**
 * Create a new RSA encoder/decoder context.
 *
 * @param [in] provCtx   Provider context.
 * @param [in] type      Type of RSA key: RSA or RSA-PSS.
 * @param [in] format    Supported format.
 * @param [in] encoding  Data format.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_enc_dec_new(WOLFPROV_CTX* provCtx, int type,
    int format, int encoding)
{
    wp_RsaEncDecCtx* ctx = NULL;
    if (wolfssl_prov_is_running()) {
        ctx = (wp_RsaEncDecCtx*)OPENSSL_zalloc(sizeof(wp_RsaEncDecCtx));
    }
    if (ctx != NULL) {
        ctx->provCtx  = provCtx;
        ctx->type     = type;
        ctx->format   = format;
        ctx->encoding = encoding;
    }
    return ctx;
}

/**
 * Dispose of RSA encoder/decoder context object.
 *
 * @param [in, out] ctx  RSA encoder/decoder context object.
 */
static void wp_rsa_enc_dec_free(wp_RsaEncDecCtx* ctx)
{
    OPENSSL_free(ctx);
}

/**
 * Return the settable parameters for the RSA encoder/decoder context.
 *
 * @param [in] provCtx  Provider context. Unused.
 * @return  Array of parameters with data type.
 */
static const OSSL_PARAM* wp_rsa_enc_dec_settable_ctx_params(
    WOLFPROV_CTX* provCtx)
{
    static const OSSL_PARAM wp_rsa_enc_dec_supported_settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    (void)provCtx;
    return wp_rsa_enc_dec_supported_settables;
}

/**
 * Set the RSA encoder/decoder context parameters.
 *
 * @param [in, out] ctx     RSA encoder/decoder context object.
 * @param [in]      params  Array of parameters.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_enc_dec_set_ctx_params(wp_RsaEncDecCtx* ctx,
    const OSSL_PARAM params[])
{
    int ok = 1;

    if (!wp_cipher_from_params(params, &ctx->cipher, &ctx->cipherName)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Common base of RSA PKCS #1.5 and PSS OID. */
unsigned char rsa_pkcs1_oid[] = {
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01
};
/** Size of RSA PKCS OID. */
#define RSA_PKCS1_OID_SZ    sizeof(rsa_pkcs1_oid)
/** Last byte of RSA PKCS #1.5 OID. */
#define RSA_PKCS1_5_BYTE    0x01
/** Last byte of RSA PKCS #1 PSS OID. */
#define RSA_PKCS1_PSS_BYTE  0x0a

/**
 * Find the OID in the data.
 *
 * @param [in]  data    DER encoding.
 * @param [in]  len     Length, in bytes, of DER encoding.
 * @param [in]  oid     OID to look for.
 * @param [in]  oidLen  Length, in bytes, of OID.
 * @param [out] offset  Index atr which OID was found.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_find_oid(unsigned char* data, word32 len, unsigned char* oid,
    word32 oidLen, word32* offset)
{
    int ok = 0;
    word32 i;

    for (i = 0; i < len - RSA_PKCS1_OID_SZ - 1; i++) {
        /* Find the base OID. */
        if (XMEMCMP(data + i, oid, oidLen) == 0) {
            ok = 1;
            *offset = i;
            break;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Determine RSA key type  based on OID and type into key.
 *
 * Assumes that the key data is already parsed and proven valid.
 *
 * @param [in, out] rsa   RSA key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_determine_type(wp_Rsa* rsa, unsigned char* data, word32 len)
{
    int ok = 1;
    word32 idx = 0;

    if (wp_rsa_find_oid(data, len, rsa_pkcs1_oid, RSA_PKCS1_OID_SZ, &idx)) {
        /* Check OID is for PKCS #1.5. */
        if (data[idx + RSA_PKCS1_OID_SZ] == RSA_PKCS1_5_BYTE) {
            rsa->type = RSA_FLAG_TYPE_RSA;
        }
        /* Check OID is for PKCS #1 PSS. */
        else if (data[idx + RSA_PKCS1_OID_SZ] == RSA_PKCS1_PSS_BYTE) {
            rsa->type = RSA_FLAG_TYPE_RSASSAPSS;
        }
        else {
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the PSS parameters from the DER encoded RSA-PSS parameters.
 *
 * TODO: rework to use tables of DER encodings.
 *
 * @param [out] rsa   RSA key object.
 * @param [in]  data  Buffer holding DER encoded parameters.
 * @param [in]  len   Length of DER encoded parameters in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_pss_get_params(wp_Rsa* rsa, unsigned char* data, word32 len)
{
    int ok;
    word32 idx = 0;
    wp_RsaPssParams* pss = &rsa->pssParams;

    ok = wp_rsa_find_oid(data, len, rsa_pkcs1_oid, RSA_PKCS1_OID_SZ, &idx);
    if (ok) {
        /* Step over PSS algorithm. */
        idx += 11;

        if (data[idx] != 0x30) {
            ok = 0;
        }
        else {
            idx += 2;
        }
    }
    if (ok && (data[idx] == 0xa0)) {
        /* Hash algorithm */
        if (XMEMCMP(data + idx, sha256AlgId, sizeof(sha256AlgId)) == 0) {
            pss->hashType = WC_HASH_TYPE_SHA256;
            XSTRNCPY(pss->mdName, "SHA256", sizeof(pss->mdName));
            idx += sizeof(sha256AlgId);
        }
        else if (XMEMCMP(data + idx, sha256AlgIdNull,
                         sizeof(sha256AlgIdNull)) == 0) {
            pss->hashType = WC_HASH_TYPE_SHA256;
            XSTRNCPY(pss->mdName, "SHA256", sizeof(pss->mdName));
            idx += sizeof(sha256AlgIdNull);
        }
        else if (XMEMCMP(data + idx, sha384AlgId, sizeof(sha384AlgId)) == 0) {
            pss->hashType = WC_HASH_TYPE_SHA384;
            XSTRNCPY(pss->mdName, "SHA384", sizeof(pss->mdName));
            idx += sizeof(sha384AlgId);
        }
        else if (XMEMCMP(data + idx, sha384AlgIdNull,
                         sizeof(sha384AlgIdNull)) == 0) {
            pss->hashType = WC_HASH_TYPE_SHA384;
            XSTRNCPY(pss->mdName, "SHA384", sizeof(pss->mdName));
            idx += sizeof(sha384AlgIdNull);
        }
        else if (XMEMCMP(data + idx, sha512AlgId, sizeof(sha512AlgId)) == 0) {
            pss->hashType = WC_HASH_TYPE_SHA512;
            XSTRNCPY(pss->mdName, "SHA512", sizeof(pss->mdName));
            idx += sizeof(sha512AlgId);
        }
        else if (XMEMCMP(data + idx, sha512AlgIdNull,
                         sizeof(sha512AlgIdNull)) == 0) {
            pss->hashType = WC_HASH_TYPE_SHA512;
            XSTRNCPY(pss->mdName, "SHA512", sizeof(pss->mdName));
            idx += sizeof(sha512AlgIdNull);
        }
        else {
            ok = 0;
        }
    }
    if (ok && (data[idx] == 0xa1)) {
        /* MGF algorithm */
        if (XMEMCMP(data + idx, mgf1Sha256AlgId,
                    sizeof(mgf1Sha256AlgId)) == 0) {
            pss->mgf = WC_MGF1SHA256;
            XSTRNCPY(pss->mgfMdName, "SHA256", sizeof(pss->mgfMdName));
            idx += sizeof(mgf1Sha256AlgId);
        }
        else if (XMEMCMP(data + idx, mgf1Sha256AlgIdNull,
                         sizeof(mgf1Sha256AlgIdNull)) == 0) {
            pss->mgf = WC_MGF1SHA256;
            XSTRNCPY(pss->mgfMdName, "SHA256", sizeof(pss->mgfMdName));
            idx += sizeof(mgf1Sha256AlgIdNull);
        }
        else if (XMEMCMP(data + idx, mgf1Sha384AlgId,
                         sizeof(mgf1Sha384AlgId)) == 0) {
            pss->mgf = WC_MGF1SHA384;
            XSTRNCPY(pss->mgfMdName, "SHA384", sizeof(pss->mgfMdName));
            idx += sizeof(mgf1Sha384AlgId);
        }
        else if (XMEMCMP(data + idx, mgf1Sha384AlgIdNull,
                         sizeof(mgf1Sha384AlgIdNull)) == 0) {
            pss->mgf = WC_MGF1SHA384;
            XSTRNCPY(pss->mgfMdName, "SHA384", sizeof(pss->mgfMdName));
            idx += sizeof(mgf1Sha384AlgIdNull);
        }
        else if (XMEMCMP(data + idx, mgf1Sha512AlgId,
                         sizeof(mgf1Sha512AlgId)) == 0) {
            pss->mgf = WC_MGF1SHA512;
            XSTRNCPY(pss->mgfMdName, "SHA512", sizeof(pss->mgfMdName));
            idx += sizeof(mgf1Sha512AlgId);
        }
        else if (XMEMCMP(data + idx, mgf1Sha512AlgIdNull,
                         sizeof(mgf1Sha512AlgIdNull)) == 0) {
            pss->mgf = WC_MGF1SHA512;
            XSTRNCPY(pss->mgfMdName, "SHA512", sizeof(pss->mgfMdName));
            idx += sizeof(mgf1Sha512AlgIdNull);
        }
        else {
            ok = 0;
        }
    }
    if (ok && (data[idx] == 0xa2)) {
        /* Salt length. */
        if (XMEMCMP(data + idx, saltLenDer, sizeof(saltLenDer)) == 0) {
            idx += sizeof(saltLenDer);
            pss->saltLen = data[idx];
            idx++;
        }
        else if (XMEMCMP(data + idx, saltLenDer2, sizeof(saltLenDer2)) == 0) {
            idx += sizeof(saltLenDer2);
            pss->saltLen = ((int)data[idx] << 8) + data[idx + 1];
            idx += 2;
        }
        else {
            ok = 0;
        }
    }
    /* TODO: handle optional trailer: 0xa3. */
    if (ok) {
        /* Default trailer is 1. */
        pss->derTrailer = 1;
        /* PSS parameters have been seen and set. */
        rsa->pssDefSet = 1;
    }

    return ok;
}

/**
 * Decode the SubjectPublicInfo DER encoded RSA key into the RSA key object.
 *
 * @param [in, out] rsa   RSA key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_decode_spki(wp_Rsa* rsa, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;

    rc = wc_RsaPublicKeyDecode(data, &idx, &rsa->key, len);
    if (rc != 0) {
        ok = 0;
    }
    if (ok && !wp_rsa_determine_type(rsa, data, len)) {
        ok = 0;
    }
    if (ok && (rsa->type == RSA_FLAG_TYPE_RSASSAPSS)) {
        /* We need to check for pss params to allow a rejection for non-pkcs8
         * keys. If we dont reject then the keytype gets set to RSA-PSS
         * which is wrong. For non-pkcs8 fail here for PSS decoder
         * and let the base RSA pick it up instead */
        ok = wp_rsa_pss_get_params(rsa, data, len);
    }
    if (ok) {
        rsa->bits = wc_RsaEncryptSize(&rsa->key) * 8;
        rsa->hasPub = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the PrivateKeyInfo DER encoded RSA key into the RSA key object.
 *
 * @param [in, out] rsa   RSA key object.
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_decode_pki(wp_Rsa* rsa, unsigned char* data, word32 len)
{
    int ok = 1;
    int rc;
    word32 idx = 0;

    rc = wc_RsaPrivateKeyDecode(data, &idx, &rsa->key, len);
    if (rc != 0) {
        ok = 0;
    }
#if LIBWOLFSSL_VERSION_HEX < 0x05000000 || defined(HAVE_FIPS)
    if (!ok) {
        idx = 0;
        rc = wc_GetPkcs8TraditionalOffset(data, &idx, len);
        if (rc >= 0) {
            rc = wc_RsaPrivateKeyDecode(data, &idx, &rsa->key, len);
            if (rc == 0) {
                 ok = 1;
            }
        }
    }
#endif
    if (ok && !wp_rsa_determine_type(rsa, data, len)) {
        ok = 0;
    }
    if (ok && (rsa->type == RSA_FLAG_TYPE_RSASSAPSS)) {
        ok = wp_rsa_pss_get_params(rsa, data, len);
    }
    if (ok) {
        rsa->bits = wc_RsaEncryptSize(&rsa->key) * 8;
        rsa->hasPub = 1;
        rsa->hasPriv = 1;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS

/** PBKDF2 OPID. */
unsigned char pbkdf2_oid[] = {
    42, 134, 72, 134, 247, 13, 1, 5, 12
};
/** Size of PBKDF2 OID. */
#define PBKDF2_OID_SZ    sizeof(pbkdf2_oid)

/**
 * Find the PBKDF2 OID in the key and set type.
 *
 * @param [in]      data  DER encoding.
 * @param [in]      len   Length, in bytes, of DER encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_find_pbkdf2_oid(unsigned char* data, word32 len)
{
    int ok = 0;
    word32 i;

    for (i = 0; i < 40 && i + PBKDF2_OID_SZ < len; i++) {
        /* Find the base OID. */
        if (XMEMCMP(data + i, pbkdf2_oid, PBKDF2_OID_SZ) == 0) {
            ok = 1;
            break;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the encrypted DER encoded RSA private key into the RSA key object.
 *
 * @param [in, out] rsa      RSA key object.
 * @param [in]      data     DER encoding.
 * @param [in]      len      Length, in bytes, of DER encoding.
 * @param [in]      pwCb     Password callback.
 * @param [in]      pwCbArg  Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_decode_enc_pki(wp_Rsa* rsa, unsigned char* data, word32 len,
     OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    char password[1024];
    size_t passwordSz = sizeof(password);

    /* Look for the PBKDF2 OID to know we have an encrypted key. */
    if (!wp_rsa_find_pbkdf2_oid(data, len)) {
        ok = 0;
    }
    /* Get password for decryption. */
    if (ok && !pwCb(password, passwordSz, &passwordSz, NULL, pwCbArg)) {
        ok = 0;
    }
    if (ok) {
        /* Decrypt to encoded private key. */
        int ret = wc_DecryptPKCS8Key(data, len, password, (int)passwordSz);
        if (ret <= 0) {
            ok = 0;
        }
        else {
            /* Get length of encoded private key. */
            len = (word32)ret;
        }
    }
    if (ok) {
        /* Decode private key. */
        ok = wp_rsa_decode_pki(rsa, data, len);
    }

    return ok;
}

#endif

/**
 * Construct parameters from RSA key and pass off to callback.
 *
 * @param [in] rsa        RSA key object.
 * @param [in] dataCb     Callback to pass RSA key in parameters to.
 * @param [in] dataCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_dec_send_params(wp_Rsa* rsa, OSSL_CALLBACK* dataCb,
    void* dataCbArg)
{
    int ok = 1;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
        (rsa->type == RSA_FLAG_TYPE_RSA) ? (char*)"RSA" : (char*)"RSA-PSS", 0);
    /* The address of the key object becomes the octet string pointer. */
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
        &rsa, sizeof(rsa));
    params[3] = OSSL_PARAM_construct_end();

    /* Callback to do something with RSA key object. */
    if (!dataCb(params, dataCbArg)) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Decode the data in the core BIO.
 *
 * The format of the key must be the same as the decoder's format.
 *
 * @param [in, out] ctx        RSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to read data from.
 * @param [in]      selection  Parts of key to export.
 * @param [in]      dataCb     Callback to pass RSA key in parameters to.
 * @param [in]      dataCbArg  Argument to pass to callback.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_decode(wp_RsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int decoded = 1;
    unsigned char* data = NULL;
    word32 len = 0;
    wp_Rsa* rsa = NULL;

    (void)pwCb;
    (void)pwCbArg;

    ctx->selection = selection;

    rsa = wp_rsa_base_new(ctx->provCtx, ctx->type);
    if (rsa == NULL) {
        ok = 0;
    }
    if (ok) {
        ok = wp_read_der_bio(ctx->provCtx, cBio, &data, &len);
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        if (!wp_rsa_decode_spki(rsa, data, len)) {
            ok = 0;
            decoded = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        if (!wp_rsa_decode_pki(rsa, data, len)) {
#ifdef WOLFSSL_ENCRYPTED_KEYS
            if (!wp_rsa_decode_enc_pki(rsa, data, len, pwCb, pwCbArg))
#endif
            {
                ok = 0;
                decoded = 0;
            }
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC)) {
        if ((selection == 0) ||
            (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            /* Supports decoding with or without PKCS #8 header */
            if (!wp_rsa_decode_pki(rsa, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
        else {
            /* Supports decoding with or without header */
            if (!wp_rsa_decode_spki(rsa, data, len)) {
                ok = 0;
                decoded = 0;
            }
        }
    }

    OPENSSL_clear_free(data, len);

    if (ok && decoded && !wp_rsa_dec_send_params(rsa, dataCb, dataCbArg)) {
        ok = 0;
    }

    if (!ok) {
        /* Callback takes the key. */
        wp_rsa_free(rsa);
        if (!decoded) {
            ok = 1;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA-PSS Algorithm ID in DER
 *
 * @param [in]  rsa        RSA key object.
 * @param [in]  mdName     Name of digest.
 * @param [in]  mgf1Name   Name of MGF algorithm's digest.
 * @param [in]  saltLen    Length of salt used.
 * @param [out] pssAlgId   Buffer to hold encoded RSA-PSS Algorithm ID.
 *                         May be NULL and only length calculated.
 * @param [out] len        Length of encoding.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_rsa_pss_encode_alg_id(const wp_Rsa* rsa, const char* mdName,
    const char* mgf1MdName, int saltLen, byte* pssAlgId, word32* len)
{
    int ok = 1;
    int i = 0;
    int hashLen = 0;
    const byte rsa_pss_oid[11] = {
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x0a
    };
    int seq1LenIdx;
    int seq2LenIdx;

    if (pssAlgId == NULL) {
        /* Length opf header without optional parts. */
        i = 2 + sizeof(rsa_pss_oid) + 2;
    }
    else {
        /* Encode header. */
        pssAlgId[i++] = 0x30;
        /* Remember idx to be updated as optional data added. */
        seq1LenIdx = i;
        pssAlgId[i++] = sizeof(rsa_pss_oid) + 2;
        XMEMCPY(pssAlgId + i, rsa_pss_oid, sizeof(rsa_pss_oid));
        i += sizeof(rsa_pss_oid);
        pssAlgId[i++] = 0x30;
        /* Remember idx to be updated as optional data added. */
        seq2LenIdx = i;
        pssAlgId[i++] = 0x00;
    }

    /* Digest */
    if (XSTRNCMP(mdName, "SHA1", 5) != 0) {
        if ((XMEMCMP(mdName, "SHA256", 7) == 0) ||
            (XMEMCMP(mdName, "sha256", 7) == 0)) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, sha256AlgIdNull, sizeof(sha256AlgIdNull));
                pssAlgId[seq1LenIdx] += sizeof(sha256AlgIdNull);
                pssAlgId[seq2LenIdx] += sizeof(sha256AlgIdNull);
            }
            i += sizeof(sha256AlgIdNull);
            hashLen = 32;
        }
        else if ((XMEMCMP(mdName, "SHA384", 7) == 0) ||
                 (XMEMCMP(mdName, "sha384", 7) == 0)) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, sha384AlgIdNull, sizeof(sha384AlgIdNull));
                pssAlgId[seq1LenIdx] += sizeof(sha384AlgIdNull);
                pssAlgId[seq2LenIdx] += sizeof(sha384AlgIdNull);
            }
            i += sizeof(sha384AlgIdNull);
            hashLen = 48;
        }
        else if ((XMEMCMP(mdName, "SHA512", 7) == 0) ||
                 (XMEMCMP(mdName, "sha512", 7) == 0)) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, sha512AlgIdNull, sizeof(sha512AlgIdNull));
                pssAlgId[seq1LenIdx] += sizeof(sha512AlgIdNull);
                pssAlgId[seq2LenIdx] += sizeof(sha512AlgIdNull);
            }
            i += sizeof(sha512AlgIdNull);
            hashLen = 64;
        }
        /* TODO: support more digests */
    }
    /* MGF algorithm - assumes MGF1 with a digest. */
    if (XSTRNCMP(mgf1MdName, "SHA1", 5) != 0) {
        if ((XMEMCMP(mgf1MdName, "SHA256", 7) == 0) ||
            (XMEMCMP(mgf1MdName, "sha256", 7) == 0)) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, mgf1Sha256AlgIdNull,
                    sizeof(mgf1Sha256AlgIdNull));
                pssAlgId[seq1LenIdx] += sizeof(mgf1Sha256AlgIdNull);
                pssAlgId[seq2LenIdx] += sizeof(mgf1Sha256AlgIdNull);
            }
            i += sizeof(mgf1Sha256AlgIdNull);
        }
        else if ((XMEMCMP(mgf1MdName, "SHA384", 7) == 0) ||
                 (XMEMCMP(mgf1MdName, "sha384", 7) == 0)) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, mgf1Sha384AlgIdNull,
                    sizeof(mgf1Sha384AlgIdNull));
                pssAlgId[seq1LenIdx] += sizeof(mgf1Sha384AlgIdNull);
                pssAlgId[seq2LenIdx] += sizeof(mgf1Sha384AlgIdNull);
            }
            i += sizeof(mgf1Sha384AlgIdNull);
        }
        else if ((XMEMCMP(mgf1MdName, "SHA512", 7) == 0) ||
                 (XMEMCMP(mgf1MdName, "sha512", 7) == 0)) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, mgf1Sha512AlgIdNull,
                    sizeof(mgf1Sha512AlgIdNull));
                pssAlgId[seq1LenIdx] += sizeof(mgf1Sha512AlgIdNull);
                pssAlgId[seq2LenIdx] += sizeof(mgf1Sha512AlgIdNull);
            }
            i += sizeof(mgf1Sha512AlgIdNull);
        }
        /* TODO: support more digests */
    }

    /* Determine salt length that would be used. */
    if (saltLen == RSA_PSS_SALTLEN_DIGEST) {
        saltLen = hashLen;
    }
    else if (saltLen == RSA_PSS_SALTLEN_MAX) {
        const RsaKey* key = &rsa->key;
        saltLen = wc_RsaEncryptSize(key) - hashLen - 2;
        if (((mp_count_bits(&key->n) - 1) & 0x7) == 0) {
            saltLen--;
        }
    }
    else if (saltLen == RSA_PSS_SALTLEN_AUTO) {
    #ifndef WOLFSSL_PSS_SALT_LEN_DISCOVER
        saltLen = hashLen;
    #else
        const RsaKey* key = &rsa->key;
        saltLen = wc_RsaEncryptSize(key) - hashLen - 2;
        if (((mp_count_bits(&key->n) - 1) & 0x7) == 0) {
            saltLen--;
        }
    #endif
    }
#ifdef RSA_PSS_SALTLEN_AUTO_DIGEST_MAX
    else if (saltLen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        saltLen = hashLen;
    }
#endif
    /* Encode salt length if not 0. */
    if (saltLen != 0) {
        if (saltLen < 0x80) {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, saltLenDer, sizeof(saltLenDer));
                pssAlgId[i + sizeof(saltLenDer)] = saltLen;
                pssAlgId[seq1LenIdx] += sizeof(saltLenDer) + 1;
                pssAlgId[seq2LenIdx] += sizeof(saltLenDer) + 1;
            }
            i += sizeof(saltLenDer) + 1;
        }
        else {
            if (pssAlgId != NULL) {
                XMEMCPY(pssAlgId + i, saltLenDer2, sizeof(saltLenDer2));
                pssAlgId[i + sizeof(saltLenDer2)] = 0;
                pssAlgId[i + sizeof(saltLenDer2) + 1] = saltLen;
                pssAlgId[seq1LenIdx] += sizeof(saltLenDer2) + 2;
                pssAlgId[seq2LenIdx] += sizeof(saltLenDer2) + 2;
            }
            i += sizeof(saltLenDer2) + 2;
        }
    }

    /* Return length. */
    *len = i;

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the SubjectPublicKeyInfo encoding size for the key.
 *
 * @param [in]  rsa     RSA key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_spki_size(const wp_Rsa* rsa, size_t* keyLen)
{
    int ok = 1;

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    int ret;

    ret = wc_RsaKeyToPublicDer((RsaKey*)&rsa->key, NULL, 0);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ret;
    }
#else
    int len = wc_RsaEncryptSize((RsaKey*)&rsa->key);
    if (len <= 0) {
        ok = 0;
    }
    if (ok) {
        /* TODO: rough estimate (n + e + ASN.1) */
        *keyLen = len + 50;
    }
#endif
    if (ok && (rsa->type == RSA_FLAG_TYPE_RSASSAPSS)) {
        word32 pssLen = 0;
        ok = wp_rsa_pss_encode_alg_id(rsa, rsa->pssParams.mdName,
            rsa->pssParams.mgfMdName, rsa->pssParams.saltLen, NULL, &pssLen);
        if (ok) {
            *keyLen += pssLen;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA key in a SubjectPublicKeyInfo format.
 *
 * @param [in]      rsa      RSA key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_spki(const wp_Rsa* rsa, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int ret;

    ret = wc_RsaKeyToPublicDer((RsaKey*)&rsa->key, keyData, (word32)*keyLen);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ret;
        if (rsa->type == RSA_FLAG_TYPE_RSASSAPSS) {
            word32 pssLen = 0;
            word32 i;

            /* Find where Algorithm ID is by looking for RSA PKCS#1 OID. */
            ok = wp_rsa_find_oid(keyData, ret, rsa_pkcs1_oid, RSA_PKCS1_OID_SZ,
                &i);
            if (ok) {
                i += 13;
                /* Get length of encoded RSA-PSS Algorithm ID. */
                ok = wp_rsa_pss_encode_alg_id(rsa, rsa->pssParams.mdName,
                    rsa->pssParams.mgfMdName, rsa->pssParams.saltLen, NULL,
                    &pssLen);
            }
            if (ok) {
                /* Move rest of key to after RSA-PSS Algorithm ID. */
                XMEMMOVE(keyData + 4 + pssLen, keyData + i, ret - i);
                /* Encode RSA-PSS Algorithm ID. */
                ok = wp_rsa_pss_encode_alg_id(rsa, rsa->pssParams.mdName,
                    rsa->pssParams.mgfMdName, rsa->pssParams.saltLen,
                    keyData + 4, &pssLen);
            }
            if (ok) {
                /* Update return length. */
                ret += pssLen - i;
                *keyLen = ret + 4;
                /* Update first sequence. */
                keyData[2] = (byte)(ret >> 8);
                keyData[3] = (byte)(ret & 0xff);
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the Public Key encoding size for the key.
 *
 * @param [in]  rsa     RSA key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_pub_size(const wp_Rsa* rsa, size_t* keyLen)
{
    int ok = 1;
    int ret;

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    ret = wc_RsaKeyToPublicDer_ex((RsaKey*)&rsa->key, NULL, 0, 0);
#else
    ret = wc_RsaKeyToPublicDer((RsaKey*)&rsa->key, NULL, 0);
#endif
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ret;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA key in a Public Key format.
 *
 * @param [in]      rsa      RSA key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_pub(const wp_Rsa* rsa, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int ret;

#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    ret = wc_RsaKeyToPublicDer_ex((RsaKey*)&rsa->key, keyData, (word32)*keyLen,
        0);
    if (ret <= 0) {
        ok = 0;
    }
#else
    /* TODO: Encodes with header. Strip it off. */
    ret = wc_RsaKeyToPublicDer((RsaKey*)&rsa->key, keyData, (word32)*keyLen);
    if (ret <= 0) {
        ok = 0;
    }
#endif
    if (ok) {
        *keyLen = ret;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* RSAk defined in private header <wolfssl/wolfcrypt/asn.h> */
#define RSAk       645
#if LIBWOLFSSL_VERSION_HEX >= 0x05005000
#define RSAPSSk    654
#define RSA_ALGO_ID(ctx) (ctx->type == RSA_FLAG_TYPE_RSASSAPSS \
                              ? RSAPSSk : RSAk)
#else
#define RSA_ALGO_ID(ctx) RSAk
#endif

/**
 * Get the PKCS#8 encoding size for the key.
 *
 * @param [in]  rsa     RSA key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @param [in]  algoId  Algorithm ID to use.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_pki_size(const wp_Rsa* rsa, size_t* keyLen, int algoId)
{
    int ok = 1;
    int ret;
    word32 len;

    ret = wc_RsaKeyToDer((RsaKey*)&rsa->key, NULL, 0);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        ret = wc_CreatePKCS8Key(NULL, &len, NULL, ret, algoId, NULL, 0);
        if (ret != LENGTH_ONLY_E) {
            ok = 0;
        }
    }
    if (ok) {
        *keyLen = len;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA key in a PKCS#8 format.
 *
 * @param [in]      rsa      RSA key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @param [in]      algoId   Algorithm ID to use.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_pki(const wp_Rsa* rsa, unsigned char* keyData,
    size_t* keyLen, int algoId)
{
    int ok = 1;
    int ret;
    unsigned char* pkcs1Data = NULL;
    size_t pkcs1Len = 0;
    word32 len;

    ret = wc_RsaKeyToDer((RsaKey*)&rsa->key, NULL, 0);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        pkcs1Len = ret;
        pkcs1Data = OPENSSL_malloc(pkcs1Len);
        if (pkcs1Data == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        ret = wc_RsaKeyToDer((RsaKey*)&rsa->key, pkcs1Data, (word32)pkcs1Len);
        if (ret <= 0) {
            ok = 0;
        }
    }
    if (ok) {
        pkcs1Len = ret;
        len = (word32)*keyLen;
        ret = wc_CreatePKCS8Key(keyData, &len, pkcs1Data, (word32)pkcs1Len,
            algoId, NULL, 0);
        if (ret <= 0) {
            ok = 0;
        }
    }
    if (ok) {
        *keyLen = ret;
    }

    OPENSSL_clear_free(pkcs1Data, pkcs1Len);
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the Private Key encoding size for the key.
 *
 * @param [in]  rsa     RSA key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_priv_size(const wp_Rsa* rsa, size_t* keyLen)
{
    int ok = 1;
    int ret;

    ret = wc_RsaKeyToDer((RsaKey*)&rsa->key, NULL, 0);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ret;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA key in a Private Key format.
 *
 * @param [in]      rsa      RSA key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_priv(const wp_Rsa* rsa, unsigned char* keyData,
    size_t* keyLen)
{
    int ok = 1;
    int ret;

    ret = wc_RsaKeyToDer((RsaKey*)&rsa->key, keyData, (word32)*keyLen);
    if (ret <= 0) {
        ok = 0;
    }
    if (ok) {
        *keyLen = ret;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef WOLFSSL_ENCRYPTED_KEYS
/**
 * Get the Encrypted Private Key encoding size for the key.
 *
 * @param [in]  ctx     RSA encoder/decoder context object.
 * @param [in]  rsa     RSA key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_enc_pki_size(const wp_RsaEncDecCtx* ctx,
    const wp_Rsa* rsa, size_t* keyLen)
{
    int ok;
    size_t len;
    word32 outSz;
    byte fakeData[1];
    byte fakeSalt[16];

    /* Get encode private key length. */
    ok = wp_rsa_encode_pki_size(rsa, &len, RSA_ALGO_ID(ctx));
    if (ok) {
        /* Get encrypted encode private key. */
        if (wc_EncryptPKCS8Key(fakeData, (word32)len, NULL, &outSz, "", 0,
                WP_PKCS5, WP_PBES2, ctx->cipher, fakeSalt, sizeof(fakeSalt),
                WP_PKCS12_ITERATIONS_DEFAULT, wp_provctx_get_rng(ctx->provCtx),
                NULL) != LENGTH_ONLY_E) {
            ok = 0;
        }
        else {
            /* Return the length calculated. */
            *keyLen = (size_t)outSz;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA key in a Encrypted Private Key format.
 *
 * @param [in]      ctx      RSA encoder/decoder context object.
 * @param [in]      rsa      RSA key object.
 * @param [out]     keyData  Buffer to hold encoded data.
 * @param [in, out] keyLen   On in, length of buffer in bytes.
 *                           On out, length of encoding in bytes.
 * @param [in]      pwCb     Password callback.
 * @param [in]      pwCbArg  Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_enc_pki(const wp_RsaEncDecCtx* ctx, const wp_Rsa* rsa,
    unsigned char* keyData, size_t* keyLen, OSSL_PASSPHRASE_CALLBACK* pwCb,
    void* pwCbArg)
{
    int ok = 1;
    size_t len;
    word32 outSz = (word32)*keyLen;
    byte salt[WP_MAX_SALT_SIZE];
    int saltLen = 16;
    char password[1024];
    size_t passwordSz = sizeof(password);
    byte* encodedKey = NULL;

    /* TODO: support salt length of 8 for DES3. */

    /* Encode key. */
    ok = wp_rsa_encode_pki_size(rsa, &len, RSA_ALGO_ID(ctx));
    if (ok) {
        /* Allocate buffer for encrypted key to be placed into. */
        encodedKey = XMALLOC(len, NULL, DYNAMIC_TYPE_RSA_BUFFER);
        if (encodedKey == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        /* Encode key. */
        ok = wp_rsa_encode_pki(rsa, encodedKey, &len, RSA_ALGO_ID(ctx));
    }
    /* Generate salt. */
    if (ok && (wc_RNG_GenerateBlock(wp_provctx_get_rng(ctx->provCtx), salt,
            saltLen) != 0)) {
        ok = 0;
    }
    /* Get password. */
    if (ok && !pwCb(password, passwordSz, &passwordSz, NULL, pwCbArg)) {
        ok = 0;
    }
    if (ok) {
        /* Encrypt encoded key - in and out buffers must be different. */
        if (wc_EncryptPKCS8Key(encodedKey, (word32)len, keyData, &outSz,
                password, (word32)passwordSz, WP_PKCS5, WP_PBES2, ctx->cipher,
                salt, saltLen, WP_PKCS12_ITERATIONS_DEFAULT,
                wp_provctx_get_rng(ctx->provCtx), NULL) <= 0) {
            ok = 0;
        }
        else {
            /* Return actual size of encrypted encoded private key. */
            *keyLen = (size_t)outSz;
        }
    }

    XFREE(encodedKey, NULL, DYNAMIC_TYPE_RSA_BUFFER);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Get the Encrypted PKCS#8 encoding size for the key.
 *
 * @param [in]  rsa     RSA key object.
 * @param [out] keyLen  Length of encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_epki_size(const wp_RsaEncDecCtx* ctx,
    const wp_Rsa* rsa, size_t* keyLen)
{
    int ok;
    size_t len;

    ok = wp_rsa_encode_pki_size(rsa, &len, RSA_ALGO_ID(ctx));
    if (ok) {
        *keyLen = ((len + 15) / 16) * 16;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode the RSA key in an Encrypted PKCS#8 format.
 *
 * @param [in]      ctx         RSA encoder/decoder context object.
 * @param [in]      rsa         RSA key object.
 * @param [out]     keyData     Buffer to hold encoded data.
 * @param [in, out] keyLen      On in, length of buffer in bytes.
 *                              On out, length of encoding in bytes.
 * @param [in]      pwCb        Password callback.
 * @param [in]      pwCbArg     Argument to pass to password callback.
 * @param [out]     cipherInfo  Information about encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_epki(const wp_RsaEncDecCtx* ctx, const wp_Rsa* rsa,
    unsigned char* keyData, size_t* keyLen, OSSL_PASSPHRASE_CALLBACK* pwCb,
    void* pwCbArg, byte** cipherInfo)
{
    int ok = 1;
    size_t len = *keyLen;

    /* Encode key. */
    ok = wp_rsa_encode_pki(rsa, keyData, &len, RSA_ALGO_ID(ctx));
    if (ok && (!wp_encrypt_key(ctx->provCtx, ctx->cipherName, keyData, keyLen,
            (word32)len, pwCb, pwCbArg, cipherInfo))) {
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}
#endif

/**
 * Encode the RSA key.
 *
 * @param [in]      ctx        RSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      key        RSA key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode. Unused.
 * @param [in]      pwCb       Password callback.
 * @param [in]      pwCbArg    Argument to pass to password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode(wp_RsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    const wp_Rsa* key, const OSSL_PARAM* params, int selection,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    int rc;
    BIO *out = wp_corebio_get_bio(ctx->provCtx, cBio);
    unsigned char* keyData = NULL;
    size_t keyLen;
    unsigned char* derData = NULL;
    size_t derLen = 0;
    unsigned char* pemData = NULL;
    size_t pemLen = 0;
    int pemType = PKCS8_PRIVATEKEY_TYPE;
    int private = 0;
    byte* cipherInfo = NULL;

    (void)params;
    (void)selection;
    (void)pwCb;
    (void)pwCbArg;

    if (out == NULL) {
        ok = 0;
    }

    if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        if (!wp_rsa_encode_spki_size(key, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
#ifdef WOLFSSL_ENCRYPTED_KEYS
        if (ctx->cipherName != NULL) {
            ok = wp_rsa_encode_enc_pki_size(ctx, key, &derLen);
        }
        else
#endif
        if (!wp_rsa_encode_pki_size(key, &derLen, RSA_ALGO_ID(ctx))) {
            ok = 0;
        }
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        if (!wp_rsa_encode_epki_size(ctx, key, &derLen)) {
            ok = 0;
        }
    }
#endif
    else if (ok && (ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC)) {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            if (!wp_rsa_encode_priv_size(key, &derLen)) {
                ok = 0;
            }
        }
        else {
            if (!wp_rsa_encode_pub_size(key, &derLen)) {
                ok = 0;
            }
        }
    }

    if (ok) {
        keyLen = derLen;
        keyData = derData = OPENSSL_malloc(derLen);
        if (derData == NULL) {
            ok = 0;
        }
    }
    if (ok && (ctx->format == WP_ENC_FORMAT_SPKI)) {
        pemType = PUBLICKEY_TYPE;
        if (!wp_rsa_encode_spki(key, derData, &derLen)) {
            ok = 0;
        }
    }
    else if (ok && (ctx->format == WP_ENC_FORMAT_PKI)) {
        private = 1;
#ifdef WOLFSSL_ENCRYPTED_KEYS
        if (ctx->cipherName != NULL) {
            pemType = PKCS8_ENC_PRIVATEKEY_TYPE;
            ok = wp_rsa_encode_enc_pki(ctx, key, derData, &derLen, pwCb,
                pwCbArg);
        }
        else
#endif
        if (!wp_rsa_encode_pki(key, derData, &derLen, RSA_ALGO_ID(ctx))) {
            ok = 0;
        }
    }
#ifdef WOLFSSL_ENCRYPTED_KEYS
    else if (ok && (ctx->format == WP_ENC_FORMAT_EPKI)) {
        private = 1;
        if (!wp_rsa_encode_epki(ctx, key, derData, &derLen, pwCb, pwCbArg,
                (ctx->encoding == WP_FORMAT_PEM) ? &cipherInfo : NULL)) {
            ok = 0;
        }
    }
#endif
    else if (ok && (ctx->format == WP_ENC_FORMAT_TYPE_SPECIFIC)) {
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            pemType = RSA_TYPE;
            private = 1;
            if (!wp_rsa_encode_priv(key, derData, &derLen)) {
                ok = 0;
            }
        }
        else {
            pemType = RSA_PUBLICKEY_TYPE;
            if (!wp_rsa_encode_pub(key, derData, &derLen)) {
                ok = 0;
            }
        }
    }

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
                NULL, pemType);
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
    BIO_free(out);
    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Export the RSA key object.
 *
 * @param [in] ctx          RSA encoder/decoder context object.
 * @param [in] rsa          RSA key object.
 * @param [in] size         Size of key object.
 * @param [in] exportCb     Callback to export key.
 * @param [in] exportCbArg  Argument to pass to callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_export_object(wp_RsaEncDecCtx* ctx, wp_Rsa* rsa, size_t size,
    OSSL_CALLBACK* exportCb, void* exportCbArg)
{
    /* TODO: check size to ensure it really is a wc_Rsa object.  */
    (void)size;
    return wp_rsa_export(rsa, ctx->selection, exportCb, exportCbArg);
}

/*
 * RSA SubjectPublicKeyInfo
 */

/**
 * Create a new RSA encoder/decoder context that handles decoding SPKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_DER);
}

/**
 * Return whether the SPKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        RSA encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_rsa_spki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for SPKI decoder.
 */
const OSSL_DISPATCH wp_rsa_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_rsa_spki_dec_new            },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_rsa_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_rsa_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_rsa_export_object           },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding SPKI to DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_DER);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsa_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_spki_der_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding SPKI to PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_SPKI,
        WP_FORMAT_PEM);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsa_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_spki_pem_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/*
 * RSA PrivateKeyInfo
 */

/**
 * Create a new RSA encoder/decoder context that handles decoding PKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_PKI,
        WP_FORMAT_DER);
}

/**
 * Return whether the PKI decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        RSA encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_rsa_pki_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for PKI decoder.
 */
const OSSL_DISPATCH wp_rsa_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_rsa_pki_dec_new             },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_rsa_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_rsa_export_object           },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_PKI,
        WP_FORMAT_DER);
}

/**
 * Dispatch table for PKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsa_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_pki_der_enc_new         },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_PKI,
        WP_FORMAT_PEM);
}

/**
 * Dispatch table for PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_rsa_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_pki_pem_enc_new         },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/*
 * RSA EncryptedPrivateKeyInfo
 */

/**
 * Create a new RSA encoder/decoder context that handles encoding EPKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_epki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_DER);
}

/**
 * Dispatch table for EPKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsa_epki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_epki_der_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding EPKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_epki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_EPKI,
        WP_FORMAT_PEM);
}

/**
 * Dispatch table for EPKI to PEM encoder.
 */
const OSSL_DISPATCH wp_rsa_epki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_epki_pem_enc_new        },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/*
 * RSA type-specific/legacy
 */

/**
 * Create a new RSA encoder/decoder context that handles decoding legacy.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_legacy_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA,
        WP_ENC_FORMAT_TYPE_SPECIFIC, WP_FORMAT_DER);
}

/**
 * Return whether the legacy decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        RSA encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_rsa_legacy_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for legacy decoder.
 */
const OSSL_DISPATCH wp_rsa_legacy_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_rsa_legacy_dec_new          },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_rsa_legacy_does_selection   },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_rsa_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_rsa_export_object           },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding t-s in DER.
 *
 * For RSA, type-specific means the key pair.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_kp_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA,
        WP_ENC_FORMAT_TYPE_SPECIFIC, WP_FORMAT_DER);
}

/**
 * Return whether the key pair decoder/encoder handles this part of the key.
 *
 * @param [in] ctx        RSA encoder/decoder context object.
 * @param [in] selection  Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_rsa_kp_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Dispatch table for type-specific (key pair) to DER encoder.
 */
const OSSL_DISPATCH wp_rsa_kp_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_kp_der_enc_new          },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_kp_does_selection       },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/**
 * Create a new RSA encoder/decoder context that handles encoding t-s in PEM.
 *
 * For RSA, type-specific means the key pair.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_kp_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA,
        WP_ENC_FORMAT_TYPE_SPECIFIC, WP_FORMAT_PEM);
}

/**
 * Dispatch table for type-specific(key pair) to PEM encoder.
 */
const OSSL_DISPATCH wp_rsa_kp_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_kp_pem_enc_new          },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_kp_does_selection       },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/*
 * RSA-PSS SubjectPublicKeyInfo
 */

/**
 * Create a new RSA-PSS encoder/decoder context that handles decoding SPKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsapss_spki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSASSAPSS,
        WP_ENC_FORMAT_SPKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for PSS SPKI decoder.
 */
const OSSL_DISPATCH wp_rsapss_spki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_rsapss_spki_dec_new         },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_rsa_spki_does_selection     },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_rsa_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_rsa_export_object           },
    { 0, NULL }
};

/**
 * Create a new RSA-PSS enc/dec context that handles encoding SPKI to DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsapss_spki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSASSAPSS,
        WP_ENC_FORMAT_SPKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for PSS SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsapss_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsapss_spki_der_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/**
 * Create a new RSA-PSS enc/dec context that handles encoding SPKI to PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsapss_spki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSASSAPSS,
        WP_ENC_FORMAT_SPKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for SPKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsapss_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsapss_spki_pem_enc_new     },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_spki_does_selection     },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/*
 * RSA-PSS PrivateKeyInfo
 */

/**
 * Create a new RSA-PSS encoder/decoder context that handles decoding PKI.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsapss_pki_dec_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSASSAPSS,
        WP_ENC_FORMAT_PKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for PSS PKI decoder.
 */
const OSSL_DISPATCH wp_rsapss_pki_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,         (DFUNC)wp_rsapss_pki_dec_new          },
    { OSSL_FUNC_DECODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_DECODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_DECODER_DECODE,         (DFUNC)wp_rsa_decode                  },
    { OSSL_FUNC_DECODER_EXPORT_OBJECT,  (DFUNC)wp_rsa_export_object           },
    { 0, NULL }
};

/**
 * Create a new RSA-PSS enc/dec context that handles encoding PKI in DER.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsapss_pki_der_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSASSAPSS,
        WP_ENC_FORMAT_PKI, WP_FORMAT_DER);
}

/**
 * Dispatch table for PSS PKI to DER encoder.
 */
const OSSL_DISPATCH wp_rsapss_pki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsapss_pki_der_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};

/**
 * Create a new RSA-PSS enc/dec context that handles encoding PKI in PEM.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsapss_pki_pem_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSASSAPSS,
        WP_ENC_FORMAT_PKI, WP_FORMAT_PEM);
}

/**
 * Dispatch table for PSS PKI to PEM encoder.
 */
const OSSL_DISPATCH wp_rsapss_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsapss_pki_pem_enc_new      },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_enc_dec_free            },
    { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,
                                    (DFUNC)wp_rsa_enc_dec_settable_ctx_params },
    { OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (DFUNC)wp_rsa_enc_dec_set_ctx_params  },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_pki_does_selection      },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode                  },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (DFUNC)wp_rsa_import                  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (DFUNC)wp_rsa_free                    },
    { 0, NULL }
};


/**
 * Create a new RSA text encoder context.
 *
 * @param [in] provCtx  Provider context.
 * @return  New RSA encoder/decoder context object on success.
 * @return  NULL on failure.
 */
static wp_RsaEncDecCtx* wp_rsa_text_enc_new(WOLFPROV_CTX* provCtx)
{
    return wp_rsa_enc_dec_new(provCtx, RSA_FLAG_TYPE_RSA, WP_ENC_FORMAT_TEXT,
        WP_FORMAT_TEXT);
}

/**
 * Dispose of RSA text encoder context object.
 *
 * @param [in, out] ctx  RSA encoder/decoder context object.
 */
static void wp_rsa_text_enc_free(wp_RsaEncDecCtx* ctx)
{
    wp_rsa_enc_dec_free(ctx);
}

/**
 * Return whether the RSA text encoder handles this part of the key.
 *
 * @param [in] provCtx   Provider context. Unused.
 * @param [in] selection Parts of key to handle.
 * @return  1 when supported.
 * @return  0 when not supported.
 */
static int wp_rsa_text_enc_does_selection(WOLFPROV_CTX* provCtx, int selection)
{
    int ok;

    (void)provCtx;

    /* Text encoder supports both public and private key parts */
    if (selection == 0) {
        ok = 1;
    }
    else {
        ok = ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) ||
             ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
    }

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Encode a portion of the RSA key as hexadecimal.
 *
 * @param [in]      num        An mp_int to convert to hexadecimal.
 * @param [out]     textData   Buffer to store hex in.
 * @param [in]      textLen    Size of buffer.
 * @param [in, out] pos        Current position in buffer.
 * @param [in]      label      String describing section being encoded.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_text_format_hex(const mp_int* num, char* textData,
        size_t textLen, size_t* pos, const char* label)
{
    unsigned char* binData = NULL;
    size_t binLen = 0;
    size_t printAmt;
    size_t dPos = *pos;
    int bytes = 0;
    int i;

    int ok = 1;

    if ((binLen = mp_unsigned_bin_size(num)) <= 0
            || (binData = OPENSSL_malloc(binLen)) == NULL) {
        ok = 0;
    }
    else if (mp_to_unsigned_bin((mp_int*)num, binData) != MP_OKAY) {
        ok = 0;
        OPENSSL_free(binData);
        binData = NULL;
    }
    else {
        if ((printAmt = XSNPRINTF(textData + dPos, textLen - dPos,
                "%s:\n    ", label)) <= 0) {
            ok = 0;
        }
        dPos += printAmt;

        /* OSSL adds a leading 00 if MSB is set */
        if (ok && *binData > 127) {
            if ((printAmt = XSNPRINTF(textData + dPos, textLen - dPos,
                    "00:")) <= 0) {
                ok = 0;
            }
            dPos += printAmt;
            bytes++;
        }

        /* OSSL does a newline + indent every 15 bytes */
        if (ok) {
            for (i = 0; i < (int)binLen - 1; i++) {
                if (bytes >= 14) {
                    if ((printAmt = XSNPRINTF(textData + dPos,
                            textLen - dPos, "%02x:\n    ", binData[i])) <= 0) {
                        ok = 0;
                        break;
                    }
                    bytes = 0;
                }
                else {
                    if ((printAmt = XSNPRINTF(textData + dPos,
                            textLen - dPos, "%02x:", binData[i])) <= 0) {
                        ok = 0;
                        break;
                    }
                    bytes++;
                }
                dPos += printAmt;
            }
            if (ok && (printAmt = XSNPRINTF(textData + dPos,
                    textLen - dPos, "%02x\n", binData[i])) <= 0) {
                ok = 0;
            }
            dPos += printAmt;
        }

        OPENSSL_free(binData);
        binData = NULL;
    }

    if (ok) {
        *pos = dPos;
    }

    return ok;
}

/**
 * Encode the RSA key in text format.
 *
 * @param [in]      ctx        RSA encoder/decoder context object.
 * @param [in, out] cBio       Core BIO to write data to.
 * @param [in]      key        RSA key object.
 * @param [in]      params     Key parameters. Unused.
 * @param [in]      selection  Parts of key to encode.
 * @param [in]      pwCb       Password callback. Unused.
 * @param [in]      pwCbArg    Argument to pass to password callback. Unused.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wp_rsa_encode_text(wp_RsaEncDecCtx* ctx, OSSL_CORE_BIO* cBio,
    const wp_Rsa* key, const OSSL_PARAM* params, int selection,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    int ok = 1;
    BIO *out = wp_corebio_get_bio(ctx->provCtx, cBio);
    int hasPriv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int hasPub = (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
    char* textData = NULL;
    size_t textLen = 0;
    size_t pos = 0;
    size_t printAmt;
    char* expStr;
    int expLen;

    (void)params;
    (void)pwCb;
    (void)pwCbArg;

    if (out == NULL) {
        ok = 0;
    }

    /* Calculate total size needed for text output */
    if (ok) {
        /* 128 bytes provides space for labels: 'modulus:', 'prime1:', etc. */
        textLen = 128;
        if (hasPriv) {
            /* displaying modulus and private exponent requires roughly 3 bytes
             * per byte in key.
             * prime1, prime2, exponent1, exponent2, and coefficient requires
             * roughly 1.5 bytes per byte inkey.
             * This is then 13.5 bytes per bytes in key + indents, which should
             * be less than bits * 2.*/
            textLen += key->bits << 1;
        }
        else if (hasPub) {
            /* displaying modulus requires roughly 3 bytes per byte in key + a
             * small amount for indents. This should be less than bits / 2 */
            textLen += key->bits >> 1;
        }

        if ((textData = OPENSSL_malloc(textLen)) == NULL) {
            ok = 0;
        }
    }

    if (ok) {
        /* OSSL uses nested macros to determine the number of primes, not sure
         * when there wouldn't be two primes */
        if (hasPriv && (printAmt = XSNPRINTF(textData + pos, textLen - pos,
                "Private-Key: (%d bit, 2 primes)\n", key->bits)) <= 0) {
            ok = 0;
        }
        else if (hasPub && (printAmt = XSNPRINTF(textData + pos,
                textLen - pos, "Public-Key: (%d bit)\n", key->bits)) <= 0) {
            ok = 0;
        }
        pos += printAmt;
    }

    /* OSSL uses 'modulus' and 'Modulus' */
    if (hasPriv) {
        ok = wp_rsa_encode_text_format_hex(&key->key.n, textData, textLen, &pos,
            "modulus");
    }
    else if (hasPub) {
        ok = wp_rsa_encode_text_format_hex(&key->key.n, textData, textLen, &pos,
            "Modulus");
    }

    /* OSSL uses 'publicExponent' and 'Exponent' */
    if (ok) {
        if (mp_radix_size((mp_int*)&key->key.e, MP_RADIX_DEC, &expLen) != MP_OKAY
                || ((expStr = OPENSSL_malloc(expLen)) == NULL)) {
            ok = 0;
        }
        else if (mp_todecimal((mp_int*)&key->key.e, expStr) != MP_OKAY) {
            ok = 0;
            OPENSSL_free(expStr);
            expStr = NULL;
        }
        else {
            if (hasPriv && (printAmt = XSNPRINTF(textData + pos,
                    textLen - pos, "publicExponent: %s ", expStr)) <= 0) {
                ok = 0;
            }
            else if (hasPub && (printAmt = XSNPRINTF(textData + pos,
                    textLen - pos, "Exponent: %s ", expStr)) <= 0) {
                ok = 0;
            }
            pos += printAmt;

            OPENSSL_free(expStr);
            expStr = NULL;
        }
    }

    if (ok) {
        if (mp_radix_size((mp_int*)&key->key.e, MP_RADIX_HEX, &expLen) != MP_OKAY
                || ((expStr = OPENSSL_malloc(expLen)) == NULL)) {
            ok = 0;
        }
        else if (mp_tohex((mp_int*)&key->key.e, expStr) != MP_OKAY) {
            ok = 0;
            OPENSSL_free(expStr);
            expStr = NULL;
        }
        else {
            /* OSSL does not print a leading zero for the hex part */
            if ((printAmt = XSNPRINTF(textData + pos,
                    textLen - pos, "(0x%s)\n",
                    (*expStr == '0') ? (expStr + 1) : (expStr))) <= 0) {
                ok = 0;
            }
            pos += printAmt;

            OPENSSL_free(expStr);
            expStr = NULL;
        }
    }

    /* Write private key components */
    if (ok && hasPriv) {
        if (ok) {
            ok = wp_rsa_encode_text_format_hex(&key->key.d, textData, textLen,
                &pos, "privateExponent");
        }

        if (ok) {
            ok = wp_rsa_encode_text_format_hex(&key->key.p, textData, textLen,
                &pos, "prime1");
        }

        if (ok) {
            ok = wp_rsa_encode_text_format_hex(&key->key.q, textData, textLen,
                &pos, "prime2");
        }

        if (ok) {
            ok = wp_rsa_encode_text_format_hex(&key->key.dP, textData, textLen,
                &pos, "exponent1");
        }

        if (ok) {
            ok = wp_rsa_encode_text_format_hex(&key->key.dQ, textData, textLen,
                &pos, "exponent2");
        }

        if (ok) {
            ok = wp_rsa_encode_text_format_hex(&key->key.u, textData, textLen,
                &pos, "coefficient");
        }
    }

    /* TODO: display RSAPSS info */

    if (ok && (BIO_write(out, textData, (int)pos) <= 0)) {
        ok = 0;
    }

    OPENSSL_free(textData);
    BIO_free(out);

    WOLFPROV_LEAVE(WP_LOG_PK, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

const OSSL_DISPATCH wp_rsa_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (DFUNC)wp_rsa_text_enc_new            },
    { OSSL_FUNC_ENCODER_FREECTX,        (DFUNC)wp_rsa_text_enc_free           },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (DFUNC)wp_rsa_text_enc_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (DFUNC)wp_rsa_encode_text             },
    { 0, NULL }
};

#endif /* WP_HAVE_RSA */

