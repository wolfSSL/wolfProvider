/* wp_internal.c
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


#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/err.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/internal.h>
#include <wolfprovider/wp_wolfprov.h>
#include <wolfprovider/wp_logging.h>
#include <wolfprovider/alg_funcs.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifdef HAVE_FIPS
#include <wolfssl/wolfcrypt/fips_test.h>
#endif

#ifndef WP_SINGLE_THREADED

#if defined(WP_HAVE_SEED_SRC) && defined(WP_HAVE_RANDOM)
#if !defined(WP_SINGLE_THREADED) && !defined(_WIN32)
#include <pthread.h>
#endif
/* Global mutex for urandom file access (used by seed callback) */
static wolfSSL_Mutex urandomMutex;

#if !defined(WP_SINGLE_THREADED) && !defined(_WIN32)
/* Re-init the mutex in a forked child so an inherited locked mutex cannot
 * deadlock entropy reads. */
static void wolfprov_urandom_atfork_child(void)
{
    wc_InitMutex(&urandomMutex);
}
#endif

/**
 * Initialize the urandom mutex on library load.
 *
 * This constructor runs when libwolfprov.so is loaded via dlopen() or at
 * program startup. It ensures the urandomMutex is initialized before use.
 */
__attribute__((constructor))
static void wolfprov_init_urandom_mutex(void)
{
    wc_InitMutex(&urandomMutex);
#if !defined(WP_SINGLE_THREADED) && !defined(_WIN32)
    (void)pthread_atfork(NULL, NULL, wolfprov_urandom_atfork_child);
#endif
}

/**
 * Get the global urandom mutex.
 *
 * @return  Pointer to the urandom mutex.
 */
wolfSSL_Mutex *wp_get_urandom_mutex(void)
{
    return &urandomMutex;
}
#endif /* WP_HAVE_SEED_SRC && WP_HAVE_RANDOM */

#ifdef HAVE_FIPS
/**
 * Structure to hold CAST self-test state for each algorithm.
 */
typedef struct wp_cast_algo_state {
    /** Mutex for the algorithm's CAST self-test. */
    wolfSSL_Mutex mutex;
    /** Initialization state: 0 = not initialized, 1 = initialized. */
    int init;
} wp_cast_algo_state;

static wp_cast_algo_state castAlgos[WP_CAST_ALGO_COUNT];

/**
 * Initialize the cast mutexes on library load.
 *
 * This constructor runs when libwolfprov.so is loaded via dlopen() or at
 * program startup. It ensures the castAlgos are initialized before any
 * wolfProvider functions are called.
 */
__attribute__((constructor))
static void wolfprov_init_cast_mutex(void)
{
    int i;
    for (i = 0; i < WP_CAST_ALGO_COUNT; i++) {
        wc_InitMutex(&castAlgos[i].mutex);
        castAlgos[i].init = 0;
    }
}

/**
 * Initialize a CAST self-test for a specific algorithm.
 *
 * Runs the algorithm-specific CAST self-test if not already initialized.
 * Uses mutex to ensure thread safety.
 *
 * @param [in] algo  Algorithm category (WP_CAST_ALGO_*).
 * @return  1 on success or already initialized.
 * @return  0 on failure.
 */
int wp_init_cast(int algo)
{
    int ok = 1;

    if (algo < 0 || algo >= WP_CAST_ALGO_COUNT) {
        WOLFPROV_ERROR_MSG(WP_LOG_COMP_PROVIDER,
            "FIPS CAST initialization failed: invalid algorithm");
        return 0;
    }

    if (castAlgos[algo].init == 0) {
        if (wp_lock(&castAlgos[algo].mutex) != 1) {
            WOLFPROV_ERROR_MSG(WP_LOG_COMP_PROVIDER,
                "FIPS CAST initialization failed: unable to acquire lock");
            return 0;
        }
        /* Make sure another thread did not complete already while we waited
         * to acquire per algo lock */
        if (castAlgos[algo].init == 0) {
            switch (algo) {
#ifdef WP_HAVE_AES
                case WP_CAST_ALGO_AES:
                    if (wc_RunCast_fips(FIPS_CAST_AES_CBC) != 0 ||
                        wc_RunCast_fips(FIPS_CAST_AES_GCM) != 0) {
                        ok = 0;
                    }
                    break;
#endif
#ifdef WP_HAVE_HMAC
                case WP_CAST_ALGO_HMAC:
                    if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA1) != 0 ||
                        wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_256) != 0 ||
                        wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_512) != 0 ||
                        wc_RunCast_fips(FIPS_CAST_HMAC_SHA3_256) != 0) {
                        ok = 0;
                    }
                    break;
#endif
#ifdef WP_HAVE_RSA
                case WP_CAST_ALGO_RSA:
                    if (wc_RunCast_fips(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0) {
                        ok = 0;
                    }
                    break;
#endif
#ifdef WP_HAVE_ECDSA
                case WP_CAST_ALGO_ECDSA:
                    if (wc_RunCast_fips(FIPS_CAST_ECDSA) != 0) {
                        ok = 0;
                    }
                    break;
#endif
#ifdef WP_HAVE_ECDH
                case WP_CAST_ALGO_ECDH:
                    if (wc_RunCast_fips(FIPS_CAST_ECC_CDH) != 0 ||
                        wc_RunCast_fips(FIPS_CAST_ECC_PRIMITIVE_Z) != 0) {
                        ok = 0;
                    }
                    break;
#endif
#ifdef WP_HAVE_DH
                case WP_CAST_ALGO_DH:
                    if (wc_RunCast_fips(FIPS_CAST_DH_PRIMITIVE_Z) != 0) {
                        ok = 0;
                    }
                    break;
#endif
#ifdef WP_HAVE_RANDOM
                case WP_CAST_ALGO_DRBG:
                    if (wc_RunCast_fips(FIPS_CAST_DRBG) != 0) {
                        ok = 0;
                    }
                    break;
#endif
                default:
                    ok = 0;
                    break;
            }

            if (ok) {
                castAlgos[algo].init = 1;
            }
        }
        if (wp_unlock(&castAlgos[algo].mutex) != 1) {
            ok = 0;
        }
    }

    if (!ok) {
        WOLFPROV_ERROR_MSG(WP_LOG_COMP_PROVIDER,
            "FIPS CAST initialization failed");
    }

    return ok;
}
#endif /* HAVE_FIPS */
#endif /* !WP_SINGLE_THREADED */

#ifdef HAVE_FIPS
/**
 * Extract the AlgorithmIdentifier OID NID from a SubjectPublicKeyInfo DER.
 *
 * Not d2i_X509_PUBKEY: its custom d2i hook drives OSSL_DECODER, which re-enters
 * this provider's decoders and recurses. ASN1_get_object + d2i_X509_ALGOR are
 * plain templates and re-entry-safe.
 *
 * @param [in] der  DER bytes.
 * @param [in] len  Length of der.
 * @return  Algorithm NID, or NID_undef if not a fully-consumed SPKI.
 */
static int wp_spki_alg_nid(const unsigned char* der, word32 len)
{
    int nid = NID_undef;
    const unsigned char* p = der;
    long plen;
    int tag, xclass, hdr;

    ERR_set_mark();
    hdr = ASN1_get_object(&p, &plen, &tag, &xclass, (long)len);
    if (!(hdr & 0x80) && (tag == V_ASN1_SEQUENCE) &&
            (xclass == V_ASN1_UNIVERSAL) &&
            ((word32)(p - der) + (word32)plen == len)) {
        const unsigned char* seqEnd = p + plen;
        X509_ALGOR* alg = d2i_X509_ALGOR(NULL, &p, plen);
        if (alg != NULL) {
            const unsigned char* bsp = p;
            long bslen;
            int bstag, bsclass, bshdr;

            /* Require the trailing BIT STRING so a foreign SEQUENCE is not
             * mistaken for an SPKI. */
            bshdr = ASN1_get_object(&bsp, &bslen, &bstag, &bsclass,
                (long)(seqEnd - p));
            if ((alg->algorithm != NULL) && !(bshdr & 0x80) &&
                    (bstag == V_ASN1_BIT_STRING) &&
                    (bsclass == V_ASN1_UNIVERSAL) &&
                    (bsp + bslen == seqEnd)) {
                nid = OBJ_obj2nid(alg->algorithm);
            }
            X509_ALGOR_free(alg);
        }
    }
    ERR_pop_to_mark();

    return nid;
}

/**
 * Extract the AlgorithmIdentifier OID NID from a PKCS#8 PrivateKeyInfo DER.
 *
 * @param [in] der  DER bytes.
 * @param [in] len  Length of der.
 * @return  Algorithm NID, or NID_undef if not a fully-consumed PKCS#8.
 */
static int wp_pki_alg_nid(const unsigned char* der, word32 len)
{
    int nid = NID_undef;
    const unsigned char* p = der;
    PKCS8_PRIV_KEY_INFO* p8;

    ERR_set_mark();
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)len);
    if (p8 != NULL) {
        if (p == der + len) {
            const ASN1_OBJECT* alg = NULL;
            if ((PKCS8_pkey_get0(&alg, NULL, NULL, NULL, p8) == 1) &&
                    (alg != NULL)) {
                nid = OBJ_obj2nid(alg);
            }
        }
        PKCS8_PRIV_KEY_INFO_free(p8);
    }
    ERR_pop_to_mark();

    return nid;
}

/* Key-algorithm OIDs (the SPKI/PKCS#8 AlgorithmIdentifier) for every key type
 * wolfProvider registers a decoder for -- keep in sync with wp_wolfprov.c. Lets
 * the precheck positively identify a foreign-but-known key and skip it before
 * instantiation, whose gated free fires the lazy CAST. Signature OIDs (e.g.
 * sha256WithRSAEncryption) never appear in a key wrapper, so they are absent by
 * design. An OID not listed can't be proven foreign. */
static const int wp_known_key_nids[] = {
    NID_rsaEncryption,
    NID_rsassaPss,
    NID_X9_62_id_ecPublicKey,
    NID_dhKeyAgreement,
    NID_dhpublicnumber,
    NID_X25519,
    NID_X448,
    NID_ED25519,
    NID_ED448
};

/**
 * Decide whether a decoder should skip key-object instantiation.
 *
 * See declaration in internal.h for the full contract.
 */
int wp_decode_should_skip(int castType, const unsigned char* der, word32 len,
    const int* allowedNids, size_t nAllowed)
{
    int nid;
    size_t i;

    if (wc_GetCastStatus_fips(castType) == FIPS_CAST_STATE_SUCCESS) {
        return 0;
    }

    /* Pull the AlgorithmIdentifier OID with both readers regardless of the
     * format label: a type-specific or mislabeled input is usually an
     * OID-bearing PKCS#8/SPKI. */
    nid = wp_pki_alg_nid(der, len);
    if (nid == NID_undef) {
        nid = wp_spki_alg_nid(der, len);
    }

    /* No OID (raw/unwrapped material) -> can't prove foreign, proceed. */
    if (nid == NID_undef) {
        return 0;
    }
    /* Owned by this decoder -> proceed. */
    for (i = 0; i < nAllowed; i++) {
        if (nid == allowedNids[i]) {
            return 0;
        }
    }
    /* Positively a different known key type -> skip. */
    for (i = 0; i < sizeof(wp_known_key_nids) / sizeof(*wp_known_key_nids); i++) {
        if (nid == wp_known_key_nids[i]) {
            return 1;
        }
    }

    /* Recognized OID but not one of ours -> can't prove foreign, proceed. */
    return 0;
}
#endif /* HAVE_FIPS */

/**
 * Get the wolfSSL random number generator from the provider context.
 *
 * @param [in] provCtx  Provider context.
 * @return  wolfSSL random number generator object.
 */
WC_RNG *wp_provctx_get_rng(WOLFPROV_CTX* provCtx)
{
    return &provCtx->rng;
}

#ifndef WP_SINGLE_THREADED
/**
 * Lock the random number generator in the provider context.
 *
 * @param [in, out] provCtx  Provider context.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_provctx_lock_rng(WOLFPROV_CTX* provCtx)
{
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_provctx_lock_rng");

    rc = wc_LockMutex(&provCtx->rng_mutex);
    if (rc != 0) {
        WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_LockMutex", rc);
        ok = 0;
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Unlock the random number generator in the provider context.
 *
 * @param [in, out] provCtx  Provider context.
 */
void wp_provctx_unlock_rng(WOLFPROV_CTX* provCtx)
{
    wc_UnLockMutex(&provCtx->rng_mutex);
}
#endif

/**
 * Lock the mutex.
 *
 * This function locks the mutex and translates the return value.
 * Use wp_unlock() to unlock after operations are complete.
 *
 * @param [in] mutex  Mutex object.
 * @return  1 on success.
 * @return  0 on failure or when single-threaded build.
 */
int wp_lock(wolfSSL_Mutex *mutex)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_KE, "wp_lock");

    if (mutex == NULL) {
        ok = 0;
    }
    else {
        rc = wc_LockMutex(mutex);
        if (rc < 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_LockMutex", rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    (void)mutex;
    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}

/**
 * Unlock the mutex.
 *
 * This function unlocks the mutex and translates the return value.
 * Should only be called after a successful wp_lock() call.
 *
 * @param [in] mutex  Mutex object.
 * @return  1 on success.
 * @return  0 on failure or when single-threaded build.
 */
int wp_unlock(wolfSSL_Mutex* mutex)
{
#ifndef WP_SINGLE_THREADED
    int ok = 1;
    int rc;

    WOLFPROV_ENTER(WP_LOG_COMP_KE, "wp_unlock");

    if (mutex == NULL) {
        ok = 0;
    }
    else {
        rc = wc_UnLockMutex(mutex);
        if (rc < 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_UnLockMutex", rc);
            ok = 0;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
#else
    (void)mutex;
    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
#endif
}


/**
 * Duplicate a configured octet buffer.
 *
 * OPENSSL_memdup() returns NULL for a zero length, so a 1-byte buffer is
 * allocated for the empty case. This preserves the non-NULL, zero-length
 * state that consumers may distinguish from a NULL (absent) buffer.
 *
 * @param [in] data  Buffer to duplicate. May be NULL.
 * @param [in] len   Length of buffer in bytes.
 * @return  Allocated copy on success.
 * @return  NULL when data is NULL, or on allocation failure.
 */
unsigned char* wp_octet_dup(const unsigned char* data, size_t len)
{
    unsigned char* ret;

    if (data == NULL) {
        ret = NULL;
    }
    else if (len == 0) {
        ret = OPENSSL_zalloc(1);
    }
    else {
        ret = OPENSSL_memdup(data, len);
    }
    return ret;
}

/**
 * Convert the string name of an object to an OpenSSL Numeric ID (NID).
 *
 * @param [in] libCtx  Library context to lookup string.
 * @param [in] name    String name of an object.
 * @param [in] propQ   Property query of object to lookup.
 * @return  NID_undef on failure.
 * @return  Numeric identifier on success.
 */
int wp_name_to_nid(OSSL_LIB_CTX* libCtx, const char* name, const char* propQ)
{
    int nid = NID_undef;

    EVP_MD* md = EVP_MD_fetch(libCtx, name, propQ);
    if (md) {
        nid = EVP_MD_type(md);
        EVP_MD_free(md);
    }
    return nid;
}

/**
 * Convert string name of a hash to a wolfCrypt hash type.
 *
 * @param [in] libCtx  Library context to lookup string.
 * @param [in] name    String name of an object.
 * @param [in] propQ   Property query of object to lookup.
 * @return  WC_HASH_TYPE_NONE on failure.
 * @return  wolfCrypt hash type on success.
 */
enum wc_HashType wp_name_to_wc_hash_type(OSSL_LIB_CTX* libCtx, const char* name,
    const char* propQ)
{
    enum wc_HashType ret = WC_HASH_TYPE_NONE;

    EVP_MD* md = EVP_MD_fetch(libCtx, name, propQ);
    if (md != NULL) {
        ret = wp_nid_to_wc_hash_type(EVP_MD_type(md));
        EVP_MD_free(md);
    }

    return ret;
}

/**
 * Convert an OpenSSL hash NID to a wolfCrypt hash OID.
 *
 * @param  nid  [in]  OpenSSL NID to convert.
 * @return  Hash type corresponding to the NID or WC_HASH_TYPE_NONE
 *          when not supported.
 */
enum wc_HashType wp_nid_to_wc_hash_type(int nid)
{
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;

    switch (nid) {
        case NID_md5:
            hashType = WC_HASH_TYPE_MD5;
            break;
        case NID_md5_sha1:
            hashType = WC_HASH_TYPE_MD5_SHA;
            break;
        case NID_sha1:
            hashType = WC_HASH_TYPE_SHA;
            break;
        case NID_sha224:
            hashType = WC_HASH_TYPE_SHA224;
            break;
        case NID_sha256:
            hashType = WC_HASH_TYPE_SHA256;
            break;
        case NID_sha384:
            hashType = WC_HASH_TYPE_SHA384;
            break;
        case NID_sha512:
            hashType = WC_HASH_TYPE_SHA512;
            break;
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    #ifndef WOLFSSL_NOSHA512_224
        case NID_sha512_224:
            hashType = WC_HASH_TYPE_SHA512_224;
            break;
    #endif
    #ifndef WOLFSSL_NOSHA512_256
        case NID_sha512_256:
            hashType = WC_HASH_TYPE_SHA512_256;
            break;
    #endif
#endif
        case NID_sha3_224:
            hashType = WC_HASH_TYPE_SHA3_224;
            break;
        case NID_sha3_256:
            hashType = WC_HASH_TYPE_SHA3_256;
            break;
        case NID_sha3_384:
            hashType = WC_HASH_TYPE_SHA3_384;
            break;
        case NID_sha3_512:
            hashType = WC_HASH_TYPE_SHA3_512;
            break;
        default:
            break;
    }

    return hashType;
}

#ifdef WP_HAVE_RSA
/**
 * Convert string name of a hash to a wolfCrypt MGF identifier.
 *
 * @param [in] libCtx  Library context to lookup string.
 * @param [in] name    String name of an object.
 * @param [in] propQ   Property query of object to lookup.
 * @return  WC_MGF1NONE on failure.
 * @return  wolfCrypt MGF identifier on success.
 */
int wp_name_to_wc_mgf(OSSL_LIB_CTX* libCtx, const char* name,
    const char* propQ)
{
    int ret = WC_MGF1NONE;

    EVP_MD* md = EVP_MD_fetch(libCtx, name, propQ);
    if (md) {
        ret = wp_mgf1_from_hash(EVP_MD_type(md));
        EVP_MD_free(md);
    }

    return ret;
}

/**
 * Convert OpenSSL hash algorithm id to a MGF1 with digest algorithm id.
 *
 * @param [in] nid  OpenSSL numeric id.
 * @return  WC_MGF1NONE when nid not supported.
 * @return  MGF1 with digest algorithm id.
 */
int wp_mgf1_from_hash(int nid)
{
    int mgf;

    switch (nid) {
        case NID_sha1:
            mgf = WC_MGF1SHA1;
            break;
        case NID_sha224:
            mgf = WC_MGF1SHA224;
            break;
        case NID_sha256:
            mgf = WC_MGF1SHA256;
            break;
        case NID_sha384:
            mgf = WC_MGF1SHA384;
            break;
        case NID_sha512:
            mgf = WC_MGF1SHA512;
            break;
        default:
            mgf = WC_MGF1NONE;
            break;
    }

    return mgf;
}
#endif

/**
 * Copies the underlying hash algorithm object.
 *
 * @param [in]  src       Hash object to copy.
 * @param [out] dst       Hash object to copy into.
 * @param [in]  hashType  Type of hash algorithm.
 * @return  1 on success.
 * @return  0 on failure.
 */
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
int wp_hash_copy(wc_HashAlg* src, wc_HashAlg* dst)
#else
int wp_hash_copy(wc_HashAlg* src, wc_HashAlg* dst, enum wc_HashType hashType)
#endif
{
    int ok = 1;
    int rc = 0;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_hash_copy");

#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
    switch ((int)src->type)
#else
    switch ((int)hashType)
#endif
    {
    case WC_HASH_TYPE_MD5:
#ifdef WP_HAVE_MD5
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Md5Copy(&src->alg.md5, &dst->alg.md5);
#else
        rc = wc_Md5Copy(&src->md5, &dst->md5);
#endif
#else
        ok = 0;
#endif
        break;
    case WC_HASH_TYPE_SHA:
#ifdef WP_HAVE_SHA1
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_ShaCopy(&src->alg.sha, &dst->alg.sha);
#else
        rc = wc_ShaCopy(&src->sha, &dst->sha);
#endif
#else
        ok = 0;
#endif
        break;
    case WC_HASH_TYPE_SHA224:
#ifdef WP_HAVE_SHA224
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha224Copy(&src->alg.sha224, &dst->alg.sha224);
#else
        rc = wc_Sha224Copy(&src->sha224, &dst->sha224);
#endif
#else
        ok = 0;
#endif
        break;
    case WC_HASH_TYPE_SHA256:
#ifdef WP_HAVE_SHA256
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha256Copy(&src->alg.sha256, &dst->alg.sha256);
#else
        rc = wc_Sha256Copy(&src->sha256, &dst->sha256);
#endif
#else
        ok = 0;
#endif
        break;
    case WC_HASH_TYPE_SHA384:
#ifdef WP_HAVE_SHA384
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha384Copy(&src->alg.sha384, &dst->alg.sha384);
#else
        rc = wc_Sha384Copy(&src->sha384, &dst->sha384);
#endif
#else
        ok = 0;
#endif
        break;
#ifdef WP_HAVE_SHA512
    case WC_HASH_TYPE_SHA512:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha512Copy(&src->alg.sha512, &dst->alg.sha512);
#else
        rc = wc_Sha512Copy(&src->sha512, &dst->sha512);
#endif
        break;
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
#if !defined(WOLFSSL_NOSHA512_224) && !defined(HAVE_FIPS) && \
        !defined(SELF_TEST)
    case WC_HASH_TYPE_SHA512_224:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha512_224Copy(&src->alg.sha512, &dst->alg.sha512);
#else
        rc = wc_Sha512_224Copy(&src->sha512, &dst->sha512);
#endif
        break;
#endif /* !WOLFSSL_NOSHA512_224 */
#if !defined(WOLFSSL_NOSHA512_256) && !defined(HAVE_FIPS) && \
        !defined(SELF_TEST)
    case WC_HASH_TYPE_SHA512_256:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha512_256Copy(&src->alg.sha512, &dst->alg.sha512);
#else
        rc = wc_Sha512_256Copy(&src->sha512, &dst->sha512);
#endif
        break;
#endif /* !WOLFSSL_NOSHA512_256 */
#endif /* LIBWOLFSSL_VERSION_HEX >= 0x05000000 */
#else
    case WC_HASH_TYPE_SHA512:
    case WC_HASH_TYPE_SHA512_224:
    case WC_HASH_TYPE_SHA512_256:
        ok = 0;
        break;
#endif /* WP_HAVE_SHA512 */
#ifdef WP_HAVE_SHA3
    case WC_HASH_TYPE_SHA3_224:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha3_224_Copy(&src->alg.sha3, &dst->alg.sha3);
#else
        rc = wc_Sha3_224_Copy(&src->sha3, &dst->sha3);
#endif
        break;
    case WC_HASH_TYPE_SHA3_256:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha3_256_Copy(&src->alg.sha3, &dst->alg.sha3);
#else
        rc = wc_Sha3_256_Copy(&src->sha3, &dst->sha3);
#endif
        break;
    case WC_HASH_TYPE_SHA3_384:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha3_384_Copy(&src->alg.sha3, &dst->alg.sha3);
#else
        rc = wc_Sha3_384_Copy(&src->sha3, &dst->sha3);
#endif
        break;
    case WC_HASH_TYPE_SHA3_512:
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
        rc = wc_Sha3_512_Copy(&src->alg.sha3, &dst->alg.sha3);
#else
        rc = wc_Sha3_512_Copy(&src->sha3, &dst->sha3);
#endif
        break;
#else
    case WC_HASH_TYPE_SHA3_224:
    case WC_HASH_TYPE_SHA3_256:
    case WC_HASH_TYPE_SHA3_384:
    case WC_HASH_TYPE_SHA3_512:
        ok = 0;
        break;
#endif
    case WC_HASH_TYPE_NONE:
    case WC_HASH_TYPE_MD2:
    case WC_HASH_TYPE_MD4:
    case WC_HASH_TYPE_MD5_SHA:
    case WC_HASH_TYPE_BLAKE2B:
    case WC_HASH_TYPE_BLAKE2S:
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
#ifdef WOLFSSL_SHAKE128
    case WC_HASH_TYPE_SHAKE128:
#endif
#ifdef WOLFSSL_SHAKE256
    case WC_HASH_TYPE_SHAKE256:
#endif
#endif
    default:
        ok = 0;
        break;
    }
    if (rc != 0) {
        WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wp_hash_copy", rc);
        ok = 0;
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
    } else {
        dst->type = src->type;
#endif
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/** Mapping of supported ciphers to key size. */
typedef struct wp_cipher {
    /** Name of cipher. */
    const char* name;
    /** wolfSSL cipher id. */
    int id;
    /** Canonical name of cipher. */
    const char* canonName;
} wp_cipher;

#ifndef AES128CBCb
    #define AES128CBCb  414
#endif
#ifndef AES192CBCb
    #define AES192CBCb  434
#endif
#ifndef AES256CBCb
    #define AES256CBCb  454
#endif

/** wolfSSL compatible cipher names and wolfSSL identifiers. */
static const wp_cipher wp_cipher_names[] = {
    { "AES-128-CBC", AES128CBCb, "AES-128-CBC" },
    { "AES-192-CBC", AES192CBCb, "AES-192-CBC" },
    { "AES-256-CBC", AES256CBCb, "AES-256-CBC" },
    { "aes-128-cbc", AES128CBCb, "AES-128-CBC" },
    { "aes-192-cbc", AES192CBCb, "AES-192-CBC" },
    { "aes-256-cbc", AES256CBCb, "AES-256-CBC" },
};

/** Number of cipher names in table.  */
#define WP_CIPHER_NAMES_LEN    \
    (sizeof(wp_cipher_names) / sizeof(*wp_cipher_names))

/**
 * Get the cipher based on the parameters in the array.
 *
 * A parameter with the name of the cipher may not be in the array.
 *
 * @param [in]  params      Array of parameters and values.
 * @param [out] cipher      wolfSSL cipher identifier.
 * @param [out] cipherName  Canonical name of cipher. May be NULL.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_cipher_from_params(const OSSL_PARAM params[], int* cipher,
    const char** cipherName)
{
    int ok = 1;
    const OSSL_PARAM* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_cipher_from_params");

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ok = 0;
        }
        if (ok) {
            size_t i;

            for (i = 0; i < WP_CIPHER_NAMES_LEN; i++) {
                if ((XSTRLEN(wp_cipher_names[i].name) == p->data_size) &&
                        (XSTRNCMP(p->data, wp_cipher_names[i].name,
                        p->data_size) == 0)) {
                    *cipher = wp_cipher_names[i].id;
                    if (cipherName != NULL) {
                        *cipherName = wp_cipher_names[i].canonName;
                    }
                    break;
                }
            }
            if (i == WP_CIPHER_NAMES_LEN) {
                ok = 0;
            }
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/* Salt length used for PBES2 EncryptedPrivateKeyInfo encoding. The same value
 * is used for the size query and the encrypt call so the reported and actual
 * output sizes agree. */
#define WP_EPKI_SALT_LEN    16

/* Maximum passphrase length read from the password callback. */
#define WP_EPKI_PASSWORD_MAX    1024

/**
 * Get the size of the PBES2 EncryptedPrivateKeyInfo encoding of a PKCS #8 key.
 *
 * The encrypted structure is larger than the plaintext (it carries the PBES2
 * AlgorithmIdentifier), and the exact size depends on the cipher, so the size
 * is obtained from wolfSSL rather than computed.
 *
 * @param [in]  provCtx   Provider context (supplies the RNG).
 * @param [in]  cipher    wolfCrypt cipher identifier to encrypt with.
 * @param [in]  plainLen  Length of the plaintext PKCS #8 key in bytes.
 * @param [out] outLen    Length of the encrypted encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_encrypt_key_pkcs8_size(WOLFPROV_CTX* provCtx, int cipher,
    word32 plainLen, size_t* outLen)
{
#if defined(HAVE_PKCS8) && !defined(NO_PWDBASED)
    int ok = 1;
    int rc = 0;
    word32 outSz = 0;
    byte fakeData[1] = { 0 };
    byte fakeSalt[WP_EPKI_SALT_LEN] = { 0 };

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_encrypt_key_pkcs8_size");

    /* A cipher must be selected to produce an encrypted key. */
    if (cipher == 0) {
        ok = 0;
    }
    if (ok) {
        /* Passing a NULL output buffer returns the required length. The _ex
         * form (wolfSSL 5.8.2+) selects the HMAC-SHA256 PBKDF2 PRF; older
         * wolfSSL uses the SHA-1 PRF. */
    #if LIBWOLFSSL_VERSION_HEX >= 0x05008002
        rc = wc_EncryptPKCS8Key_ex(fakeData, plainLen, NULL, &outSz, "", 0,
            WP_PKCS5, WP_PBES2, cipher, fakeSalt, sizeof(fakeSalt),
            WP_PKCS12_ITERATIONS_DEFAULT, HMAC_SHA256_OID,
            wp_provctx_get_rng(provCtx), NULL);
    #else
        rc = wc_EncryptPKCS8Key(fakeData, plainLen, NULL, &outSz, "", 0,
            WP_PKCS5, WP_PBES2, cipher, fakeSalt, sizeof(fakeSalt),
            WP_PKCS12_ITERATIONS_DEFAULT, wp_provctx_get_rng(provCtx), NULL);
    #endif
        if (rc != LENGTH_ONLY_E) {
            ok = 0;
        }
        else {
            *outLen = (size_t)outSz;
        }
    }

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
#else
    (void)provCtx;
    (void)cipher;
    (void)plainLen;
    (void)outLen;
    return 0;
#endif
}

/**
 * Encrypt a plaintext PKCS #8 key into a PBES2 EncryptedPrivateKeyInfo.
 *
 * Derives the key with PBKDF2 and encrypts with the requested cipher, producing
 * a standards-compliant EncryptedPrivateKeyInfo structure. The plaintext and
 * output buffers must be different (wolfSSL requirement).
 *
 * @param [in]      provCtx   Provider context (supplies the RNG).
 * @param [in]      cipher    wolfCrypt cipher identifier to encrypt with.
 * @param [in]      plain     Plaintext PKCS #8 key.
 * @param [in]      plainLen  Length of the plaintext key in bytes.
 * @param [out]     out       Buffer to hold the encrypted encoding.
 * @param [in, out] outLen    On in, size of buffer; on out, length written.
 * @param [in]      pwCb      Password callback.
 * @param [in]      pwCbArg   Argument to pass to the password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_encrypt_key_pkcs8(WOLFPROV_CTX* provCtx, int cipher,
    const unsigned char* plain, word32 plainLen,
    unsigned char* out, size_t* outLen,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
#if defined(HAVE_PKCS8) && !defined(NO_PWDBASED)
    int ok = 1;
    int rc = 0;
    word32 outSz = (word32)*outLen;
    byte salt[WP_EPKI_SALT_LEN];
#ifdef WOLFSSL_SMALL_STACK
    char* password = NULL;
#else
    char password[WP_EPKI_PASSWORD_MAX];
#endif
    size_t passwordSz = WP_EPKI_PASSWORD_MAX;
    WC_RNG* rng = wp_provctx_get_rng(provCtx);

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_encrypt_key_pkcs8");

#ifdef WOLFSSL_SMALL_STACK
    password = (char*)XMALLOC(WP_EPKI_PASSWORD_MAX, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (password == NULL) {
        ok = 0;
    }
#endif

    /* A cipher must be selected and the in/out buffers must differ. */
    if (ok && ((cipher == 0) || (plain == NULL) || (out == NULL) ||
            (plain == out))) {
        ok = 0;
    }
    /* Get the password from the callback. */
    if (ok && (!pwCb(password, passwordSz, &passwordSz, NULL, pwCbArg))) {
        ok = 0;
    }
    /* Callback reports the length written - reject one past the buffer. */
    if (ok && (passwordSz > WP_EPKI_PASSWORD_MAX)) {
        ok = 0;
    }
    if (ok) {
    #ifndef WP_SINGLE_THREADED
        wp_provctx_lock_rng(provCtx);
    #endif
        /* Generate the PBKDF2 salt. */
        rc = wc_RNG_GenerateBlock(rng, salt, sizeof(salt));
        if (rc == 0) {
            /* Encrypt into the separate output buffer as PBES2. The _ex form
             * (wolfSSL 5.8.2+) selects the HMAC-SHA256 PBKDF2 PRF; older
             * wolfSSL uses the SHA-1 PRF. */
        #if LIBWOLFSSL_VERSION_HEX >= 0x05008002
            rc = wc_EncryptPKCS8Key_ex((byte*)plain, plainLen, out, &outSz,
                password, (int)passwordSz, WP_PKCS5, WP_PBES2, cipher,
                salt, sizeof(salt), WP_PKCS12_ITERATIONS_DEFAULT,
                HMAC_SHA256_OID, rng, NULL);
        #else
            rc = wc_EncryptPKCS8Key((byte*)plain, plainLen, out, &outSz,
                password, (int)passwordSz, WP_PKCS5, WP_PBES2, cipher,
                salt, sizeof(salt), WP_PKCS12_ITERATIONS_DEFAULT, rng, NULL);
        #endif
        }
    #ifndef WP_SINGLE_THREADED
        wp_provctx_unlock_rng(provCtx);
    #endif
        if (rc <= 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_EncryptPKCS8Key",
                rc);
            ok = 0;
        }
        else {
            *outLen = (size_t)outSz;
        }
    }

    /* Password is sensitive - force zeroization. */
#ifdef WOLFSSL_SMALL_STACK
    if (password != NULL) {
        OPENSSL_cleanse(password, WP_EPKI_PASSWORD_MAX);
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    OPENSSL_cleanse(password, sizeof(password));
#endif

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
#else
    (void)provCtx;
    (void)cipher;
    (void)plain;
    (void)plainLen;
    (void)out;
    (void)outLen;
    (void)pwCb;
    (void)pwCbArg;
    return 0;
#endif
}

#if defined(HAVE_PKCS8) && !defined(NO_PWDBASED)
/* DER encoding of the PBKDF2 OID (1.2.840.113549.1.5.12). */
static const unsigned char wp_pbkdf2_oid[] = {
    42, 134, 72, 134, 247, 13, 1, 5, 12
};

/*
 * Detect whether a DER blob is a PBES2-encrypted PKCS#8 key by looking for the
 * PBKDF2 OID near the start of the encryptionAlgorithm field. Avoids prompting
 * for a passphrase on data that is not an encrypted key.
 */
static int wp_is_pbkdf2_encrypted(const unsigned char* data, word32 len)
{
    int found = 0;
    word32 i;

    for (i = 0; (i < 40) && (i + sizeof(wp_pbkdf2_oid) <= len); i++) {
        if (XMEMCMP(data + i, wp_pbkdf2_oid, sizeof(wp_pbkdf2_oid)) == 0) {
            found = 1;
            break;
        }
    }

    return found;
}
#endif

/**
 * Decrypt a PBES2 EncryptedPrivateKeyInfo to plaintext PKCS#8 in place, getting
 * the passphrase from the callback. Returns 0 without prompting when the data
 * is not a PBES2-encrypted key.
 *
 * @param [in, out] data     On in, encrypted key; on out, plaintext PKCS#8.
 * @param [in, out] len      On in, encrypted length; on out, plaintext length.
 * @param [in]      pwCb     Password callback.
 * @param [in]      pwCbArg  Argument to pass to the password callback.
 * @return  1 on success.
 * @return  0 on failure or when the data is not an encrypted PKCS#8 key.
 */
int wp_decrypt_key_pkcs8(unsigned char* data, word32* len,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
#if defined(HAVE_PKCS8) && !defined(NO_PWDBASED)
    int ok = 1;
    int rc;
#ifdef WOLFSSL_SMALL_STACK
    char* password = NULL;
#else
    char password[WP_EPKI_PASSWORD_MAX];
#endif
    size_t passwordSz = WP_EPKI_PASSWORD_MAX;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_decrypt_key_pkcs8");

    /* Only handle data that looks like a PBES2-encrypted PKCS#8 key. */
    if ((data == NULL) || (!wp_is_pbkdf2_encrypted(data, *len))) {
        ok = 0;
    }
#ifdef WOLFSSL_SMALL_STACK
    if (ok) {
        password = (char*)XMALLOC(WP_EPKI_PASSWORD_MAX, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (password == NULL) {
            ok = 0;
        }
    }
#endif
    /* Get the password from the callback. */
    if (ok && (!pwCb(password, passwordSz, &passwordSz, NULL, pwCbArg))) {
        ok = 0;
    }
    /* Callback reports the length written - reject one past the buffer. */
    if (ok && (passwordSz > WP_EPKI_PASSWORD_MAX)) {
        ok = 0;
    }
    if (ok) {
        /* Decrypt the key in place. */
        rc = wc_DecryptPKCS8Key(data, *len, password, (int)passwordSz);
        if (rc <= 0) {
            WOLFPROV_MSG_DEBUG_RETCODE(WP_LOG_LEVEL_DEBUG, "wc_DecryptPKCS8Key",
                rc);
            ok = 0;
        }
        else {
            *len = (word32)rc;
        }
    }

    /* Password is sensitive - force zeroization. */
#ifdef WOLFSSL_SMALL_STACK
    if (password != NULL) {
        OPENSSL_cleanse(password, WP_EPKI_PASSWORD_MAX);
        XFREE(password, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#else
    OPENSSL_cleanse(password, sizeof(password));
#endif

    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
#else
    (void)data;
    (void)len;
    (void)pwCb;
    (void)pwCbArg;
    return 0;
#endif
}

/**
 * Read data out of the core BIO.
 *
 * @param [in] coreBIO  Core BIO.
 * @param [out] data    New buffer holding data read.
 * @param [out] len     Length of data read.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_read_der_bio(WOLFPROV_CTX *provctx, OSSL_CORE_BIO *coreBio, unsigned char** data, word32* len)
{
    int ok = 1;
    long readLen = 1;
    unsigned char buf[128]; /* Read 128 bytes at a time. */
    unsigned char* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_read_der_bio");

    BIO *bio = wp_corebio_get_bio(provctx, coreBio);
    if (bio == NULL) {
        ok = 0;
    }

    while (ok && (readLen > 0)) {
        readLen = BIO_read(bio, buf, sizeof(buf));
        if (readLen < -1) {
            WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "BIO_read error (%d) in %s:%d", readLen, __FILE__, __LINE__);
            ok = 0;
        }
        if (ok && (readLen > 0) &&
                ((uint64_t)*len + (uint64_t)readLen > (uint64_t)UINT32_MAX)) {
            ok = 0;
        }
        if (ok && (readLen > 0)) {
            /* Reallocate for new data. */
            p = OPENSSL_realloc(*data, *len + readLen);
            if (p == NULL) {
                WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "OPENSSL_realloc error (%d) in %s:%d", readLen, __FILE__, __LINE__);
                ok = 0;
            }
        }
        if (ok && (readLen > 0)) {
            *data = p;
            /* Copy in new data. */
            XMEMCPY(*data + *len, buf, readLen);
            *len += readLen;
        }
    }

    /* buf may hold plaintext private key DER fragments. */
    OPENSSL_cleanse(buf, sizeof(buf));

    BIO_free(bio);
    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

/**
 * Read PEM data out of the core BIO.
 *
 * @param [in] coreBIO  Core BIO.
 * @param [out] data    New buffer holding data read.
 * @param [out] len     Length of data read.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_read_pem_bio(WOLFPROV_CTX *provctx, OSSL_CORE_BIO *coreBio,
    unsigned char** data, word32* len)
{
    int ok = 1;
    long readLen = 1;
    char buf[128];
    unsigned char* p;

    WOLFPROV_ENTER(WP_LOG_COMP_PROVIDER, "wp_read_pem_bio");

    BIO *bio = wp_corebio_get_bio(provctx, coreBio);
    if (bio == NULL) {
        ok = 0;
    }

    while (ok && (readLen > 0)) {
        /* Read a line at a time. */
        readLen = BIO_gets(bio, buf, sizeof(buf));
        if (readLen < -1) {
            WOLFPROV_MSG(WP_LOG_COMP_PROVIDER, "BIO_read error (%d) in %s:%d",
                readLen, __FILE__, __LINE__);
            ok = 0;
        }
        if (ok && (readLen > 0)) {
            /* Reallocate for new data. */
            p = OPENSSL_realloc(*data, *len + readLen);
            if (p == NULL) {
                WOLFPROV_MSG(WP_LOG_COMP_PROVIDER,
                    "OPENSSL_realloc error (%d) in %s:%d", readLen, __FILE__,
                    __LINE__);
                ok = 0;
            }
        }
        if (ok && (readLen > 0)) {
            *data = p;
            /* Copy in new data. */
            XMEMCPY(*data + *len, (unsigned char*)buf, readLen);
            *len += readLen;
        }
        /* Last line should have footer. */
        if (XMEMCMP(buf, "-----END ", 9) == 0) {
            break;
        }
    }

    /* buf may hold plaintext private key PEM line fragments. */
    OPENSSL_cleanse(buf, sizeof(buf));

    BIO_free(bio);
    WOLFPROV_LEAVE(WP_LOG_COMP_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__),
        ok);
    return ok;
}

/**
 * Get the underlying BIO object from the core BIO.
 *
 * @param [in]  coreBio  Core BIO.
 * @return  NULL on failure.
 * @return  Underlying BIO on success.
 */
BIO* wp_corebio_get_bio(WOLFPROV_CTX* provCtx, OSSL_CORE_BIO *coreBio)
{
    BIO *outBio;

    if ((provCtx == NULL) || (provCtx->coreBioMethod == NULL))
        return NULL;

    if ((outBio = BIO_new(provCtx->coreBioMethod)) == NULL)
        return NULL;
    if (!wolfssl_prov_bio_up_ref(coreBio)) {
        BIO_free(outBio);
        return NULL;
    }
    BIO_set_data(outBio, coreBio);
    return outBio;
}


/**
 * Constant time, set mask when first value is equal to second.
 *
 * @param [in] a  First value.
 * @param [in] b  Second value.
 * @return  All bits set when true.
 * @return  0 when false.
 */
byte wp_ct_byte_mask_eq(byte a, byte b)
{
    return (~(((int32_t)b - a) >> 31)) & (~(((int32_t)a - b) >> 31));
}

/**
 * Constant time, set mask when first value is not equal to second.
 *
 * @param [in] a  First value.
 * @param [in] b  Second value.
 * @return  All bits set when true.
 * @return  0 when false.
 */
byte wp_ct_byte_mask_ne(byte a, byte b)
{
    return ~wp_ct_byte_mask_eq(a, b);
}

/**
 * Constant time, set mask when first value is greater than or equal second.
 *
 * @param [in] a  First value.
 * @param [in] b  Second value.
 * @return  All bits set when true.
 * @return  0 when false.
 */
byte wp_ct_int_mask_gte(int a, int b)
{
    return ((((uint32_t)a - (uint32_t)b) >> 31) - 1);
}

/**
 * Constant time, set mask when first value is equal to second.
 *
 * @param [in] a  First value.
 * @param [in] b  Second value.
 * @return  All bits set when a == b.
 * @return  0 when a != b.
 */
byte wp_ct_int_mask_eq(int a, int b)
{
    /* Same as wolfSSL ctMaskEq: ~GT & ~LT */
    byte gt = (byte)((((uint32_t)a - (uint32_t)b - 1) >> 31) - 1);
    byte lt = (byte)((((uint32_t)b - (uint32_t)a - 1) >> 31) - 1);
    return (byte)((byte)(~gt) & (byte)(~lt));
}

/**
 * Constant time, set mask when first value is less than second.
 *
 * @param [in] a  First value.
 * @param [in] b  Second value.
 * @return  All bits set when a < b.
 * @return  0 when a >= b.
 */
byte wp_ct_int_mask_lt(int a, int b)
{
    /* Same as wolfSSL ctMaskLT */
    return (byte)((((uint32_t)b - (uint32_t)a - 1) >> 31) - 1);
}

/**
 * Constant time byte select: returns a when mask is 0xff, b when mask is 0x00.
 *
 * @param [in] mask  Selection mask (0xff or 0x00).
 * @param [in] a     Value returned when mask is all-ones.
 * @param [in] b     Value returned when mask is all-zeros.
 * @return  Selected byte value.
 */
byte wp_ct_byte_mask_sel(byte mask, byte a, byte b)
{
    return (byte)((mask & a) | (~mask & b));
}

/* Big-endian word32 <-> byte[4] conversions shared across KDF sources.
 * We are not guaranteed to have these available from wolfssl, so implement
 * them here. Consumed by SSHKDF (mpint length decode) and KBKDF
 * (counter / length encode). */

void wp_c32toa(word32 wc_u32, byte* c) {
#ifdef WOLFSSL_USE_ALIGN
    c[0] = (byte)((wc_u32 >> 24) & 0xff);
    c[1] = (byte)((wc_u32 >> 16) & 0xff);
    c[2] = (byte)((wc_u32 >>  8) & 0xff);
    c[3] = (byte) (wc_u32 &        0xff);
#elif defined(LITTLE_ENDIAN_ORDER)
    *(word32*)c = ByteReverseWord32(wc_u32);
#else
    *(word32*)c = wc_u32;
#endif
}

word32 wp_atoc32(const byte* c) {
#ifdef WOLFSSL_USE_ALIGN
    return ((word32)c[0] << 24) | ((word32)c[1] << 16)
         | ((word32)c[2] <<  8) |  (word32)c[3];
#elif defined(LITTLE_ENDIAN_ORDER)
    return ByteReverseWord32(*(const word32*)c);
#else
    return *(const word32*)c;
#endif
}

