/* wp_internal.c
 *
 * Copyright (C) 2021 wolfSSL Inc.
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
 * along with wolfProvider.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <openssl/evp.h>

#include <wolfprovider/internal.h>

#include <wolfssl/wolfcrypt/rsa.h>

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

    rc = wc_LockMutex(&provCtx->rng_mutex);
    if (rc != 0) {
        ok = 0;
    }

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
    int nid;

    EVP_MD* md = EVP_MD_fetch(libCtx, name, propQ);
    nid = EVP_MD_type(md);
    EVP_MD_free(md);

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
        case NID_sha512_224:
            hashType = WC_HASH_TYPE_SHA512_224;
            break;
        case NID_sha512_256:
            hashType = WC_HASH_TYPE_SHA512_256;
            break;
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
    int ret;

    EVP_MD* md = EVP_MD_fetch(libCtx, name, propQ);
    ret = wp_mgf1_from_hash(EVP_MD_type(md));
    EVP_MD_free(md);

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

/** wolfSSL compatable cipher names and wolfSSL identifiers. */
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

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ok = 0;
        }
        if (ok) {
            size_t i;

            for (i = 0; i < WP_CIPHER_NAMES_LEN; i++) {
                if (XSTRNCMP(p->data, wp_cipher_names[i].name,
                        p->data_size) == 0) {
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

    return ok;
}

/**
 * Encrypt the PKCS #8 key.
 *
 * Calls password callback and generates a random IV.
 *
 * @param [in]      provCtx     Provider context.
 * @param [in]      cipherName  Name of cipher to encrypt with.
 * @param [in, out] keyData     On in, PKCS #8 encoded key.
 *                              On out, encrypted PKCS #8 encoded key.
 * @param [in, out] keyLen      On in, length of buffer in bytes.
 *                              On out, length of encrypted key in bytes.
 * @param [in]      pkcs8Len    Length of PKCS #8 key in bytes.
 * @param [in]      pwCb        Password callback.
 * @param [in]      pwCbArg     Argument to pass to password callback.
 * @param [out]     cipherInfo  Information about encryption.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_encrypt_key(WOLFPROV_CTX* provCtx, const char* cipherName,
    unsigned char* keyData, size_t* keyLen, word32 pkcs8Len,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg, byte** cipherInfo)
{
    int ok = 1;
    int rc;
    word32 len = *keyLen;
    EncryptedInfo info[1];
    word32 cipherInfoSz;
    char password[1024];
    size_t passwordSz = sizeof(password);

    /* Get password. */
    if (!pwCb(password, passwordSz, &passwordSz, NULL, pwCbArg)) {
        ok = 0;
    }
    if (ok) {
        XMEMSET(info, 0, sizeof(EncryptedInfo));
        XSTRNCPY(info->name, cipherName, NAME_SZ-1);
        info->name[NAME_SZ-1] = '\0';

        rc = wc_EncryptedInfoGet(info, info->name);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        /* Calculate random IV. */
        WC_RNG* rng = wp_provctx_get_rng(provCtx);

    #ifndef WP_SINGLE_THREADED
        wp_provctx_lock_rng(provCtx);
    #endif
        rc = wc_RNG_GenerateBlock(rng, info->iv, info->ivSz);
    #ifndef WP_SINGLE_THREADED
        wp_provctx_unlock_rng(provCtx);
    #endif
        if (rc < 0) {
            ok = 0;
        }
    }
    if (ok) {
        /* Pad with zeros. */
        XMEMSET(keyData + pkcs8Len, 0, len - pkcs8Len);

        /* Encrypt key and padding. */
        rc = wc_BufferKeyEncrypt(info, keyData, len, (byte*)password,
            passwordSz, WC_MD5);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok && (cipherInfo != NULL)) {
        /* cipher name | ',' | hex encoded IV */
        cipherInfoSz = (word32)(XSTRLEN(info->name) + 2 + info->ivSz * 2);
        *cipherInfo = (byte*)OPENSSL_malloc(cipherInfoSz);
        if (*cipherInfo == NULL) {
            ok = 0;
        }
    }
    if (ok && (cipherInfo != NULL)) {
        word32 idx = (word32)XSTRLEN(info->name);
        XSTRNCPY((char*)*cipherInfo, info->name, cipherInfoSz);
        cipherInfoSz -= idx;
        XSTRNCAT((char*)*cipherInfo, ",", cipherInfoSz);
        cipherInfoSz--;
        rc = Base16_Encode(info->iv, info->ivSz, *cipherInfo + idx,
            &cipherInfoSz);
        if (rc != 0) {
            ok = 0;
        }
    }
    if (ok) {
        *keyLen = len;
    }

    return ok;
}

/* TODO: Structure could change! */
/*
 * Copy of Core BIO structure as it isn't public and need to get the BIO out.
 */
struct ossl_core_bio_st {
    /* Reference count. */
    int ref_cnt;
    /* Read/write reference count lock. */
    CRYPTO_RWLOCK *ref_lock;
    /* Underlying BIO. */
    BIO *bio;
};

/**
 * Read data out of the core BIO.
 *
 * @param [in] coreBIO  Core BIO.
 * @param [out] data    New buffer holding data read.
 * @param [out] len     Length of data read.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wp_read_der_bio(OSSL_CORE_BIO *coreBio, unsigned char** data, word32* len)
{
    int ok = 1;
    long readLen;
    unsigned char buf[128]; /* Read 128 bytes at a time. */
    unsigned char* p;

    do {
        readLen = BIO_read(coreBio->bio, buf, sizeof(buf));
        if (readLen < -1) {
            ok = 0;
        }
        if (ok && (readLen > 0)) {
            /* Reallocate for new data. */
            p = OPENSSL_realloc(*data, *len + readLen);
            if (p == NULL) {
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
    while (ok && (readLen > 0));

    return ok;
}

/**
 * Get the underlying BIO from the core BIO.
 *
 * @param [in]  coreBio  Core BIO.
 * @return  NULL on failure.
 * @return  Underlying BIO on success.
 */
BIO* wp_corebio_get_bio(OSSL_CORE_BIO *coreBio)
{
    return coreBio->bio;
}


/**
 * Constant time, set mask when first value is equal to second.
 *
 * @param [in] a  First valuue.
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
 * @param [in] a  First valuue.
 * @param [in] b  Second value.
 * @return  All bits set when true.
 * @return  0 when false.
 */
byte wp_ct_byte_mask_ne(byte a, byte b)
{
    return (((int32_t)b - a) >> 31) & (((int32_t)a - b) >> 31);
}

/**
 * Constant time, set mask when first value is greater than or equal second.
 *
 * @param [in] a  First valuue.
 * @param [in] b  Second value.
 * @return  All bits set when true.
 * @return  0 when false.
 */
byte wp_ct_int_mask_gte(int a, int b)
{
    return ((((uint32_t)a - (uint32_t)b) >> 31) - 1);
}

