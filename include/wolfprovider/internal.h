/* internal.h
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

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <openssl/bio.h>

#ifdef WOLFENGINE_USER_SETTINGS
    #include "user_settings.h"
#endif
#include <wolfssl/options.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "wp_params.h"

#ifndef AES_BLOCK_SIZE
    #include <openssl/aes.h>
    #ifndef AES_BLOCK_SIZE
        #ifdef WC_NO_COMPAT_AES_BLOCK_SIZE
            #define AES_BLOCK_SIZE WC_AES_BLOCK_SIZE
        #else
            #error AES_BLOCK_SIZE not defined when it should be
        #endif
    #endif
#endif

#ifndef WP_INTERNAL_H
#define WP_INTERNAL_H

/** Maximum value of a size_t. */
#define MAX_SIZE_T    ((size_t)-1)

/** Maximum supported digest name size. */
#define WP_MAX_MD_NAME_SIZE     15
/** Maximum supported cipher name size. */
#define WP_MAX_CIPH_NAME_SIZE   15
/** Maximum supported cipher name size. */
#define WP_MAX_MAC_NAME_SIZE    6

/** Maximum supported digest name size. */
#define WP_MAX_PROPS_SIZE       80

/* DER key encoding/decoding formats. */
/** SubjectPublicKeyInfo encoding format. */
#define WP_ENC_FORMAT_SPKI              1
/** PrivateKeyInfo encoding format. */
#define WP_ENC_FORMAT_PKI               2
/** EncryptedPrivateKeyInfo encoding format. */
#define WP_ENC_FORMAT_EPKI              3
/** Type-specific encoding format. */
#define WP_ENC_FORMAT_TYPE_SPECIFIC     4
/** X9_62 encoding format. */
#define WP_ENC_FORMAT_X9_62             5
/** Text encoding format. */
#define WP_ENC_FORMAT_TEXT              6

/* Data format. */
/** DER - Binary encoding. */
#define WP_FORMAT_DER           0
/** PEM - Text encoding. */
#define WP_FORMAT_PEM           1
/** Human readable text encoding. */
#define WP_FORMAT_TEXT          2

/* MAC key types. */
/** HMAC key type. */
#define WP_MAC_TYPE_HMAC    1
/** CMAC key type. */
#define WP_MAC_TYPE_CMAC    2

/** PKCS5 encoding */
#define WP_PKCS5            5
/** PBES2 encoding */
#define WP_PBES2            13
/** Default iterations for PKCS#12 PBKDF2. */
#define WP_PKCS12_ITERATIONS_DEFAULT    2048

/** Maximum salt length for PKCS. */
#define WP_MAX_SALT_SIZE    64

/** Default salt length for PSS. */
#define WP_RSA_DEFAULT_SALT_LEN     20

/* These values are taken from ssl.h.
 * Can't include this header as it redeclares OpenSSL types.
 */
/* Named Groups */
enum {
    WOLFSSL_NAMED_GROUP_INVALID = 0,
    WOLFSSL_ECC_SECP160K1 = 15,
    WOLFSSL_ECC_SECP160R1 = 16,
    WOLFSSL_ECC_SECP160R2 = 17,
    WOLFSSL_ECC_SECP192K1 = 18,
    WOLFSSL_ECC_SECP192R1 = 19,
    WOLFSSL_ECC_SECP224K1 = 20,
    WOLFSSL_ECC_SECP224R1 = 21,
    WOLFSSL_ECC_SECP256K1 = 22,
    WOLFSSL_ECC_SECP256R1 = 23,
    WOLFSSL_ECC_SECP384R1 = 24,
    WOLFSSL_ECC_SECP521R1 = 25,
    WOLFSSL_ECC_BRAINPOOLP256R1 = 26,
    WOLFSSL_ECC_BRAINPOOLP384R1 = 27,
    WOLFSSL_ECC_BRAINPOOLP512R1 = 28,
    WOLFSSL_ECC_X25519    = 29,
    WOLFSSL_ECC_X448      = 30,
    WOLFSSL_ECC_MAX       = 30,

    WOLFSSL_FFDHE_2048    = 256,
    WOLFSSL_FFDHE_3072    = 257,
    WOLFSSL_FFDHE_4096    = 258,
    WOLFSSL_FFDHE_6144    = 259,
    WOLFSSL_FFDHE_8192    = 260
};


/**
 * wolfSSL provider context.
 */
typedef struct WOLFPROV_CTX {
    /** Cached handle to a resource. */
    const OSSL_CORE_HANDLE *handle;
    /** Library context to use in all cases. */
    OSSL_LIB_CTX *libCtx;
   /** Random number generator. */
   WC_RNG rng;
#ifndef WP_SINGLE_THREADED
   /** Mutex for use of random number generator. */
   wolfSSL_Mutex rng_mutex;
#endif
   BIO_METHOD *coreBioMethod;
} WOLFPROV_CTX;


WC_RNG* wp_provctx_get_rng(WOLFPROV_CTX* provCtx);
#ifndef WP_SINGLE_THREADED
int wp_provctx_lock_rng(WOLFPROV_CTX* provCtx);
void wp_provctx_unlock_rng(WOLFPROV_CTX* provCtx);
#endif

int wolfssl_prov_get_capabilities(void *provctx, const char *capability,
    OSSL_CALLBACK *cb, void *arg);

int wp_name_to_nid(OSSL_LIB_CTX* libCtx, const char* name, const char* propQ);
enum wc_HashType wp_name_to_wc_hash_type(OSSL_LIB_CTX* libCtx, const char* name,
    const char* propQ);
enum wc_HashType wp_nid_to_wc_hash_type(int nid);
int wp_name_to_wc_mgf(OSSL_LIB_CTX* libCtx, const char* name,
    const char* propQ);
int wp_mgf1_from_hash(int nid);
#if LIBWOLFSSL_VERSION_HEX >= 0x05007004
int wp_hash_copy(wc_HashAlg* src, wc_HashAlg* dst);
#else
int wp_hash_copy(wc_HashAlg* src, wc_HashAlg* dst, enum wc_HashType hashType);
#endif

int wp_cipher_from_params(const OSSL_PARAM params[], int* cipher,
    const char** cipherName);

int wp_encrypt_key(WOLFPROV_CTX* provCtx, const char* cipherName,
    unsigned char* keyData, size_t* keyLen, word32 pkcs8Len,
    OSSL_PASSPHRASE_CALLBACK *pwCb, void *pwCbArg, byte** cipherInfo);

int wp_read_der_bio(WOLFPROV_CTX* provCtx, OSSL_CORE_BIO *coreBio, unsigned char** data, word32* len);
int wp_read_pem_bio(WOLFPROV_CTX *provctx, OSSL_CORE_BIO *coreBio,
    unsigned char** data, word32* len);
BIO* wp_corebio_get_bio(WOLFPROV_CTX* provCtx, OSSL_CORE_BIO *coreBio);

byte wp_ct_byte_mask_eq(byte a, byte b);
byte wp_ct_byte_mask_ne(byte a, byte b);
byte wp_ct_int_mask_gte(int a, int b);

#endif /* WP_INTERNAL_H */

