/* settings.h
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

#ifndef WOLFPROV_SETTINGS_H
#define WOLFPROV_SETTINGS_H

#include <wolfssl/options.h>
#ifdef WOLFPROV_USER_SETTINGS
    #include "user_settings.h"
#endif
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/settings.h>

/* wc_RNG_DRBG_Reseed is only reliably exported in non-FIPS >= 5.7.2 and FIPS
 * v6+. FIPS v5.x bundles are inconsistent (some keep it WOLFSSL_LOCAL), so use
 * the native reseed only where it's exported, else fall back to DRBG
 * re-instantiation. WP_NO_DRBG_RESEED forces the fallback. */
#if defined(WP_NO_DRBG_RESEED)
    /* caller forced the re-instantiation fallback */
#elif !defined(HAVE_FIPS)
    #if LIBWOLFSSL_VERSION_HEX >= 0x05007002
        #define WP_HAVE_DRBG_RESEED
    #endif
#elif defined(HAVE_FIPS_VERSION_MAJOR) && HAVE_FIPS_VERSION_MAJOR >= 6
    #define WP_HAVE_DRBG_RESEED
#endif

#define WP_HAVE_DIGEST
#if !defined(NO_MD5)
    #define WP_HAVE_MD5
    #if !defined(NO_SHA)
        #define WP_HAVE_MD5_SHA1
    #endif
#endif
#if !defined(NO_SHA)
    #define WP_HAVE_SHA1
#endif
#ifdef WOLFSSL_SHA224
    #define WP_HAVE_SHA224
#endif
#define WP_HAVE_SHA256
#ifdef WOLFSSL_SHA384
    #define WP_HAVE_SHA384
#endif
#ifdef WOLFSSL_SHA512
    #define WP_HAVE_SHA512
#endif
#if (LIBWOLFSSL_VERSION_HEX >= 0x05000000) && !defined(WOLFSSL_NOSHA512_224)
    #define WP_HAVE_SHA512_224
#endif
#if (LIBWOLFSSL_VERSION_HEX >= 0x05000000) && !defined(WOLFSSL_NOSHA512_256)
    #define WP_HAVE_SHA512_256
#endif
#ifdef WOLFSSL_SHA3
    #define WP_HAVE_SHA3
    #define WP_HAVE_SHA3_224
    #define WP_HAVE_SHA3_256
    #define WP_HAVE_SHA3_384
    #define WP_HAVE_SHA3_512
    #if (LIBWOLFSSL_VERSION_HEX >= 0x05000000) && defined(WOLFSSL_SHAKE256) && \
        !defined(WOLFSSL_NO_SHAKE256)
         #define WP_HAVE_SHAKE_256
    #endif
#endif

#ifndef NO_HMAC
    #define WP_HAVE_HMAC
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES) && defined(WOLFSSL_AES_DIRECT)
    #define WP_HAVE_CMAC
#endif
#ifdef HAVE_AESGCM
    #define WP_HAVE_GMAC
#endif

#ifndef NO_AES
    #define WP_HAVE_AES
#endif
#ifdef HAVE_AES_ECB
    #define WP_HAVE_AESECB
#endif
#ifndef NO_AES_CBC
    #define WP_HAVE_AESCBC
    #define WP_HAVE_AESCTS
    #define WP_HAVE_KRB5KDF
#endif
#ifndef NO_DES3
    #define WP_HAVE_DES3CBC
#endif
#ifdef WOLFSSL_AES_COUNTER
    #define WP_HAVE_AESCTR
#endif
#ifdef HAVE_AESGCM
    #define WP_HAVE_AESGCM
#endif
#ifdef HAVE_AESCCM
    #define WP_HAVE_AESCCM
#endif
#ifdef WOLFSSL_AES_CFB
    #define WP_HAVE_AESCFB
#endif

#ifndef WC_NO_RNG
    #define WP_HAVE_RANDOM
#endif

#if !defined(NO_KDF) && defined(HAVE_HKDF)
    #define WP_HAVE_HKDF
#endif
#ifdef WOLFSSL_HAVE_PRF
    #define WP_HAVE_TLS1_PRF
#endif
#ifndef NO_PWDBASED
    #define WP_HAVE_PBE
#endif
#ifdef WOLFSSL_WOLFSSH
    #define WP_HAVE_SSHKDF
#endif

#ifndef NO_DH
    #define WP_HAVE_DH
#endif
#ifndef NO_RSA
    #define WP_HAVE_RSA
    #if defined(WC_RSA_PSS) && LIBWOLFSSL_VERSION_HEX >= 0x05005000
        #define WP_RSA_PSS_ENCODING
    #endif
#endif

#ifdef HAVE_ECC
    #define WP_HAVE_ECC
    #ifndef NO_ECC_SECP
        #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 192
            #define WP_HAVE_EC_P192
        #endif
        #if (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 224
            #define WP_HAVE_EC_P224
        #endif
        #if (!defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
            #define WP_HAVE_EC_P256
        #endif
        #if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
            #define WP_HAVE_EC_P384
        #endif
        #if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
            #define WP_HAVE_EC_P521
        #endif
    #endif
    #if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
        #define WP_HAVE_ECDSA
    #endif
    #ifdef HAVE_ECC_DHE
        #define WP_HAVE_ECDH
    #endif
    #define WP_HAVE_ECKEYGEN
#endif
#ifdef HAVE_CURVE25519
     #define WP_HAVE_X25519
#endif
#ifdef HAVE_ED25519
     #define WP_HAVE_ED25519
#endif
#ifdef HAVE_CURVE448
     #define WP_HAVE_X448
#endif
#ifdef HAVE_ED448
     #define WP_HAVE_ED448
#endif
/* PQC: gate on both wolfSSL feature macro AND header availability. On wolfSSL
 * master with --enable-all-crypto (no --enable-experimental), the feature
 * macros can be defined in options.h while the mlkem.h / dilithium.h headers
 * are not installed, so probe the headers too. */
#ifdef WOLFSSL_HAVE_MLKEM
    #if defined(__has_include)
        /* wc_mlkem.h is present in both v5.9.1-stable (alongside mlkem.h)
         * and on master (where mlkem.h was removed). Probe wc_mlkem.h only. */
        #if __has_include(<wolfssl/wolfcrypt/wc_mlkem.h>)
            #define WP_HAVE_MLKEM
            #define WP_HAVE_ML_KEM_512
            #define WP_HAVE_ML_KEM_768
            #define WP_HAVE_ML_KEM_1024
        #endif
    #else
        #define WP_HAVE_MLKEM
        #define WP_HAVE_ML_KEM_512
        #define WP_HAVE_ML_KEM_768
        #define WP_HAVE_ML_KEM_1024
    #endif
#endif
#ifdef HAVE_DILITHIUM
    #if defined(__has_include)
        #if __has_include(<wolfssl/wolfcrypt/dilithium.h>)
            #define WP_HAVE_MLDSA
            #define WP_HAVE_ML_DSA_44
            #define WP_HAVE_ML_DSA_65
            #define WP_HAVE_ML_DSA_87
        #endif
    #else
        #define WP_HAVE_MLDSA
        #define WP_HAVE_ML_DSA_44
        #define WP_HAVE_ML_DSA_65
        #define WP_HAVE_ML_DSA_87
    #endif
#endif
#if !defined(NO_AES_CBC) && (defined(WP_HAVE_HMAC) || defined(WP_HAVE_CMAC))
    #define WP_HAVE_KBKDF
#endif
#ifndef WP_NO_FORCE_FAIL
    #define WP_CHECK_FORCE_FAIL
#endif

#endif /* WOLFPROV_SETTINGS_H */

