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

#ifndef NO_DH
    #define WP_HAVE_DH
#endif
#ifndef NO_RSA
    #define WP_HAVE_RSA
    #if defined(WC_RSA_PSS) && LIBWOLFSSL_VERSION_HEX >= 0x05005000
        #define WOLFSSL_RSA_PSS_ENCODING
    #endif
#endif

#ifdef HAVE_ECC
    #define WP_HAVE_ECC
    #ifndef NO_ECC_SECP
        #if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
            #define WP_HAVE_EC_P192
        #endif
        #if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
            #define WP_HAVE_EC_P224
        #endif
        #if defined(HAVE_ECC256) || defined(HAVE_ALL_CURVES)
            #define WP_HAVE_EC_P256
        #endif
        #if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
            #define WP_HAVE_EC_P384
        #endif
        #if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
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
#ifndef WP_NO_FORCE_FAIL
    #define WP_CHECK_FORCE_FAIL
#endif

#endif /* WOLFPROV_SETTINGS_H */

