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
#include <openssl/opensslv.h>

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
/* PQC is opt-in and per-algorithm: ML-KEM is compiled only when
 * build-wolfprovider.sh --enable-mlkem / --enable-pqc defines
 * WOLFPROV_HAVE_MLKEM, and ML-DSA only when --enable-mldsa / --enable-pqc
 * defines WOLFPROV_HAVE_MLDSA. Without those flags no PQC code is built
 * regardless of what the linked wolfSSL enables. Each also requires the
 * canonical wolfSSL header (wc_mlkem.h / wc_mldsa.h; older wolfSSL exposing
 * only dilithium.h is treated as PQC-absent) and OpenSSL >= 3.6: OpenSSL 3.5
 * has the algorithms but not the seed, ikme, security-category and FIPS 204
 * signature message params wolfProvider uses, which arrived in 3.6. To support
 * OpenSSL 3.5 later, add param-name fallbacks and lower this floor. The build
 * script enforces these version floors so a wrong version is an explicit error
 * rather than a silent no-op. */
#if !defined(__has_include)
    #define WP_MLKEM_HEADER
    #define WP_MLDSA_HEADER
#else
    #if __has_include(<wolfssl/wolfcrypt/wc_mlkem.h>)
        #define WP_MLKEM_HEADER
    #endif
    #if __has_include(<wolfssl/wolfcrypt/wc_mldsa.h>)
        #define WP_MLDSA_HEADER
    #endif
#endif
/* wolfSSL must be master or v5.9.2-stable+: a release newer than v5.9.1, or a
 * dev build carrying wc_mldsa.h. wc_mldsa.h is the deliberate post-v5.9.1
 * marker for BOTH algorithms because the PQC seed/message API and that header
 * shipped together after v5.9.1; master still reports the v5.9.1 version hex,
 * so the hex check alone cannot tell them apart. wc_mlkem.h is NOT used here:
 * it already exists in v5.9.1, so it cannot mark "newer than v5.9.1". An
 * ML-KEM-only build against a wolfSSL stripped of wc_mldsa.h fails closed with
 * the #error below, which is the safe outcome. */
#if (LIBWOLFSSL_VERSION_HEX > 0x05009001L) || defined(WP_MLDSA_HEADER)
    #define WP_WOLFSSL_PQC_CAPABLE
#endif
#if defined(WOLFPROV_HAVE_MLKEM) && defined(WOLFSSL_HAVE_MLKEM) && \
    defined(WP_MLKEM_HEADER) && defined(WP_WOLFSSL_PQC_CAPABLE) && \
    (OPENSSL_VERSION_NUMBER >= 0x30600000L)
    #define WP_HAVE_MLKEM
    #define WP_HAVE_ML_KEM_512
    #define WP_HAVE_ML_KEM_768
    #define WP_HAVE_ML_KEM_1024
#endif
#if defined(WOLFPROV_HAVE_MLDSA) && defined(WOLFSSL_HAVE_MLDSA) && \
    defined(WP_MLDSA_HEADER) && defined(WP_WOLFSSL_PQC_CAPABLE) && \
    (OPENSSL_VERSION_NUMBER >= 0x30600000L)
    #define WP_HAVE_MLDSA
    #define WP_HAVE_ML_DSA_44
    #define WP_HAVE_ML_DSA_65
    #define WP_HAVE_ML_DSA_87
#endif
/* Fail loudly if PQC was requested but the prerequisites are missing, so a
 * direct ./configure (bypassing the build script's version gate) does not
 * silently produce a non-PQC build. */
#if defined(WOLFPROV_HAVE_MLKEM) && !defined(WP_HAVE_MLKEM)
    #error "ML-KEM requested but unavailable: needs OpenSSL >= 3.6 and wolfSSL master or v5.9.2-stable+ with ML-KEM."
#endif
#if defined(WOLFPROV_HAVE_MLDSA) && !defined(WP_HAVE_MLDSA)
    #error "ML-DSA requested but unavailable: needs OpenSSL >= 3.6 and wolfSSL master or v5.9.2-stable+ with ML-DSA."
#endif
#if !defined(NO_AES_CBC) && (defined(WP_HAVE_HMAC) || defined(WP_HAVE_CMAC))
    #define WP_HAVE_KBKDF
#endif
#ifndef WP_NO_FORCE_FAIL
    #define WP_CHECK_FORCE_FAIL
#endif

#endif /* WOLFPROV_SETTINGS_H */

