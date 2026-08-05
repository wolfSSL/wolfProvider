/* user_settings.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

/* wolfSSL configuration for wolfProvider on Windows / Visual Studio, x64.
 * wolfSSL and wolfProvider must both be built against this same file; a
 * divergent copy is an ABI mismatch, not a build error. */

#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

/* Deliberately absent: HAVE___UINT128_T, HAVE_GETPID, HAVE_C___ATOMIC and
 * WOLFSSL_HAVE_ATOMIC_H are autotools probe results that are wrong under MSVC
 * and change struct WC_RNG and the atomic int type. Do not restore them. */

#undef  HAVE_LIMITS_H
#define HAVE_LIMITS_H 1

#undef  WOLFSSL_HAVE_ASSERT_H
#define WOLFSSL_HAVE_ASSERT_H

#undef  WOLFSSL_WOLFSSH
#define WOLFSSL_WOLFSSH

#undef  HAVE_THREAD_LS
#define HAVE_THREAD_LS

#undef  NO_DO178
#define NO_DO178

/* Also selects SP_INT_BITS 8192; without it FFDHE-8192 breaks at run time. */

#undef  WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

/* --- Algorithm and feature enables ---------------------------------------- */

#undef  WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_ASN_TEMPLATE

#undef  HAVE_ECC_CDH
#define HAVE_ECC_CDH

#undef  HAVE_ECC_KOBLITZ
#define HAVE_ECC_KOBLITZ

#undef  HAVE_ECC_SECPR2
#define HAVE_ECC_SECPR2

#undef  HAVE_ECC_SECPR3
#define HAVE_ECC_SECPR3

#undef  WOLFSSL_DES_ECB
#define WOLFSSL_DES_ECB

#undef  HAVE_AES_DECRYPT
#define HAVE_AES_DECRYPT

#undef  HAVE_AES_ECB
#define HAVE_AES_ECB

#undef  WOLFSSL_ALT_NAMES
#define WOLFSSL_ALT_NAMES

#undef  HAVE_FFDHE_2048
#define HAVE_FFDHE_2048

#undef  HAVE_FFDHE_3072
#define HAVE_FFDHE_3072

#undef  WOLFSSL_ASN_ALL
#define WOLFSSL_ASN_ALL

#undef  WOLFSSL_DH_EXTRA
#define WOLFSSL_DH_EXTRA

#undef  WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT
#define WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT

#undef  WOLFSSL_HAVE_ISSUER_NAMES
#define WOLFSSL_HAVE_ISSUER_NAMES

#undef  WC_KDF_NIST_SP_800_56C
#define WC_KDF_NIST_SP_800_56C

#undef  WC_RNG_BANK_SUPPORT
#define WC_RNG_BANK_SUPPORT

#undef  NO_OLD_WC_NAMES
#define NO_OLD_WC_NAMES

#undef  NO_OLD_SSL_NAMES
#define NO_OLD_SSL_NAMES

#undef  NO_OLD_SHA_NAMES
#define NO_OLD_SHA_NAMES

#undef  NO_OLD_MD5_NAME
#define NO_OLD_MD5_NAME

#undef  OPENSSL_COEXIST
#define OPENSSL_COEXIST

/* --- Side-channel hardening and threading --------------------------------- */

#undef  ERROR_QUEUE_PER_THREAD
#define ERROR_QUEUE_PER_THREAD

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

#undef  ATOMIC_USER
#define ATOMIC_USER

#undef  HAVE_PK_CALLBACKS
#define HAVE_PK_CALLBACKS

#undef  HAVE_AES_ECB
#define HAVE_AES_ECB

#undef  WOLFSSL_AES_CBC_LENGTH_CHECKS
#define WOLFSSL_AES_CBC_LENGTH_CHECKS

#undef  HAVE_AESCCM
#define HAVE_AESCCM

#undef  WOLFSSL_AES_EAX
#define WOLFSSL_AES_EAX

#undef  WOLFSSL_AES_OFB
#define WOLFSSL_AES_OFB

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_AES_CFB
#define WOLFSSL_AES_CFB

#undef  WOLFSSL_ARMASM_NO_HW_CRYPTO
#define WOLFSSL_ARMASM_NO_HW_CRYPTO

/* USE_INTEL_SPEEDUP is omitted: MASM coverage is a subset of GAS coverage, so
 * the AVX2 paths do not link. */

#undef  WOLFSSL_AESNI
#define WOLFSSL_AESNI

#undef  WOLFSSL_USE_ALIGN
#define WOLFSSL_USE_ALIGN

/* --- Ciphers and digests -------------------------------------------------- */

#undef  HAVE_CAMELLIA
#define HAVE_CAMELLIA

#undef  WOLFSSL_MD2
#define WOLFSSL_MD2

#undef  HAVE_NULL_CIPHER
#define HAVE_NULL_CIPHER

#undef  WOLFSSL_RIPEMD
#define WOLFSSL_RIPEMD

#undef  HAVE_BLAKE2B
#define HAVE_BLAKE2B

#undef  HAVE_BLAKE2S
#define HAVE_BLAKE2S

#undef  WOLFSSL_SHA224
#define WOLFSSL_SHA224

#undef  WOLFSSL_SHA512
#define WOLFSSL_SHA512

#undef  WOLFSSL_SHA384
#define WOLFSSL_SHA384

#undef  SESSION_CERTS
#define SESSION_CERTS

#undef  WOLFSSL_SEP
#define WOLFSSL_SEP

#undef  KEEP_PEER_CERT
#define KEEP_PEER_CERT

#undef  HAVE_HKDF
#define HAVE_HKDF

#undef  HAVE_X963_KDF
#define HAVE_X963_KDF

/* --- ECC ------------------------------------------------------------------ */

#undef  HAVE_ECC
#define HAVE_ECC

#undef  ECC_SHAMIR
#define ECC_SHAMIR

#undef  ECC_MIN_KEY_SZ
#define ECC_MIN_KEY_SZ 192

#undef  HAVE_ECC_BRAINPOOL
#define HAVE_ECC_BRAINPOOL

#undef  FP_ECC
#define FP_ECC

#undef  HAVE_ECC_ENCRYPT
#define HAVE_ECC_ENCRYPT

#undef  WOLFCRYPT_HAVE_ECCSI
#define WOLFCRYPT_HAVE_ECCSI

#undef  WOLFSSL_PUBLIC_MP
#define WOLFSSL_PUBLIC_MP

#undef  WOLFCRYPT_HAVE_SAKKE
#define WOLFCRYPT_HAVE_SAKKE

/* --- RSA, encodings, MACs ------------------------------------------------- */

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  WC_RSA_PSS
#define WC_RSA_PSS

#undef  WOLFSSL_PSS_LONG_SALT
#define WOLFSSL_PSS_LONG_SALT

#undef  HAVE_ANON
#define HAVE_ANON

#undef  WOLFSSL_ASN_PRINT
#define WOLFSSL_ASN_PRINT

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

#undef  WOLFSSL_BASE16
#define WOLFSSL_BASE16

#undef  WOLFSSL_SIPHASH
#define WOLFSSL_SIPHASH

#undef  HAVE_CMAC_KDF
#define HAVE_CMAC_KDF

#undef  WOLFSSL_CMAC
#define WOLFSSL_CMAC

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_AES_XTS
#define WOLFSSL_AES_XTS

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_CUSTOM_CURVES
#define WOLFSSL_CUSTOM_CURVES

#undef  HAVE_CURVE448
#define HAVE_CURVE448

#undef  HAVE_ED448
#define HAVE_ED448

#undef  WOLFSSL_ED448_STREAMING_VERIFY
#define WOLFSSL_ED448_STREAMING_VERIFY

#undef  WC_SRTP_KDF
#define WC_SRTP_KDF

#undef  HAVE_AES_ECB
#define HAVE_AES_ECB

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

/* --- SHA-3, ML-KEM, ChaCha/Poly, DRBG ------------------------------------- */

#undef  WOLFSSL_SHA3
#define WOLFSSL_SHA3

#undef  WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE128

#undef  WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE256

#undef  WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_MLKEM

#undef  WOLFSSL_TLS_NO_MLKEM_STANDALONE
#define WOLFSSL_TLS_NO_MLKEM_STANDALONE

#undef  WOLFSSL_PQC_HYBRIDS
#define WOLFSSL_PQC_HYBRIDS

#undef  HAVE_POLY1305
#define HAVE_POLY1305

#undef  HAVE_CHACHA
#define HAVE_CHACHA

#undef  HAVE_XCHACHA
#define HAVE_XCHACHA

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

#undef  WOLFSSL_DRBG_SHA512
#define WOLFSSL_DRBG_SHA512

/* --- TLS extensions, OCSP, CRL -------------------------------------------- */

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_CERTIFICATE_STATUS_REQUEST
#define HAVE_CERTIFICATE_STATUS_REQUEST

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_CERTIFICATE_STATUS_REQUEST_V2
#define HAVE_CERTIFICATE_STATUS_REQUEST_V2

#undef  HAVE_CRL
#define HAVE_CRL

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SNI
#define HAVE_SNI

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  HAVE_FFDHE_2048
#define HAVE_FFDHE_2048

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFSSL_TLS13
#define WOLFSSL_TLS13

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_EXTENDED_MASTER
#define HAVE_EXTENDED_MASTER

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SNI
#define HAVE_SNI

#undef  HAVE_MAX_FRAGMENT
#define HAVE_MAX_FRAGMENT

#undef  HAVE_TRUNCATED_HMAC
#define HAVE_TRUNCATED_HMAC

#undef  HAVE_ALPN
#define HAVE_ALPN

#undef  HAVE_TRUSTED_CA
#define HAVE_TRUSTED_CA

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFCRYPT_HAVE_SRP
#define WOLFCRYPT_HAVE_SRP

#undef  ASN_BER_TO_DER
#define ASN_BER_TO_DER

#undef  HAVE_ENCRYPT_THEN_MAC
#define HAVE_ENCRYPT_THEN_MAC

#undef  WOLFSSL_ENCRYPTED_KEYS
#define WOLFSSL_ENCRYPTED_KEYS

#undef  HAVE_SCRYPT
#define HAVE_SCRYPT

/* --- Single-precision (SP) math, x86-64 assembly -------------------------- */

#undef  WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_RSA

#undef  WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_DH

#undef  WOLFSSL_SP_4096
#define WOLFSSL_SP_4096

#undef  WOLFSSL_SP_LARGE_CODE
#define WOLFSSL_SP_LARGE_CODE

#undef  WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_ECC

#undef  HAVE_ECC384
#define HAVE_ECC384

#undef  WOLFSSL_SP_384
#define WOLFSSL_SP_384

#undef  HAVE_ECC521
#define HAVE_ECC521

#undef  WOLFSSL_SP_521
#define WOLFSSL_SP_521

#undef  WOLFSSL_SP_1024
#define WOLFSSL_SP_1024

#undef  WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_MATH_ALL

#undef  WOLFSSL_SP_X86_64
#define WOLFSSL_SP_X86_64

#undef  WOLFSSL_SP_ASM
#define WOLFSSL_SP_ASM

#undef  WOLFSSL_SP_X86_64_ASM
#define WOLFSSL_SP_X86_64_ASM

#undef  WOLF_CRYPTO_CB
#define WOLF_CRYPTO_CB

#undef  WC_NO_ASYNC_THREADING
#define WC_NO_ASYNC_THREADING

#undef  HAVE_AES_KEYWRAP
#define HAVE_AES_KEYWRAP

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  WOLFSSL_HASH_FLAGS
#define WOLFSSL_HASH_FLAGS

#undef  HAVE_DH_DEFAULT_PARAMS
#define HAVE_DH_DEFAULT_PARAMS

#undef  RSA_MAX_SIZE
#define RSA_MAX_SIZE 4096

#undef  MAX_ECC_BITS
#define MAX_ECC_BITS 1024

/* --- Certificate generation, key generation, misc ------------------------- */

#undef  HAVE_CURVE25519
#define HAVE_CURVE25519

#undef  HAVE_ED25519
#define HAVE_ED25519

#undef  WOLFSSL_SYS_CA_CERTS
#define WOLFSSL_SYS_CA_CERTS

#undef  WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN

#undef  WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_REQ

#undef  WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_GEN

#undef  WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_EXT

#undef  HAVE_OCSP
#define HAVE_OCSP

#undef  HAVE_OPENSSL_CMD
#define HAVE_OPENSSL_CMD

#undef  WOLFSSL_ED25519_STREAMING_VERIFY
#define WOLFSSL_ED25519_STREAMING_VERIFY

#undef  WOLFSSL_AES_SIV
#define WOLFSSL_AES_SIV

#undef  WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_COUNTER

#undef  WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_DIRECT

#undef  HAVE_PKCS7
#define HAVE_PKCS7

#undef  NO_DES3_TLS_SUITES
#define NO_DES3_TLS_SUITES

#undef  GCM_TABLE_4BIT
#define GCM_TABLE_4BIT

#undef  HAVE_AESGCM
#define HAVE_AESGCM

#undef  WOLFSSL_AESGCM_STREAM
#define WOLFSSL_AESGCM_STREAM

#undef  WOLFSSL_AESXTS_STREAM
#define WOLFSSL_AESXTS_STREAM

#undef  WOLFSSL_PUBLIC_MP
#define WOLFSSL_PUBLIC_MP

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SERVER_RENEGOTIATION_INFO
#define HAVE_SERVER_RENEGOTIATION_INFO

#undef  HAVE_COMP_KEY
#define HAVE_COMP_KEY

#undef  WOLFSSL_ALLOW_RC4
#define WOLFSSL_ALLOW_RC4

#undef  WOLFSSL_TLS_OCSP_MULTI
#define WOLFSSL_TLS_OCSP_MULTI

#undef  HAVE_WC_INTROSPECTION
#define HAVE_WC_INTROSPECTION

#undef  WC_RSA_NO_PADDING
#define WC_RSA_NO_PADDING

#undef  WOLFSSL_PUBLIC_MP
#define WOLFSSL_PUBLIC_MP

#undef  HAVE_PUBLIC_FFDHE
#define HAVE_PUBLIC_FFDHE

#undef  HAVE_FFDHE_6144
#define HAVE_FFDHE_6144

#undef  HAVE_FFDHE_8192
#define HAVE_FFDHE_8192

#undef  WOLFSSL_PSS_LONG_SALT
#define WOLFSSL_PSS_LONG_SALT

#undef  WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_PSS_SALT_LEN_DISCOVER

#undef  RSA_MIN_SIZE
#define RSA_MIN_SIZE 1024

#undef  WOLFSSL_OLD_OID_SUM
#define WOLFSSL_OLD_OID_SUM

#undef  WC_RNG_SEED_CB
#define WC_RNG_SEED_CB

#endif /* _WIN_USER_SETTINGS_H_ */
