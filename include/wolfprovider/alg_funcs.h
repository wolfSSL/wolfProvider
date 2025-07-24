/* alg_funcs.h
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
#include <openssl/types.h>

#ifdef WOLFPROVIDER_USER_SETTINGS
    #include "user_settings.h"
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
    #include <wolfssl/wolfcrypt/kdf.h>
#endif

#include <wolfprovider/internal.h>
#include <wolfprovider/wp_logging.h>

#ifndef WP_ALG_FUNCS_H
#define WP_ALG_FUNCS_H

typedef void (*DFUNC)(void);

/* Digest names. */

#define WP_NAMES_MD5           "MD5:SSL3-MD5:1.2.840.113549.2.5"

#define WP_NAMES_MD5_SHA1      "MD5-SHA1"

#define WP_NAMES_SHA1          "SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26"

#define WP_NAMES_SHA2_224      \
    "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define WP_NAMES_SHA2_256      \
    "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define WP_NAMES_SHA2_384      \
    "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define WP_NAMES_SHA2_512      \
    "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"
#define WP_NAMES_SHA2_512_224  \
    "SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5"
#define WP_NAMES_SHA2_512_256  \
    "SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6"


#define WP_NAMES_SHA3_224      "SHA3-224:2.16.840.1.101.3.4.2.7"
#define WP_NAMES_SHA3_256      "SHA3-256:2.16.840.1.101.3.4.2.8"
#define WP_NAMES_SHA3_384      "SHA3-384:2.16.840.1.101.3.4.2.9"
#define WP_NAMES_SHA3_512      "SHA3-512:2.16.840.1.101.3.4.2.10"

#define WP_NAMES_SHAKE_256     "SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12"

/* Cipher names. */

#define WP_NAMES_AES_256_GCM "AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46"
#define WP_NAMES_AES_192_GCM "AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26"
#define WP_NAMES_AES_128_GCM "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6"

#define WP_NAMES_AES_256_CCM "AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47"
#define WP_NAMES_AES_192_CCM "AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27"
#define WP_NAMES_AES_128_CCM "AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7"

#define WP_NAMES_AES_256_CBC "AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42"
#define WP_NAMES_AES_192_CBC "AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22"
#define WP_NAMES_AES_128_CBC "AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2"

#define WP_NAMES_AES_256_ECB "AES-256-ECB:2.16.840.1.101.3.4.1.41"
#define WP_NAMES_AES_192_ECB "AES-192-ECB:2.16.840.1.101.3.4.1.21"
#define WP_NAMES_AES_128_ECB "AES-128-ECB:2.16.840.1.101.3.4.1.1"

#define WP_NAMES_AES_256_CTR "AES-256-CTR"
#define WP_NAMES_AES_192_CTR "AES-192-CTR"
#define WP_NAMES_AES_128_CTR "AES-128-CTR"

#define WP_NAMES_AES_256_CFB "AES-256-CFB:2.16.840.1.101.3.4.1.44"
#define WP_NAMES_AES_192_CFB "AES-192-CFB:2.16.840.1.101.3.4.1.24"
#define WP_NAMES_AES_128_CFB "AES-128-CFB:2.16.840.1.101.3.4.1.4"

#define WP_NAMES_AES_256_WRAP   \
    "AES-256-WRAP:id-aes256-wrap:AES256-WRAP:2.16.840.1.101.3.4.1.45"
#define WP_NAMES_AES_192_WRAP \
    "AES-192-WRAP:id-aes192-wrap:AES192-WRAP:2.16.840.1.101.3.4.1.25"
#define WP_NAMES_AES_128_WRAP \
    "AES-128-WRAP:id-aes128-wrap:AES128-WRAP:2.16.840.1.101.3.4.1.5"

#define WP_NAMES_AES_256_CTS "AES-256-CBC-CTS"
#define WP_NAMES_AES_192_CTS "AES-192-CBC-CTS"
#define WP_NAMES_AES_128_CTS "AES-128-CBC-CTS"

#define WP_NAMES_DES_EDE3_CBC "DES-EDE3-CBC:DES3:1.2.840.113549.3.7"

/* Internal cipher flags. */
#define WP_CIPHER_FLAG_AEAD             0x0001
#define WP_CIPHER_FLAG_CUSTOM_IV        0x0002
#define WP_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#define WP_CIPHER_FLAG_RAND_KEY         0x0010
/* Internal flags that are only used within the provider */
#define WP_CIPHER_FLAG_INVERSE_CIPHER   0x0200


/* MAC names. */
#define WP_NAMES_HMAC           "HMAC"
#define WP_NAMES_CMAC           "CMAC"
#define WP_NAMES_GMAC           "GMAC"

/* KDF names. */
#define WP_NAMES_HKDF           "HKDF"
#define WP_NAMES_PBKDF2         "PBKDF2:1.2.840.113549.1.5.12"
#define WP_NAMES_PKCS12KDF      "PKCS12KDF"
#define WP_NAMES_TLS1_3_KDF     "TLS13-KDF"
#define WP_NAMES_TLS1_PRF       "TLS1-PRF"
#define WP_NAMES_KRB5KDF        "KRB5KDF"

/* Signature names. */
#define WP_NAMES_RSA            "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define WP_NAMES_RSA_PSS        "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"

/* ECC names. */
#define WP_NAMES_EC             "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define WP_NAMES_ECDH           "ECDH"
#define WP_NAMES_ECDSA          "ECDSA"

/* ECX names */
#define WP_NAMES_X25519         "X25519"
#define WP_NAMES_X448           "X448"
#define WP_NAMES_ED25519        "ED25519"
#define WP_NAMES_ED448          "ED448"

/* DH names. */
#define WP_NAMES_DH             "DH"
#define WP_NAMES_DHX            "DHX"

/* DRBG names. */
#define WP_NAMES_CTR_DRBG       "CTR-DRBG"
#define WP_NAMES_HASH_DRBG      "HASH-DRBG"

/* Decoder names. */
#define WP_NAMES_DER            "DER"

/* Store names. */
#define WP_NAMES_FILE           "file"

int wolfssl_prov_is_running(void);
WC_RNG* wolfssl_prov_get_rng(WOLFPROV_CTX* provctx);

int wp_lock(wolfSSL_Mutex* mutex);
int wp_unlock(wolfSSL_Mutex* mutex);

/* Internal RSA types and functions. */
typedef struct wp_Rsa wp_Rsa;

int wp_rsa_up_ref(wp_Rsa* rsa);
void wp_rsa_free(wp_Rsa* rsa);
int wp_rsa_get_type(wp_Rsa* rsa);
int wp_rsa_get_bits(wp_Rsa* rsa);
wolfSSL_Mutex* wp_rsa_get_mutex(wp_Rsa* rsa);
RsaKey* wp_rsa_get_key(wp_Rsa* rsa);
void wp_rsa_get_pss_mds(wp_Rsa* rsa, char** mdName, char** mgfMdName);
int wp_rsa_get_pss_salt_len(wp_Rsa* rsa);
int wp_rsa_get_pss_params_set(wp_Rsa* rsa);
int wp_rsa_check_key_size(wp_Rsa* rsa, int allow1024);
int wp_rsa_pss_encode_alg_id(const wp_Rsa* rsa, const char* mdName,
    const char* mgf1Name, int saltLen, byte* pssAlgId, word32* len);

/* Internal ECC types and functions. */
typedef struct wp_Ecc wp_Ecc;

int wp_ecc_up_ref(wp_Ecc* ecc);
void wp_ecc_free(wp_Ecc* ecc);
ecc_key* wp_ecc_get_key(wp_Ecc* ecc);
WC_RNG* wp_ecc_get_rng(wp_Ecc* ecc);
int wp_ecc_get_size(wp_Ecc* ecc);
int wp_ecc_check_usage(wp_Ecc* ecc);
wolfSSL_Mutex* wp_ecc_get_mutex(wp_Ecc* ecc);

/* Internal ECX types and functions. */
typedef struct wp_Ecx wp_Ecx;

int wp_ecx_up_ref(wp_Ecx* ecx);
void wp_ecx_free(wp_Ecx* ecx);
void* wp_ecx_get_key(wp_Ecx* ecx);
wolfSSL_Mutex* wp_ecx_get_mutex(wp_Ecx* ecx);

/* Internal DH types and functions. */
typedef struct wp_Dh wp_Dh;

int wp_dh_up_ref(wp_Dh* dh);
void wp_dh_free(wp_Dh* dh);
int wp_dh_get_size(const wp_Dh* dh);
DhKey* wp_dh_get_key(wp_Dh* dh);
int wp_dh_get_priv(wp_Dh* dh, unsigned char** priv, word32* privSz);
int wp_dh_get_pub(wp_Dh* dh, unsigned char** pub, word32* pubSz);
int wp_dh_match(const wp_Dh* dh1, const wp_Dh* dh2, int selection);

/* Internal MAC types and functions. */
typedef struct wp_Mac wp_Mac;

int wp_mac_up_ref(wp_Mac* mac);
void wp_mac_free(wp_Mac* mac);
int wp_mac_get_type(wp_Mac* mac);
int wp_mac_get_private_key(wp_Mac* mac, unsigned char** priv, size_t* privLen);
char* wp_mac_get_ciphername(wp_Mac* mac);
char* wp_mac_get_properties(wp_Mac* mac);

/* Internal KDF types and functions. */
typedef struct wp_Kdf wp_Kdf;

int wp_kdf_up_ref(wp_Kdf* kdf);
void wp_kdf_free(wp_Kdf* kdf);

/* Digest implementations. */
extern const OSSL_DISPATCH wp_md5_functions[];
extern const OSSL_DISPATCH wp_md5_sha1_functions[];
extern const OSSL_DISPATCH wp_sha1_functions[];

extern const OSSL_DISPATCH wp_sha224_functions[];
extern const OSSL_DISPATCH wp_sha256_functions[];
extern const OSSL_DISPATCH wp_sha384_functions[];
extern const OSSL_DISPATCH wp_sha512_functions[];
extern const OSSL_DISPATCH wp_sha512_224_functions[];
extern const OSSL_DISPATCH wp_sha512_256_functions[];

extern const OSSL_DISPATCH wp_sha3_224_functions[];
extern const OSSL_DISPATCH wp_sha3_256_functions[];
extern const OSSL_DISPATCH wp_sha3_384_functions[];
extern const OSSL_DISPATCH wp_sha3_512_functions[];

extern const OSSL_DISPATCH wp_shake_256_functions[];

/* Cipher implementations. */
extern const OSSL_DISPATCH wp_aes256gcm_functions[];
extern const OSSL_DISPATCH wp_aes192gcm_functions[];
extern const OSSL_DISPATCH wp_aes128gcm_functions[];

extern const OSSL_DISPATCH wp_aes256ccm_functions[];
extern const OSSL_DISPATCH wp_aes192ccm_functions[];
extern const OSSL_DISPATCH wp_aes128ccm_functions[];

extern const OSSL_DISPATCH wp_aes256cbc_functions[];
extern const OSSL_DISPATCH wp_aes192cbc_functions[];
extern const OSSL_DISPATCH wp_aes128cbc_functions[];

extern const OSSL_DISPATCH wp_aes256ecb_functions[];
extern const OSSL_DISPATCH wp_aes192ecb_functions[];
extern const OSSL_DISPATCH wp_aes128ecb_functions[];

extern const OSSL_DISPATCH wp_aes256ctr_functions[];
extern const OSSL_DISPATCH wp_aes192ctr_functions[];
extern const OSSL_DISPATCH wp_aes128ctr_functions[];

extern const OSSL_DISPATCH wp_aes256cfb_functions[];
extern const OSSL_DISPATCH wp_aes192cfb_functions[];
extern const OSSL_DISPATCH wp_aes128cfb_functions[];

extern const OSSL_DISPATCH wp_aes256wrap_functions[];
extern const OSSL_DISPATCH wp_aes192wrap_functions[];
extern const OSSL_DISPATCH wp_aes128wrap_functions[];

extern const OSSL_DISPATCH wp_aes256cts_functions[];
extern const OSSL_DISPATCH wp_aes192cts_functions[];
extern const OSSL_DISPATCH wp_aes128cts_functions[];

extern const OSSL_DISPATCH wp_des3cbc_functions[];

/* MAC implementations. */
extern const OSSL_DISPATCH wp_hmac_functions[];
extern const OSSL_DISPATCH wp_cmac_functions[];
extern const OSSL_DISPATCH wp_gmac_functions[];

/* KDF implementations. */
extern const OSSL_DISPATCH wp_kdf_hkdf_functions[];
extern const OSSL_DISPATCH wp_kdf_pbkdf2_functions[];
extern const OSSL_DISPATCH wp_kdf_pkcs12_functions[];
extern const OSSL_DISPATCH wp_kdf_tls1_3_kdf_functions[];
extern const OSSL_DISPATCH wp_kdf_tls1_prf_functions[];
extern const OSSL_DISPATCH wp_kdf_krb5kdf_functions[];

/* Signature implementations. */
extern const OSSL_DISPATCH wp_rsa_signature_functions[];
extern const OSSL_DISPATCH wp_ecdsa_signature_functions[];
extern const OSSL_DISPATCH wp_ed25519_signature_functions[];
extern const OSSL_DISPATCH wp_ed448_signature_functions[];
extern const OSSL_DISPATCH wp_hmac_signature_functions[];
extern const OSSL_DISPATCH wp_cmac_signature_functions[];

/* Asymmetric cipher implementations. */
extern const OSSL_DISPATCH wp_rsa_asym_cipher_functions[];

/* KEM implementations. */
extern const OSSL_DISPATCH wp_rsa_asym_kem_functions[];

/* Key Management implementations. */
extern const OSSL_DISPATCH wp_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH wp_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH wp_ecc_keymgmt_functions[];
extern const OSSL_DISPATCH wp_x25519_keymgmt_functions[];
extern const OSSL_DISPATCH wp_x448_keymgmt_functions[];
extern const OSSL_DISPATCH wp_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH wp_ed448_keymgmt_functions[];
extern const OSSL_DISPATCH wp_dh_keymgmt_functions[];
extern const OSSL_DISPATCH wp_hmac_keymgmt_functions[];
extern const OSSL_DISPATCH wp_cmac_keymgmt_functions[];
extern const OSSL_DISPATCH wp_kdf_keymgmt_functions[];

/* Key exchange implementations. */
extern const OSSL_DISPATCH wp_ecdh_keyexch_functions[];
extern const OSSL_DISPATCH wp_x25519_keyexch_functions[];
extern const OSSL_DISPATCH wp_x448_keyexch_functions[];
extern const OSSL_DISPATCH wp_dh_keyexch_functions[];
extern const OSSL_DISPATCH wp_hkdf_keyexch_functions[];
extern const OSSL_DISPATCH wp_tls1_prf_keyexch_functions[];

/* DRBG implementations. */
extern const OSSL_DISPATCH wp_drbg_functions[];

/* Decode implementations. */
extern const OSSL_DISPATCH wp_rsa_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_rsa_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_rsa_legacy_decoder_functions[];
extern const OSSL_DISPATCH wp_rsapss_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_rsapss_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_dh_type_specific_decoder_functions[];
extern const OSSL_DISPATCH wp_dh_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_dh_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_ecc_type_specific_decoder_functions[];
extern const OSSL_DISPATCH wp_ecc_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_ecc_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_ecc_x9_62_decoder_functions[];
extern const OSSL_DISPATCH wp_x25519_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_x25519_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_x448_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_x448_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_ed448_spki_decoder_functions[];
extern const OSSL_DISPATCH wp_ed448_pki_decoder_functions[];
extern const OSSL_DISPATCH wp_pem_to_der_decoder_functions[];
extern const OSSL_DISPATCH wp_epki_to_pki_decoder_functions[];
/* Encode implementations. */
extern const OSSL_DISPATCH wp_rsa_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_epki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_kp_der_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_kp_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_rsa_text_encoder_functions[];
extern const OSSL_DISPATCH wp_rsapss_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_rsapss_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_rsapss_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_rsapss_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_type_specific_der_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_type_specific_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_dh_epki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_type_specific_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_type_specific_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_epki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_x9_62_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ecc_x9_62_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_x25519_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_x25519_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_x25519_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_x25519_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_x25519_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_x25519_epki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ed25519_epki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_x448_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_x448_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_x448_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_x448_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_x448_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_x448_epki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ed448_spki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ed448_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ed448_pki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ed448_pki_pem_encoder_functions[];
extern const OSSL_DISPATCH wp_ed448_epki_der_encoder_functions[];
extern const OSSL_DISPATCH wp_ed448_epki_pem_encoder_functions[];

/* Storage implementations. */
extern const OSSL_DISPATCH wp_file_store_functions[];

#endif /* WP_ALG_FUNCS_H */

