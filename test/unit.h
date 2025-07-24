/* unit.h
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

#ifndef UNIT_H
#define UNIT_H

/* OpenSSL 3.0.0 has deprecated the ENGINE API. */
#define OPENSSL_API_COMPAT      10101

#include <string.h>

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/wp_logging.h>

#ifdef TEST_MULTITHREADED
#define PRINT_MSG(str)
#define PRINT_ERR_MSG(str)
#else
#define PRINT_MSG(str, ...)     printf("MSG: " str "\n", ##__VA_ARGS__)
#define PRINT_ERR_MSG(str, ...) printf("ERR: " str "\n", ##__VA_ARGS__)
#endif
#ifdef WOLFPROV_DEBUG
void print_buffer(const char *desc, const unsigned char *buffer, size_t len);
#define PRINT_BUFFER(d, b, l)  print_buffer(d, b, l)
#else
#define PRINT_BUFFER(d, b, l)
#endif
#ifdef TEST_MULTITHREADED
#define TEST_DECL(func, data)        { #func, func, data, 0, 0, 0, 0, 0, 0 }
#else
#define TEST_DECL(func, data)        { #func, func, data, 0, 0, 0 }
#endif

#ifndef CERTS_DIR
#define CERTS_DIR "./certs"
#endif

typedef int (*TEST_FUNC)(void *data);
typedef struct TEST_CASE {
    const char   *name;
    TEST_FUNC     func;
    void         *data;
    int           err;
    unsigned int  run:1;
    unsigned int  done:1;
#ifdef TEST_MULTITHREADED
    unsigned int  attempted:1;
    pthread_t     thread;
    int           cnt;
#endif
} TEST_CASE;

int test_logging(void *data);

#define WP_VALGRIND_TEST 0x1


extern OSSL_LIB_CTX* wpLibCtx;
extern OSSL_LIB_CTX* osslLibCtx;
extern int noKeyLimits;


#ifdef WP_HAVE_DIGEST

int test_digest_op(const EVP_MD *md, unsigned char *msg,
                   size_t len, unsigned char *prev,
                   unsigned int *prevLen);
int test_sha(void *data);
int test_sha224(void *data);
int test_sha256(void *data);
int test_sha384(void *data);
int test_sha512(void *data);
int test_sha3_224(void *data);
int test_sha3_256(void *data);
int test_sha3_384(void *data);
int test_sha3_512(void *data);
#ifdef WP_HAVE_SHAKE_256
int test_shake_256(void *data);
#endif

#endif /* WP_HAVE_DIGEST */

#ifdef WP_HAVE_HMAC
int test_hmac_create(void *data);
#endif /* WP_HAVE_HMAC */

#ifdef WP_HAVE_CMAC
int test_cmac_create(void *data);
#endif /* WP_HAVE_HMAC */

#ifdef WP_HAVE_GMAC
int test_gmac_create(void *data);
#endif /* WP_HAVE_GMAC */

#ifdef WP_HAVE_TLS1_PRF
int test_tls1_prf(void *data);
#endif

#ifdef WP_HAVE_HKDF
int test_hkdf(void *data);
#endif

#ifdef WP_HAVE_KRB5KDF
int test_krb5kdf(void *data);
#endif

#ifdef WP_HAVE_DES3CBC
int test_des3_cbc(void *data);
int test_des3_cbc_stream(void *data);
#endif

#ifdef WP_HAVE_AESECB

int test_aes128_ecb(void *data);
int test_aes192_ecb(void *data);
int test_aes256_ecb(void *data);
int test_aes128_ecb_stream(void *data);
int test_aes192_ecb_stream(void *data);
int test_aes256_ecb_stream(void *data);

#endif

#ifdef WP_HAVE_AESCBC

int test_aes128_cbc(void *data);
int test_aes192_cbc(void *data);
int test_aes256_cbc(void *data);
int test_aes128_cbc_stream(void *data);
int test_aes192_cbc_stream(void *data);
int test_aes256_cbc_stream(void *data);
int test_aes256_cbc_multiple(void *data);

#endif

#ifdef WP_HAVE_AESCTR

int test_aes128_ctr_stream(void *data);
int test_aes192_ctr_stream(void *data);
int test_aes256_ctr_stream(void *data);

#endif

#ifdef WP_HAVE_AESCFB

int test_aes128_cfb_stream(void *data);
int test_aes192_cfb_stream(void *data);
int test_aes256_cfb_stream(void *data);

#endif

int test_cipher_null_zero(void *data);

#ifdef WP_HAVE_AESGCM

int test_aes128_gcm(void *data);
int test_aes192_gcm(void *data);
int test_aes256_gcm(void *data);
int test_aes128_gcm_fixed(void *data);
int test_aes128_gcm_tls(void *data);

#endif /* WP_HAVE_AESGCM */

#ifdef WP_HAVE_AESCCM

int test_aes128_ccm(void *data);
int test_aes192_ccm(void *data);
int test_aes256_ccm(void *data);
int test_aes128_ccm_tls(void *data);

#endif /* WP_HAVE_AESCCM */

#ifdef WP_HAVE_AESCTS

int test_aes128_cts(void *data);
int test_aes256_cts(void *data);

#endif

#ifdef WP_HAVE_RANDOM

int test_random(void *data);

#endif

int test_digest_sign(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *data,
    size_t len, const char *md, unsigned char *sig, size_t *sigLen,
    int padMode);

int test_digest_verify(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx,
    unsigned char *data, size_t len, const char *md, unsigned char *sig,
    size_t sigLen, int padMode);

int test_pkey_sign(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *hash,
    size_t hashLen, unsigned char *sig, size_t *sigLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md);
int test_pkey_verify(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *hash,
    size_t hashLen, unsigned char *sig, size_t sigLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md);
int test_pkey_verify_recover(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *hash,
    size_t hashLen, unsigned char *sig, size_t sigLen, int padMode);

int test_pkey_enc(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *msg,
    size_t msgLen, unsigned char *ciphertext, size_t cipherLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md);
int test_pkey_dec(EVP_PKEY *pkey, OSSL_LIB_CTX* libCtx, unsigned char *msg,
    size_t msgLen, unsigned char *ciphertext, size_t cipherLen, int padMode,
    const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md);

#ifdef WP_HAVE_RSA
int test_pkey_enc_rsa(EVP_PKEY *pkey, unsigned char *msg, size_t msgLen,
                  unsigned char *ciphertext, size_t cipherLen, int padMode,
                  const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md);
int test_pkey_dec_rsa(EVP_PKEY *pkey, unsigned char *msg, size_t msgLen,
                  unsigned char *ciphertext, size_t cipherLen, int padMode,
                  const EVP_MD *rsaMd, const EVP_MD *rsaMgf1Md);
int test_rsa_sign_sha1(void *data);
int test_rsa_sign_verify_pkcs1(void *data);
int test_rsa_sign_verify_recover_pkcs1(void *data);
int test_rsa_sign_verify_pss(void *data);
int test_rsa_sign_verify_x931(void *data);
int test_rsa_enc_dec_pkcs1(void *data);
int test_rsa_enc_dec_oaep(void *data);
int test_rsa_enc_dec_nopad(void *data);
int test_rsa_pkey_keygen(void *data);
int test_rsa_pkey_invalid_key_size(void *data);
int test_rsa_get_params(void *data);

int test_rsa_load_key(void* data);
int test_rsa_load_cert(void* data);
int test_rsa_fromdata(void* data);
int test_rsa_decode(void* data);
int test_rsa_null_init(void* data);
#endif /* WP_HAVE_RSA */

#ifdef WP_HAVE_DH
int test_dh_pgen_pkey(void *data);
int test_dh_pkey(void *data);
int test_dh_decode(void *data);
int test_dh_get_params(void *data);
int test_dh_krb5_keygen(void *data);
#endif /* WP_HAVE_DH */

#ifdef WP_HAVE_ECC

#ifdef WP_HAVE_ECKEYGEN

int test_eckeygen_name(void *data);

#ifdef WP_HAVE_EC_P192
int test_eckeygen_p192(void *data);
#endif /* WP_HAVE_EC_P192 */

#ifdef WP_HAVE_EC_P224
int test_eckeygen_p224(void *data);
#endif /* WP_HAVE_EC_P224 */

#ifdef WP_HAVE_EC_P256
int test_eckeygen_p256(void *data);
#endif /* WP_HAVE_EC_P256 */

#ifdef WP_HAVE_EC_P384
int test_eckeygen_p384(void *data);
#endif /* WP_HAVE_EC_P384 */

#ifdef WP_HAVE_EC_P521
int test_eckeygen_p521(void *data);
#endif /* WP_HAVE_EC_P521 */

#ifdef WP_HAVE_X25519
int test_eckeygen_x25519(void *data);
#endif /* WP_HAVE_X25519 */

#ifdef WP_HAVE_X448
int test_eckeygen_x448(void *data);
#endif /* WP_HAVE_X448 */

#endif /* WP_HAVE_ECKEYGEN */

#ifdef WP_HAVE_ECDH

#ifdef WP_HAVE_ECKEYGEN

#ifdef WP_HAVE_EC_P192
int test_ecdh_p192_keygen(void *data);
#endif /* WP_HAVE_EC_P192 */
#ifdef WP_HAVE_EC_P224
int test_ecdh_p224_keygen(void *data);
#endif /* WP_HAVE_EC_P224 */
#ifdef WP_HAVE_EC_P256
int test_ecdh_p256_keygen(void *data);
#endif /* WP_HAVE_EC_P256 */
#ifdef WP_HAVE_EC_P384
int test_ecdh_p384_keygen(void *data);
#endif /* WP_HAVE_EC_P384 */
#ifdef WP_HAVE_EC_P521
int test_ecdh_p521_keygen(void *data);
#endif /* WP_HAVE_EC_P521 */
#ifdef WP_HAVE_X25519
int test_ecdh_x25519_keygen(void *data);
#endif /* WP_HAVE_X25510 */
#ifdef WP_HAVE_X448
int test_ecdh_x448_keygen(void *data);
#endif /* WP_HAVE_X448 */

#endif /* WP_HAVE_ECKEYGEN */

#ifdef WP_HAVE_EC_P192
int test_ecdh_p192(void *data);
#endif /* WP_HAVE_EC_P192 */
#ifdef WP_HAVE_EC_P224
int test_ecdh_p224(void *data);
#endif /* WP_HAVE_EC_P224 */
#ifdef WP_HAVE_EC_P256
int test_ecdh_p256(void *data);
#endif /* WP_HAVE_EC_P256 */
#ifdef WP_HAVE_EC_P384
int test_ecdh_p384(void *data);
#endif /* WP_HAVE_EC_P384 */
#ifdef WP_HAVE_EC_P521
int test_ecdh_p521(void *data);
#endif /* WP_HAVE_EC_P521 */

#endif /* WP_HAVE_ECDH */

#ifdef WP_HAVE_ECDSA

#ifdef WP_HAVE_EC_P192
int test_ecdsa_p192_pkey(void *data);
int test_ecdsa_p192(void *data);
#endif /* WP_HAVE_EC_P192 */

#ifdef WP_HAVE_EC_P224
int test_ecdsa_p224_pkey(void *data);
int test_ecdsa_p224(void *data);
#endif /* WP_HAVE_EC_P224 */

#ifdef WP_HAVE_EC_P521
int test_ecdsa_p521_pkey(void *data);
#endif /* WP_HAVE_EC_P521 */

#ifdef WP_HAVE_EC_P256
int test_ecdsa_p256_pkey(void *data);
int test_ecdsa_p256(void *data);
#endif /* WP_HAVE_EC_P256 */

#ifdef WP_HAVE_EC_P384
int test_ecdsa_p384_pkey(void *data);
int test_ecdsa_p384(void *data);
#endif /* WP_HAVE_EC_P384 */

#ifdef WP_HAVE_EC_P521
int test_ecdsa_p521(void *data);
#endif /* WP_HAVE_EC_P521 */

int test_ec_load_key(void* data);
int test_ec_load_cert(void* data);
#endif /* WP_HAVE_ECDSA */

int test_ec_decode(void* data);
int test_ec_import(void* data);
int test_ec_null_init(void* data);

#endif /* WP_HAVE_ECC */

#ifdef WP_HAVE_PBE
int test_pbe(void *data);
#endif /* WP_HAVE_PBE */

#if defined(WP_HAVE_ED25519) || defined(WP_HAVE_ED448)
int test_ecx_sign_verify(void *data);
int test_ecx_sign_verify_raw_priv(void *data);
int test_ecx_sign_verify_raw_pub(void *data);
int test_ecx_misc(void *data);
int test_ecx_null_init(void *data);
#endif

int test_pkcs7_x509_sign_verify(void *data);
int test_x509_cert(void *data);

#endif /* UNIT_H */
