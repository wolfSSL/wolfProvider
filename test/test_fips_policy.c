/* test_fips_policy.c
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

#include "unit.h"
#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/proverr.h>

#ifdef WP_FIPS_DENY_LEGACY

/* Run first: a successful fetch must not leave errors from other algorithms
 * being constructed, and denial methods must survive NO_MD5/NO_DES3 builds. */
int test_fips_legacy_algorithms(void* data)
{
    static const char* digests[] = {
        "MD5", "SSL3-MD5", "1.2.840.113549.2.5", "MD5-SHA1"
    };
    static const char* ciphers[] = {
        "DES-EDE3-CBC", "DES3", "1.2.840.113549.3.7"
    };
    EVP_MD* md;
    EVP_CIPHER* cipher;
    unsigned char out[EVP_MAX_MD_SIZE], key[24], iv[8] = {0};
    unsigned int outLen;
    size_t i;
    int enc, err = 0;

    (void)data;
    ERR_clear_error();
    md = EVP_MD_fetch(wpLibCtx, "SHA256", "provider=wolfprov");
    if ((md == NULL) || (ERR_peek_error() != 0)) {
        PRINT_ERR_MSG("FIPS digest discovery left an error");
        err = 1;
    }
    EVP_MD_free(md);
#ifdef WP_HAVE_AESCBC
    cipher = EVP_CIPHER_fetch(wpLibCtx, "AES-128-CBC", "provider=wolfprov");
    if ((cipher == NULL) || (ERR_peek_error() != 0)) {
        PRINT_ERR_MSG("FIPS cipher discovery left an error");
        err = 1;
    }
    EVP_CIPHER_free(cipher);
#endif

    for (i = 0; !err && (i < sizeof(digests) / sizeof(digests[0])); i++) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        md = EVP_MD_fetch(wpLibCtx, digests[i], "provider=wolfprov");
        if ((ctx == NULL) || (md == NULL) || (ERR_peek_error() != 0) ||
            (EVP_MD_get0_provider(md) != wpProv) ||
            (EVP_MD_get_block_size(md) != 64) ||
            (EVP_MD_get_size(md) != ((i == 3) ? 36 : 16)) ||
            (EVP_MD_gettable_params(md) == NULL)) {
            PRINT_ERR_MSG("Invalid denial metadata: %s", digests[i]);
            err = 1;
        }
        if (!err && ((EVP_DigestInit_ex2(ctx, md, NULL) != 0) ||
                (ERR_peek_error() == 0))) {
            PRINT_ERR_MSG("FIPS digest initialization was not rejected: %s",
                digests[i]);
            err = 1;
        }
        ERR_clear_error();
        if (!err && ((EVP_Digest("abc", 3, out, &outLen, md, NULL) != 0) ||
                (ERR_peek_error() == 0))) {
            PRINT_ERR_MSG("FIPS digest operation was not rejected: %s",
                digests[i]);
            err = 1;
        }
        ERR_clear_error();
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
    }

    for (i = 0; i < sizeof(key); i++) {
        key[i] = (unsigned char)(i + 1);
    }
    for (i = 0; !err && (i < sizeof(ciphers) / sizeof(ciphers[0])); i++) {
        cipher = EVP_CIPHER_fetch(wpLibCtx, ciphers[i], "provider=wolfprov");
        if ((cipher == NULL) || (ERR_peek_error() != 0) ||
            (EVP_CIPHER_get0_provider(cipher) != wpProv) ||
            (EVP_CIPHER_get_key_length(cipher) != 24) ||
            (EVP_CIPHER_get_iv_length(cipher) != 8) ||
            (EVP_CIPHER_get_block_size(cipher) != 8) ||
            (EVP_CIPHER_gettable_params(cipher) == NULL)) {
            PRINT_ERR_MSG("Invalid denial metadata: %s", ciphers[i]);
            err = 1;
        }
        for (enc = 0; !err && (enc <= 1); enc++) {
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if ((ctx == NULL) ||
                (EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, NULL) != 0) ||
                (ERR_peek_error() == 0)) {
                PRINT_ERR_MSG("FIPS cipher initialization was not rejected: %s",
                    ciphers[i]);
                err = 1;
            }
            ERR_clear_error();
            EVP_CIPHER_CTX_free(ctx);
        }
        EVP_CIPHER_free(cipher);
    }
    ERR_clear_error();
    return err;
}

#if defined(WP_HAVE_HKDF) || defined(WP_HAVE_PBE) || defined(WP_HAVE_TLS1_PRF)
/* These KDFs call wolfCrypt directly after resolving a digest name. A denial
 * method's successful fetch must never enable the underlying MD5 operation. */
static int test_fips_kdf_digest(const char* name, const char* deniedDigest)
{
    EVP_KDF* kdf = EVP_KDF_fetch(wpLibCtx, name, "provider=wolfprov");
    const char* digests[] = { "SHA256", NULL };
    unsigned char key[64] = {0}, salt[16] = {0}, out[32];
    uint64_t iterations = 1000;
    int i, err = 0;

    digests[1] = deniedDigest;
    if ((kdf == NULL) || (EVP_KDF_get0_provider(kdf) != wpProv)) {
        PRINT_ERR_MSG("Failed to fetch FIPS KDF: %s", name);
        err = 1;
    }
    for (i = 0; !err && (i < 2); i++) {
        EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
        OSSL_PARAM params[6];
        size_t n = 0;
        params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)digests[i], 0);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_PROPERTIES, "provider=wolfprov", 0);
        if (strcmp(name, "PBKDF2") == 0) {
            params[n++] = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD, key, sizeof(key));
            params[n++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER,
                &iterations);
        }
        else {
            params[n++] = OSSL_PARAM_construct_octet_string(
                (strcmp(name, "TLS1-PRF") == 0) ? OSSL_KDF_PARAM_SECRET :
                OSSL_KDF_PARAM_KEY, key, sizeof(key));
        }
        params[n++] = OSSL_PARAM_construct_octet_string(
            (strcmp(name, "TLS1-PRF") == 0) ? OSSL_KDF_PARAM_SEED :
            OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
        params[n] = OSSL_PARAM_construct_end();
        ERR_clear_error();
        if ((ctx == NULL) ||
            (EVP_KDF_derive(ctx, out, sizeof(out), params) != (i == 0)) ||
            ((i == 1) && (ERR_peek_error() == 0))) {
            PRINT_ERR_MSG("Incorrect FIPS KDF policy: %s / %s", name,
                digests[i]);
            err = 1;
        }
        ERR_clear_error();
        EVP_KDF_CTX_free(ctx);
    }
    EVP_KDF_free(kdf);
    return err;
}
#endif

int test_fips_legacy_kdfs(void* data)
{
    int err = 0;
    (void)data;
#ifdef WP_HAVE_HKDF
    err = test_fips_kdf_digest("HKDF", "MD5");
#endif
#ifdef WP_HAVE_PBE
    if (!err) {
        err = test_fips_kdf_digest("PBKDF2", "MD5");
    }
#endif
#ifdef WP_HAVE_TLS1_PRF
    if (!err) {
        err = test_fips_kdf_digest("TLS1-PRF", "MD5-SHA1");
    }
#endif
    return err;
}

/* Use real encrypted keys to exercise the cipher, PRF and PEM restrictions. */
int test_fips_legacy_key_decrypt(void* data)
{
    int err = 0;
#ifdef WP_HAVE_RSA
    static const struct {
        const char* cipher;
        int pbe, prf, allowed, traditional;
    } cases[] = {
        { "AES-128-CBC", -1, NID_hmacWithSHA256, 1, 0 },
        { "AES-192-CBC", -1, NID_hmacWithSHA256, 1, 0 },
        { "AES-256-CBC", -1, NID_hmacWithSHA256, 1, 0 },
        /* SHA1 is the default PBKDF2 PRF and is omitted from the DER. */
        { "AES-256-CBC", -1, NID_hmacWithSHA1, 1, 0 },
#ifndef OPENSSL_NO_MD5
        { "AES-256-CBC", -1, NID_hmacWithMD5, 0, 0 },
        { "AES-256-CBC", -1, NID_undef, 0, 1 },
#endif
#ifndef OPENSSL_NO_DES
        { "DES-EDE3-CBC", -1, NID_hmacWithSHA256, 0, 0 },
        { "DES-EDE3-CBC", NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
            NID_undef, 0, 0 },
#endif
    };
    BIO* input = BIO_new_file(CERTS_DIR "/server-key.pem", "r");
    EVP_PKEY* key = NULL;
    PKCS8_PRIV_KEY_INFO* p8 = NULL;
    const char* pass = "wolfprov-test-pass";
    unsigned char salt[16] = {0};
    int scheme, format;

    if (input != NULL) {
        key = PEM_read_bio_PrivateKey_ex(input, NULL, NULL, NULL,
            osslLibCtx, NULL);
    }
    if (key != NULL) {
        p8 = EVP_PKEY2PKCS8(key);
    }
    err = (p8 == NULL);
    for (scheme = 0; !err &&
            (scheme < (int)(sizeof(cases) / sizeof(cases[0]))); scheme++) {
        EVP_CIPHER* cipher = EVP_CIPHER_fetch(osslLibCtx,
            cases[scheme].cipher, NULL);
        X509_SIG* epki = NULL;
#ifndef WP_HAVE_PKCS8_ENC
        /* Keep rejection coverage when this build cannot import AES keys. */
        if (cases[scheme].allowed) {
            EVP_CIPHER_free(cipher);
            continue;
        }
#endif
        err = (cipher == NULL);
        if (!err && !cases[scheme].traditional) {
            if (cases[scheme].pbe == -1) {
                X509_ALGOR* alg = PKCS5_pbe2_set_iv_ex(cipher, 2048, salt,
                    sizeof(salt), NULL, cases[scheme].prf, osslLibCtx);
                if (alg != NULL) {
                    epki = PKCS8_set0_pbe_ex(pass, (int)XSTRLEN(pass), p8,
                        alg, osslLibCtx, NULL);
                    if (epki == NULL) {
                        X509_ALGOR_free(alg);
                    }
                }
            }
            else {
                epki = PKCS8_encrypt_ex(cases[scheme].pbe, cipher,
                    pass, (int)XSTRLEN(pass), salt, sizeof(salt), 2048, p8,
                    osslLibCtx, NULL);
            }
            err = (epki == NULL);
        }
        for (format = cases[scheme].traditional; !err && (format < 2);
                format++) {
            BIO* encoded = BIO_new(BIO_s_mem());
            EVP_PKEY* decoded = NULL;
            OSSL_DECODER_CTX* ctx = NULL;
            char* bytes = NULL;
            unsigned long code;
            int rc = 0, denied = 0;

            if (encoded != NULL) {
                if (cases[scheme].traditional) {
                    rc = PEM_write_bio_PrivateKey_traditional(encoded, key,
                        cipher, (const unsigned char*)pass,
                        (int)XSTRLEN(pass), NULL, NULL);
                }
                else {
                    rc = (format == 0) ? i2d_PKCS8_bio(encoded, epki) :
                        PEM_write_bio_PKCS8(encoded, epki);
                }
            }
            err = (rc != 1);
            if (!err) {
                ctx = OSSL_DECODER_CTX_new_for_pkey(&decoded,
                    (format == 0) ? "DER" : "PEM", NULL, "RSA",
                    EVP_PKEY_KEYPAIR, wpLibCtx, "provider=wolfprov");
                err = (ctx == NULL) ||
                    (OSSL_DECODER_CTX_set_passphrase(ctx,
                        (const unsigned char*)pass, XSTRLEN(pass)) != 1);
            }
            ERR_clear_error();
            if (!err) {
                size_t len = (size_t)BIO_get_mem_data(encoded, &bytes);
                const unsigned char* p = (const unsigned char*)bytes;
                rc = OSSL_DECODER_from_data(ctx, &p, &len);
                while ((code = ERR_get_error()) != 0) {
                    denied |= (ERR_GET_LIB(code) == ERR_LIB_PROV) &&
                        (ERR_GET_REASON(code) == PROV_R_NOT_SUPPORTED);
                }
                /* Some bundles lack AES-192 PKCS#8 support. The policy must
                 * allow it; verify the key when the decoder supports it. */
                if (cases[scheme].allowed && (rc == 0) &&
                        (strcmp(cases[scheme].cipher, "AES-192-CBC") == 0)) {
                    err = denied || (decoded != NULL);
                }
                else if (cases[scheme].allowed) {
                    err = (rc != 1) || (decoded == NULL) ||
                        (EVP_PKEY_eq(key, decoded) != 1);
                }
                else {
                    err = (rc != 0) || (decoded != NULL) || !denied;
                }
            }
            if (err) {
                PRINT_ERR_MSG("Incorrect FIPS encrypted-key policy: %d / %d",
                    scheme, format);
            }
            OSSL_DECODER_CTX_free(ctx);
            EVP_PKEY_free(decoded);
            BIO_free(encoded);
        }
        X509_SIG_free(epki);
        EVP_CIPHER_free(cipher);
    }
    PKCS8_PRIV_KEY_INFO_free(p8);
    EVP_PKEY_free(key);
    BIO_free(input);
#endif
    (void)data;
    ERR_clear_error();
    return err;
}
#endif /* WP_FIPS_DENY_LEGACY */
