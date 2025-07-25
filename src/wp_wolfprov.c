/* wolfprov.c
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

#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>
#include <openssl/bio.h>

#include "wolfprovider/version.h"
#include "wolfprovider/settings.h"
#include "wolfprovider/wp_wolfprov.h"
#include "wolfprovider/alg_funcs.h"

#include "wolfssl/wolfcrypt/logging.h"

const char* wolfprovider_id = "libwolfprov";

/* Core function that gets the table of parameters. */
static OSSL_FUNC_core_gettable_params_fn* c_gettable_params = NULL;
/* Core function that gets the parameters. */
static OSSL_FUNC_core_get_params_fn* c_get_params = NULL;

/* Parameters provided to the core */
static const OSSL_PARAM wolfssl_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

#ifdef WP_CHECK_FORCE_FAIL
static int forceFail = 0;
#endif

/*
 * Get he table of parameters supported by wolfProv.
 *
 * @param [in] provCtx  Unused.
 * @return  Table of supported parameters.
 */
static const OSSL_PARAM* wolfprov_gettable_params(void* provCtx)
{
    (void)provCtx;

    return wolfssl_param_types;
}

/*
 * Returns whether the provider is running/usable.
 *
 * In FIPS, if there is an issue with the integrity check, then this can return
 * 0 to indicate provider is unusable.
 *
 * @return  1 indicating provider is running.
 */
int wolfssl_prov_is_running(void)
{
#ifdef WP_CHECK_FORCE_FAIL
    if (forceFail) {
      WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 0);
      return 0;
    }
#endif
    /* Always running. */
    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

WC_RNG* wolfssl_prov_get_rng(WOLFPROV_CTX* provCtx)
{
    return &provCtx->rng;
}

static OSSL_FUNC_BIO_read_ex_fn *c_bio_read_ex = NULL;
static OSSL_FUNC_BIO_write_ex_fn *c_bio_write_ex = NULL;
static OSSL_FUNC_BIO_gets_fn *c_bio_gets = NULL;
static OSSL_FUNC_BIO_puts_fn *c_bio_puts = NULL;
static OSSL_FUNC_BIO_ctrl_fn *c_bio_ctrl = NULL;
static OSSL_FUNC_BIO_free_fn *c_bio_free = NULL;
static OSSL_FUNC_BIO_up_ref_fn *c_bio_up_ref = NULL;

static int wolfssl_prov_bio_read_ex(OSSL_CORE_BIO *bio, void *data, size_t data_len,
                          size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(bio, data, data_len, bytes_read);
}

static int wolfssl_prov_bio_write_ex(OSSL_CORE_BIO *bio, const void *data, size_t data_len,
                           size_t *written)
{
    if (c_bio_write_ex == NULL)
        return 0;
    return c_bio_write_ex(bio, data, data_len, written);
}

static int wolfssl_prov_bio_gets(OSSL_CORE_BIO *bio, char *buf, int size)
{
    if (c_bio_gets == NULL)
        return -1;
    return c_bio_gets(bio, buf, size);
}

static int wolfssl_prov_bio_puts(OSSL_CORE_BIO *bio, const char *str)
{
    if (c_bio_puts == NULL)
        return -1;
    return c_bio_puts(bio, str);
}

static int wolfssl_prov_bio_ctrl(OSSL_CORE_BIO *bio, int cmd, long num, void *ptr)
{
    if (c_bio_ctrl == NULL)
        return -1;
    return c_bio_ctrl(bio, cmd, num, ptr);
}

static int wolfssl_prov_bio_free(OSSL_CORE_BIO *bio)
{
    if (c_bio_free == NULL)
        return 0;
    return c_bio_free(bio);
}

int wolfssl_prov_bio_up_ref(OSSL_CORE_BIO *bio)
{
    if (c_bio_up_ref == NULL)
        return 0;
    return c_bio_up_ref(bio);
}


static int bio_core_read_ex(BIO *bio, char *data, size_t data_len,
                            size_t *bytes_read)
{
    return wolfssl_prov_bio_read_ex(BIO_get_data(bio), data, data_len, bytes_read);
}

static int bio_core_write_ex(BIO *bio, const char *data, size_t data_len,
                             size_t *written)
{
    return wolfssl_prov_bio_write_ex(BIO_get_data(bio), data, data_len, written);
}

static long bio_core_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    return wolfssl_prov_bio_ctrl(BIO_get_data(bio), cmd, num, ptr);
}

static int bio_core_gets(BIO *bio, char *buf, int size)
{
    return wolfssl_prov_bio_gets(BIO_get_data(bio), buf, size);
}

static int bio_core_puts(BIO *bio, const char *str)
{
    return wolfssl_prov_bio_puts(BIO_get_data(bio), str);
}

static int bio_core_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}
        
static int bio_core_free(BIO *bio)
{
    BIO_set_init(bio, 0);
    wolfssl_prov_bio_free(BIO_get_data(bio));
    
    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}

/*
 * Creates a new provider context object.
 *
 * @return  NULL on memory allocation failure.
 * @return  On success, provider context object.
 */
static WOLFPROV_CTX* wolfssl_prov_ctx_new(void)
{
    WOLFPROV_CTX* ctx;

#ifdef WC_RNG_SEED_CB
    wc_SetSeed_Cb(wc_GenerateSeed);
#endif

    ctx = (WOLFPROV_CTX*)OPENSSL_zalloc(sizeof(WOLFPROV_CTX));
    if ((ctx != NULL) && (wc_InitRng(&ctx->rng) != 0)) {
        OPENSSL_free(ctx);
        ctx = NULL;
    }
#ifndef WP_SINGLE_THREADED
    if ((ctx != NULL) && (wc_InitMutex(&ctx->rng_mutex) != 0)) {
        wc_FreeRng(&ctx->rng);
        OPENSSL_free(ctx);
        ctx = NULL;
    }
#endif

    if (ctx != NULL) {
        ctx->coreBioMethod = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, "BIO to Core filter");
        if (ctx->coreBioMethod == NULL
            || !BIO_meth_set_write_ex(ctx->coreBioMethod, bio_core_write_ex)
            || !BIO_meth_set_read_ex(ctx->coreBioMethod, bio_core_read_ex)
            || !BIO_meth_set_puts(ctx->coreBioMethod, bio_core_puts)
            || !BIO_meth_set_gets(ctx->coreBioMethod, bio_core_gets)
            || !BIO_meth_set_ctrl(ctx->coreBioMethod, bio_core_ctrl)
            || !BIO_meth_set_create(ctx->coreBioMethod, bio_core_new)
            || !BIO_meth_set_destroy(ctx->coreBioMethod, bio_core_free)) {
            BIO_meth_free(ctx->coreBioMethod);
#ifndef WP_SINGLE_THREADED
            wc_FreeMutex(&ctx->rng_mutex);
#endif
            wc_FreeRng(&ctx->rng);
            OPENSSL_free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

/*
 * Disposes of provider context object.
 *
 * @param [in] ctx  wolfSSL provider context object to dispose of.
 */
static void wolfssl_prov_ctx_free(WOLFPROV_CTX* ctx)
{
    BIO_meth_free(ctx->coreBioMethod);
#ifndef WP_SINGLE_THREADED
    wc_FreeMutex(&ctx->rng_mutex);
#endif
    wc_FreeRng(&ctx->rng);
    OPENSSL_free(ctx);
}

/*
 * Stores the library context object in the wolfSSL provider object.
 *
 * @param [in] ctx     wolfSSL provider context object.
 * @param [in] libCtx  Library context object.
 */
static void wolfssl_prov_ctx_set0_lib_ctx(WOLFPROV_CTX* ctx,
        OSSL_LIB_CTX* libCtx)
{
    if (ctx != NULL) {
        ctx->libCtx = libCtx;
    }
}

/*
 * Stores the handle in the wolfSSL provider object.
 *
 * @param [in] ctx     wolfSSL provider context object.
 * @param [in] handle  Handle to the core.
 */
static void wolfssl_prov_ctx_set0_handle(WOLFPROV_CTX* ctx,
        const OSSL_CORE_HANDLE* handle)
{
    if (ctx != NULL) {
        ctx->handle = handle;
    }
}

/*
 * Gets the parameters of the provider.
 *
 * @param [in]      provCtx  Provider context to get parameters for.
 * @param [in, out] params   Parameter id and space for value.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfprov_get_params(void* provCtx, OSSL_PARAM params[])
{
    int ok = 1;
    OSSL_PARAM* p;

    (void)provCtx;

    /* Look for provider name as a parameter to return. */
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    /* Set the string if name requested. */
    if ((p != NULL) && (!OSSL_PARAM_set_utf8_ptr(p, "wolfSSL Provider"))) {
        ok = 0;
    }
    if (ok) {
       /* Look for provider version as a parameter to return. */
        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
        /* Set the string if version requested. */
        if ((p != NULL) &&
                (!OSSL_PARAM_set_utf8_ptr(p, LIBWOLFPROV_VERSION_STRING))) {
            ok = 0;
        }
    }
    if (ok) {
       /* Look for provider build info as a parameter to return. */
        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
        /* Set the string if build info requested - wolfSSL version. */
        if ((p != NULL) && (!OSSL_PARAM_set_utf8_ptr(p,
                "wolfSSL " LIBWOLFSSL_VERSION_STRING))) {
            ok = 0;
        }
    }
    if (ok) {
       /* Look for provider status as a parameter to return. */
        p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
        /* Set the value if status requested - is running?. */
        if ((p != NULL) &&
               (!OSSL_PARAM_set_int(p, wolfssl_prov_is_running()))) {
            ok = 0;
        }
    }
    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifdef HAVE_FIPS
/* Properties of wolfSSL provider: name and FIPS wolfSSL. */
#define WOLFPROV_PROPERTIES     "provider=wolfprov,fips=yes"
#else
/* Properties of wolfSSL provider: name only. */
#define WOLFPROV_PROPERTIES     "provider=wolfprov"
#endif

/* List of digest algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_digests[] = {
#ifdef WP_HAVE_MD5
    /* MD5 */
    { WP_NAMES_MD5, WOLFPROV_PROPERTIES, wp_md5_functions,
      "" },
#endif
#ifdef WP_HAVE_MD5_SHA1
    /* MD5-SHA1 */
    { WP_NAMES_MD5_SHA1, WOLFPROV_PROPERTIES, wp_md5_sha1_functions,
      "" },
#endif
#ifdef WP_HAVE_SHA1
    /* SHA-1 */
    { WP_NAMES_SHA1, WOLFPROV_PROPERTIES, wp_sha1_functions,
      "" },
#endif

    /* SHA-2 */
#ifdef WP_HAVE_SHA224
    { WP_NAMES_SHA2_224, WOLFPROV_PROPERTIES, wp_sha224_functions,
      "" },
#endif
#ifdef WP_HAVE_SHA256
    { WP_NAMES_SHA2_256, WOLFPROV_PROPERTIES, wp_sha256_functions,
      "" },
#endif
#ifdef WP_HAVE_SHA384
    { WP_NAMES_SHA2_384, WOLFPROV_PROPERTIES, wp_sha384_functions,
      "" },
#endif
#ifdef WP_HAVE_SHA512
    { WP_NAMES_SHA2_512, WOLFPROV_PROPERTIES, wp_sha512_functions,
      "" },
#if LIBWOLFSSL_VERSION_HEX >= 0x05000000
#ifndef WOLFSSL_NOSHA512_224
    { WP_NAMES_SHA2_512_224, WOLFPROV_PROPERTIES,
      wp_sha512_224_functions,
      "" },
#endif /* !WOLFSSL_NOSHA512_224 */
#ifndef WOLFSSL_NOSHA512_256
    { WP_NAMES_SHA2_512_256, WOLFPROV_PROPERTIES,
      wp_sha512_256_functions,
      "" },
#endif /* !WOLFSSL_NOSHA512_256 */
#endif
#endif /* WP_HAVE_SHA512 */

    /* SHA-3 */
#ifdef WP_HAVE_SHA3
    { WP_NAMES_SHA3_224, WOLFPROV_PROPERTIES, wp_sha3_224_functions,
      "" },
    { WP_NAMES_SHA3_256, WOLFPROV_PROPERTIES, wp_sha3_256_functions,
      "" },
    { WP_NAMES_SHA3_384, WOLFPROV_PROPERTIES, wp_sha3_384_functions,
      "" },
    { WP_NAMES_SHA3_512, WOLFPROV_PROPERTIES, wp_sha3_512_functions,
      "" },
#endif

#ifdef WP_HAVE_SHAKE_256
    /* SHAKE */
    { WP_NAMES_SHAKE_256, WOLFPROV_PROPERTIES, wp_shake_256_functions,
      "" },
#endif

    { NULL, NULL, NULL, NULL }
};

/* List of cipher algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_ciphers[] = {
#ifdef WP_HAVE_AESGCM
    /* AES-GCM */
    { WP_NAMES_AES_256_GCM, WOLFPROV_PROPERTIES, wp_aes256gcm_functions,
      "" },
    { WP_NAMES_AES_192_GCM, WOLFPROV_PROPERTIES, wp_aes192gcm_functions,
      "" },
    { WP_NAMES_AES_128_GCM, WOLFPROV_PROPERTIES, wp_aes128gcm_functions,
      "" },
#endif

#ifdef WP_HAVE_AESCCM
    /* AES-CCM */
    { WP_NAMES_AES_256_CCM, WOLFPROV_PROPERTIES, wp_aes256ccm_functions,
      "" },
    { WP_NAMES_AES_192_CCM, WOLFPROV_PROPERTIES, wp_aes192ccm_functions,
      "" },
    { WP_NAMES_AES_128_CCM, WOLFPROV_PROPERTIES, wp_aes128ccm_functions,
      "" },
#endif

#ifdef WP_HAVE_AESCBC
    /* AES-CBC */
    { WP_NAMES_AES_256_CBC, WOLFPROV_PROPERTIES, wp_aes256cbc_functions,
      "" },
    { WP_NAMES_AES_192_CBC, WOLFPROV_PROPERTIES, wp_aes192cbc_functions,
      "" },
    { WP_NAMES_AES_128_CBC, WOLFPROV_PROPERTIES, wp_aes128cbc_functions,
      "" },
#endif

#ifdef WP_HAVE_AESECB
    /* AES-ECB */
    { WP_NAMES_AES_256_ECB, WOLFPROV_PROPERTIES, wp_aes256ecb_functions,
      "" },
    { WP_NAMES_AES_192_ECB, WOLFPROV_PROPERTIES, wp_aes192ecb_functions,
      "" },
    { WP_NAMES_AES_128_ECB, WOLFPROV_PROPERTIES, wp_aes128ecb_functions,
      "" },
#endif

#ifdef WP_HAVE_AESCTR
    /* AES-CTR */
    { WP_NAMES_AES_256_CTR, WOLFPROV_PROPERTIES, wp_aes256ctr_functions,
      "" },
    { WP_NAMES_AES_192_CTR, WOLFPROV_PROPERTIES, wp_aes192ctr_functions,
      "" },
    { WP_NAMES_AES_128_CTR, WOLFPROV_PROPERTIES, wp_aes128ctr_functions,
      "" },
#endif

#ifdef WP_HAVE_AESCFB
    /* AES-CFB */
    { WP_NAMES_AES_256_CFB, WOLFPROV_PROPERTIES, wp_aes256cfb_functions,
      "" },
    { WP_NAMES_AES_192_CFB, WOLFPROV_PROPERTIES, wp_aes192cfb_functions,
      "" },
    { WP_NAMES_AES_128_CFB, WOLFPROV_PROPERTIES, wp_aes128cfb_functions,
      "" },
#endif

#ifdef WP_HAVE_AESCTS
    /* AES-CTS */
    { WP_NAMES_AES_256_CTS, WOLFPROV_PROPERTIES, wp_aes256cts_functions,
      "" },
    { WP_NAMES_AES_192_CTS, WOLFPROV_PROPERTIES, wp_aes192cts_functions,
      "" },
    { WP_NAMES_AES_128_CTS, WOLFPROV_PROPERTIES, wp_aes128cts_functions,
      "" },
#endif

#ifdef HAVE_AES_KEYWRAP
    /* AES Kwy Wrap - unpadded */
    { WP_NAMES_AES_256_WRAP, WOLFPROV_PROPERTIES, wp_aes256wrap_functions,
      "" },
    { WP_NAMES_AES_192_WRAP, WOLFPROV_PROPERTIES, wp_aes192wrap_functions,
      "" },
    { WP_NAMES_AES_128_WRAP, WOLFPROV_PROPERTIES, wp_aes128wrap_functions,
      "" },
#endif

#ifdef WP_HAVE_DES3CBC
    { WP_NAMES_DES_EDE3_CBC, WOLFPROV_PROPERTIES, wp_des3cbc_functions,
     "" },
#endif

    { NULL, NULL, NULL, NULL }
};

/* List of MAC algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_macs[] = {
#ifdef WP_HAVE_HMAC
    { WP_NAMES_HMAC, WOLFPROV_PROPERTIES, wp_hmac_functions,
      "" },
#endif
#ifdef WP_HAVE_CMAC
    { WP_NAMES_CMAC, WOLFPROV_PROPERTIES, wp_cmac_functions,
      "" },
#endif
#ifdef WP_HAVE_AESGCM
    { WP_NAMES_GMAC, WOLFPROV_PROPERTIES, wp_gmac_functions,
      "" },
#endif

    { NULL, NULL, NULL, NULL }
};

/* List of KDF algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_kdfs[] = {
    { WP_NAMES_HKDF, WOLFPROV_PROPERTIES, wp_kdf_hkdf_functions,
      "" },
#ifndef NO_PWDBASED
    { WP_NAMES_PBKDF2, WOLFPROV_PROPERTIES, wp_kdf_pbkdf2_functions,
      "" },
#endif
#ifndef NO_PWDBASED
    { WP_NAMES_PKCS12KDF, WOLFPROV_PROPERTIES, wp_kdf_pkcs12_functions,
      "" },
#endif
    { WP_NAMES_TLS1_3_KDF, WOLFPROV_PROPERTIES, wp_kdf_tls1_3_kdf_functions,
      "" },
#ifdef WP_HAVE_TLS1_PRF
    { WP_NAMES_TLS1_PRF, WOLFPROV_PROPERTIES, wp_kdf_tls1_prf_functions,
      "" },
#endif
#ifdef WP_HAVE_KRB5KDF
    { WP_NAMES_KRB5KDF, WOLFPROV_PROPERTIES, wp_kdf_krb5kdf_functions,
      "" },
#endif

    { NULL, NULL, NULL, NULL }
};

/* List of RNG algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_rands[] = {
    { WP_NAMES_CTR_DRBG, WOLFPROV_PROPERTIES, wp_drbg_functions,
      "" },
    { WP_NAMES_HASH_DRBG, WOLFPROV_PROPERTIES, wp_drbg_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of key gen/import/export implementations available in wolfSSL provider.
 */
static const OSSL_ALGORITHM wolfprov_keymgmt[] = {
#ifdef WP_HAVE_RSA
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_keymgmt_functions,
      "RSA" },
    { WP_NAMES_RSA_PSS, WOLFPROV_PROPERTIES, wp_rsapss_keymgmt_functions,
      "RSA_PSS" },
#endif

#ifdef WP_HAVE_ECC
    { WP_NAMES_EC, WOLFPROV_PROPERTIES, wp_ecc_keymgmt_functions,
      "ECC" },
#endif

#ifdef WP_HAVE_X25519
    { WP_NAMES_X25519, WOLFPROV_PROPERTIES, wp_x25519_keymgmt_functions,
      "X25519" },
#endif
#ifdef WP_HAVE_X448
    { WP_NAMES_X448, WOLFPROV_PROPERTIES, wp_x448_keymgmt_functions,
      "X448" },
#endif

#ifdef WP_HAVE_ED25519
    { WP_NAMES_ED25519, WOLFPROV_PROPERTIES, wp_ed25519_keymgmt_functions,
      "X25519" },
#endif
#ifdef WP_HAVE_ED448
    { WP_NAMES_ED448, WOLFPROV_PROPERTIES, wp_ed448_keymgmt_functions,
      "X448" },
#endif

#ifdef WP_HAVE_DH
    { WP_NAMES_DH, WOLFPROV_PROPERTIES, wp_dh_keymgmt_functions,
      "DH" },
    { WP_NAMES_DHX, WOLFPROV_PROPERTIES, wp_dh_keymgmt_functions,
      "DHX" },
#endif

#ifdef WP_HAVE_HMAC
    { WP_NAMES_HMAC, WOLFPROV_PROPERTIES, wp_hmac_keymgmt_functions,
      "HMAC" },
#endif
#ifdef WP_HAVE_CMAC
    { WP_NAMES_CMAC, WOLFPROV_PROPERTIES, wp_cmac_keymgmt_functions,
      "CMAC" },
#endif

#ifdef WP_HAVE_HKDF
    { WP_NAMES_HKDF, WOLFPROV_PROPERTIES, wp_kdf_keymgmt_functions,
      "HKDF" },
#endif
    { WP_NAMES_TLS1_PRF, WOLFPROV_PROPERTIES, wp_kdf_keymgmt_functions,
      "HKDF" },
    { WP_NAMES_TLS1_3_KDF, WOLFPROV_PROPERTIES, wp_kdf_keymgmt_functions,
      "HKDF" },

    { NULL, NULL, NULL, NULL }
};

/* List of key exchange algorithm implementations available in wolfSSL provider.
 */
static const OSSL_ALGORITHM wolfprov_keyexch[] = {
#ifdef WP_HAVE_ECDH
    { WP_NAMES_ECDH, WOLFPROV_PROPERTIES, wp_ecdh_keyexch_functions,
      "" },
#endif
#ifdef WP_HAVE_X25519
    { WP_NAMES_X25519, WOLFPROV_PROPERTIES, wp_x25519_keyexch_functions,
      "" },
#endif
#ifdef WP_HAVE_X448
    { WP_NAMES_X448, WOLFPROV_PROPERTIES, wp_x448_keyexch_functions,
      "" },
#endif
#ifdef WP_HAVE_DH
    { WP_NAMES_DH, WOLFPROV_PROPERTIES, wp_dh_keyexch_functions,
      "" },
#endif

    { WP_NAMES_HKDF, WOLFPROV_PROPERTIES, wp_hkdf_keyexch_functions,
      "" },
    { WP_NAMES_TLS1_PRF, WOLFPROV_PROPERTIES, wp_tls1_prf_keyexch_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of signature algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_signature[] = {
#ifdef WP_HAVE_RSA
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_signature_functions,
      "" },
#endif
#ifdef WP_HAVE_ECDSA
    { WP_NAMES_ECDSA, WOLFPROV_PROPERTIES, wp_ecdsa_signature_functions,
      "" },
#endif
#ifdef WP_HAVE_ED25519
    { WP_NAMES_ED25519, WOLFPROV_PROPERTIES, wp_ed25519_signature_functions,
      "" },
#endif
#ifdef WP_HAVE_ED448
    { WP_NAMES_ED448, WOLFPROV_PROPERTIES, wp_ed448_signature_functions,
      "" },
#endif
#ifdef WP_HAVE_HMAC
    { WP_NAMES_HMAC, WOLFPROV_PROPERTIES, wp_hmac_signature_functions,
      "" },
#endif
#ifdef WP_HAVE_CMAC
    { WP_NAMES_CMAC, WOLFPROV_PROPERTIES, wp_cmac_signature_functions,
      "" },
#endif

    { NULL, NULL, NULL, NULL }
};

/* List of asymmetric encryption/decryption algorithm implementations available
 * in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_asym_cipher[] = {
#ifdef WP_HAVE_RSA
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_asym_cipher_functions,
      "" },
#endif

    { NULL, NULL, NULL, NULL }
};

/* List of asymmetric key encryption mechanism algorithm implementations
 * available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_asym_kem[] = {
#ifdef WP_HAVE_RSA
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_asym_kem_functions,
      "" },
#endif
    { NULL, NULL, NULL, NULL }
};


/* The properties to indicate the supported DER format. */
#define WP_ENCODER_PROPERTIES(format, encoding) \
    WOLFPROV_PROPERTIES ",output=" #encoding ",structure=" #format

/* List of ASN.1 encoding implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_encoder[] = {
#ifdef WP_HAVE_RSA
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_rsa_spki_der_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_rsa_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_rsa_pki_der_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_rsa_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_rsa_epki_der_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_rsa_epki_pem_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(type-specific, der),
      wp_rsa_kp_der_encoder_functions,
      "" },
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(type-specific, pem),
      wp_rsa_kp_pem_encoder_functions,
      "" },
#ifdef WOLFSSL_RSA_PSS_ENCODING
    { WP_NAMES_RSA_PSS, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_rsapss_spki_der_encoder_functions,
      "" },
    { WP_NAMES_RSA_PSS, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_rsapss_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_RSA_PSS, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_rsapss_pki_der_encoder_functions,
      "" },
    { WP_NAMES_RSA_PSS, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_rsapss_pki_pem_encoder_functions,
      "" },
    /*{ WP_NAMES_RSA, WOLFPROV_PROPERTIES ",output=text", \*/
    { WP_NAMES_RSA, WP_ENCODER_PROPERTIES(type-specific, text), \
      wp_rsa_text_encoder_functions,
      "" }, 
#endif
#endif /* WP_HAVE_RSA */

#ifdef WP_HAVE_DH
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(type-specific, der),
      wp_dh_type_specific_der_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(type-specific, pem),
      wp_dh_type_specific_pem_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_dh_spki_der_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_dh_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_dh_pki_der_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_dh_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_dh_epki_der_encoder_functions,
      "" },
    { WP_NAMES_DH, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_dh_epki_pem_encoder_functions,
      "" },
#endif

#ifdef WP_HAVE_ECC
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(type-specific, der),
      wp_ecc_type_specific_der_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(type-specific, pem),
      wp_ecc_type_specific_pem_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_ecc_spki_der_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_ecc_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_ecc_pki_der_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_ecc_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_ecc_epki_der_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_ecc_epki_pem_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(X9_62, der),
      wp_ecc_x9_62_der_encoder_functions,
      "" },
    { WP_NAMES_EC, WP_ENCODER_PROPERTIES(X9_62, pem),
      wp_ecc_x9_62_pem_encoder_functions,
      "" },
#endif

#ifdef WP_HAVE_X25519
    { WP_NAMES_X25519, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_x25519_spki_der_encoder_functions,
      "" },
    { WP_NAMES_X25519, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_x25519_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_X25519, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_x25519_pki_der_encoder_functions,
      "" },
    { WP_NAMES_X25519, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_x25519_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_X25519, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_x25519_epki_der_encoder_functions,
      "" },
    { WP_NAMES_X25519, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_x25519_epki_pem_encoder_functions,
      "" },
#endif

#ifdef WP_HAVE_ED25519
    { WP_NAMES_ED25519, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_ed25519_spki_der_encoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_ed25519_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_ed25519_pki_der_encoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_ed25519_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_ed25519_epki_der_encoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_ed25519_epki_pem_encoder_functions,
      "" },
#endif

#ifdef WP_HAVE_X448
    { WP_NAMES_X448, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_x448_spki_der_encoder_functions,
      "" },
    { WP_NAMES_X448, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_x448_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_X448, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_x448_pki_der_encoder_functions,
      "" },
    { WP_NAMES_X448, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_x448_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_X448, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_x448_epki_der_encoder_functions,
      "" },
    { WP_NAMES_X448, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_x448_epki_pem_encoder_functions,
      "" },
#endif

#ifdef WP_HAVE_ED448
    { WP_NAMES_ED448, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, der),
      wp_ed448_spki_der_encoder_functions,
      "" },
    { WP_NAMES_ED448, WP_ENCODER_PROPERTIES(SubjectPublicKeyInfo, pem),
      wp_ed448_spki_pem_encoder_functions,
      "" },
    { WP_NAMES_ED448, WP_ENCODER_PROPERTIES(PrivateKeyInfo, der),
      wp_ed448_pki_der_encoder_functions,
      "" },
    { WP_NAMES_ED448, WP_ENCODER_PROPERTIES(PrivateKeyInfo, pem),
      wp_ed448_pki_pem_encoder_functions,
      "" },
    { WP_NAMES_ED448, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, der),
      wp_ed448_epki_der_encoder_functions,
      "" },
    { WP_NAMES_ED448, WP_ENCODER_PROPERTIES(EncryptedPrivateKeyInfo, pem),
      wp_ed448_epki_pem_encoder_functions,
      "" },
#endif

    { NULL, NULL, NULL, NULL }
};


/* The properties to indicate the supported DER format. */
#define WP_DECODER_PROPERTIES(format) \
    WOLFPROV_PROPERTIES ",input=der,structure=" #format

/**
 * Create dummy decoder.
 *
 * @param [in] provCtx  Provider context.
 * @return  Provider context as a dummy decoder object.
 */
static WOLFPROV_CTX* wp_dummy_dec_new(WOLFPROV_CTX* provCtx)
{
    return provCtx;
}
/**
 * Dispose of dummy decoder.
 *
 * @param [in] provCtx  Provider context as a dummy decoder object. Unused.
 */
static void wp_dummy_dec_free(WOLFPROV_CTX* provCtx)
{
    (void)provCtx;
    return;
}
/**
 * Dummy decoder.
 *
 * @param [in] ctx        Provider context as a dummy decoder object. Unused.
 * @param [in] cBio       Core BIO to read data from. Unused.
 * @param [in] selection  Parts of key to export. Unused.
 * @param [in] dataCb     Callback to pass ECX key in parameters to. Unused.
 * @param [in] dataCbArg  Argument to pass to callback. Unused.
 * @param [in] pwCb       Password callback. Unused.
 * @param [in] pwCbArg    Argument to pass to password callback. Unused.
 * @return  1 on success.
 */
static int wp_dummy_decode(WOLFPROV_CTX* ctx, OSSL_CORE_BIO* cBio,
    int selection, OSSL_CALLBACK* dataCb, void* dataCbArg,
    OSSL_PASSPHRASE_CALLBACK* pwCb, void* pwCbArg)
{
    (void)ctx;
    (void)cBio;
    (void)selection;
    (void)dataCb;
    (void)dataCbArg;
    (void)pwCb;
    (void)pwCbArg;

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), 1);
    return 1;
}
/**
 * Dispatch table for dummy decoder.
 */
const OSSL_DISPATCH wp_dummy_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX,  (DFUNC)wp_dummy_dec_new  },
    { OSSL_FUNC_DECODER_FREECTX, (DFUNC)wp_dummy_dec_free },
    { OSSL_FUNC_DECODER_DECODE,  (DFUNC)wp_dummy_decode   },
    { 0, NULL }
};

/* List of ASN.1 decoding implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_decoder[] = {
#ifdef WP_HAVE_RSA
    { WP_NAMES_RSA, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_rsa_spki_decoder_functions,
      "" },
    { WP_NAMES_RSA, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_rsa_pki_decoder_functions,
      "" },
    { WP_NAMES_RSA, WP_DECODER_PROPERTIES(type-specific),
      wp_rsa_legacy_decoder_functions,
      "" },
    { WP_NAMES_RSA_PSS, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_rsapss_spki_decoder_functions,
      "" },
    { WP_NAMES_RSA_PSS, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_rsapss_pki_decoder_functions,
      "" },
#endif

#ifdef WP_HAVE_DH
    { WP_NAMES_DH, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_dh_spki_decoder_functions,
      "" },
    { WP_NAMES_DH, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_dh_pki_decoder_functions,
      "" },
    { WP_NAMES_DH, WP_DECODER_PROPERTIES(type-specific),
      wp_dh_type_specific_decoder_functions,
      "" },
    /* Add the same decoders for name "DHX" */
    { WP_NAMES_DHX, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_dh_spki_decoder_functions,
      "" },
    { WP_NAMES_DHX, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_dh_pki_decoder_functions,
      "" },
    { WP_NAMES_DHX, WP_DECODER_PROPERTIES(type-specific),
      wp_dh_type_specific_decoder_functions,
      "" },
#endif

#ifdef WP_HAVE_ECC
    { WP_NAMES_EC, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_ecc_spki_decoder_functions,
      "" },
    { WP_NAMES_EC, WP_DECODER_PROPERTIES(X9_62),
      wp_ecc_x9_62_decoder_functions,
      "" },
    { WP_NAMES_EC, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_ecc_pki_decoder_functions,
      "" },
    { WP_NAMES_EC, WP_DECODER_PROPERTIES(type-specific),
      wp_ecc_type_specific_decoder_functions,
      "" },
#endif

#ifdef WP_HAVE_X25519
    { WP_NAMES_X25519, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_x25519_spki_decoder_functions,
      "" },
    { WP_NAMES_X25519, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_x25519_pki_decoder_functions,
      "" },
#endif

#ifdef WP_HAVE_ED25519
    { WP_NAMES_ED25519, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_ed25519_spki_decoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_ed25519_pki_decoder_functions,
      "" },
#endif

#ifdef WP_HAVE_X448
    { WP_NAMES_X448, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_x448_spki_decoder_functions,
      "" },
    { WP_NAMES_X448, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_x448_pki_decoder_functions,
      "" },
#endif

#ifdef WP_HAVE_ED448
    { WP_NAMES_ED448, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_ed448_spki_decoder_functions,
      "" },
    { WP_NAMES_ED448, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_ed448_pki_decoder_functions,
      "" },
#endif

    /* Dummy decoder added to match PKI bit not match EPKI from context.
     * Flag set to say context type checked even though it didn't match and
     * not checked again.
     * PEM to DER implementation strips encryption.
     */
    { WP_NAMES_DER, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_dummy_decoder_functions,
      "" },

    { WP_NAMES_DER, WOLFPROV_PROPERTIES ",input=pem",
      wp_pem_to_der_decoder_functions,
      "" },

    { WP_NAMES_DER, WP_DECODER_PROPERTIES(EncryptedPrivateKeyInfo),
      wp_epki_to_pki_decoder_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of storage implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_store[] = {
    { WP_NAMES_FILE, WOLFPROV_PROPERTIES, wp_file_store_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/*
 * Returns the list of implementations available in wolfSSL provider for an
 * operation.
 *
 * @param [in]  provCtx   Provider context.
 * @param [in]  id        Id of operation.
 * @param [out] no_cache  Set to 0 as all pointers are cacheable.
 * @return  NULL on unupported operation.
 * @return  Otherwise a list of implementations for an operation.
 */
static const OSSL_ALGORITHM* wolfprov_query(void* provCtx, int id,
        int* no_cache)
{
    const OSSL_ALGORITHM* alg;

    (void)provCtx;

    *no_cache = 0;

    switch (id) {
        case OSSL_OP_DIGEST:
            alg = wolfprov_digests;
            break;
        case OSSL_OP_CIPHER:
            alg = wolfprov_ciphers;
            break;
        case OSSL_OP_MAC:
            alg = wolfprov_macs;
            break;
        case OSSL_OP_KDF:
            alg = wolfprov_kdfs;
            break;
        case OSSL_OP_RAND:
            alg = wolfprov_rands;
            break;
        case OSSL_OP_KEYMGMT:
            alg = wolfprov_keymgmt;
            break;
        case OSSL_OP_KEYEXCH:
            alg = wolfprov_keyexch;
            break;
        case OSSL_OP_SIGNATURE:
            alg = wolfprov_signature;
            break;
        case OSSL_OP_ASYM_CIPHER:
            alg = wolfprov_asym_cipher;
            break;
        case OSSL_OP_KEM:
            alg = wolfprov_asym_kem;
            break;
        case OSSL_OP_ENCODER:
            alg = wolfprov_encoder;
            break;
        case OSSL_OP_DECODER:
            alg = wolfprov_decoder;
            break;
        case OSSL_OP_STORE:
            alg = wolfprov_store;
            break;
        default:
            alg = NULL;
            break;
    }

    return alg;
}

/*
 * Teardown the provider context.
 *
 * @param [in] provCtx  Provider context.
 */
static void wolfprov_teardown(void* provCtx)
{
    wolfssl_prov_ctx_free(provCtx);
}

/* Table of functions the core will invoke. */
static const OSSL_DISPATCH wolfprov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (DFUNC)wolfprov_teardown            },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (DFUNC)wolfprov_gettable_params     },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (DFUNC)wolfprov_get_params          },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (DFUNC)wolfprov_query               },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
                                         (DFUNC)wolfssl_prov_get_capabilities },
    { 0, NULL }
};

#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>

    static void wp_fipsCb(int ok, int err, const char* hash)
    {
        (void)ok;
        (void)err;
        (void)hash;
        WOLFPROV_MSG(WP_LOG_PROVIDER,
           "in my Fips callback, ok = %d, err = %d\n", ok, err);
        WOLFPROV_MSG(WP_LOG_PROVIDER,
           "message = %s\n", wc_GetErrorString(err));
        WOLFPROV_MSG(WP_LOG_PROVIDER,
           "hash = %s\n", hash);

#ifdef WC_NO_ERR_TRACE
        if (err == WC_NO_ERR_TRACE(IN_CORE_FIPS_E)) {
#else
        if (err == IN_CORE_FIPS_E) {
#endif
            WOLFPROV_MSG(WP_LOG_PROVIDER,
               "In core integrity hash check failure, copy above hash\n");
            WOLFPROV_MSG(WP_LOG_PROVIDER,
               "into verifyCore[] in fips_test.c and rebuild\n");
        }
    }
#endif

/*
 * Initializes the wolfSSL provider.
 *
 * @param [in]  handle   Handle to the core.
 * @param [in]  in       Dispatch table from previous provider.
 * @param [out] out      Dispatch table of wolfSSL provider.
 * @param [out] provCtx  New provider context.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfssl_provider_init(const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in, const OSSL_DISPATCH** out, void** provCtx)
{
    int ok = 1;

#ifdef WOLFPROV_DEBUG
    ok = (wolfProv_Debugging_ON() == 0);
    if (ok) {
        if (wolfSSL_Debugging_ON() != 0) {
            WOLFPROV_MSG(WP_LOG_PROVIDER,
              "WARNING: wolfProvider built with debug but underlying wolfSSL is not!"
              "Building wolfSSl with debug is highly recommended, proceeding...");
        }
        else {
            wolfSSL_SetLoggingPrefix("wolfSSL");
        }
    }
#endif

#ifdef HAVE_FIPS
    wolfCrypt_SetCb_fips(wp_fipsCb);
#endif

#ifdef WP_CHECK_FORCE_FAIL
    char *forceFailEnv = NULL;
#if defined(XGETENV) && !defined(NO_GETENV)
    forceFailEnv = XGETENV("WOLFPROV_FORCE_FAIL");
    if (forceFailEnv != NULL && XATOI(forceFailEnv) == 1) {
        WOLFPROV_MSG(WP_LOG_PROVIDER, "WOLFPROV_FORCE_FAIL=1, Forcing failure\n");
        forceFail = 1;
    }
#else
#error "Force failure check enabled but impossible to perform without XGETENV, use -DWP_NO_FORCE_FAIL"
#endif
#endif

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
            case OSSL_FUNC_CORE_GETTABLE_PARAMS:
                c_gettable_params = OSSL_FUNC_core_gettable_params(in);
                break;
            case OSSL_FUNC_CORE_GET_PARAMS:
                c_get_params = OSSL_FUNC_core_get_params(in);
                break;
            case OSSL_FUNC_BIO_READ_EX:
                c_bio_read_ex = OSSL_FUNC_BIO_read_ex(in);
                break;
            case OSSL_FUNC_BIO_WRITE_EX:
                c_bio_write_ex = OSSL_FUNC_BIO_write_ex(in);
                break;
            case OSSL_FUNC_BIO_GETS:
                c_bio_gets = OSSL_FUNC_BIO_gets(in);
                break;
            case OSSL_FUNC_BIO_PUTS:
                c_bio_puts = OSSL_FUNC_BIO_puts(in);
                break;
            case OSSL_FUNC_BIO_CTRL:
                c_bio_ctrl = OSSL_FUNC_BIO_ctrl(in);
                break;
            case OSSL_FUNC_BIO_FREE:
                c_bio_free = OSSL_FUNC_BIO_free(in);
                break;
            case OSSL_FUNC_BIO_UP_REF:
                c_bio_up_ref = OSSL_FUNC_BIO_up_ref(in);
                break;
            default:
                /* Just ignore anything we don't understand */
                break;
        }
    }

    if (ok) {
        /* Create a new provider context. */
        *provCtx = wolfssl_prov_ctx_new();
        if (*provCtx == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        /* Using the OSSL_FUNC_core_get_libctx can yield you an
         * uninitialized libctx in certain init flows. Instead create
         * a new child libctx. The child libctx being NULL is allowed. */
        wolfssl_prov_ctx_set0_lib_ctx(*provCtx,
            OSSL_LIB_CTX_new_child(handle, in));
        /* Cache the handle in provider context. */
        wolfssl_prov_ctx_set0_handle(*provCtx, handle);

        /* Return out dispatch table. */
        *out = wolfprov_dispatch_table;
    }

    WOLFPROV_LEAVE(WP_LOG_PROVIDER, __FILE__ ":" WOLFPROV_STRINGIZE(__LINE__), ok);
    return ok;
}

#ifndef WP_NO_DYNAMIC_PROVIDER
/*
 * Initializes the wolfSSL provider - entry point for a dynamic library.
 *
 * @param [in]  handle   Handle to the core.
 * @param [in]  in       Dispatch table from previous provider.
 * @param [out] out      Dispatch table of wolfSSL provider.
 * @param [out] provCtx  New provider context.
 * @return  1 on success.
 * @return  0 on failure.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in, const OSSL_DISPATCH** out, void** provCtx)
{
    return wolfssl_provider_init(handle, in, out, provCtx);
}
#endif

