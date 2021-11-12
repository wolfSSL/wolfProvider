/* wolfprov.c
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

#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/prov_ssl.h>

#include "wolfprovider/version.h"
#include "wolfprovider/wp_wolfprov.h"
#include "wolfprovider/alg_funcs.h"


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

/*
 * Get he table of parameters supported by wolfProv.
 *
 * @param [in] provCtx  Unused.
 * @return  Table of supported paramaters.
 */
static const OSSL_PARAM* wolfprov_gettable_params(void* provCtx)
{
    (void)provCtx;

    return wolfssl_param_types;
}

/*
 * Returns whether the provider is running/useable.
 *
 * In FIPS, if there is an issue with the integrity check, then this can return
 * 0 to indicate provider is unuseable.
 *
 * @return  1 indicating provider is running.
 */
int wolfssl_prov_is_running(void)
{
    /* Always running. */
    return 1;
}

WC_RNG* wolfssl_prov_get_rng(WOLFPROV_CTX* provCtx)
{
    return &provCtx->rng;
}

/*
 * Creates a new provider context oject.
 *
 * @return  NULL on memory allocation failure.
 * @return  On success, provider context object.
 */
static WOLFPROV_CTX* wolfssl_prov_ctx_new(void)
{
    WOLFPROV_CTX* ctx;

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

    return ctx;
}

/*
 * Disposes of provider context object.
 *
 * @param [in] ctx  wolfSSL provider context object to dispose of.
 */
static void wolfssl_prov_ctx_free(WOLFPROV_CTX* ctx)
{
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
    /* MD5 */
    { WP_NAMES_MD5, WOLFPROV_PROPERTIES, wp_md5_functions,
      "" },
    /* MD5-SHA1 */
    { WP_NAMES_MD5_SHA1, WOLFPROV_PROPERTIES, wp_md5_sha1_functions,
      "" },
    /* SHA-1 */
    { WP_NAMES_SHA1, WOLFPROV_PROPERTIES, wp_sha1_functions,
      "" },

    /* SHA-2 */
    { WP_NAMES_SHA2_224, WOLFPROV_PROPERTIES, wp_sha224_functions,
      "" },
    { WP_NAMES_SHA2_256, WOLFPROV_PROPERTIES, wp_sha256_functions,
      "" },
    { WP_NAMES_SHA2_384, WOLFPROV_PROPERTIES, wp_sha384_functions,
      "" },
    { WP_NAMES_SHA2_512, WOLFPROV_PROPERTIES, wp_sha512_functions,
      "" },
    { WP_NAMES_SHA2_512_224, WOLFPROV_PROPERTIES,
      wp_sha512_224_functions,
      "" },
    { WP_NAMES_SHA2_512_256, WOLFPROV_PROPERTIES,
      wp_sha512_256_functions,
      "" },

    /* SHA-3 */
    { WP_NAMES_SHA3_224, WOLFPROV_PROPERTIES, wp_sha3_224_functions,
      "" },
    { WP_NAMES_SHA3_256, WOLFPROV_PROPERTIES, wp_sha3_256_functions,
      "" },
    { WP_NAMES_SHA3_384, WOLFPROV_PROPERTIES, wp_sha3_384_functions,
      "" },
    { WP_NAMES_SHA3_512, WOLFPROV_PROPERTIES, wp_sha3_512_functions,
      "" },

    /* SHAKE */
    { WP_NAMES_SHAKE_256, WOLFPROV_PROPERTIES, wp_shake_256_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of cipher algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_ciphers[] = {
    /* AES-GCM */
    { WP_NAMES_AES_256_GCM, WOLFPROV_PROPERTIES, wp_aes256gcm_functions,
      "" },
    { WP_NAMES_AES_192_GCM, WOLFPROV_PROPERTIES, wp_aes192gcm_functions,
      "" },
    { WP_NAMES_AES_128_GCM, WOLFPROV_PROPERTIES, wp_aes128gcm_functions,
      "" },

    /* AES-CCM */
    { WP_NAMES_AES_256_CCM, WOLFPROV_PROPERTIES, wp_aes256ccm_functions,
      "" },
    { WP_NAMES_AES_192_CCM, WOLFPROV_PROPERTIES, wp_aes192ccm_functions,
      "" },
    { WP_NAMES_AES_128_CCM, WOLFPROV_PROPERTIES, wp_aes128ccm_functions,
      "" },

    /* AES-CBC */
    { WP_NAMES_AES_256_CBC, WOLFPROV_PROPERTIES, wp_aes256cbc_functions,
      "" },
    { WP_NAMES_AES_192_CBC, WOLFPROV_PROPERTIES, wp_aes192cbc_functions,
      "" },
    { WP_NAMES_AES_128_CBC, WOLFPROV_PROPERTIES, wp_aes128cbc_functions,
      "" },

    /* AES-ECB */
    { WP_NAMES_AES_256_ECB, WOLFPROV_PROPERTIES, wp_aes256ecb_functions,
      "" },
    { WP_NAMES_AES_192_ECB, WOLFPROV_PROPERTIES, wp_aes192ecb_functions,
      "" },
    { WP_NAMES_AES_128_ECB, WOLFPROV_PROPERTIES, wp_aes128ecb_functions,
      "" },

    /* AES-CTR */
    { WP_NAMES_AES_256_CTR, WOLFPROV_PROPERTIES, wp_aes256ctr_functions,
      "" },
    { WP_NAMES_AES_192_CTR, WOLFPROV_PROPERTIES, wp_aes192ctr_functions,
      "" },
    { WP_NAMES_AES_128_CTR, WOLFPROV_PROPERTIES, wp_aes128ctr_functions,
      "" },

    /* AES Kwy Wrap - unpadded */
    { WP_NAMES_AES_256_WRAP, WOLFPROV_PROPERTIES, wp_aes256wrap_functions,
      "" },
    { WP_NAMES_AES_192_WRAP, WOLFPROV_PROPERTIES, wp_aes192wrap_functions,
      "" },
    { WP_NAMES_AES_128_WRAP, WOLFPROV_PROPERTIES, wp_aes128wrap_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of MAC algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_macs[] = {
    { WP_NAMES_HMAC, WOLFPROV_PROPERTIES, wp_hmac_functions,
      "" },
    { WP_NAMES_CMAC, WOLFPROV_PROPERTIES, wp_cmac_functions,
      "" },
    { WP_NAMES_GMAC, WOLFPROV_PROPERTIES, wp_gmac_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of KDF algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_kdfs[] = {
    { WP_NAMES_HKDF, WOLFPROV_PROPERTIES, wp_kdf_hkdf_functions,
      "" },
    { WP_NAMES_PBKDF2, WOLFPROV_PROPERTIES, wp_kdf_pbkdf2_functions,
      "" },
    { WP_NAMES_PKCS12KDF, WOLFPROV_PROPERTIES, wp_kdf_pkcs12_functions,
      "" },
    { WP_NAMES_TLS1_3_KDF, WOLFPROV_PROPERTIES, wp_kdf_tls1_3_kdf_functions,
      "" },
    { WP_NAMES_TLS1_PRF, WOLFPROV_PROPERTIES, wp_kdf_tls1_prf_functions,
      "" },

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
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_keymgmt_functions,
      "RSA" },
    { WP_NAMES_RSA_PSS, WOLFPROV_PROPERTIES, wp_rsapss_keymgmt_functions,
      "RSA_PSS" },

    { WP_NAMES_EC, WOLFPROV_PROPERTIES, wp_ecc_keymgmt_functions,
      "ECC" },

    { WP_NAMES_X25519, WOLFPROV_PROPERTIES, wp_x25519_keymgmt_functions,
      "X25519" },
    { WP_NAMES_X448, WOLFPROV_PROPERTIES, wp_x448_keymgmt_functions,
      "X448" },

    { WP_NAMES_ED25519, WOLFPROV_PROPERTIES, wp_ed25519_keymgmt_functions,
      "X25519" },
    { WP_NAMES_ED448, WOLFPROV_PROPERTIES, wp_ed448_keymgmt_functions,
      "X448" },

    { WP_NAMES_DH, WOLFPROV_PROPERTIES, wp_dh_keymgmt_functions,
      "DH" },
    { WP_NAMES_DHX, WOLFPROV_PROPERTIES, wp_dh_keymgmt_functions,
      "DHX" },

    { WP_NAMES_HMAC, WOLFPROV_PROPERTIES, wp_hmac_keymgmt_functions,
      "HMAC" },
    { WP_NAMES_CMAC, WOLFPROV_PROPERTIES, wp_cmac_keymgmt_functions,
      "CMAC" },

    { WP_NAMES_HKDF, WOLFPROV_PROPERTIES, wp_kdf_keymgmt_functions,
      "HKDF" },
    { WP_NAMES_TLS1_PRF, WOLFPROV_PROPERTIES, wp_kdf_keymgmt_functions,
      "HKDF" },
    { WP_NAMES_TLS1_3_KDF, WOLFPROV_PROPERTIES, wp_kdf_keymgmt_functions,
      "HKDF" },

    { NULL, NULL, NULL, NULL }
};

/* List of key exchange algorithm implementations available in wolfSSL provider.
 */
static const OSSL_ALGORITHM wolfprov_keyexch[] = {
    { WP_NAMES_ECDH, WOLFPROV_PROPERTIES, wp_ecdh_keyexch_functions,
      "" },
    { WP_NAMES_X25519, WOLFPROV_PROPERTIES, wp_x25519_keyexch_functions,
      "" },
    { WP_NAMES_X448, WOLFPROV_PROPERTIES, wp_x448_keyexch_functions,
      "" },
    { WP_NAMES_DH, WOLFPROV_PROPERTIES, wp_dh_keyexch_functions,
      "" },

    { WP_NAMES_HKDF, WOLFPROV_PROPERTIES, wp_hkdf_keyexch_functions,
      "" },
    { WP_NAMES_TLS1_PRF, WOLFPROV_PROPERTIES, wp_tls1_prf_keyexch_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of signature algorithm implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_signature[] = {
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_signature_functions,
      "" },
    { WP_NAMES_ECDSA, WOLFPROV_PROPERTIES, wp_ecdsa_signature_functions,
      "" },
    { WP_NAMES_ED25519, WOLFPROV_PROPERTIES, wp_ed25519_signature_functions,
      "" },
    { WP_NAMES_ED448, WOLFPROV_PROPERTIES, wp_ed448_signature_functions,
      "" },
    { WP_NAMES_HMAC, WOLFPROV_PROPERTIES, wp_hmac_signature_functions,
      "" },
    { WP_NAMES_CMAC, WOLFPROV_PROPERTIES, wp_cmac_signature_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of asymmetric encryption/decryption algorithm implementations available
 * in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_asym_cipher[] = {
    { WP_NAMES_RSA, WOLFPROV_PROPERTIES, wp_rsa_asym_cipher_functions,
      "" },

    { NULL, NULL, NULL, NULL }
};

/* List of asymmetric key encryption mechanicm algorithm implementations
 * available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_asym_kem[] = {
    { NULL, NULL, NULL, NULL }
};


/* The properties to indicate the supported DER format. */
#define WP_ENCODER_PROPERTIES(format, encoding) \
    WOLFPROV_PROPERTIES ",output=" #encoding ",structure=" #format

/* List of ASN.1 encoding implementations available in wolfSSL provider. */
static const OSSL_ALGORITHM wolfprov_encoder[] = {
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
#ifdef WOLFSSL_RSA_PSS_ENCODING
    /* TODO: RSA-PSS encoding isn't supported in wolfSSL */
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
#endif

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

    { WP_NAMES_DH, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_dh_spki_decoder_functions,
      "" },
    { WP_NAMES_DH, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_dh_pki_decoder_functions,
      "" },
    { WP_NAMES_DH, WP_DECODER_PROPERTIES(type-specific),
      wp_dh_type_specific_decoder_functions,
      "" },

    { WP_NAMES_EC, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_ecc_spki_decoder_functions,
      "" },
    { WP_NAMES_EC, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_ecc_pki_decoder_functions,
      "" },
    { WP_NAMES_EC, WP_DECODER_PROPERTIES(type-specific),
      wp_ecc_type_specific_decoder_functions,
      "" },

    { WP_NAMES_X25519, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_x25519_spki_decoder_functions,
      "" },
    { WP_NAMES_X25519, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_x25519_pki_decoder_functions,
      "" },

    { WP_NAMES_ED25519, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_ed25519_spki_decoder_functions,
      "" },
    { WP_NAMES_ED25519, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_ed25519_pki_decoder_functions,
      "" },

    { WP_NAMES_X448, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_x448_spki_decoder_functions,
      "" },
    { WP_NAMES_X448, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_x448_pki_decoder_functions,
      "" },

    { WP_NAMES_ED448, WP_DECODER_PROPERTIES(SubjectPublicKeyInfo),
      wp_ed448_spki_decoder_functions,
      "" },
    { WP_NAMES_ED448, WP_DECODER_PROPERTIES(PrivateKeyInfo),
      wp_ed448_pki_decoder_functions,
      "" },

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
    OSSL_FUNC_core_get_libctx_fn* c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
            case OSSL_FUNC_CORE_GETTABLE_PARAMS:
                c_gettable_params = OSSL_FUNC_core_gettable_params(in);
                break;
            case OSSL_FUNC_CORE_GET_PARAMS:
                c_get_params = OSSL_FUNC_core_get_params(in);
                break;
            case OSSL_FUNC_CORE_GET_LIBCTX:
                c_get_libctx = OSSL_FUNC_core_get_libctx(in);
                break;
            default:
                /* Just ignore anything we don't understand */
                break;
        }
    }

    if (c_get_libctx == NULL) {
        ok = 0;
    }

    if (ok) {
        /* Create a new provider context. */
        *provCtx = wolfssl_prov_ctx_new();
        if (*provCtx == NULL) {
            ok = 0;
        }
    }
    if (ok) {
        /* Store the library context in provider context. */
        wolfssl_prov_ctx_set0_lib_ctx(*provCtx,
            (OSSL_LIB_CTX*)c_get_libctx(handle));
        /* Cache the handle in provider context. */
        wolfssl_prov_ctx_set0_handle(*provCtx, handle);

        /* Return out dispatch table. */
        *out = wolfprov_dispatch_table;
    }

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

