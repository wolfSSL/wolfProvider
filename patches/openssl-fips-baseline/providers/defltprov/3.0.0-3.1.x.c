/*
 * Copyright 2019-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Modified for wolfProvider FIPS Baseline - Minimal default provider for 3.0.0-3.1.x
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_util.h"
#include "prov/seeding.h"
#include "internal/nelem.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn deflt_gettable_params;
static OSSL_FUNC_provider_get_params_fn deflt_get_params;
static OSSL_FUNC_provider_query_operation_fn deflt_query;

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM deflt_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *deflt_gettable_params(void *provctx)
{
    return deflt_param_types;
}

static int deflt_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Default Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/*
 * FIPS Baseline: Minimal algorithm sets for wolfProvider testing
 * 3.0.0-3.1.x version - uses simpler algorithm structure without composite signatures
 */

/* FIPS Baseline Digests */
static const OSSL_ALGORITHM deflt_digests[] = {
    { PROV_NAMES_SHA1, "provider=default", ossl_sha1_functions },
    { PROV_NAMES_SHA2_224, "provider=default", ossl_sha224_functions },
    { PROV_NAMES_SHA2_256, "provider=default", ossl_sha256_functions },
    { PROV_NAMES_SHA2_384, "provider=default", ossl_sha384_functions },
    { PROV_NAMES_SHA2_512, "provider=default", ossl_sha512_functions },
    { PROV_NAMES_SHA2_512_224, "provider=default", ossl_sha512_224_functions },
    { PROV_NAMES_SHA2_512_256, "provider=default", ossl_sha512_256_functions },
    { PROV_NAMES_SHA3_224, "provider=default", ossl_sha3_224_functions },
    { PROV_NAMES_SHA3_256, "provider=default", ossl_sha3_256_functions },
    { PROV_NAMES_SHA3_384, "provider=default", ossl_sha3_384_functions },
    { PROV_NAMES_SHA3_512, "provider=default", ossl_sha3_512_functions },
    { PROV_NAMES_SHAKE_128, "provider=default", ossl_shake_128_functions },
    { PROV_NAMES_SHAKE_256, "provider=default", ossl_shake_256_functions },
    { PROV_NAMES_KECCAK_KMAC_128, "provider=default", ossl_keccak_kmac_128_functions },
    { PROV_NAMES_KECCAK_KMAC_256, "provider=default", ossl_keccak_kmac_256_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline Ciphers - AES only */
static const OSSL_ALGORITHM_CAPABLE deflt_ciphers[] = {
    ALG(PROV_NAMES_AES_256_ECB, ossl_aes256ecb_functions),
    ALG(PROV_NAMES_AES_192_ECB, ossl_aes192ecb_functions),
    ALG(PROV_NAMES_AES_128_ECB, ossl_aes128ecb_functions),
    ALG(PROV_NAMES_AES_256_CBC, ossl_aes256cbc_functions),
    ALG(PROV_NAMES_AES_192_CBC, ossl_aes192cbc_functions),
    ALG(PROV_NAMES_AES_128_CBC, ossl_aes128cbc_functions),
    ALG(PROV_NAMES_AES_256_OFB, ossl_aes256ofb_functions),
    ALG(PROV_NAMES_AES_192_OFB, ossl_aes192ofb_functions),
    ALG(PROV_NAMES_AES_128_OFB, ossl_aes128ofb_functions),
    ALG(PROV_NAMES_AES_256_CTR, ossl_aes256ctr_functions),
    ALG(PROV_NAMES_AES_192_CTR, ossl_aes192ctr_functions),
    ALG(PROV_NAMES_AES_128_CTR, ossl_aes128ctr_functions),
    ALG(PROV_NAMES_AES_256_GCM, ossl_aes256gcm_functions),
    ALG(PROV_NAMES_AES_192_GCM, ossl_aes192gcm_functions),
    ALG(PROV_NAMES_AES_128_GCM, ossl_aes128gcm_functions),
    ALG(PROV_NAMES_AES_256_CCM, ossl_aes256ccm_functions),
    ALG(PROV_NAMES_AES_192_CCM, ossl_aes192ccm_functions),
    ALG(PROV_NAMES_AES_128_CCM, ossl_aes128ccm_functions),
    { { NULL, NULL, NULL }, NULL }
};
static OSSL_ALGORITHM exported_ciphers[OSSL_NELEM(deflt_ciphers)];

/* FIPS Baseline MACs */
static const OSSL_ALGORITHM deflt_macs[] = {
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, "provider=default", ossl_cmac_functions },
#endif
    { PROV_NAMES_GMAC, "provider=default", ossl_gmac_functions },
    { PROV_NAMES_HMAC, "provider=default", ossl_hmac_functions },
    { PROV_NAMES_KMAC_128, "provider=default", ossl_kmac128_functions },
    { PROV_NAMES_KMAC_256, "provider=default", ossl_kmac256_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline KDFs */
static const OSSL_ALGORITHM deflt_kdfs[] = {
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_hkdf_functions },
    { PROV_NAMES_TLS1_3_KDF, "provider=default", ossl_kdf_tls1_3_kdf_functions },
    { PROV_NAMES_PBKDF2, "provider=default", ossl_kdf_pbkdf2_functions },
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_tls1_prf_functions },
    { PROV_NAMES_KBKDF, "provider=default", ossl_kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline Key Exchange */
static const OSSL_ALGORITHM deflt_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { PROV_NAMES_DH, "provider=default", ossl_dh_keyexch_functions },
#endif
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_ECDH, "provider=default", ossl_ecdh_keyexch_functions },
#endif
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_tls1_prf_keyexch_functions },
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_hkdf_keyexch_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline RNGs */
static const OSSL_ALGORITHM deflt_rands[] = {
    { PROV_NAMES_CTR_DRBG, "provider=default", ossl_drbg_ctr_functions },
    { PROV_NAMES_HASH_DRBG, "provider=default", ossl_drbg_hash_functions },
    { PROV_NAMES_HMAC_DRBG, "provider=default", ossl_drbg_ossl_hmac_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline Signatures - 3.3.x style (no composite names) */
static const OSSL_ALGORITHM deflt_signature[] = {
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_signature_functions },
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_ECDSA, "provider=default", ossl_ecdsa_signature_functions },
#endif
    { PROV_NAMES_HMAC, "provider=default", ossl_mac_legacy_hmac_signature_functions },
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, "provider=default", ossl_mac_legacy_cmac_signature_functions },
#endif
    { NULL, NULL, NULL }
};

/* FIPS Baseline Asymmetric Ciphers */
static const OSSL_ALGORITHM deflt_asym_cipher[] = {
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline KEM */
static const OSSL_ALGORITHM deflt_asym_kem[] = {
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_asym_kem_functions },
    { NULL, NULL, NULL }
};

/* FIPS Baseline Key Management */
static const OSSL_ALGORITHM deflt_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { PROV_NAMES_DH, "provider=default", ossl_dh_keymgmt_functions,
      PROV_DESCS_DH },
    { PROV_NAMES_DHX, "provider=default", ossl_dhx_keymgmt_functions,
      PROV_DESCS_DHX },
#endif
    { PROV_NAMES_RSA, "provider=default", ossl_rsa_keymgmt_functions,
      PROV_DESCS_RSA },
    { PROV_NAMES_RSA_PSS, "provider=default", ossl_rsapss_keymgmt_functions,
      PROV_DESCS_RSA_PSS },
#ifndef OPENSSL_NO_EC
    { PROV_NAMES_EC, "provider=default", ossl_ec_keymgmt_functions,
      PROV_DESCS_EC },
#endif
    { PROV_NAMES_TLS1_PRF, "provider=default", ossl_kdf_keymgmt_functions,
      PROV_DESCS_TLS1_PRF_SIGN },
    { PROV_NAMES_HKDF, "provider=default", ossl_kdf_keymgmt_functions,
      PROV_DESCS_HKDF_SIGN },
    { PROV_NAMES_HMAC, "provider=default", ossl_mac_legacy_keymgmt_functions,
      PROV_DESCS_HMAC_SIGN },
#ifndef OPENSSL_NO_CMAC
    { PROV_NAMES_CMAC, "provider=default", ossl_cmac_legacy_keymgmt_functions,
      PROV_DESCS_CMAC_SIGN },
#endif
    { NULL, NULL, NULL }
};

/* FIPS Baseline Encoders/Decoders - minimal */
static const OSSL_ALGORITHM deflt_encoder[] = {
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_decoder[] = {
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM deflt_store[] = {
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *deflt_query(void *provctx, int operation_id,
                                          int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return deflt_digests;
    case OSSL_OP_CIPHER:
        return exported_ciphers;
    case OSSL_OP_MAC:
        return deflt_macs;
    case OSSL_OP_KDF:
        return deflt_kdfs;
    case OSSL_OP_RAND:
        return deflt_rands;
    case OSSL_OP_KEYMGMT:
        return deflt_keymgmt;
    case OSSL_OP_KEYEXCH:
        return deflt_keyexch;
    case OSSL_OP_SIGNATURE:
        return deflt_signature;
    case OSSL_OP_ASYM_CIPHER:
        return deflt_asym_cipher;
    case OSSL_OP_KEM:
        return deflt_asym_kem;
    case OSSL_OP_ENCODER:
        return deflt_encoder;
    case OSSL_OP_DECODER:
        return deflt_decoder;
    case OSSL_OP_STORE:
        return deflt_store;
    }
    return NULL;
}

static void deflt_teardown(void *provctx)
{
    BIO_meth_free(ossl_prov_ctx_get0_core_bio_method(provctx));
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH deflt_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))deflt_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))deflt_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))deflt_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))deflt_query },
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))ossl_prov_get_capabilities },
    { 0, NULL }
};

OSSL_provider_init_fn ossl_default_provider_init;

int ossl_default_provider_init(const OSSL_CORE_HANDLE *handle,
                               const OSSL_DISPATCH *in,
                               const OSSL_DISPATCH **out,
                               void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    BIO_METHOD *corebiometh;

    if (!ossl_prov_bio_from_dispatch(in)
            || !ossl_prov_seeding_from_dispatch(in))
        return 0;
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

    if (c_get_libctx == NULL)
        return 0;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
            || (corebiometh = ossl_bio_prov_init_bio_method()) == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx,
                              (OSSL_LIB_CTX *)c_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_bio_method(*provctx, corebiometh);

    ossl_prov_cache_exported_algorithms(deflt_ciphers, exported_ciphers);

    *out = deflt_dispatch_table;

    return 1;
}
