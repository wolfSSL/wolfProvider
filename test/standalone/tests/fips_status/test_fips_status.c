/* test_fips_status.c
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

/* Exercises the FIPS-status gate in wolfssl_prov_is_running(): a healthy
 * module must report OSSL_PROV_PARAM_STATUS == 1 and perform a crypto op;
 * after a forced FIPS failure it must report 0 and reject the same op.
 *
 * Failure-injection mechanism is chosen at compile time from what the build
 * provides: wolfCrypt_SetStatus_fips() when the FIPS module was built with
 * HAVE_FORCE_FIPS_FAILURE (the define propagates via wolfssl options.h),
 * else ELF symbol interposition of wolfCrypt_GetStatus_fips() on Linux.
 * Interposition assumes a shared libwolfssl.
 *
 * A FIPS build with neither mechanism (non-Linux, no HAVE_FORCE_FIPS_FAILURE)
 * skips the failure phase. A non-FIPS build has no gate, so it checks the
 * healthy path only - unless WOLFSSL_ISFIPS=1 says FIPS was intended, which
 * means the build degraded and the gate would go untested. */

#if defined(__linux__) && !defined(_GNU_SOURCE)
/* Exposes RTLD_DEFAULT from glibc <dlfcn.h>; must precede any system header. */
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WOLFPROV_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#if defined(HAVE_FIPS) && defined(HAVE_FORCE_FIPS_FAILURE)
    #include <wolfssl/wolfcrypt/fips_test.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
    #define WP_CAN_FORCE_FIPS_FAILURE
#elif defined(HAVE_FIPS) && defined(__linux__)
    #include <wolfssl/wolfcrypt/fips_test.h>
    #include <wolfssl/wolfcrypt/error-crypt.h>
    #include <dlfcn.h>
    #define WP_CAN_FORCE_FIPS_FAILURE
    #define WP_USE_INTERPOSITION
#endif

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <wolfprovider/settings.h>
#include <wolfprovider/wp_logging.h>

#include "../../test_common.h"

#ifdef WP_USE_INTERPOSITION
static int forcedStatus = 0;

/* ELF executable-first resolution lands libwolfprov's call here, so the test
 * drives the status the provider sees. This exercises the provider gate, not
 * the real module POST - only the SetStatus path does that. */
int wolfCrypt_GetStatus_fips(void)
{
    return forcedStatus;
}
#endif

/* Read OSSL_PROV_PARAM_STATUS from the provider. Returns the status integer,
 * or -1 if the parameter could not be read. */
static int wp_get_prov_status(OSSL_PROVIDER *prov)
{
    int status = -1;
    OSSL_PARAM params[] = {
        { OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, &status, sizeof(status), 0 },
        { NULL, 0, NULL, 0, 0 }
    };

    if (OSSL_PROVIDER_get_params(prov, params) != 1) {
        TEST_ERROR("Failed to get provider status parameter");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return status;
}

/* Key and IV sizes of the AES-256-CBC probe below. */
#define WP_AES256_KEY_SZ    32
#define WP_AES_BLOCK_SZ     16

/* Run the gated AES-256-CBC encrypt init used to probe provider operability.
 * Returns 1 if the init succeeded, 0 if the provider rejected it, or -1 on a
 * setup error (fetch/alloc failure) unrelated to the provider running state. */
static int wp_aes_encrypt_init(OSSL_LIB_CTX *libctx)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char key[WP_AES256_KEY_SZ];
    unsigned char iv[WP_AES_BLOCK_SZ];
    int result = -1;

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));

    cipher = EVP_CIPHER_fetch(libctx, "AES-256-CBC", NULL);
    cctx = EVP_CIPHER_CTX_new();
    if (cipher != NULL && cctx != NULL) {
        result = (EVP_EncryptInit_ex(cctx, cipher, NULL, key, iv) == 1) ? 1 : 0;
    }

    if (cctx != NULL) {
        EVP_CIPHER_CTX_free(cctx);
    }
    if (cipher != NULL) {
        EVP_CIPHER_free(cipher);
    }
    return result;
}

#ifdef WP_CAN_FORCE_FIPS_FAILURE
/* Force the FIPS status the provider observes to a failure code.
 * Returns 0 on success, non-zero if the mechanism is unavailable. */
static int wp_force_fips_failure(void)
{
#ifdef WP_USE_INTERPOSITION
    int (*resolved)(void);

    /* Our definition must be first in global scope, else the provider cannot
     * be seeing it. Passing does not prove libwolfprov binds here; the status
     * assertion after injection is what proves that. */
    resolved = (int (*)(void))dlsym(RTLD_DEFAULT, "wolfCrypt_GetStatus_fips");
    if (resolved != &wolfCrypt_GetStatus_fips) {
        TEST_ERROR("Symbol interposition not in effect");
        return 1;
    }
    TEST_INFO("Forcing FIPS failure via interposed wolfCrypt_GetStatus_fips()");
    forcedStatus = IN_CORE_FIPS_E;
    return 0;
#else
    TEST_INFO("Forcing FIPS failure via wolfCrypt_SetStatus_fips()");
    if (wolfCrypt_SetStatus_fips(IN_CORE_FIPS_E) != 0) {
        TEST_ERROR("wolfCrypt_SetStatus_fips failed");
        return 1;
    }
    return 0;
#endif
}
#endif /* WP_CAN_FORCE_FIPS_FAILURE */

int main(int argc, char *argv[])
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
#ifndef HAVE_FIPS
    const char* fipsEnv = NULL;
#endif
    int status;
    int op;
    int ret = TEST_FAILURE;

    (void)argc;
    (void)argv;

    TEST_INFO("Starting FIPS provider status test");

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        TEST_ERROR("Failed to create OpenSSL library context");
        goto cleanup;
    }

    prov = OSSL_PROVIDER_load(libctx, "libwolfprov");
    if (prov == NULL) {
        TEST_ERROR("Failed to load libwolfprov provider");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Healthy module must report status 1 and perform a real crypto op. */
    status = wp_get_prov_status(prov);
    TEST_INFO("Provider status (healthy): %d", status);
    if (status != 1) {
        TEST_ERROR("Expected status 1 for healthy provider, got %d", status);
        goto cleanup;
    }

    op = wp_aes_encrypt_init(libctx);
    if (op < 0) {
        TEST_ERROR("Setup error running healthy crypto operation");
        goto cleanup;
    }
    if (op != 1) {
        TEST_ERROR("Healthy crypto operation was unexpectedly rejected");
        goto cleanup;
    }
    TEST_INFO("Crypto operation succeeded while healthy");

#ifdef WP_CAN_FORCE_FIPS_FAILURE
    /* Force a FIPS failure and confirm the provider now reports status 0
     * and rejects the same crypto operation that just succeeded. */
    if (wp_force_fips_failure() != 0) {
        goto cleanup;
    }

    status = wp_get_prov_status(prov);
    TEST_INFO("Provider status (after forced failure): %d", status);
    if (status != 0) {
        TEST_ERROR("Expected status 0 after FIPS failure, got %d", status);
        goto cleanup;
    }

    op = wp_aes_encrypt_init(libctx);
    if (op < 0) {
        TEST_ERROR("Setup error running post-failure crypto operation");
        goto cleanup;
    }
    if (op != 0) {
        TEST_ERROR("Crypto operation not rejected after FIPS failure");
        goto cleanup;
    }
    TEST_INFO("Crypto operation correctly rejected after FIPS failure");
#elif defined(HAVE_FIPS)
    /* Non-Linux FIPS build without HAVE_FORCE_FIPS_FAILURE: no way to inject a
     * failure here. A platform limit, not a regression, so skip. */
    TEST_INFO("SKIP: no FIPS failure-injection mechanism on this platform");
#else
    /* A build meant to be FIPS that lost HAVE_FIPS would pass the healthy path
     * while testing no gate at all. WOLFSSL_ISFIPS says FIPS was intended. */
    fipsEnv = getenv("WOLFSSL_ISFIPS");
    if (fipsEnv != NULL && strcmp(fipsEnv, "1") == 0) {
        TEST_ERROR("WOLFSSL_ISFIPS=1 but wolfSSL was built without FIPS");
        goto cleanup;
    }
    TEST_INFO("Not a FIPS build - only the healthy path applies");
#endif

    ret = TEST_SUCCESS;

cleanup:
    if (prov != NULL) {
        OSSL_PROVIDER_unload(prov);
    }
    if (libctx != NULL) {
        OSSL_LIB_CTX_free(libctx);
    }

    if (ret == TEST_SUCCESS) {
        TEST_INFO("Test PASSED");
    }
    else {
        TEST_ERROR("Test FAILED");
    }
    return ret;
}
