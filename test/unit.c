/* unit.c
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

#ifdef TEST_MULTITHREADED
#include <unistd.h>
#endif

#include <wolfprovider/wp_wolfprov.h>
#include <openssl/err.h>

#include "unit.h"

OSSL_LIB_CTX* wpLibCtx = NULL;
OSSL_LIB_CTX* osslLibCtx = NULL;
int noKeyLimits = 0;

#ifdef WOLFPROV_DEBUG
void print_buffer(const char *desc, const unsigned char *buffer, size_t len)
{
    size_t i;

    printf("%s:\n", desc);
    for (i = 0; i < len; i++) {
        printf("%02x ", buffer[i]);
        if ((i % 16) == 15) {
            printf("\n");
        }
    }
    if ((i % 16) != 0) {
        printf("\n");
    }
}
#endif

static int debug = 1;
static unsigned long flags = 0;

TEST_CASE test_case[] = {
    TEST_DECL(test_logging, &debug),
#ifdef WP_HAVE_SHA1
    TEST_DECL(test_sha, NULL),
#endif
#ifdef WP_HAVE_SHA224
    TEST_DECL(test_sha224, NULL),
#endif
#ifdef WP_HAVE_SHA256
    TEST_DECL(test_sha256, NULL),
#endif
#ifdef WP_HAVE_SHA384
    TEST_DECL(test_sha384, NULL),
#endif
#ifdef WP_HAVE_SHA512
    TEST_DECL(test_sha512, NULL),
#endif
#ifdef WP_HAVE_SHA3_224
    TEST_DECL(test_sha3_224, NULL),
#endif
#ifdef WP_HAVE_SHA3_256
    TEST_DECL(test_sha3_256, NULL),
#endif
#ifdef WP_HAVE_SHA3_384
    TEST_DECL(test_sha3_384, NULL),
#endif
#ifdef WP_HAVE_SHA3_512
    TEST_DECL(test_sha3_512, NULL),
#endif
#ifdef WP_HAVE_SHAKE_256
    TEST_DECL(test_shake_256, NULL),
#endif
#ifdef WP_HAVE_HMAC
    TEST_DECL(test_hmac_create, NULL),
#endif
#ifdef WP_HAVE_CMAC
    TEST_DECL(test_cmac_create, &flags),
#endif
#ifdef WP_HAVE_GMAC
    TEST_DECL(test_gmac_create, &flags),
#endif
#ifdef WP_HAVE_TLS1_PRF
    TEST_DECL(test_tls1_prf, NULL),
#endif
#ifdef WP_HAVE_HKDF
    TEST_DECL(test_hkdf, NULL),
#endif
#ifdef WP_HAVE_KRB5KDF
    TEST_DECL(test_krb5kdf, NULL),
#endif
#ifdef WP_HAVE_DES3CBC
    TEST_DECL(test_des3_cbc, NULL),
    TEST_DECL(test_des3_cbc_stream, NULL),
#endif
#ifdef WP_HAVE_AESECB
    TEST_DECL(test_aes128_ecb, NULL),
    TEST_DECL(test_aes192_ecb, NULL),
    TEST_DECL(test_aes256_ecb, NULL),
    TEST_DECL(test_aes128_ecb_stream, NULL),
    TEST_DECL(test_aes192_ecb_stream, NULL),
    TEST_DECL(test_aes256_ecb_stream, NULL),
#endif
#ifdef WP_HAVE_AESCBC
    TEST_DECL(test_aes128_cbc, NULL),
    TEST_DECL(test_aes192_cbc, NULL),
    TEST_DECL(test_aes256_cbc, NULL),
    TEST_DECL(test_aes128_cbc_stream, NULL),
    TEST_DECL(test_aes192_cbc_stream, NULL),
    TEST_DECL(test_aes256_cbc_stream, NULL),
    TEST_DECL(test_aes256_cbc_multiple, NULL),
#endif
#ifdef WP_HAVE_AESCTR
    TEST_DECL(test_aes128_ctr_stream, NULL),
    TEST_DECL(test_aes192_ctr_stream, NULL),
    TEST_DECL(test_aes256_ctr_stream, NULL),
#endif
#ifdef WP_HAVE_AESCFB
    TEST_DECL(test_aes128_cfb_stream, NULL),
    TEST_DECL(test_aes192_cfb_stream, NULL),
    TEST_DECL(test_aes256_cfb_stream, NULL),
#endif
#ifdef WP_HAVE_AESCTS
    TEST_DECL(test_aes128_cts, NULL),
    TEST_DECL(test_aes256_cts, NULL),
#endif
    TEST_DECL(test_cipher_null_zero, NULL),
#ifdef WP_HAVE_AESGCM
    TEST_DECL(test_aes128_gcm, NULL),
    TEST_DECL(test_aes192_gcm, NULL),
    TEST_DECL(test_aes256_gcm, NULL),
    TEST_DECL(test_aes128_gcm_fixed, NULL),
    TEST_DECL(test_aes128_gcm_tls, NULL),
#endif
#ifdef WP_HAVE_AESCCM
    TEST_DECL(test_aes128_ccm, NULL),
    TEST_DECL(test_aes192_ccm, NULL),
    TEST_DECL(test_aes256_ccm, NULL),
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    TEST_DECL(test_aes128_ccm_tls, NULL),
#endif
#endif
#ifdef WP_HAVE_RANDOM
    TEST_DECL(test_random, NULL),
#endif
#ifdef WP_HAVE_DH
    TEST_DECL(test_dh_pgen_pkey, NULL),
    TEST_DECL(test_dh_pkey, NULL),
    TEST_DECL(test_dh_decode, NULL),
    TEST_DECL(test_dh_krb5_keygen, NULL),
#ifndef WOLFPROV_QUICKTEST
    TEST_DECL(test_dh_get_params, NULL),
#endif
#endif /* WP_HAVE_DH */
#ifdef WP_HAVE_RSA
    TEST_DECL(test_rsa_sign_sha1, NULL),
    TEST_DECL(test_rsa_sign_verify_pkcs1, NULL),
    TEST_DECL(test_rsa_sign_verify_recover_pkcs1, NULL),
    TEST_DECL(test_rsa_sign_verify_pss, NULL),
    TEST_DECL(test_rsa_sign_verify_x931, NULL),
    TEST_DECL(test_rsa_enc_dec_pkcs1, NULL),
    TEST_DECL(test_rsa_enc_dec_oaep, NULL),
    TEST_DECL(test_rsa_enc_dec_nopad, NULL),
    TEST_DECL(test_rsa_pkey_keygen, NULL),
    TEST_DECL(test_rsa_pkey_invalid_key_size, NULL),
#ifndef WOLFPROV_QUICKTEST
    TEST_DECL(test_rsa_get_params, NULL),
#endif
    TEST_DECL(test_rsa_load_key, NULL),
    TEST_DECL(test_rsa_load_cert, NULL),
    TEST_DECL(test_rsa_fromdata, NULL),
    TEST_DECL(test_rsa_decode, NULL),
    TEST_DECL(test_rsa_null_init, NULL),
#endif /* WP_HAVE_RSA */
#ifdef WP_HAVE_EC_P192
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p192, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p192_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p192, NULL),
    #endif
    #ifdef WP_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p192_pkey, NULL),
        TEST_DECL(test_ecdsa_p192, NULL),
    #endif
#endif
#ifdef WP_HAVE_EC_P224
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p224, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p224_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p224, NULL),
    #endif
    #ifdef WP_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p224_pkey, NULL),
        TEST_DECL(test_ecdsa_p224, NULL),
    #endif
#endif
#ifdef WP_HAVE_EC_P256
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p256, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p256_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p256, NULL),
    #endif
    #ifdef WP_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p256_pkey, NULL),
        TEST_DECL(test_ecdsa_p256, NULL),
    #endif
    TEST_DECL(test_ec_decode, NULL),
    TEST_DECL(test_ec_import, NULL),
    TEST_DECL(test_ec_null_init, NULL),
#endif
#ifdef WP_HAVE_EC_P384
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p384, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p384_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p384, NULL),
    #endif
    #ifdef WP_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p384_pkey, NULL),
        TEST_DECL(test_ecdsa_p384, NULL),
    #endif
#endif
#ifdef WP_HAVE_EC_P521
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_p521, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_p521_keygen, NULL),
    #endif
        TEST_DECL(test_ecdh_p521, NULL),
    #endif
    #ifdef WP_HAVE_ECDSA
        TEST_DECL(test_ecdsa_p521_pkey, NULL),
        TEST_DECL(test_ecdsa_p521, NULL),
    #endif
#endif
#ifdef WP_HAVE_X25519
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_x25519, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_x25519_keygen, NULL),
    #endif
    #endif
#endif
#ifdef WP_HAVE_X448
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_eckeygen_x448, NULL),
    #endif
    #ifdef WP_HAVE_ECDH
    #ifdef WP_HAVE_ECKEYGEN
        TEST_DECL(test_ecdh_x448_keygen, NULL),
    #endif
    #endif
#endif
#ifdef WP_HAVE_ECKEYGEN
    TEST_DECL(test_eckeygen_name, NULL),
#endif

#ifdef WP_HAVE_ECDSA
    TEST_DECL(test_ec_load_key, NULL),
    TEST_DECL(test_ec_load_cert, NULL),
#endif /* WP_HAVE_ECDSA */

#ifdef WP_HAVE_PBE
    TEST_DECL(test_pbe, NULL),
#endif

#if defined(WP_HAVE_ED25519) || defined(WP_HAVE_ED448)
    TEST_DECL(test_ecx_sign_verify, NULL),
    TEST_DECL(test_ecx_sign_verify_raw_priv, NULL),
    TEST_DECL(test_ecx_sign_verify_raw_pub, NULL),
    TEST_DECL(test_ecx_misc, NULL),
    TEST_DECL(test_ecx_null_init, NULL),
#endif

    TEST_DECL(test_pkcs7_x509_sign_verify, NULL),
    TEST_DECL(test_x509_cert, NULL),
};
#define TEST_CASE_CNT   (int)(sizeof(test_case) / sizeof(*test_case))

static void usage(void)
{
    printf("\n");
    printf("Usage: unit.test [options]\n");
    printf("  --help          Show this usage information.\n");
    printf("  --static        Run the tests using the static provider.\n");
    printf("  --dir <path>    Location of wolfprovider shared library.\n");
    printf("                  Default: .libs (relative to test directory)\n");
    printf("  --provider <str>  Name of wolfssl provider. Default: libwolfprov\n");
    printf("  --no-key-limits   No limits on key size.\n");
#ifdef TEST_MULTITHREADED
    printf("  --secs <num>    Number of seconds to run for. Default: 10\n");
#endif
    printf("  --no-debug      Disable debug logging\n");
    printf("  --list          Display all test cases\n");
    printf("  --valgrind      Run wolfSSL only tests for Valgrind where OpenSSL "
                              "has issues\n");
    printf("  <num>           Run this test case, but not all\n");
}

#ifdef TEST_MULTITHREADED

static CRYPTO_RWLOCK *testLock = NULL;
static int stop = 0;
static int secs = 10;

static int LockInit()
{
    int err = 0;

    testLock = CRYPTO_THREAD_lock_new();
    if (testLock == NULL) {
        err = 1;
    }

    return err;
}

static void LockFree()
{
    CRYPTO_THREAD_lock_free(testLock);
}

static int LockRW()
{
    return CRYPTO_THREAD_write_lock(testLock) != 1;
}

static int UnlockRW()
{
    return CRYPTO_THREAD_unlock(testLock) != 1;
}

static int LockRO()
{
    return CRYPTO_THREAD_read_lock(testLock) != 1;
}

static int UnlockRO()
{
    return CRYPTO_THREAD_unlock(testLock) != 1;
}

static void *run_test(void *args)
{
    TEST_CASE *testCase = (TEST_CASE *)args;

    if (LockRO() != 0) {
        fprintf(stderr, "Locking failed\n");
    }
    else {
        while (!stop && !testCase->err) {
            testCase->err = testCase->func(testCase->data);
            testCase->cnt++;
        }
        testCase->done = 1;

        UnlockRO();
    }

    return NULL;
}

static int run_tests(int runAll)
{
    int err = 0;
    int i;

    err = LockInit();
    if (err != 0)
        fprintf(stderr, "Failed to initialize mutex!\n");
    else {
        err = LockRW();
        if (err != 0)
            fprintf(stderr, "Failed to lock mutex!\n");
        else {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                test_case[i].attempted = 0;

                if (!runAll && !test_case[i].run)
                    continue;

                if (err == 0) {
                    test_case[i].attempted = 1;

                    fprintf(stderr, "%d: %s ...\n", i + 1, test_case[i].name);

                    err = pthread_create(&test_case[i].thread, NULL, run_test,
                                                                 &test_case[i]);
                    if (err != 0)
                        fprintf(stderr, "Failed to create thread for: %d\n", i);
                }
            }

            UnlockRW();
        }
    }

    fprintf(stderr, "Running test cases for %d seconds\n", secs);
    for (i = 0; i < secs; i++) {
        sleep(1);
        fprintf(stderr, ".");
    }
    fprintf(stderr, "\n");

    stop = 1;
    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (!test_case[i].attempted)
            continue;

        pthread_join(test_case[i].thread, 0);
        fprintf(stderr, "%d: %s ... %d ... ", i + 1, test_case[i].name,
                                                              test_case[i].cnt);
        if (!test_case[i].err)
            fprintf(stderr, "PASSED\n");
        else
            fprintf(stderr, "FAILED (err: %d)\n", test_case[i].err);
        }

    LockFree();
    stop = 0;

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (test_case[i].done && test_case[i].err != 0) {
            err = test_case[i].err;
            break;
        }
    }

    if (err == 0) {
        printf("###### TESTSUITE SUCCESS\n");
    }
    else {
        for (i = 0; i < TEST_CASE_CNT; i++) {
            if (test_case[i].err) {
                printf("## FAIL: %d: %s (err: %d)\n", i + 1, test_case[i].name, test_case[i].err);
            }
        }
        printf("###### TESTSUITE FAILED\n");
    }

    return err;
}

#else

static int run_tests(int runAll)
{
    int err = 0;
    int i;

    printf("###### TESTSUITE START\n");
    if (flags) {
        printf("Using flags value %lx\n", flags);
    }
    printf("\n");

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (!runAll && !test_case[i].run) {
            continue;
        }

        printf("#### Start: %d - %s\n", i + 1, test_case[i].name);

        test_case[i].err = 0;
        test_case[i].err = test_case[i].func(test_case[i].data);
        test_case[i].done = 1;

        if (!test_case[i].err)
            printf("#### SUCCESS: %d - %s\n", i + 1, test_case[i].name);
        else
            printf("#### FAILED: %d - %s (err: %d)\n", i + 1, test_case[i].name, test_case[i].err);
        printf("\n");
    }

    for (i = 0; i < TEST_CASE_CNT; i++) {
        if (test_case[i].done && test_case[i].err != 0) {
            err = test_case[i].err;
            break;
        }
    }

    if (err == 0) {
        printf("###### TESTSUITE SUCCESS\n");
    }
    else {
        for (i = 0; i < TEST_CASE_CNT; i++) {
            if (test_case[i].err) {
                printf("## FAIL: %d: %s (err: %d)\n", i + 1, test_case[i].name, test_case[i].err);
            }
        }
        printf("###### TESTSUITE FAILED\n");
    }

    return err;
}

#endif

int main(int argc, char* argv[])
{
    int err = 0;
    OSSL_PROVIDER* osslProv = NULL;
    OSSL_PROVIDER* wpProv = NULL;
    int staticTest = 0;
    const char *name = wolfprovider_id;
    const char *dir = ".libs";
    int i;
    int runAll = 1;
    int runTests = 1;

    for (--argc, ++argv; argc > 0; argc--, argv++) {
        if (strncmp(*argv, "--help", 6) == 0) {
            usage();
            runAll = 0;
            break;
        }
        else if (strncmp(*argv, "--static", 9) == 0) {
            staticTest = 1;
        }
        else if (strncmp(*argv, "--valgrind", 11) == 0) {
            flags = flags | WP_VALGRIND_TEST;
        }
        else if (strncmp(*argv, "--dir", 6) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing directory argument\n");
                usage();
                err = 1;
                break;
            }
            dir = *argv;
            printf("Provider directory: %s\n", dir);
        }
        else if (strncmp(*argv, "--provider", 9) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing provider argument\n");
                usage();
                err = 1;
                break;
            }
            name = *argv;
            printf("Provider: %s\n", name);
        }
        else if (strncmp(*argv, "--no-key-limits", 11) == 0) {
            noKeyLimits = 1;
        }
#ifdef TEST_MULTITHREADED
        else if (strncmp(*argv, "--secs", 7) == 0) {
            argc--;
            argv++;
            if (argc == 0) {
                printf("\n");
                printf("Missing seconds argument\n");
                usage();
                err = 1;
                break;
            }
            secs = atoi(*argv);
            printf("Running tests for %d seconds\n", secs);
        }
#endif
        else if (strncmp(*argv, "--no-debug", 11) == 0) {
            debug = 0;
        }
        else if (strncmp(*argv, "--list", 7) == 0) {
            for (i = 0; i < TEST_CASE_CNT; i++) {
                printf("%2d: %s\n", i + 1, test_case[i].name);
            }
            runTests = 0;
        }
        else if ((i = atoi(*argv)) > 0) {
            if (i > TEST_CASE_CNT) {
                printf("Test case %d not found\n", i);
                err = 1;
                break;
            }

            printf("Run test case: %d\n", i);
            test_case[i-1].run = 1;
            runAll = 0;
        }
        else {
            printf("\n");
            printf("Unrecognized option: %s\n", *argv);
            usage();
            err = 1;
            break;
        }
    }

    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    if (err == 0 && runTests) {
        printf("\n");

        (void)staticTest;
        printf("Running tests using dynamic provider.\n");
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

        wpLibCtx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_set_default_search_path(wpLibCtx, dir);
        wpProv = OSSL_PROVIDER_load(wpLibCtx, name);
        if (wpProv == NULL) {
            PRINT_ERR_MSG("Failed to find wolf provider!\n");
            ERR_print_errors_fp(stderr);
            err = 1;
        }

        osslLibCtx = OSSL_LIB_CTX_new();
        osslProv = OSSL_PROVIDER_load(osslLibCtx, "default");
        if (osslProv == NULL) {
            PRINT_ERR_MSG("Failed to find default provider!\n");
            ERR_print_errors_fp(stderr);
            err = 1;
        }
    }

    if (err == 0 && runTests) {
        err = run_tests(runAll);
    }

    OSSL_PROVIDER_unload(osslProv);
    OSSL_LIB_CTX_free(osslLibCtx);
    OSSL_PROVIDER_unload(wpProv);
    OSSL_LIB_CTX_free(wpLibCtx);

    OPENSSL_cleanup();

    return err;
}

