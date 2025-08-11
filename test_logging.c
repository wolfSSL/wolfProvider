#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

int test_hkdf_logging() {
    printf("=== Testing HKDF Logging ===\n");
    
    OSSL_PROVIDER *wolfprov = OSSL_PROVIDER_load(NULL, "wolfprovider");
    if (!wolfprov) {
        printf("Failed to load wolfProvider\n");
        return 0;
    }
    
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", "provider=wolfprovider");
    if (!kdf) {
        printf("Failed to fetch HKDF\n");
        OSSL_PROVIDER_unload(wolfprov);
        return 0;
    }
    
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx) {
        printf("Failed to create HKDF context\n");
        EVP_KDF_free(kdf);
        OSSL_PROVIDER_unload(wolfprov);
        return 0;
    }
    
    unsigned char key[32] = "test_key_1234567890123456789012";
    unsigned char salt[16] = "test_salt_123456";
    unsigned char info[16] = "test_info_123456";
    unsigned char output[32];
    
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, sizeof(key)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info)),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, (int[]){EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND}),
        OSSL_PARAM_construct_end()
    };
    
    printf("Setting HKDF parameters (should see ENTER/LEAVE and debug logs)...\n");
    if (EVP_KDF_CTX_set_params(ctx, params) <= 0) {
        printf("Failed to set HKDF parameters\n");
    } else {
        printf("HKDF parameters set successfully\n");
    }
    
    printf("Deriving HKDF key (should see detailed debug logs)...\n");
    if (EVP_KDF_derive(ctx, output, sizeof(output), NULL) <= 0) {
        printf("Failed to derive HKDF key\n");
    } else {
        printf("HKDF derivation successful\n");
    }
    
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    OSSL_PROVIDER_unload(wolfprov);
    
    return 1;
}

int test_algorithm_queries() {
    printf("\n=== Testing Algorithm Query Logging ===\n");
    
    OSSL_PROVIDER *wolfprov = OSSL_PROVIDER_load(NULL, "wolfprovider");
    if (!wolfprov) {
        printf("Failed to load wolfProvider\n");
        return 0;
    }
    
    printf("Querying algorithms (should see query logs)...\n");
    
    EVP_MD *md = EVP_MD_fetch(NULL, "SHA256", "provider=wolfprovider");
    if (md) {
        printf("SHA256 fetch successful\n");
        EVP_MD_free(md);
    }
    
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "provider=wolfprovider");
    if (cipher) {
        printf("AES-256-CBC fetch successful\n");
        EVP_CIPHER_free(cipher);
    }
    
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", "provider=wolfprovider");
    if (kdf) {
        printf("PBKDF2 fetch successful\n");
        EVP_KDF_free(kdf);
    }
    
    OSSL_PROVIDER_unload(wolfprov);
    return 1;
}

int main() {
    printf("wolfProvider Enhanced Logging System Test\n");
    printf("=========================================\n");
    printf("Note: Enable wolfProvider debugging to see detailed logs\n\n");
    
    if (!test_hkdf_logging()) {
        printf("HKDF logging test failed\n");
        return 1;
    }
    
    if (!test_algorithm_queries()) {
        printf("Algorithm query test failed\n");
        return 1;
    }
    
    printf("\n=== All Tests Completed ===\n");
    printf("Check the output above for logging behavior\n");
    printf("To see detailed logs, set WOLFPROV_DEBUG=1 environment variable\n");
    
    return 0;
}
