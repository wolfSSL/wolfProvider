#include <stdio.h>
#include <stdlib.h>

/* Test Configuration 1: Level 3 with cipher components */
#define WOLFPROV_DEBUG 1
#define WOLFPROV_LOG_LEVEL 3
#define WOLFPROV_LOG_COMPONENTS_FILTER (WP_LOG_AES | WP_LOG_DES)

#include "include/wolfprovider/wp_logging.h"

int main() {
    printf("=== Macro Combination Test: Level 3 + Ciphers ===\n");
    printf("Configuration:\n");
    printf("  WOLFPROV_LOG_LEVEL: %d\n", WOLFPROV_LOG_LEVEL);
    printf("  WOLFPROV_LOG_COMPONENTS_FILTER: 0x%x (AES|DES)\n", WOLFPROV_LOG_COMPONENTS_FILTER);
    printf("  WOLFPROV_COMPILE_TIME_LEVEL: 0x%x\n", WOLFPROV_COMPILE_TIME_LEVEL);
    
    printf("\nLevel 3 should include:\n");
    printf("  ERROR: %s\n", (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_ERROR) ? "YES" : "NO");
    printf("  ENTER: %s\n", (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_ENTER) ? "YES" : "NO");
    printf("  LEAVE: %s\n", (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_LEAVE) ? "YES" : "NO");
    printf("  INFO: %s\n", (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_INFO) ? "YES" : "NO");
    printf("  VERBOSE: %s\n", (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_VERBOSE) ? "YES" : "NO");
    printf("  DEBUG: %s\n", (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_DEBUG) ? "YES" : "NO");
    
    printf("\nComponent filtering:\n");
    printf("  AES VERBOSE: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_AES, WP_LOG_VERBOSE));
    printf("  DES VERBOSE: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_DES, WP_LOG_VERBOSE));
    printf("  HKDF VERBOSE: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_VERBOSE));
    printf("  RSA VERBOSE: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_RSA, WP_LOG_VERBOSE));
    
    return 0;
}
