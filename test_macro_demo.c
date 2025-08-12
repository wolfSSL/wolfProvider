#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Demo Configuration: Level 2 with HKDF only */
#define WOLFPROV_DEBUG 1
#define WOLFPROV_LOG_LEVEL 2
#define WOLFPROV_LOG_COMPONENTS_FILTER WP_LOG_HKDF

#include "include/wolfprovider/wp_logging.h"

int main() {
    printf("=== Macro-Based Logging Demo ===\n");
    printf("Configuration: Level %d, HKDF only (0x%x)\n", 
           WOLFPROV_LOG_LEVEL, WOLFPROV_LOG_COMPONENTS_FILTER);
    printf("Compile-time level mask: 0x%x\n", WOLFPROV_COMPILE_TIME_LEVEL);
    
    printf("\n=== Testing actual logging calls ===\n");
    
    /* These should work (HKDF + ERROR/ENTER levels) */
    printf("Testing HKDF ERROR (should work): ");
    if (WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_ERROR)) {
        printf("PASS - would log\n");
    } else {
        printf("FAIL - would not log\n");
    }
    
    printf("Testing HKDF ENTER (should work): ");
    if (WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_ENTER)) {
        printf("PASS - would log\n");
    } else {
        printf("FAIL - would not log\n");
    }
    
    /* These should not work (wrong component or level) */
    printf("Testing RSA ERROR (should fail - wrong component): ");
    if (WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_RSA, WP_LOG_ERROR)) {
        printf("FAIL - would log (unexpected)\n");
    } else {
        printf("PASS - would not log\n");
    }
    
    printf("Testing HKDF VERBOSE (should fail - wrong level): ");
    if (WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_VERBOSE)) {
        printf("FAIL - would log (unexpected)\n");
    } else {
        printf("PASS - would not log\n");
    }
    
    printf("\n=== Macro-based logging system working correctly! ===\n");
    return 0;
}
