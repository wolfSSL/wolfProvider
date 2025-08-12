#include <stdio.h>
#include <stdlib.h>

/* Test different macro configurations */
#define WOLFPROV_DEBUG 1
#define WOLFPROV_LOG_LEVEL 2
#define WOLFPROV_LOG_COMPONENTS_FILTER WP_LOG_HKDF

#include "include/wolfprovider/wp_logging.h"

int main() {
    printf("=== Macro-Based Logging Configuration Test ===\n");
    printf("WOLFPROV_LOG_LEVEL: %d\n", WOLFPROV_LOG_LEVEL);
    printf("WOLFPROV_LOG_COMPONENTS_FILTER: 0x%x\n", WOLFPROV_LOG_COMPONENTS_FILTER);
    printf("WOLFPROV_COMPILE_TIME_LEVEL: 0x%x\n", WOLFPROV_COMPILE_TIME_LEVEL);
    
    /* Test compile-time checks */
    printf("HKDF ERROR check: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_ERROR));
    printf("HKDF ENTER check: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_ENTER));
    printf("HKDF VERBOSE check: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_HKDF, WP_LOG_VERBOSE));
    printf("RSA ERROR check: %d\n", WOLFPROV_COMPILE_TIME_CHECK(WP_LOG_RSA, WP_LOG_ERROR));
    
    printf("\n=== Testing different configurations ===\n");
    printf("Level 2 includes ERROR (0x%x): %s\n", WP_LOG_ERROR, 
           (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_ERROR) ? "YES" : "NO");
    printf("Level 2 includes ENTER (0x%x): %s\n", WP_LOG_ENTER,
           (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_ENTER) ? "YES" : "NO");
    printf("Level 2 includes VERBOSE (0x%x): %s\n", WP_LOG_VERBOSE,
           (WOLFPROV_COMPILE_TIME_LEVEL & WP_LOG_VERBOSE) ? "YES" : "NO");
    
    return 0;
}
