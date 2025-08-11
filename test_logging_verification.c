#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WOLFPROV_DEBUG
#include "include/wolfprovider/wp_logging.h"
#else
#define WP_LOG_ERROR 1
#define WP_LOG_VERBOSE 16
#define WP_LOG_DEBUG 32
#define WP_LOG_FULL_DEBUG 62
#define WP_LOG_LEVEL_ALL 127
#define WP_LOG_HKDF 131072
#define WP_LOG_ECC 2097152
#define WP_LOG_RSA 256
#define WP_LOG_AES 2048
#define WP_LOG_HMAC 32768
#define WP_LOG_COMPONENTS_ALL -1

int wolfProv_ParseLogLevel(const char* levelStr) { return 0; }
int wolfProv_ParseComponents(const char* componentStr) { return 0; }
void wolfProv_InitLoggingFromEnv(void) { }
#endif

int main() {
    printf("=== Logging Verification Test ===\n");
    
    setenv("WOLFPROV_DEBUG", "1", 1);
    setenv("WOLFPROV_LOG_LEVEL", "all", 1);
    setenv("WOLFPROV_LOG_COMPONENTS", "hkdf", 1);
    
    printf("Environment variables set:\n");
    printf("  WOLFPROV_DEBUG=%s\n", getenv("WOLFPROV_DEBUG"));
    printf("  WOLFPROV_LOG_LEVEL=%s\n", getenv("WOLFPROV_LOG_LEVEL"));
    printf("  WOLFPROV_LOG_COMPONENTS=%s\n", getenv("WOLFPROV_LOG_COMPONENTS"));
    
#ifdef WOLFPROV_DEBUG
    printf("\nWOLFPROV_DEBUG is defined - logging should work\n");
    
    wolfProv_InitLoggingFromEnv();
    printf("Called wolfProv_InitLoggingFromEnv()\n");
    
    int level = wolfProv_ParseLogLevel("all");
    int components = wolfProv_ParseComponents("hkdf");
    printf("Parsed log level 'all': %d\n", level);
    printf("Parsed components 'hkdf': %d\n", components);
    
    printf("\nTesting direct logging calls:\n");
    WOLFPROV_MSG(WP_LOG_HKDF, "Test HKDF message");
    WOLFPROV_MSG_DEBUG(WP_LOG_HKDF, "Test HKDF debug message");
    WOLFPROV_ENTER(WP_LOG_HKDF, "test_function");
    WOLFPROV_LEAVE(WP_LOG_HKDF, "test_function", 1);
#else
    printf("\nWOLFPROV_DEBUG is NOT defined - logging is disabled\n");
#endif
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
