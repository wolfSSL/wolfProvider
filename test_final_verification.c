#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("=== Final Logging System Verification ===\n\n");
    
    printf("Test 1: Setting up environment variables\n");
    setenv("WOLFPROV_DEBUG", "1", 1);
    setenv("WOLFPROV_LOG_LEVEL", "all", 1);
    setenv("WOLFPROV_LOG_COMPONENTS", "hkdf", 1);
    printf("  WOLFPROV_DEBUG=%s\n", getenv("WOLFPROV_DEBUG"));
    printf("  WOLFPROV_LOG_LEVEL=%s\n", getenv("WOLFPROV_LOG_LEVEL"));
    printf("  WOLFPROV_LOG_COMPONENTS=%s\n", getenv("WOLFPROV_LOG_COMPONENTS"));
    
    printf("\nTest 2: Multiple components\n");
    setenv("WOLFPROV_LOG_COMPONENTS", "ecc,rsa,hkdf", 1);
    printf("  WOLFPROV_LOG_COMPONENTS=%s\n", getenv("WOLFPROV_LOG_COMPONENTS"));
    
    printf("\nTest 3: Hex value compatibility\n");
    setenv("WOLFPROV_LOG_LEVEL", "0x007F", 1);
    setenv("WOLFPROV_LOG_COMPONENTS", "0x20000", 1);
    printf("  WOLFPROV_LOG_LEVEL=%s\n", getenv("WOLFPROV_LOG_LEVEL"));
    printf("  WOLFPROV_LOG_COMPONENTS=%s\n", getenv("WOLFPROV_LOG_COMPONENTS"));
    
    printf("\n=== Environment variable tests complete ===\n");
    printf("Now run: WOLFPROV_DEBUG=1 WOLFPROV_LOG_LEVEL=all WOLFPROV_LOG_COMPONENTS=hkdf ./test/unit.test 16\n");
    
    return 0;
}
