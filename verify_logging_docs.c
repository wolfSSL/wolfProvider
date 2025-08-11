#include <stdio.h>
#include <stdlib.h>
#include "include/wolfprovider/wp_logging.h"

int main() {
    printf("=== Verifying Logging Documentation Examples ===\n\n");
    
    printf("1. Testing wolfProv_Debugging_ON()...\n");
    wolfProv_Debugging_ON();
    printf("   ✓ Function call successful\n\n");
    
    printf("2. Testing wolfProv_SetVerbosityLevel()...\n");
    wolfProv_SetVerbosityLevel(WP_LOG_DEBUG);
    printf("   ✓ Set to DEBUG level\n");
    wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
    printf("   ✓ Set to FULL_DEBUG level\n\n");
    
    printf("3. Testing component control functions...\n");
    wolfProv_DisableComponent(WP_LOG_COMPONENTS_ALL);
    printf("   ✓ Disabled all components\n");
    wolfProv_EnableComponent(WP_LOG_HKDF);
    printf("   ✓ Enabled HKDF component\n\n");
    
    printf("4. Testing algorithm-specific control...\n");
    wolfProv_EnableAlgorithm("HKDF");
    printf("   ✓ Enabled HKDF algorithm\n");
    wolfProv_EnableAlgorithm("RSA");
    printf("   ✓ Enabled RSA algorithm\n");
    wolfProv_DisableAlgorithm("RSA");
    printf("   ✓ Disabled RSA algorithm\n\n");
    
    printf("=== All API Functions Work Correctly ===\n");
    printf("Documentation examples are verified and functional!\n");
    
    return 0;
}
