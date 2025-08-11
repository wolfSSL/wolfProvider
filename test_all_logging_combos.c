#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

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
int wolfProv_EnableComponent(int component) { return 0; }
int wolfProv_DisableComponent(int component) { return 0; }
int wolfProv_IsComponentEnabled(int component) { return 0; }
int wolfProv_SetVerbosityLevel(int level) { return 0; }
int wolfProv_GetVerbosityLevel(void) { return 0; }
int wolfProv_EnableAlgorithm(const char* algorithm) { return 0; }
int wolfProv_DisableAlgorithm(const char* algorithm) { return 0; }
#endif

int run_test_with_env(const char* log_level, const char* log_components, const char* test_name, const char* output_file) {
    pid_t pid = fork();
    if (pid == 0) {
        setenv("WOLFPROV_DEBUG", "1", 1);
        if (log_level) setenv("WOLFPROV_LOG_LEVEL", log_level, 1);
        if (log_components) setenv("WOLFPROV_LOG_COMPONENTS", log_components, 1);
        
        freopen(output_file, "w", stdout);
        freopen(output_file, "a", stderr);
        
        printf("=== Test: %s ===\n", test_name);
        printf("WOLFPROV_LOG_LEVEL=%s\n", log_level ? log_level : "unset");
        printf("WOLFPROV_LOG_COMPONENTS=%s\n", log_components ? log_components : "unset");
        printf("=== Starting HKDF Test ===\n");
        
        execl("./test/unit.test", "./test/unit.test", "16", NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    }
    return -1;
}

int main() {
    printf("=== Comprehensive Logging Combination Tests ===\n\n");
    
    printf("Running Test 1: Error level with HKDF...\n");
    run_test_with_env("error", "hkdf", "Error level with HKDF", "/tmp/test1_error_hkdf.log");
    
    printf("Running Test 2: Verbose level with HKDF...\n");
    run_test_with_env("verbose", "hkdf", "Verbose level with HKDF", "/tmp/test2_verbose_hkdf.log");
    
    printf("Running Test 3: Debug level with HKDF...\n");
    run_test_with_env("debug", "hkdf", "Debug level with HKDF", "/tmp/test3_debug_hkdf.log");
    
    printf("Running Test 4: Full debug with HKDF...\n");
    run_test_with_env("full_debug", "hkdf", "Full debug with HKDF", "/tmp/test4_full_debug_hkdf.log");
    
    printf("Running Test 5: All levels with HKDF...\n");
    run_test_with_env("all", "hkdf", "All levels with HKDF", "/tmp/test5_all_hkdf.log");
    
    printf("Running Test 6: Verbose with multiple components...\n");
    run_test_with_env("verbose", "ecc,rsa,hkdf", "Verbose with ECC,RSA,HKDF", "/tmp/test6_multi_components.log");
    
    printf("Running Test 7: Hex log level compatibility...\n");
    run_test_with_env("0x007F", "0x20000", "Hex values compatibility", "/tmp/test7_hex_compat.log");
    
    printf("Running Test 8: Debug with all components...\n");
    run_test_with_env("debug", "all", "Debug with all components", "/tmp/test8_all_components.log");
    
    printf("\n=== All tests completed ===\n");
    printf("Output files saved to /tmp/test*.log\n");
    printf("Use 'cat /tmp/test*.log' to view results\n");
    
    return 0;
}
