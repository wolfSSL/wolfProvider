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

static int test_count = 0;
static int test_passed = 0;

void test_log_level_parsing() {
    printf("\n=== Testing Log Level Parsing ===\n");
    
    int result;
    
    result = wolfProv_ParseLogLevel("error");
    printf("Test %d: 'error' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_ERROR, 
           (result == WP_LOG_ERROR) ? "PASS" : "FAIL");
    if (result == WP_LOG_ERROR) test_passed++;
    
    result = wolfProv_ParseLogLevel("verbose");
    printf("Test %d: 'verbose' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_VERBOSE,
           (result == WP_LOG_VERBOSE) ? "PASS" : "FAIL");
    if (result == WP_LOG_VERBOSE) test_passed++;
    
    result = wolfProv_ParseLogLevel("debug");
    printf("Test %d: 'debug' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_DEBUG,
           (result == WP_LOG_DEBUG) ? "PASS" : "FAIL");
    if (result == WP_LOG_DEBUG) test_passed++;
    
    result = wolfProv_ParseLogLevel("full_debug");
    printf("Test %d: 'full_debug' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_FULL_DEBUG,
           (result == WP_LOG_FULL_DEBUG) ? "PASS" : "FAIL");
    if (result == WP_LOG_FULL_DEBUG) test_passed++;
    
    result = wolfProv_ParseLogLevel("all");
    printf("Test %d: 'all' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_LEVEL_ALL,
           (result == WP_LOG_LEVEL_ALL) ? "PASS" : "FAIL");
    if (result == WP_LOG_LEVEL_ALL) test_passed++;
    
    result = wolfProv_ParseLogLevel("0x007F");
    printf("Test %d: '0x007F' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_LEVEL_ALL,
           (result == WP_LOG_LEVEL_ALL) ? "PASS" : "FAIL");
    if (result == WP_LOG_LEVEL_ALL) test_passed++;
}

void test_component_parsing() {
    printf("\n=== Testing Component Parsing ===\n");
    
    int result;
    
    result = wolfProv_ParseComponents("hkdf");
    printf("Test %d: 'hkdf' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_HKDF,
           (result == WP_LOG_HKDF) ? "PASS" : "FAIL");
    if (result == WP_LOG_HKDF) test_passed++;
    
    result = wolfProv_ParseComponents("ecc");
    printf("Test %d: 'ecc' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_ECC,
           (result == WP_LOG_ECC) ? "PASS" : "FAIL");
    if (result == WP_LOG_ECC) test_passed++;
    
    result = wolfProv_ParseComponents("rsa");
    printf("Test %d: 'rsa' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_RSA,
           (result == WP_LOG_RSA) ? "PASS" : "FAIL");
    if (result == WP_LOG_RSA) test_passed++;
    
    result = wolfProv_ParseComponents("ecc,rsa");
    int expected = WP_LOG_ECC | WP_LOG_RSA;
    printf("Test %d: 'ecc,rsa' -> %d (expected: %d) %s\n", ++test_count, result, expected,
           (result == expected) ? "PASS" : "FAIL");
    if (result == expected) test_passed++;
    
    result = wolfProv_ParseComponents("hkdf,aes,hmac");
    expected = WP_LOG_HKDF | WP_LOG_AES | WP_LOG_HMAC;
    printf("Test %d: 'hkdf,aes,hmac' -> %d (expected: %d) %s\n", ++test_count, result, expected,
           (result == expected) ? "PASS" : "FAIL");
    if (result == expected) test_passed++;
    
    result = wolfProv_ParseComponents("0x20000");
    printf("Test %d: '0x20000' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_HKDF,
           (result == WP_LOG_HKDF) ? "PASS" : "FAIL");
    if (result == WP_LOG_HKDF) test_passed++;
    
    result = wolfProv_ParseComponents("all");
    printf("Test %d: 'all' -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_COMPONENTS_ALL,
           (result == WP_LOG_COMPONENTS_ALL) ? "PASS" : "FAIL");
    if (result == WP_LOG_COMPONENTS_ALL) test_passed++;
}

void test_api_functions() {
    printf("\n=== Testing API Functions ===\n");
    
    int result;
    
    result = wolfProv_EnableComponent(WP_LOG_HKDF);
    printf("Test %d: wolfProv_EnableComponent(WP_LOG_HKDF) -> %d %s\n", ++test_count, result,
           (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    result = wolfProv_IsComponentEnabled(WP_LOG_HKDF);
    printf("Test %d: wolfProv_IsComponentEnabled(WP_LOG_HKDF) -> %d %s\n", ++test_count, result,
           (result != 0) ? "PASS" : "FAIL");
    if (result != 0) test_passed++;
    
    result = wolfProv_DisableComponent(WP_LOG_HKDF);
    printf("Test %d: wolfProv_DisableComponent(WP_LOG_HKDF) -> %d %s\n", ++test_count, result,
           (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    result = wolfProv_IsComponentEnabled(WP_LOG_HKDF);
    printf("Test %d: wolfProv_IsComponentEnabled(WP_LOG_HKDF) after disable -> %d %s\n", ++test_count, result,
           (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    result = wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
    printf("Test %d: wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG) -> %d %s\n", ++test_count, result,
           (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    result = wolfProv_GetVerbosityLevel();
    printf("Test %d: wolfProv_GetVerbosityLevel() -> %d (expected: %d) %s\n", ++test_count, result, WP_LOG_FULL_DEBUG,
           (result == WP_LOG_FULL_DEBUG) ? "PASS" : "FAIL");
    if (result == WP_LOG_FULL_DEBUG) test_passed++;
    
    result = wolfProv_EnableAlgorithm("HKDF");
    printf("Test %d: wolfProv_EnableAlgorithm(\"HKDF\") -> %d %s\n", ++test_count, result,
           (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    result = wolfProv_DisableAlgorithm("HKDF");
    printf("Test %d: wolfProv_DisableAlgorithm(\"HKDF\") -> %d %s\n", ++test_count, result,
           (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
}

int run_unit_test_with_env(const char* log_level, const char* components, int test_num) {
    pid_t pid = fork();
    if (pid == 0) {
        setenv("WOLFPROV_DEBUG", "1", 1);
        if (log_level) setenv("WOLFPROV_LOG_LEVEL", log_level, 1);
        if (components) setenv("WOLFPROV_LOG_COMPONENTS", components, 1);
        
        char test_str[16];
        snprintf(test_str, sizeof(test_str), "%d", test_num);
        execl("./test/unit.test", "./test/unit.test", test_str, NULL);
        exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    }
    return -1;
}

void test_environment_variables() {
    printf("\n=== Testing Environment Variable Integration ===\n");
    
    int result;
    
    printf("Test %d: HKDF test with WOLFPROV_LOG_LEVEL=verbose WOLFPROV_LOG_COMPONENTS=hkdf\n", ++test_count);
    result = run_unit_test_with_env("verbose", "hkdf", 16);
    printf("Result: %s\n", (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    printf("Test %d: ECC test with WOLFPROV_LOG_LEVEL=debug WOLFPROV_LOG_COMPONENTS=ecc\n", ++test_count);
    result = run_unit_test_with_env("debug", "ecc", 6);
    printf("Result: %s\n", (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    printf("Test %d: RSA test with WOLFPROV_LOG_LEVEL=full_debug WOLFPROV_LOG_COMPONENTS=rsa\n", ++test_count);
    result = run_unit_test_with_env("full_debug", "rsa", 5);
    printf("Result: %s\n", (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    printf("Test %d: Multiple algorithms with WOLFPROV_LOG_LEVEL=all WOLFPROV_LOG_COMPONENTS=ecc,rsa,hkdf\n", ++test_count);
    result = run_unit_test_with_env("all", "ecc,rsa,hkdf", 5);
    printf("Result: %s\n", (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
    
    printf("Test %d: Hex bitmask compatibility WOLFPROV_LOG_LEVEL=0x007F WOLFPROV_LOG_COMPONENTS=0x20000\n", ++test_count);
    result = run_unit_test_with_env("0x007F", "0x20000", 16);
    printf("Result: %s\n", (result == 0) ? "PASS" : "FAIL");
    if (result == 0) test_passed++;
}

int main() {
    printf("=== Comprehensive Logging System Test ===\n");
    printf("Testing string-based environment variable parsing and API functions\n");
    
    test_log_level_parsing();
    test_component_parsing();
    test_api_functions();
    test_environment_variables();
    
    printf("\n=== Test Summary ===\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_count - test_passed);
    printf("Success rate: %.1f%%\n", (float)test_passed / test_count * 100);
    
    return (test_passed == test_count) ? 0 : 1;
}
