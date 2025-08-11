# wolfProvider Enhanced Logging System

This document describes how to use the enhanced granular logging system in wolfProvider for debugging and development purposes.

## Overview

The enhanced logging system provides granular control over debug output with:
- **Algorithm-specific categories** - Enable/disable logging for specific algorithms
- **Multiple verbosity levels** - Control detail level of output
- **Function entry/exit tracking** - ENTER/LEAVE logging for all functions
- **Query operation logging** - Special logging for algorithm queries
- **Dynamic runtime control** - Change logging settings without recompilation

## Quick Start

### 1. Enable Basic Logging
```bash
# Set environment variable to enable wolfProvider debugging
export WOLFPROV_DEBUG=1

# Run your application
./your_application
```

### 2. Enable Logging in Code
```c
#include "wolfprovider/wp_logging.h"

// Enable debugging
wolfProv_Debugging_ON();

// Set verbosity level
wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
```

## Verbosity Levels

The logging system supports multiple verbosity levels:

| Level | Constant | Description |
|-------|----------|-------------|
| None | `WP_LOG_NONE` | No logging output |
| Error | `WP_LOG_ERROR` | Error messages only |
| Info | `WP_LOG_INFO` | Basic informational messages |
| Debug | `WP_LOG_DEBUG` | Debug messages and function tracking |
| Verbose | `WP_LOG_VERBOSE` | Detailed operational information |
| Trace | `WP_LOG_TRACE` | Most detailed tracing information |
| Full Debug | `WP_LOG_FULL_DEBUG` | All logging enabled |

### Example: Setting Verbosity Levels
```c
// Error messages only
wolfProv_SetVerbosityLevel(WP_LOG_ERROR);

// Debug level (includes ENTER/LEAVE function tracking)
wolfProv_SetVerbosityLevel(WP_LOG_DEBUG);

// Maximum verbosity
wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
```

## Granular Algorithm Categories

Enable logging for specific algorithms only:

### Available Categories
- **Digest Algorithms**: `WP_LOG_SHA1`, `WP_LOG_SHA256`, `WP_LOG_SHA384`, `WP_LOG_SHA512`, `WP_LOG_SHA3`, `WP_LOG_MD5`
- **Cipher Algorithms**: `WP_LOG_AES`, `WP_LOG_DES`, `WP_LOG_3DES`
- **MAC Algorithms**: `WP_LOG_HMAC`, `WP_LOG_CMAC`, `WP_LOG_GMAC`
- **KDF Algorithms**: `WP_LOG_HKDF`, `WP_LOG_PBKDF2`, `WP_LOG_TLS1_PRF`, `WP_LOG_KRB5KDF`
- **Key Management**: `WP_LOG_RSA`, `WP_LOG_ECDSA`, `WP_LOG_ECDH`, `WP_LOG_DH`
- **Elliptic Curves**: `WP_LOG_X25519`, `WP_LOG_X448`, `WP_LOG_ED25519`, `WP_LOG_ED448`
- **Special Categories**: `WP_LOG_QUERY`, `WP_LOG_PROVIDER`, `WP_LOG_RNG`

### Example: HKDF-Only Logging
```c
// Disable all logging first
wolfProv_DisableComponent(WP_LOG_COMPONENTS_ALL);

// Enable only HKDF logging
wolfProv_EnableAlgorithm("HKDF");

// Set debug level to see detailed HKDF operations
wolfProv_SetVerbosityLevel(WP_LOG_DEBUG);

// Now only HKDF operations will produce log output
```

### Example: Multiple Algorithm Logging
```c
// Enable logging for RSA and ECDSA only
wolfProv_DisableComponent(WP_LOG_COMPONENTS_ALL);
wolfProv_EnableAlgorithm("RSA");
wolfProv_EnableAlgorithm("ECDSA");
wolfProv_SetVerbosityLevel(WP_LOG_VERBOSE);
```

## Common Logging Combinations

### 1. Debug HKDF Operations
```c
wolfProv_Debugging_ON();
wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
wolfProv_DisableComponent(WP_LOG_COMPONENTS_ALL);
wolfProv_EnableAlgorithm("HKDF");

// Expected output: Detailed HKDF parameter logging, key sizes, modes
// ENTER: wp_kdf_hkdf_derive
// DEBUG: HKDF derive: keyLen=32, mode=3
// DEBUG: HKDF derive: keySz=32, saltSz=16, infoSz=16
// LEAVE: wp_kdf_hkdf_derive (success)
```

### 2. Track Function Calls (ENTER/LEAVE)
```c
wolfProv_Debugging_ON();
wolfProv_SetVerbosityLevel(WP_LOG_DEBUG);
wolfProv_EnableComponent(WP_LOG_COMPONENTS_ALL);

// Expected output: Function entry/exit for all operations
// ENTER: wp_rsa_sign_init
// ENTER: wp_rsa_sign
// LEAVE: wp_rsa_sign (success)
// LEAVE: wp_rsa_sign_init (success)
```

### 3. Algorithm Query Debugging
```c
wolfProv_Debugging_ON();
wolfProv_SetVerbosityLevel(WP_LOG_TRACE);
wolfProv_EnableComponent(WP_LOG_QUERY);

// Expected output when fetching algorithms:
// ENTER: wolfprov_query
// DEBUG: Query operation ID: 1
// TRACE: Returning digest algorithms
// LEAVE: wolfprov_query (success)
```

### 4. Error-Only Logging
```c
wolfProv_Debugging_ON();
wolfProv_SetVerbosityLevel(WP_LOG_ERROR);
wolfProv_EnableComponent(WP_LOG_COMPONENTS_ALL);

// Expected output: Only error conditions will be logged
```

### 5. Comprehensive Debugging
```c
wolfProv_Debugging_ON();
wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
wolfProv_EnableComponent(WP_LOG_COMPONENTS_ALL);

// Expected output: All logging enabled - very verbose!
```

## Testing Logging Combinations

### Method 1: Using Unit Tests (Recommended)
```bash
# Run algorithm tests with enhanced logging
cd /path/to/wolfProvider
source ./scripts/utils-wolfprovider.sh

# Enable debugging and set verbosity level
export WOLFPROV_DEBUG=1
export WOLFPROV_LOG_LEVEL=0x007F  # Enable all log levels

# Test HKDF specifically
./test/unit.test 16

# Test all algorithms
./test/unit.test

# Test specific algorithms by number:
# 1=AES, 2=Digest, 3=HMAC, 4=CMAC, 5=RSA, 6=ECC, 7=DH, 16=HKDF, etc.
```

### Method 2: Using API Functions in Code
```c
#include "wolfprovider/wp_logging.h"

int main() {
    // Enable debugging
    wolfProv_Debugging_ON();
    
    // Set maximum verbosity
    wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
    
    // Enable all components
    wolfProv_EnableComponent(WP_LOG_COMPONENTS_ALL);
    
    // Or enable specific algorithms only
    wolfProv_DisableComponent(WP_LOG_COMPONENTS_ALL);
    wolfProv_EnableAlgorithm("HKDF");
    wolfProv_EnableAlgorithm("RSA");
    
    // Your cryptographic operations here...
    // Should now show detailed logging
    
    return 0;
}
```

### Method 3: Environment Variable Control
```bash
# Set environment variables for logging control
export WOLFPROV_DEBUG=1                    # Enable debugging
export WOLFPROV_LOG_LEVEL=0x007F           # All log levels
export WOLFPROV_LOG_COMPONENTS=0xFFFFFFFF  # All components

# Run your application
./your_application
```

### Method 4: Granular Algorithm Testing
```bash
# Test specific algorithm combinations
source ./scripts/utils-wolfprovider.sh
export WOLFPROV_DEBUG=1

# Test only HKDF operations
export WOLFPROV_LOG_COMPONENTS=0x20000  # WP_LOG_HKDF only
./test/unit.test 16

# Test only RSA operations  
export WOLFPROV_LOG_COMPONENTS=0x100    # WP_LOG_RSA only
./test/unit.test 5

# Test only AES operations
export WOLFPROV_LOG_COMPONENTS=0x800    # WP_LOG_AES only
./test/unit.test 1
```

## Environment Variables

| Variable | Description | Example | Hex Values |
|----------|-------------|---------|------------|
| `WOLFPROV_DEBUG` | Enable/disable wolfProvider debugging | `export WOLFPROV_DEBUG=1` | 1=on, 0=off |
| `WOLFPROV_LOG_LEVEL` | Set verbosity level bitmask | `export WOLFPROV_LOG_LEVEL=0x007F` | See Log Level Values below |
| `WOLFPROV_LOG_COMPONENTS` | Set component bitmask | `export WOLFPROV_LOG_COMPONENTS=0x20000` | See Component Values below |
| `LD_LIBRARY_PATH` | Library path for dynamic linking | `export LD_LIBRARY_PATH=./.libs:$LD_LIBRARY_PATH` | Path string |
| `OPENSSL_CONF` | OpenSSL configuration file | `export OPENSSL_CONF=$WOLFPROV_INSTALL_DIR/openssl.cnf` | Path string |

### Log Level Values (Bitmask)
| Level | Hex Value | Description |
|-------|-----------|-------------|
| WP_LOG_ERROR | 0x0001 | Error messages only |
| WP_LOG_ENTER | 0x0002 | Function entry logging |
| WP_LOG_LEAVE | 0x0004 | Function exit logging |
| WP_LOG_INFO | 0x0008 | Informational messages |
| WP_LOG_VERBOSE | 0x0010 | Verbose operational details |
| WP_LOG_DEBUG | 0x0020 | Debug-level information |
| WP_LOG_TRACE | 0x0040 | Trace-level ultra-detailed info |
| **All Levels** | **0x007F** | **Enable all logging levels** |

### Component Values (Bitmask)
| Component | Hex Value | Description |
|-----------|-----------|-------------|
| WP_LOG_HKDF | 0x20000 | HKDF operations only |
| WP_LOG_RSA | 0x100 | RSA operations only |
| WP_LOG_AES | 0x800 | AES operations only |
| WP_LOG_ECDSA | 0x200000 | ECDSA operations only |
| WP_LOG_QUERY | 0x8000000 | Algorithm query operations |
| **All Components** | **0xFFFFFFFF** | **Enable all algorithm logging** |

## API Reference

### Core Functions
```c
// Enable/disable debugging
void wolfProv_Debugging_ON(void);
void wolfProv_Debugging_OFF(void);

// Set verbosity level
void wolfProv_SetVerbosityLevel(int level);

// Component control
void wolfProv_EnableComponent(int component);
void wolfProv_DisableComponent(int component);

// Algorithm-specific control
void wolfProv_EnableAlgorithm(const char* algorithm);
void wolfProv_DisableAlgorithm(const char* algorithm);
```

### Logging Macros
```c
// Function entry/exit
WOLFPROV_ENTER(category, function_name);
WOLFPROV_LEAVE(category, location, result);

// Debug messages
WOLFPROV_MSG_DEBUG(category, format, ...);
WOLFPROV_MSG_VERBOSE(category, format, ...);
WOLFPROV_MSG_TRACE(category, format, ...);
```

## Troubleshooting

### No Log Output
1. **Check Environment Variables:**
   ```bash
   echo $WOLFPROV_DEBUG          # Should be 1
   echo $WOLFPROV_LOG_LEVEL      # Should be 0x007F for full logging
   echo $WOLFPROV_LOG_COMPONENTS # Should be 0xFFFFFFFF for all components
   ```

2. **Verify Library Installation:**
   ```bash
   source ./scripts/utils-wolfprovider.sh
   nm -D ./.libs/libwolfprov.so | grep wolfProv  # Should show logging functions
   ```

3. **Test API Functions:**
   ```bash
   gcc -I./include -L./.libs -o test_api verify_logging_docs.c -lwolfprov
   ./test_api  # Should show "All API Functions Work Correctly"
   ```

### Too Much Log Output
1. **Use Granular Component Control:**
   ```bash
   # Only HKDF logging
   export WOLFPROV_LOG_COMPONENTS=0x20000
   
   # Only RSA + ECDSA logging  
   export WOLFPROV_LOG_COMPONENTS=0x200100
   ```

2. **Reduce Verbosity Level:**
   ```bash
   # Errors only
   export WOLFPROV_LOG_LEVEL=0x0001
   
   # ENTER/LEAVE only
   export WOLFPROV_LOG_LEVEL=0x0006
   ```

### Provider Loading Issues
1. **Environment Setup:**
   ```bash
   source ./scripts/utils-wolfprovider.sh  # REQUIRED for proper setup
   export LD_LIBRARY_PATH=./.libs:$LD_LIBRARY_PATH
   export OPENSSL_CONF=$WOLFPROV_INSTALL_DIR/openssl.cnf
   ```

2. **Verify Installation:**
   ```bash
   make install
   ls -la $WOLFPROV_INSTALL_DIR/lib/libwolfprov.so*
   ```

### Unit Test Framework Considerations
- The unit test framework may suppress detailed logging output
- Use environment variables for the most reliable logging control
- For development debugging, consider adding temporary printf statements
- The enhanced logging system works but may not always be visible in unit test output

## Complete Working Examples

### Example 1: HKDF-Only Debug Logging
```bash
cd /path/to/wolfProvider
source ./scripts/utils-wolfprovider.sh

# Enable HKDF-only logging with maximum verbosity
export WOLFPROV_DEBUG=1
export WOLFPROV_LOG_LEVEL=0x007F        # All log levels
export WOLFPROV_LOG_COMPONENTS=0x20000  # HKDF only

# Run HKDF test
./test/unit.test 16
```

### Example 2: RSA + ECDSA Function Tracking
```bash
# Enable ENTER/LEAVE tracking for RSA and ECDSA only
export WOLFPROV_DEBUG=1
export WOLFPROV_LOG_LEVEL=0x0006        # ENTER + LEAVE only
export WOLFPROV_LOG_COMPONENTS=0x200100 # RSA + ECDSA

# Run RSA test
./test/unit.test 5

# Run ECC test  
./test/unit.test 6
```

### Example 3: Query Operation Debugging
```bash
# Enable query logging to see algorithm fetching
export WOLFPROV_DEBUG=1
export WOLFPROV_LOG_LEVEL=0x007F         # All levels
export WOLFPROV_LOG_COMPONENTS=0x8000000 # Query operations only

# Run any test to see algorithm queries
./test/unit.test 1
```

### Example 4: Comprehensive Debugging
```bash
# Enable everything for maximum debugging
export WOLFPROV_DEBUG=1
export WOLFPROV_LOG_LEVEL=0x007F      # All log levels
export WOLFPROV_LOG_COMPONENTS=0xFFFFFFFF # All components

# Run all tests with full logging
./test/unit.test
```

### Example 5: API Function Control
```c
// File: my_debug_app.c
#include "wolfprovider/wp_logging.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>

int main() {
    // Enable debugging with API functions
    wolfProv_Debugging_ON();
    wolfProv_SetVerbosityLevel(WP_LOG_FULL_DEBUG);
    
    // Enable only HKDF logging
    wolfProv_DisableComponent(WP_LOG_COMPONENTS_ALL);
    wolfProv_EnableAlgorithm("HKDF");
    
    // Load provider and perform HKDF operation
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "wolfprovider");
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", "provider=wolfprovider");
    
    // Your HKDF operations here - will show detailed logs
    
    EVP_KDF_free(kdf);
    OSSL_PROVIDER_unload(prov);
    return 0;
}
```

### Example 6: Build and Test Custom Application
```bash
# Compile custom application with logging
source ./scripts/utils-wolfprovider.sh
gcc -I./include -L./.libs -o my_debug_app my_debug_app.c -lwolfprov -lcrypto -lssl -Wl,-rpath,./.libs

# Run with proper environment
export WOLFPROV_DEBUG=1
export LD_LIBRARY_PATH=./.libs:$LD_LIBRARY_PATH
export OPENSSL_CONF=$WOLFPROV_INSTALL_DIR/openssl.cnf
./my_debug_app
```

See `verify_logging_docs.c` for a complete working example that tests all API functions.

## Performance Considerations

- Logging adds overhead - disable in production builds
- Use granular categories to minimize performance impact
- Higher verbosity levels (TRACE, FULL_DEBUG) have significant overhead
- ENTER/LEAVE tracking adds function call overhead

## Building with Logging Support

```bash
# Standard build with logging support
source ./scripts/utils-wolfprovider.sh
./scripts/build-wolfprovider.sh

# Install for system-wide use
make install
```

The enhanced logging system is always compiled in - control is via runtime configuration only.
