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

### Using the Test Program
```bash
# Build the test program (requires proper OpenSSL configuration)
cd /path/to/wolfProvider
source ./scripts/utils-wolfprovider.sh
gcc -I. -I./include -L./.libs -o test_logging test_logging.c -lwolfprov -lcrypto -lssl -Wl,-rpath,./.libs

# Run with debugging enabled and proper OpenSSL configuration
export WOLFPROV_DEBUG=1
export LD_LIBRARY_PATH=./.libs:$LD_LIBRARY_PATH
export OPENSSL_CONF=$WOLFPROV_INSTALL_DIR/openssl.cnf
./test_logging
```

### Using Unit Tests (Recommended)
```bash
# Run specific algorithm tests with logging (easiest method)
cd /path/to/wolfProvider
source ./scripts/utils-wolfprovider.sh
export WOLFPROV_DEBUG=1

# Test HKDF specifically - should show detailed ENTER/LEAVE and debug logs
./test/unit.test 16

# Test all algorithms with logging
./test/unit.test

# Note: Enhanced logging output may require specific verbosity settings
# The unit test framework may suppress detailed logging output
# For verbose logging, try setting WOLFPROV_LOG_LEVEL environment variable
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `WOLFPROV_DEBUG` | Enable/disable wolfProvider debugging | `export WOLFPROV_DEBUG=1` |
| `LD_LIBRARY_PATH` | Library path for dynamic linking | `export LD_LIBRARY_PATH=./.libs:$LD_LIBRARY_PATH` |
| `OPENSSL_CONF` | OpenSSL configuration file | `export OPENSSL_CONF=$WOLFPROV_INSTALL_DIR/openssl.cnf` |

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
1. Verify `WOLFPROV_DEBUG=1` is set
2. Check that `wolfProv_Debugging_ON()` is called
3. Ensure verbosity level is appropriate (`WP_LOG_DEBUG` or higher)
4. Verify the correct component categories are enabled

### Too Much Log Output
1. Use granular categories to limit output to specific algorithms
2. Lower the verbosity level (e.g., `WP_LOG_ERROR` only)
3. Disable unnecessary components with `wolfProv_DisableComponent()`

### Provider Loading Issues
1. Ensure `LD_LIBRARY_PATH` includes the wolfProvider library path
2. Check that `OPENSSL_CONF` points to the correct configuration
3. Verify the provider is properly installed with `make install`

## Examples

See `test_logging.c` for complete working examples of:
- HKDF logging with parameter details
- Algorithm query logging
- Granular category control
- Verbosity level testing

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
