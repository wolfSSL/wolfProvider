# OpenSSL Default Provider Replacement Patch

> **Note**: For comprehensive Open Source Project (OSP) patches and integration work, visit the main wolfSSL OSP repository: **https://github.com/wolfSSL/osp/tree/master/wolfProvider**

This directory contains the patch for replacing OpenSSL's default provider with wolfProvider.

## Purpose

The patch modifies OpenSSL's provider registration to substitute wolfProvider as the "default" provider, ensuring that all default provider operations are handled by wolfProvider instead of OpenSSL's built-in implementation.

## Compatibility

- **Supported Versions**: OpenSSL 3.0 and later
- **Patch Target**: `crypto/provider_predefined.c`

This directory contains only the OpenSSL default provider replacement functionality.