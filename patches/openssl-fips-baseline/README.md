# OpenSSL FIPS Baseline Patches

Patches that enforce FIPS algorithm restrictions on OpenSSL, enabling applications to test FIPS compliance before integrating a certified FIPS module.

**Warning: Testing only. FIPS POST bypassed, not FIPS compliant.**

## Purpose

These patches modify OpenSSL to reject non-FIPS-compliant cryptographic operations. This allows you to:

- Identify FIPS compatibility issues early in development
- Test application behavior under FIPS restrictions
- Validate error handling for blocked algorithms

## Quick Start

```bash
# Patch your OpenSSL source
./scripts/patch-openssl-fips.sh --openssl-src=/path/to/openssl-3.x

# Build and install OpenSSL
cd /path/to/openssl-3.x
./Configure --prefix=/your/install/path
make -j$(nproc)
make install

# Verify
openssl list -providers
# Expected: OpenSSL Default Provider (FIPS Baseline)
```

## Restrictions Enforced

| Restriction | Requirement |
|-------------|-------------|
| RSA Key Size | 2048 bits minimum |
| SHA1 Signing | Blocked (verify allowed) |
| ECDSA Curves | P-256, P-384, P-521 only |
| PBKDF2 Password | 14 bytes minimum |
| DH Groups | FFDHE only, 2048+ bits |

## Options

```bash
# Preview changes without modifying files
./scripts/patch-openssl-fips.sh -s /path/to/openssl --dry-run --verbose

# Skip backup creation
./scripts/patch-openssl-fips.sh -s /path/to/openssl --no-backup

# Restore original files
cd /path/to/openssl
cp .fips-baseline-backup-<timestamp>/providers/*.c providers/
cp .fips-baseline-backup-<timestamp>/providers/fips/*.c providers/fips/
```

## Version Support

OpenSSL 3.0.x - 3.6.x. Version-appropriate patches selected automatically.

## Common Errors

When restrictions are hit, OpenSSL returns errors like:

| Operation | Error |
|-----------|-------|
| RSA keygen < 2048 | `operation not supported for this keytype` |
| SHA1 signing | `digest not allowed` |
| P-192 curve | `invalid curve` |
| PBKDF2 short password | `invalid salt length` |
| MODP DH groups | `unsupported named group` |

Update your application to use FIPS-compliant parameters, then proceed to integrate a certified FIPS module.
