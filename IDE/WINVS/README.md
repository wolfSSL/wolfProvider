Visual Studio solution for wolfProvider
=======================================

`wolfprovider.sln` builds **`libwolfprov.dll`**, an OpenSSL 3.x provider backed
by wolfSSL. The filename matters: `-provider libwolfprov` resolves to
`libwolfprov.dll`.

Four configurations, x64 only:

| Configuration | Purpose |
|---|---|
| `DLL Release\|x64` | the shipped provider |
| `DLL Debug\|x64` | same, debug CRT |
| `Static Release\|x64` | builds `unit-test.exe`. Not for distribution. |
| `Static Debug\|x64` | same, debug CRT |

The static library exists only so the unit tests can link wolfProvider
internals. A `.lib` cannot act as a provider: OpenSSL loads one with
`LoadLibraryA` followed by a lookup of `OSSL_provider_init`.


Prerequisites
-------------

- Visual Studio 2022 with the C++ toolset (v143) and MASM (`ml64.exe`).
- Perl, NASM and git, to build OpenSSL. Strawberry Perl includes NASM.

No `configure` step is involved anywhere on Windows.


Directory layout
----------------

wolfProvider, wolfSSL and OpenSSL sit side by side:

    C:\src\
        openssl\
        wolfProvider\
        wolfssl\

`wolfprovider.props` expresses this as `..\..\..\..\wolfssl` and
`..\..\..\..\openssl`, relative to each project directory. Override any macro on
the command line, e.g. `/p:wolfCryptDir=D:\wolfssl`.


Building
--------

**1. OpenSSL**, shared, release CRT:

    cd C:\src\openssl
    perl Configure VC-WIN64A shared no-tests --prefix=C:\out\openssl --openssldir=C:\out\openssl\ssl
    nmake
    nmake install_sw

Two paths come out of this and they are not interchangeable. The **build tree**
(`C:\src\openssl`) is `openSslDir` and must hold `libcrypto.lib` directly. The
**install prefix** (`C:\out\openssl`) is what you run. Pointing `openSslDir` at
the prefix fails later with `LNK1104`.

For a Debug wolfProvider, build a second OpenSSL with `--debug` into
`C:\src\openssl-debug`. `Configure` writes into the source tree, so release and
debug cannot share one checkout.

**2. wolfSSL**, as a DLL, using the `user_settings.h` in this directory:

    copy IDE\WINVS\user_settings.h C:\src\wolfssl\IDE\WIN\user_settings.h
    cd C:\src\wolfssl
    msbuild wolfssl64.sln /t:wolfssl /p:Configuration="DLL Release" /p:Platform=x64

**3. wolfProvider**:

    cd C:\src\wolfProvider
    msbuild IDE\WINVS\wolfprovider.sln /p:Configuration="DLL Release" /p:Platform=x64

Output is `IDE\WINVS\DLL Release\x64\libwolfprov.dll`.

The Debug configurations link `/MDd` and need a `/MDd` OpenSSL and wolfSSL
`DLL Debug|x64`. Never mix runtimes: `/MD` against `/MDd` links cleanly and then
corrupts the heap.


Running
-------

`libwolfprov.dll` imports `wolfssl.dll`, and the process that searches for it is
the application loading the provider. OpenSSL uses a bare `LoadLibraryA`, which
does not add the module's own directory to the search path, so **putting
`wolfssl.dll` beside `libwolfprov.dll` does not work.** Put it on the loading
process's `PATH`:

    $env:PATH = "C:\src\wolfssl\DLL Release\x64;$env:PATH"
    openssl list -providers -provider-path "C:\src\wolfProvider\IDE\WINVS\DLL Release\x64" -provider libwolfprov


User macros
-----------

Set in `wolfprovider.props`, overridable with `/p:`:

| Macro | Default |
|---|---|
| `wolfCryptDir` | `..\..\..\..\wolfssl` |
| `openSslDir` | `..\..\..\..\openssl` (build tree, holds `libcrypto.lib`) |
| `openSslDirDebug` | `..\..\..\..\openssl-debug` |
| `userSettingsDir` | `..` (this directory) |
| `wolfSslLib` | `wolfssl.lib` |

plus `wolfCryptDllRelease64` and friends for the wolfSSL output directories.


FIPS
----

A FIPS build is wolfSSL's standard Windows FIPS procedure, then wolfProvider
pointed at the bundle. wolfSSL is linked **shared**, including FIPS; the module
passes its in-core integrity check that way.

    msbuild IDE\WINVS\wolfprovider.sln /p:Configuration="DLL Release" /p:Platform=x64 ^
        /p:wolfCryptDir="C:\src\wolfssl-fips" ^
        /p:userSettingsDir="C:\src\wolfssl-fips\IDE\WIN10" ^
        /p:wolfCryptDllRelease64="C:\src\wolfssl-fips\IDE\WIN10\DLL Release\x64" ^
        /p:wolfSslLib=wolfssl-fips.lib

wolfSSL and wolfProvider must compile against the **same** `user_settings.h`, so
`userSettingsDir` points at the bundle's copy. A layout-changing macro going
asymmetric between the two builds is silent and fatal.


Unit tests
----------

Build `Static Release|x64` and run `IDE\WINVS\Static Release\x64\unit-test.exe`
with the wolfSSL and OpenSSL DLL directories on `PATH`. `WP_UNIT_STATIC_PROVIDER`
is defined in the Static configurations only, so the test registers the linked-in
provider instead of loading the DLL; defining it elsewhere would put two copies
of wolfProvider in one process.

Building `unit-test.vcxproj` in a DLL configuration fails at link with ten
unresolved externals. That is correct: the DLL exports one symbol and the tests
reach internals. Do not widen `wolfprovider.def` to fix it.


Known limitations
-----------------

- `USE_INTEL_SPEEDUP` is unavailable: wolfSSL ships 15 x86-64 features as GAS
  `.S` but only 6 as MASM `.asm`. AES-NI and the SP big-integer paths are still
  enabled.
- SEED-SRC is not supported on Windows.
- A `WOLFPROV_DEBUG` unit-test build does not compile; `test_logging.c` uses
  `setenv()`.
- No automated Windows CI yet.
