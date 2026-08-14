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
internals. A `.lib` cannot act as a provider.


Prerequisites
-------------

- Visual Studio 2022 with the C++ toolset (v143) and MASM (`ml64.exe`).
- Perl, NASM and git, to build OpenSSL. Strawberry Perl includes NASM.

Run everything below from a Developer Command Prompt, or after `vcvars64.bat`.
`msbuild` and `nmake` are not on `PATH` otherwise.

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
    nmake install_ssldirs

`install_sw` alone does not write `openssl.cnf`.

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

    $env:PATH = "C:\src\wolfssl\DLL Release\x64;C:\out\openssl\bin;$env:PATH"
    openssl list -providers -provider-path "C:\src\wolfProvider\IDE\WINVS\DLL Release\x64" -provider libwolfprov

Under FIPS the dependency is `wolfssl-fips.dll`, inside the bundle:

    $env:PATH = "C:\src\wolfssl-fips\IDE\WIN10\DLL Release\x64;$env:PATH"

In `openssl.cnf`, use forward slashes in the `module` path.

The module is `libwolfprov` but the property it registers is `provider=wolfprov`
(plus `fips=yes` under FIPS):

    openssl dgst -sha256 -provider-path "...\DLL Release\x64" ^
        -provider libwolfprov -propquery "provider=wolfprov" file.bin


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
pointed at the bundle. Unpack it alongside the other trees; the commands below
assume `C:\src\wolfssl-fips`. `DLL Release|x64` and `DLL Debug|x64` are the
approved FIPS configurations.

Enable FIPS near the top of the bundle's `IDE\WIN10\user_settings.h`: for a
commercial bundle set the `#if 0` over `HAVE_FIPS_VERSION 5` to `#if 1`, for
FIPS-Ready uncomment `/* #define WOLFSSL_FIPS_READY */`. Each is tested on the
line below it, so define it there and nowhere else in the file.

Copy `user_settings-fips.h` from this directory next to it and include it after
the `#endif` closing `_WIN_USER_SETTINGS_H_`:

    #include "user_settings-fips.h"

Build the FIPS DLL and the test app that reports its hash. Both are pinned to
`v110`, so retarget on the command line, and name the `.vcxproj` files rather
than `wolfssl-fips.sln`, which MSBuild 17 cannot load (`MSB4025`).

    cd C:\src\wolfssl-fips\IDE\WIN10
    msbuild wolfssl-fips.vcxproj /p:Configuration="DLL Release" /p:Platform=x64 ^
        /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=10.0
    msbuild test.vcxproj /p:Configuration="DLL Release" /p:Platform=x64 ^
        /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=10.0

Leave the project's optimiser and linker settings as shipped.

Run `test.exe` from `DLL Release\x64\` and follow wolfSSL's `verifyCore`
procedure with the hash it prints. The hash covers only the wolfSSL DLL, so
rebuilding wolfProvider never invalidates it.

Then build wolfProvider against the bundle, from the wolfProvider root:

    cd C:\src\wolfProvider
    msbuild IDE\WINVS\wolfprovider.sln /p:Configuration="DLL Release" /p:Platform=x64 ^
        /p:wolfCryptDir="C:\src\wolfssl-fips" ^
        /p:userSettingsDir="C:\src\wolfssl-fips\IDE\WIN10" ^
        /p:wolfCryptDllRelease64="C:\src\wolfssl-fips\IDE\WIN10\DLL Release\x64" ^
        /p:wolfSslLib=wolfssl-fips.lib

Both builds must compile against the same `user_settings.h`, which is why
`userSettingsDir` points at the bundle's copy.


Unit tests
----------

Build `Static Release|x64` and run `IDE\WINVS\Static Release\x64\unit-test.exe`
with the wolfSSL DLL directory and `C:\out\openssl\bin` on `PATH`. Against a
FIPS bundle pass the same overrides as the provider build, `wolfCryptDllRelease64`
included — the Static configurations link it too. `WP_UNIT_STATIC_PROVIDER`
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
