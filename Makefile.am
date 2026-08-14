
SUFFIXES =
TESTS =
noinst_PROGRAMS =
noinst_HEADERS =
check_PROGRAMS =
dist_noinst_SCRIPTS =
DISTCLEANFILES =
CLEANFILES =
pkginclude_HEADERS =
EXTRA_DIST =

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libwolfprov.la

EXTRA_DIST+=ChangeLog.md
EXTRA_DIST+=README.md
EXTRA_DIST+=examples
EXTRA_DIST+=docs
EXTRA_DIST+=patches
EXTRA_DIST+=provider.conf
EXTRA_DIST+=provider-fips.conf

# Not EXTRA_DIST+=IDE: that is recursive and not .gitignore-aware, and both
# IDE/WINVS and IDE/Android are built into.
include src/include.am
include include/include.am
include test/include.am
include certs/include.am
include scripts/include.am
include examples/include.am
include IDE/include.am

#noinst_PROGRAMS += bench
#bench_SOURCES    = bench.c
#bench_LDADD      = libwolfprov.la
#DISTCLEANFILES  += .libs/bench

test: check
# By default, make distcheck will only add wolfProvider/ as an include directory.
# So, for example, a file like unit.h that has #include
# <wolfprovider/we_logging.h> won't be able to find wp_logging.h, because
# wolfProvider/include isn't an include directory. We add it here.
#
# The OpenSSL lib and include directories won't be visible to make distcheck
# either because make distcheck runs ./configure with no other options. If
# OpenSSL isn't installed in a standard location, this naked configure command
# will fail to find it. We tell it where to find the include and lib directory
# for OpenSSL here.
#
# The '--with-wolfssl' doesn't get propagated during a distcheck either, but it
# is necessary when they are installed somewhere other than /usr/local.
AM_DISTCHECK_CONFIGURE_FLAGS=CPPFLAGS="-I@abs_top_srcdir@/include" --with-openssl=@OPENSSL_INSTALL_DIR@ --with-wolfssl=@WOLFSSL_INSTALL_DIR@

# SBOM generation (CRA compliance). The recipe is the vendored wolfGlass
# fragment at tools/sbom/sbom.am. wolfProvider declares what it is (a shared
# library that links wolfSSL and OpenSSL) and includes it. gen-sbom is vendored
# next to the fragment, so `make sbom` does not need a wolfSSL source tree.
# Set WOLFSSL_DIR only when you want the SBOM to read the linked wolfSSL
# version from wolfssl/version.h.
SBOM_PKGNAME      = wolfprovider
SBOM_LICENSE_FILE = $(srcdir)/COPYING
SBOM_LIB_STEM     = libwolfprov
SBOM_DEP_WOLFSSL  = yes
SBOM_DEP_OPENSSL  = yes

# AC_CONFIG_HEADERS puts our config.h in include/, not the build root, so the
# fragment's default would silently miss every AC_DEFINE feature macro: the
# -include is $(wildcard)-guarded, so a wrong path drops out without an error
# and the SBOM records an empty feature set.
SBOM_CONFIG_H     = $(abs_builddir)/include/config.h

# wolfProvider is GPLv3-or-later (per the per-file source headers: "either
# version 3 of the License, or (at your option) any later version") or
# commercial.  Pin the header-accurate SPDX id here so the SBOM is correct
# regardless of the gen-sbom version's licence detection; commercial licensees
# can override it (e.g. LicenseRef-wolfSSL-Commercial).
SBOM_LICENSE_OVERRIDE ?= GPL-3.0-or-later

# Automake inlines this include into Makefile. Do not assign SBOM_GEN or
# SBOM_VENDOR_DIR here: Automake -Werror treats a second assignment in
# tools/sbom/sbom.am as fatal and skips Makefile.in. The fragment default
# SBOM_VENDOR_DIR is $(srcdir)/tools/sbom.

EXTRA_DIST += tools/sbom

include tools/sbom/sbom.am

