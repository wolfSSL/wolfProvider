
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
EXTRA_DIST+=IDE
EXTRA_DIST+=examples
EXTRA_DIST+=docs
EXTRA_DIST+=patches
EXTRA_DIST+=provider.conf
EXTRA_DIST+=provider-fips.conf

include src/include.am
include include/include.am
include test/include.am
include certs/include.am
include scripts/include.am
include examples/include.am

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

# SBOM generation (CRA compliance).  The recipe is shared across the wolfSSL
# stack's autotools products in scripts/sbom.am; wolfProvider just declares what
# it is (a shared library that links both wolfSSL and OpenSSL) and includes it.
# WOLFSSL_DIR must point to a wolfssl source tree containing scripts/gen-sbom;
# it defaults to the --with-wolfssl location, which is an install prefix, so for
# `make sbom` pass a source tree: make sbom WOLFSSL_DIR=/path/to/wolfssl.
SBOM_PKGNAME      = wolfprovider
SBOM_LICENSE_FILE = $(srcdir)/COPYING
SBOM_LIB_STEM     = libwolfprov
SBOM_DEP_WOLFSSL  = yes
SBOM_DEP_OPENSSL  = yes

# wolfProvider is GPLv3-or-later (per the per-file source headers: "either
# version 3 of the License, or (at your option) any later version") or
# commercial.  Pin the header-accurate SPDX id here so the SBOM is correct
# regardless of the gen-sbom version's licence detection; commercial licensees
# can override it (e.g. LicenseRef-wolfSSL-Commercial).
SBOM_LICENSE_OVERRIDE ?= GPL-3.0-or-later

EXTRA_DIST += scripts/sbom.am

include scripts/sbom.am

