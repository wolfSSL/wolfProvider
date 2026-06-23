
SUFFIXES =
TESTS =
noinst_PROGRAMS =
noinst_HEADERS =
check_PROGRAMS =
dist_noinst_SCRIPTS =
DISTCLEANFILES =
pkginclude_HEADERS =
EXTRA_DIST =

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libwolfprov.la

EXTRA_DIST+=ChangeLog.md
EXTRA_DIST+=README.md
EXTRA_DIST+=IDE
EXTRA_DIST+=examples

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

# ---------------------------------------------------------------------------
# SBOM generation (CycloneDX + SPDX) via wolfssl's gen-sbom script
# ---------------------------------------------------------------------------
WOLFSSL_DIR ?= $(WOLFSSL_INSTALL_DIR)
WOLFSSL_INCLUDEDIR ?= $(WOLFSSL_DIR)/include
PRODUCT   = wolfprov
VERSION   = $(shell grep LIBWOLFPROV_VERSION_STRING $(srcdir)/include/wolfprovider/version.h 2>/dev/null | sed 's/.*"\(.*\)".*/\1/')
GEN_SBOM  = $(WOLFSSL_DIR)/scripts/gen-sbom
SBOM_OPTS = --name $(PRODUCT) \
            --version $(VERSION) \
            --supplier "wolfSSL Inc." \
            --options-h $(WOLFSSL_INCLUDEDIR)/wolfssl/options.h \
            --lib $(builddir)/_sbom_stage$(libdir)/libwolfprov.so.0.0.0

SBOM_OUT_DIR = $(builddir)
SBOM_CDX     = $(SBOM_OUT_DIR)/$(PRODUCT)-$(VERSION).cdx.json
SBOM_SPDX_J  = $(SBOM_OUT_DIR)/$(PRODUCT)-$(VERSION).spdx.json
SBOM_SPDX_TV = $(SBOM_OUT_DIR)/$(PRODUCT)-$(VERSION).spdx

.PHONY: sbom install-sbom uninstall-sbom

sbom: all
	@if test -z "$(WOLFSSL_DIR)"; then \
	    echo "ERROR: WOLFSSL_DIR not set. Usage: make sbom WOLFSSL_DIR=/path/to/wolfssl"; \
	    exit 1; \
	fi
	@if test -z "$(PYTHON3)"; then \
	    echo "ERROR: python3 not found in PATH."; exit 1; fi
	$(MAKE) install DESTDIR=$(builddir)/_sbom_stage
	$(PYTHON3) $(GEN_SBOM) $(SBOM_OPTS)
	rm -rf $(builddir)/_sbom_stage

install-sbom: sbom
	$(MKDIR_P) $(DESTDIR)$(datadir)/doc/$(PRODUCT)
	$(INSTALL_DATA) $(SBOM_CDX) $(SBOM_SPDX_J) $(SBOM_SPDX_TV) \
	    $(DESTDIR)$(datadir)/doc/$(PRODUCT)/

uninstall-sbom:
	-rm -f $(DESTDIR)$(datadir)/doc/$(PRODUCT)/$(PRODUCT)-*.cdx.json
	-rm -f $(DESTDIR)$(datadir)/doc/$(PRODUCT)/$(PRODUCT)-*.spdx.json
	-rm -f $(DESTDIR)$(datadir)/doc/$(PRODUCT)/$(PRODUCT)-*.spdx

uninstall-hook: uninstall-sbom

