# wolfProvider test-deps container.
#
# Bakes in the union of apt packages every PR workflow used to install at
# job time. Goal: zero `apt-get update` calls during PR CI. Built and
# pushed to ghcr.io/wolfssl/wolfprovider-test-deps:bookworm by the
# publish-test-deps-image.yml workflow.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PERL_MM_USE_DEFAULT=1

# One apt-get update + one apt-get install. Anything you add here ships
# in the image; do not add per-workflow installs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # core build toolchain
        build-essential gcc g++ make m4 gettext \
        autoconf automake autoconf-archive autopoint autotools-dev \
        libtool libtool-bin pkg-config pkgconf \
        cmake meson ninja-build bison flex gperf gengetopt help2man \
        clang clang-tools cppcheck libc++-dev \
        # vcs, transport, compression, scripting
        git git-all curl wget ca-certificates patch xxd dpkg-dev jq \
        gawk perl python3 python3-pip python3-venv python3-wheel \
        python3-setuptools python3-yaml python3-jinja2 python3-six \
        python3-pytest python3-dnspython python3-hypothesis \
        python3-impacket python3-cryptography python3-pycryptodome \
        python3-cmarkgfm python3-docutils python-dev-is-python3 \
        cpanminus \
        # editors, debug, system bits
        valgrind vim vim-common groff sudo procps psmisc bc less \
        bsdextrautils util-linux kmod systemd cryptsetup-bin \
        ca-certificates dbus \
        # networking, ssh, vnc, sniffers
        net-tools netcat-openbsd iproute2 iw bridge-utils \
        openssh-client openssh-server expect \
        tigervnc-viewer xvfb \
        wireless-regdb wireless-tools \
        # zlib / xz / lzma / bz2 / lzo / lz4 / zstd
        zlib1g zlib1g-dev liblzma-dev libbz2-dev liblzo2-dev \
        liblz4-dev libzstd-dev libzstd1 \
        # crypto / TLS adjacents. libssl3/libssl-dev are the *stock* Debian
        # versions; replace-default mode dpkg-installs wolfprov-patched
        # debs on top (and apt-marks them held) at job time.
        openssl libssl-dev libssl3 \
        libgcrypt20-dev libgpg-error-dev \
        libgnutls28-dev gnutls-bin \
        libp11-dev libp11-kit-dev libargon2-dev libcbor-dev \
        libcurl4-openssl-dev libidn2-dev libnghttp2-dev nghttp2 \
        libpsl-dev libpsl5 \
        libpcsclite-dev opensc pcsc-tools pcscd \
        libtss2-dev tpm2-tools tpm2-abrmd swtpm softhsm2 \
        libfido2-dev \
        libsasl2-dev libldap2-dev libldb-dev libldb2 \
        libpcre2-dev libpcre3-dev \
        libreadline-dev libsqlite3-dev libpopt-dev libpcap-dev libpcap0.8 \
        libseccomp-dev libwrap0-dev libudev-dev libdevmapper-dev libcap-dev \
        libcap-ng-dev libcap2 libacl1-dev libattr1-dev libblkid-dev \
        libmount-dev libdw-dev libdbus-1-dev libglib2.0-dev \
        libgstreamer1.0-dev gstreamer1.0-plugins-base-apps \
        libhiredis-dev libjansson-dev libjemalloc-dev libjson-c-dev \
        libxml2-dev libcunit1-dev libcmocka-dev libpam0g-dev \
        libpng-dev libjpeg-dev libusb-1.0-0-dev libuv1-dev libverto-dev \
        libavahi-client-dev libavahi-compat-libdnssd-dev libmemcached-dev \
        libutf8proc-dev libxxhash-dev libkeyutils-dev libcom-err2 \
        libcjose-dev libeac-dev libefivar-dev libncurses5-dev \
        libncursesw5-dev libiberty-dev libltdl-dev libltdl7 \
        libperl-dev linux-libc-dev binutils-dev uuid-dev \
        # X11 (x11vnc, qt5network5)
        libx11-dev libxdamage-dev libxext-dev libxfixes-dev libxi-dev \
        libxinerama-dev libxrandr-dev libxss-dev libxtst-dev \
        libxkbcommon-dev libvncserver-dev x11proto-core-dev \
        # netlink (hostap)
        libnl-3-dev libnl-route-3-dev libnl-genl-3-dev libnl-genl-3-200 \
        # krb5 build deps (e2fsprogs headers)
        comerr-dev ss-dev libss2 \
        # sscep test
        scep \
        # extras called out by specific workflows
        check apache2-dev acl attr fakeroot \
        asciidoctor docbook-xsl pandoc xsltproc man2html \
        memcached vsftpd pps-tools tshark \
        opam \
    && rm -rf /var/lib/apt/lists/*

# Perl modules used by app test suites. Baked in so transient CPAN
# flakes don't poison a PR run.
RUN cpanm --notest \
        Net::DNS \
        Proc::Find Net::SSLeay IO::Socket::SSL \
    && rm -rf /root/.cpanm

# OpenSSL/wolfSSL come from .deb packages pulled at job time via ORAS.
# We do NOT pre-install them here; the workflows do
#   dpkg -i $WOLFSSL_PACKAGES_PATH/libwolfssl_*.deb
# and then apt-mark hold them to stop test-dep apt installs from
# clobbering the wolfprov-patched libssl3.
