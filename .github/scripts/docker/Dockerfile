# Dockerfile
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfProvider.
#
# wolfProvider is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfProvider is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wolfProvider. If not, see <http://www.gnu.org/licenses/>.
# 
# This image contains all the dependcies required to build wolfProvider and 
# test with our OSP integrations in `.github/workflows`. Using the docker allows
# us to avoid having to install all the dependencies on the host machine and 
# speed up the build process.

FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Common dependencies used by build-wolfprovider.yml and most OSP workflows
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    devscripts \
    debhelper \
    dh-autoreconf \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    ca-certificates \
    openssl \
    dpkg-dev \
    lintian \
    fakeroot \
    dh-exec \
    equivs \
    expect \
    xxd \
    bc \
    libdistro-info-perl \
    \
    # Common OSP build dependencies
    autoconf \
    automake \
    make \
    \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for bind9.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnutls-bin \
    libidn2-dev \
    libuv1-dev \
    libnghttp2-dev \
    libcap-dev \
    libjemalloc-dev \
    zlib1g-dev \
    libxml2-dev \
    libjson-c-dev \
    libcmocka-dev \
    python3-pytest \
    python3-dnspython \
    python3-hypothesis \
    patch \
    iproute2 \
    net-tools \
    perl \
    && PERL_MM_USE_DEFAULT=1 cpan -i Net::DNS \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for curl.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    nghttp2 \
    libpsl5 \
    libpsl-dev \
    python3-impacket \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for openldap.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    libjansson-dev \
    check \
    groff \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for grpc.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libc++-dev \
    python3-six \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for nginx.yml workflow
# Note: Net::SSLeay and IO::Socket::SSL are installed in the workflow itself
# after OpenSSL packages are installed (which provide the required headers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    libpcre3-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for tcpdump.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    flex \
    bison \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for tpm2-tools.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    dbus \
    vim-common \
    autoconf-archive \
    python3 \
    python3-yaml \
    python3-pip \
    libefivar-dev \
    libcmocka-dev \
    pandoc \
    libtss2-dev \
    tpm2-abrmd \
    swtpm \
    tpm2-tools \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for rsync.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    gawk \
    python3-cmarkgfm \
    acl \
    libacl1-dev \
    attr \
    libattr1-dev \
    libxxhash-dev \
    libzstd-dev \
    liblz4-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for tnftp.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    vsftpd \
    libncurses5-dev \
    libncursesw5-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for x11vnc.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6-dev \
    libjpeg-dev \
    x11proto-core-dev \
    libxss-dev \
    libavahi-client-dev \
    libvncserver-dev \
    libx11-dev \
    libxdamage-dev \
    libxext-dev \
    libxfixes-dev \
    libxi-dev \
    libxinerama-dev \
    libxrandr-dev \
    libxtst-dev \
    xvfb \
    tigervnc-viewer \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for cjose.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjansson-dev \
    check \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for git-ssh-dr.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    openssh-server \
    net-tools \
    git-all \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for hostap.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libpcap-dev \
    libcurl4-openssl-dev \
    libnl-3-dev \
    binutils-dev \
    libiberty-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    libdbus-1-dev \
    bridge-utils \
    tshark \
    python3-pycryptodome \
    libsqlite3-dev \
    libzstd1 \
    wireless-tools \
    iw \
    flex \
    bison \
    python3-pip \
    procps \
    systemd \
    kmod \
    wireless-regdb \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for iperf.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libc++-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for krb5.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    bison \
    flex \
    libldap2-dev \
    libkeyutils-dev \
    libverto-dev \
    libcom-err2 \
    comerr-dev \
    libss2 \
    ss-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libcryptsetup.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    asciidoctor \
    gettext \
    autopoint \
    uuid-dev \
    libdevmapper-dev \
    libpopt-dev \
    libjson-c-dev \
    libargon2-dev \
    libblkid-dev \
    bsdextrautils \
    kmod \
    util-linux \
    cryptsetup-bin \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libeac3.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    help2man \
    gengetopt \
    m4 \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libfido2.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libudev-dev \
    libcbor-dev \
    libpcsclite-dev \
    pcscd \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libhashkit2.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    bison \
    flex \
    memcached \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libnice.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    meson \
    ninja-build \
    libglib2.0-dev \
    libgstreamer1.0-dev \
    libunwind-dev \
    gstreamer1.0-plugins-base-apps \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for liboauth2.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcurl4-openssl-dev \
    libcjose-dev \
    apache2-dev \
    libhiredis-dev \
    libmemcached-dev \
    autotools-dev \
    check \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libssh2.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libc++-dev \
    python3-impacket \
    openssh-client \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libtss2.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcunit1-dev \
    autoconf-archive \
    gettext \
    libjson-c-dev \
    libcurl4-openssl-dev \
    acl \
    libusb-1.0-0-dev \
    uuid-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for libwebsockets.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    libcap2 \
    zlib1g \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for net-snmp.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libperl-dev \
    gettext \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for opensc.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    autotools-dev \
    libeac-dev \
    gengetopt \
    libpcsclite-dev \
    libreadline-dev \
    docbook-xsl \
    xsltproc \
    pcscd \
    softhsm2 \
    opensc \
    pcsc-tools \
    vim \
    libjson-c-dev \
    libp11-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for openssh.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    patch \
    zlib1g-dev \
    kmod \
    util-linux \
    cryptsetup-bin \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for openvpn.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    liblzo2-dev \
    libpam0g-dev \
    liblz4-dev \
    libcap-ng-dev \
    linux-libc-dev \
    man2html \
    libcmocka-dev \
    python3-docutils \
    libnl-genl-3-dev \
    libnl-genl-3-200 \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for pam-pkcs11.yml workflow
# (already covered by common dependencies - build-essential, autoconf, automake, libtool, pkg-config)

# Dependencies for ppp.yml workflow
# (already covered by common dependencies - build-essential, autoconf, libtool, patch)

# Dependencies for python3-ntp.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    bison \
    libcap-dev \
    libseccomp-dev \
    libavahi-compat-libdnssd-dev \
    pps-tools \
    python-dev-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for socat.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libc++-dev \
    curl \
    net-tools \
    netcat-openbsd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for sscep.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    scep \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for sssd.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldb-dev \
    libldb2 \
    python3-ldb \
    bc \
    libcap-dev \
    libutf8proc-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for stunnel.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf-archive \
    libwrap0-dev \
    python3-venv \
    python3-cryptography \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for systemd.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    meson \
    ninja-build \
    libmount-dev \
    gperf \
    python3-pytest \
    python3-jinja2 \
    python3-pip \
    libuv1-dev \
    libnghttp2-dev \
    libcap-dev \
    uuid-dev \
    libdevmapper-dev \
    libpopt-dev \
    libjson-c-dev \
    libargon2-dev \
    libblkid-dev \
    asciidoctor \
    pkgconf \
    zlib1g-dev \
    libgcrypt20-dev \
    libgpg-error-dev \
    libgnutls28-dev \
    libp11-kit-dev \
    libfido2-dev \
    libtss2-dev \
    libdw-dev \
    libbz2-dev \
    liblzma-dev \
    liblz4-dev \
    libzstd-dev \
    libxkbcommon-dev \
    libglib2.0-dev \
    libdbus-1-dev \
    python3-setuptools \
    python3-wheel \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for xmlsec.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libtool-bin \
    libltdl-dev \
    libltdl7 \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependencies for qt5network5.yml workflow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcre2-dev \
    zlib1g-dev \
    cmake \
    ninja-build \
    bison \
    flex \
    libpng-dev \
    libjpeg-dev \
    && rm -rf /var/lib/apt/lists/*

# Note: The following workflows don't require additional dependencies beyond common:
# - asan.yml: Uses build-wolfprovider.sh script (no extra deps)
# - cmdline.yml: Uses build-wolfprovider.sh script (no extra deps)
# - codespell.yml: Uses external action (no extra deps)
# - debian-package.yml: Uses packages from build job (no extra deps)
# - fips-ready.yml: Downloads FIPS bundle (no extra deps)
# - multi-compiler.yml: Installs compiler packages dynamically via matrix (CC/CXX)
# - openssl-version.yml: Uses build-wolfprovider.sh script (no extra deps)
# - simple.yml: Uses build-wolfprovider.sh script (no extra deps)
