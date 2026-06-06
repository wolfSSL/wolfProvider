# oqs-demos nginx, but with wolfProvider in place of liboqs + oqs-provider.
#
# Mirrors https://github.com/open-quantum-safe/oqs-demos/tree/main/nginx: build
# a quantum-safe OpenSSL provider, build nginx against that OpenSSL, generate an
# ML-DSA CA + server certificate, and serve TLS 1.3 with PQC groups. The only
# swap is the crypto provider: wolfProvider (backed by wolfSSL) instead of
# oqs-provider, restricted to the FIPS 203 / FIPS 204 algorithms wolfProvider
# implements. The default groups and SIG_ALG below are the wolfProvider-
# supported subset of the oqs-demos defaults.
#
# Build context is the wolfProvider repository root:
#   docker build -f .github/nginx/Dockerfile -t wolfprov-nginx .

ARG WOLFSSL_REF=master
ARG OPENSSL_REF=openssl-3.6.0
ARG NGINX_VERSION=1.28.0
ARG SIG_ALG=ML-DSA-65
ARG DEFAULT_GROUPS=MLKEM512:MLKEM768:MLKEM1024:X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024
ARG REPLACE_DEFAULT_FLAG=--replace-default
ARG WP_OPENSSL_CONF=/opt/wolfProvider/openssl-install/ssl/openssl.cnf

FROM ubuntu:22.04 AS build
ARG WOLFSSL_REF
ARG OPENSSL_REF
ARG NGINX_VERSION
ARG SIG_ALG
ARG DEFAULT_GROUPS
ARG REPLACE_DEFAULT_FLAG
ARG WP_OPENSSL_CONF
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git cmake autoconf automake libtool pkg-config \
        libpcre3-dev zlib1g-dev wget ca-certificates perl python3 \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSL 3.6+, wolfSSL, and wolfProvider. REPLACE_DEFAULT_FLAG is
# --replace-default (wolfProvider is the compile-time default) or empty
# (wolfProvider is a loadable module selected at runtime via provider.conf).
# The matrix passes both REPLACE_DEFAULT_FLAG and the matching WP_OPENSSL_CONF.
COPY . /opt/wolfProvider
WORKDIR /opt/wolfProvider
RUN OPENSSL_TAG=${OPENSSL_REF} WOLFSSL_TAG=${WOLFSSL_REF} \
        ./scripts/build-wolfprovider.sh --enable-pqc ${REPLACE_DEFAULT_FLAG}

ENV WOLFPROV_ROOT=/opt/wolfProvider
ENV O=/opt/wolfProvider/openssl-install

# Build nginx against the wolfProvider-backed OpenSSL. The download and build
# run BEFORE LD_LIBRARY_PATH points at the wolfProvider OpenSSL: otherwise
# wget's own HTTPS to nginx.org would route through wolfProvider and fail
# certificate verification. nginx finds the libs at runtime via -rpath.
WORKDIR /opt/wolfProvider
RUN wget -q "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && tar -zxf "nginx-${NGINX_VERSION}.tar.gz" && rm "nginx-${NGINX_VERSION}.tar.gz"
WORKDIR /opt/wolfProvider/nginx-${NGINX_VERSION}
RUN ./configure --prefix=/opt/nginx --with-http_ssl_module \
        --with-cc-opt="-I${O}/include" \
        --with-ld-opt="-L${O}/lib -L${O}/lib64 -Wl,-rpath,${O}/lib -Wl,-rpath,${O}/lib64 -Wl,-rpath,/opt/wolfProvider/wolfprov-install/lib -Wl,-rpath,/opt/wolfProvider/wolfssl-install/lib" \
    && make -j"$(nproc)" && make install

# From here on cert generation and the runtime server go through wolfProvider.
# In replace-default builds WP_OPENSSL_CONF is the stock openssl.cnf (a no-op);
# in non-replace builds it is provider.conf, which activates only wolfProvider
# so the PQC crypto is genuinely served by wolfSSL, not OpenSSL's native PQC.
ENV LD_LIBRARY_PATH=/opt/wolfProvider/wolfprov-install/lib:/opt/wolfProvider/wolfssl-install/lib:/opt/wolfProvider/openssl-install/lib:/opt/wolfProvider/openssl-install/lib64
ENV OPENSSL_CONF=${WP_OPENSSL_CONF}
ENV OPENSSL_MODULES=/opt/wolfProvider/wolfprov-install/lib

# Generate the ML-DSA CA + server certificate through wolfProvider (the oqs-demos
# SIG_ALG=mldsa65 arrangement) and lay down the PQC nginx config + test page.
WORKDIR /opt/nginx
COPY .github/nginx/nginx.conf /opt/nginx/conf/nginx.conf
RUN mkdir -p pki cacert logs html \
    && echo "wolfProvider quantum-safe nginx" > html/index.html \
    && "${O}/bin/openssl" req -x509 -new -newkey "${SIG_ALG}" -nodes \
        -keyout cacert/CA.key -out cacert/CA.crt -subj "/CN=wolfProvider PQC CA" \
        -days 365 -addext basicConstraints=critical,CA:TRUE \
        -addext keyUsage=critical,keyCertSign \
    && "${O}/bin/openssl" genpkey -algorithm "${SIG_ALG}" -out pki/server.key \
    && "${O}/bin/openssl" req -new -key pki/server.key -subj "/CN=oqs-nginx" \
        -addext subjectAltName=DNS:localhost -out server.csr \
    && "${O}/bin/openssl" x509 -req -in server.csr -CA cacert/CA.crt -CAkey cacert/CA.key \
        -CAcreateserial -days 365 -copy_extensions copy -out pki/server.crt

COPY .github/nginx/test.sh /opt/nginx/test.sh
RUN chmod +x /opt/nginx/test.sh

ENV DEFAULT_GROUPS=${DEFAULT_GROUPS}
EXPOSE 4433

# Default: serve. The CI test step overrides this with test.sh.
CMD ["/opt/nginx/sbin/nginx", "-c", "/opt/nginx/conf/nginx.conf", "-g", "daemon off;"]
