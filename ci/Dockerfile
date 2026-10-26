# syntax=docker/dockerfile:1
#
# The build the CI workflow (.github/workflows/ci.yml) runs: twist built with
# gcc, warnings as errors, and its unit tests ("make check").  It does not run
# the integration tests, which need peers on the network and skip without
# them, or the fuzzers.  Build from the repository root, so that the sources
# are in the context:
#
#   docker build --target check -f ci/Dockerfile .
#
# To build against other commits of the two libraries than the tips of their
# main branches, name them:
#
#   docker build --target check -f ci/Dockerfile \
#     --build-arg QUICKSTEP_REF=<commit> --build-arg FOXTROT_REF=<commit> .

# ---- Build: the libraries twist needs, then twist, with gcc ----------------
FROM ubuntu:24.04 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         autoconf autopoint automake build-essential ca-certificates curl \
         bzip2 gettext git libbrotli-dev libgnutls28-dev libreadline-dev \
         libtool pkg-config texinfo zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# foxtrot needs libgcrypt 1.12.4 or newer, and that needs a newer libgpg-error
# than Ubuntu 24.04 has: both are built here.  The versions and checksums are
# quickstep's and foxtrot's.
ARG GPGERROR_VERSION=1.61
ARG GPGERROR_SHA256=7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93
ARG LIBGCRYPT_VERSION=1.12.4
ARG LIBGCRYPT_SHA256=d77f68f48879510e79a2f65977ccc68981781ea0923e5bdffac2a193ea3d660e
RUN curl -fsSL -o gpgrt.tar.bz2 \
         https://gnupg.org/ftp/gcrypt/gpgrt/libgpg-error-${GPGERROR_VERSION}.tar.bz2 \
    && echo "${GPGERROR_SHA256}  gpgrt.tar.bz2" | sha256sum -c - \
    && tar xjf gpgrt.tar.bz2 \
    && cd libgpg-error-${GPGERROR_VERSION} \
    && ./configure --prefix=/usr/local --disable-static --disable-doc \
         --disable-tests \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf gpgrt.tar.bz2 libgpg-error-${GPGERROR_VERSION} \
    && ldconfig
# The loader must find these, not the older libgpg-error and libgcrypt that
# Ubuntu's own packages pull in: twist's configure checks the libgcrypt that a
# program is given, and refuses an older one.
ENV LD_LIBRARY_PATH=/usr/local/lib
RUN curl -fsSL -o libgcrypt.tar.bz2 \
         https://gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-${LIBGCRYPT_VERSION}.tar.bz2 \
    && echo "${LIBGCRYPT_SHA256}  libgcrypt.tar.bz2" | sha256sum -c - \
    && tar xjf libgcrypt.tar.bz2 \
    && cd libgcrypt-${LIBGCRYPT_VERSION} \
    && ./configure --prefix=/usr/local --disable-static --disable-doc \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf libgcrypt.tar.bz2 libgcrypt-${LIBGCRYPT_VERSION} \
    && ldconfig

# quickstep (TLS and QUIC) and foxtrot (SSH), from the commit named, which is
# the tip of main unless the build says otherwise.  The workflow names the
# commits, so that a change to either one is a change to these layers and the
# cache does not hand back an old build.  GnuTLS is wanted explicitly: it is
# quickstep's certificate checking, which twist cannot do without.
ARG QUICKSTEP_REF=main
ARG FOXTROT_REF=main
ENV CC=gcc PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
RUN mkdir /deps-quickstep && cd /deps-quickstep \
    && git init -q \
    && git remote add origin https://github.com/cpkb-bluezoo/quickstep.git \
    && git fetch -q --depth 1 origin "${QUICKSTEP_REF}" \
    && git checkout -q FETCH_HEAD \
    && ./autogen.sh \
    && ./configure --prefix=/usr/local --with-gnutls --without-wolfssl \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /deps-quickstep
RUN mkdir /deps-foxtrot && cd /deps-foxtrot \
    && git init -q \
    && git remote add origin https://github.com/cpkb-bluezoo/foxtrot.git \
    && git fetch -q --depth 1 origin "${FOXTROT_REF}" \
    && git checkout -q FETCH_HEAD \
    && ./autogen.sh \
    && ./configure --prefix=/usr/local --with-gnutls \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /deps-foxtrot

WORKDIR /src
COPY . .

# Extra arguments for configure.  The workflow builds with --with-brotli, which
# fails if libbrotli is not found, and with --without-brotli, so that both
# builds of the optional dependency are tested.
ARG TWIST_CONFIGURE=

# Warnings are errors: the tree is expected to build cleanly with gcc.
RUN ./bootstrap \
    && ./configure $TWIST_CONFIGURE \
    && make -j"$(nproc)" CFLAGS="-g -O2 -Werror"

# ---- Check: the unit tests --------------------------------------------------
# "docker build --target check" runs them; a failing test fails the build.
# "make check" is the unit tests of tests/, in-process and with no peer on the
# network.  The integration tests (make check-integration) and the fuzzers
# (make check-fuzz) are not run here.
FROM build AS check
RUN make check -j"$(nproc)" CFLAGS="-g -O2 -Werror" \
    || (cat tests/test-suite.log; exit 1)

# ---- Integration: the lab ---------------------------------------------------
# The peers the integration tests dial, installed beside twist in a clean
# GNU userland, so that the result does not depend on what the host has.  Run
# by integration/lab.sh with podman; see HACKING.  Not run by CI.
#
# sshd and the other servers run as the unprivileged user "lab", as they do on
# a developer's machine, and the tests make their own keys and certificates.
FROM build AS integration
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         curl nghttp2 nghttp2-client nodejs openssh-client openssh-server \
         openssl python3 python3-pip tftp-hpa vsftpd \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --break-system-packages aioquic==1.2.0 \
    && mkdir -p /run/sshd \
    && useradd -m lab \
    && chown -R lab /src
WORKDIR /src
# The container starts as root only to make /etc/resolv.conf writable
# (integration/lab-init.sh), and the tests run as "lab".
# A peer that is not installed makes a test skip (exit 77); in the lab that is
# a failure, so the result is checked for skips.
CMD ["integration/lab-init.sh"]
