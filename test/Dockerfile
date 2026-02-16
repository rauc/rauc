FROM debian:bookworm

# Add backports for pkcs11-provider
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" \
  > /etc/apt/sources.list.d/backports.list

# Required for building
RUN apt-get update -q && apt-get install -q -y --no-install-recommends \
  gcc \
  g++ \
  meson \
  libtool \
  libglib2.0-dev \
  libcurl3-dev \
  libssl-dev \
  libdbus-1-dev \
  libjson-glib-dev \
  libfdisk-dev \
  libnl-genl-3-dev \
  pkcs11-provider

# Required for building the cgi example
RUN apt-get install -q -y --no-install-recommends \
  autoconf \
  automake \
  make \
  xz-utils

# Required for testing
RUN apt-get install -q -y --no-install-recommends \
  acl \
  squashfs-tools \
  dosfstools \
  lcov \
  slirp \
  python3-pyasn1 \
  python3-pyasn1-modules \
  python3-pytest \
  python3-pydbus \
  python3-dasbus \
  python3-sphinx \
  python3-sphinx-rtd-theme \
  dbus \
  dbus-x11 \
  grub-common \
  opensc \
  opensc-pkcs11 \
  libengine-pkcs11-openssl \
  pkcs11-provider \
  fakeroot \
  faketime \
  pseudo \
  time \
  tree \
  kmod \
  uncrustify \
  casync \
  qemu-system-x86 \
  procps \
  mtd-utils \
  mmc-utils \
  python3-aiohttp \
  python3-requests \
  nginx-light \
  fdisk

# Required for test environment setup
RUN apt-get install -q -y --no-install-recommends \
  sudo \
  python3-pip \
  git \
  curl && \
  curl -sLo /usr/bin/codecov https://codecov.io/bash && \
  chmod +x /usr/bin/codecov

# Install softhsm2 only on working architectures (32 bit arm seems broken)
RUN test "$(uname -m)" = "armv7l" && exit 0; \
    apt-get install -q -y --no-install-recommends softhsm2

# Build and install the optional desync (pinned to version 0.9.3) only on x86_64
ENV GOPATH=/go
RUN test "$(uname -m)" != "x86_64" && exit 0; \
    apt-get install -q -y --no-install-recommends golang && \
    git clone https://github.com/folbricht/desync.git /tmp/desync && \
    cd /tmp/desync/cmd/desync && \
    git checkout c508eeb0865a5a7c2c9b1158a5f0414265d869df && \
    go install && \
    cp /go/bin/desync /usr/bin/desync && \
    rm -rf /tmp/desync /go

# Create required directories for bind mounts
RUN mkdir -p /lib/modules /var/run/dbus

# Remove apt lists
RUN rm -rf /var/lib/apt/lists/*

RUN adduser --disabled-password --comment "" rauc-ci && \
    echo "rauc-ci ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/rauc-ci

USER rauc-ci
