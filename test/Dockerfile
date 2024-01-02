FROM debian:bullseye

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
  libnl-genl-3-dev

# Required for building the cgi example
RUN apt-get update -q && apt-get install -q -y --no-install-recommends \
  autoconf \
  automake \
  make \
  xz-utils

# Required for testing
RUN apt-get install -q -y --no-install-recommends \
  squashfs-tools \
  dosfstools \
  lcov \
  slirp \
  python3-sphinx \
  python3-sphinx-rtd-theme \
  dbus \
  dbus-x11 \
  grub-common \
  softhsm2 \
  opensc \
  opensc-pkcs11 \
  libengine-pkcs11-openssl \
  fakeroot \
  faketime \
  pseudo \
  time \
  kmod \
  uncrustify \
  casync \
  qemu-system-x86 \
  procps \
  mtd-utils \
  python3-aiohttp \
  nginx-light \
  fdisk \
  golang

# Required for test environment setup
RUN apt-get install -q -y --no-install-recommends \
  python3-pip \
  git \
  curl && \
  rm -rf /var/lib/apt/lists/* && \
  curl -sLo /usr/bin/codecov https://codecov.io/bash && \
  chmod +x /usr/bin/codecov

# Install the optional desync (pinned to version 0.9.3)
ENV GOPATH=/go
RUN git clone https://github.com/folbricht/desync.git /tmp/desync && \
    cd /tmp/desync/cmd/desync && \
    git checkout c508eeb0865a5a7c2c9b1158a5f0414265d869df && \
    go install && \
    cp /go/bin/desync /usr/bin/desync && \
    rm -rf /tmp/desync

# Create required directories for bind mounts
RUN mkdir -p /lib/modules /var/run/dbus

RUN adduser --disabled-password --gecos "" rauc-ci

USER rauc-ci
