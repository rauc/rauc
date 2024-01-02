FROM debian:bullseye

# Required for building
RUN apt-get update && apt-get install -y \
  meson \
  libtool \
  libglib2.0-dev \
  libcurl3-dev \
  libssl-dev \
  libdbus-1-dev \
  libjson-glib-dev \
  libfdisk-dev \
  libnl-genl-3-dev

# Required for testing
RUN apt-get update && apt-get install -y \
  squashfs-tools \
  dosfstools \
  lcov \
  slirp \
  python3-sphinx \
  python3-sphinx-rtd-theme \
  dbus-x11 \
  grub-common \
  softhsm2 \
  opensc \
  opensc-pkcs11 \
  libengine-pkcs11-openssl \
  faketime \
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
RUN apt-get update && apt-get install -y \
  python3-pip \
  git \
  gcc-10 \
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
RUN mkdir -p /lib/modules && \
    mkdir -p /var/run/dbus

# We want to run as non-root user equaling uid of Travis' user 'travis' (2000)
ENV user travis

RUN useradd -u 2000 -m -d /home/${user} ${user} \
 && chown -R ${user} /home/${user}

USER ${user}
