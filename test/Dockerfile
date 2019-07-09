FROM debian:buster

# Required for building (base)
RUN apt-get update && apt-get install -y \
  automake \
  libtool \
  libglib2.0-dev \
  libcurl3-dev \
  libssl-dev \
  libdbus-1-dev

# Reqired for building (extended)
RUN apt-get update && apt-get install -y \
  libjson-glib-dev

# Rquired for testing
RUN apt-get update && apt-get install -y \
  squashfs-tools \
  dosfstools \
  lcov \
  slirp \
  python-sphinx \
  dbus-x11 \
  user-mode-linux \
  grub-common \
  softhsm2 \
  opensc \
  opensc-pkcs11 \
  libengine-pkcs11-openssl \
  faketime \
  kmod \
  uncrustify \
  casync

# Required for test environment setup
RUN apt-get update && apt-get install -y \
  python3-pip \
  git \
  gcc-7 \
  curl && \
  curl -sLo /usr/bin/codecov https://codecov.io/bash && \
  chmod +x /usr/bin/codecov

# Create required directories for bind mounts
RUN mkdir -p /lib/modules && \
    mkdir -p /var/run/dbus

RUN pip3 install --upgrade cpp-coveralls

# We want to run as non-root user equaling uid of Travis' user 'travis' (2000)
ENV user travis

RUN useradd -u 2000 -m -d /home/${user} ${user} \
 && chown -R ${user} /home/${user}

USER ${user}
