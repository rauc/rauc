#!/bin/sh

test_description="rauc binary tests"

. ./sharness.sh

export G_DEBUG="fatal-criticals"

TEST_TMPDIR=$(mktemp -d)

CA_DEV="${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev"
CA_REL="${SHARNESS_TEST_DIRECTORY}/openssl-ca/rel"
if [ -e "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so" ]; then
  SOFTHSM2_MOD="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
else
  SOFTHSM2_MOD="/usr/lib/softhsm/libsofthsm2.so"
fi

# Provide functions to start and stop a dedicated session bus
start_session_bus ()
{
  eval $(dbus-launch --sh-syntax)
}
stop_session_bus ()
{
  kill ${DBUS_SESSION_BUS_PID}
}

# If running under qemu use the prepared system bus otherwise start a
# dedicated session bus
select_system_or_session_bus ()
{
  if grep -q "init=[^ ]*/qemu-test-init" /proc/cmdline; then
    export DBUS_STARTER_BUS_TYPE=system
  else
    start_session_bus
    cleanup stop_session_bus
    export DBUS_STARTER_BUS_TYPE=session
  fi
}

# Provide functions to start and stop the RAUC background service using the test
# configuration
start_rauc_dbus_service ()
{
  rauc "$@" service&
  RAUC_DBUS_SERVICE_PID=$!

  # The timeout is measured in nanoseconds
  TIMEOUT=$(( 5 * 1000 * 1000 * 1000 ))
  END=$(( $(date +%s%N) + ${TIMEOUT} ))

  # Wait for RAUC's background service to appear on the bus or the timeout
  # period to elapse
  while true; do
    dbus-send --${DBUS_STARTER_BUS_TYPE} --dest=de.pengutronix.rauc \
      --reply-timeout=1000 --print-reply --type=method_call \
      / org.freedesktop.DBus.Peer.Ping > /dev/null 2>&1 && break
    test $(date +%s%N) -ge ${END} && break
  done
}
stop_rauc_dbus_service ()
{
  kill ${RAUC_DBUS_SERVICE_PID}
  wait ${RAUC_DBUS_SERVICE_PID}
}
start_rauc_dbus_service_with_system ()
{
  rm -rf ${SHARNESS_TEST_DIRECTORY}/images &&
  mkdir ${SHARNESS_TEST_DIRECTORY}/images &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/rootfs-0 &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/rootfs-1 &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/appfs-0 &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/appfs-1 &&
  start_rauc_dbus_service "$@"
}
stop_rauc_dbus_service_with_system ()
{
  stop_rauc_dbus_service &&
  rm -r ${SHARNESS_TEST_DIRECTORY}/images
}

prepare_softhsm2 ()
{
  export SOFTHSM2_CONF="${SHARNESS_TRASH_DIRECTORY}/softhsm2.conf"
  export SOFTHSM2_DIR="${SHARNESS_TRASH_DIRECTORY}/softhsm2.tokens"

  echo "directories.tokendir = $SOFTHSM2_DIR" > "$SOFTHSM2_CONF"
  mkdir -p "$SOFTHSM2_DIR"

  pkcs11-tool --module ${SOFTHSM2_MOD} --init-token --label rauc --so-pin 0000
  pkcs11-tool --module ${SOFTHSM2_MOD} -l --so-pin 0000 --new-pin 1111 --init-pin

  p11-kit list-modules

  openssl engine pkcs11 -tt -vvvv

  openssl x509 -in ${CA_DEV}/autobuilder-1.cert.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y cert -w /proc/self/fd/0 \
    --label autobuilder-1 --id 01
  openssl rsa -in ${CA_DEV}/private/autobuilder-1.pem -inform pem -pubout -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y pubkey -w /proc/self/fd/0 \
    --label autobuilder-1 --id 01
  openssl rsa -in ${CA_DEV}/private/autobuilder-1.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y privkey -w /proc/self/fd/0 \
    --label autobuilder-1 --id 01

  openssl x509 -in ${CA_DEV}/autobuilder-2.cert.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y cert -w /proc/self/fd/0 \
    --label autobuilder-2 --id 02
  openssl rsa -in ${CA_DEV}/private/autobuilder-2.pem -inform pem -pubout -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y pubkey -w /proc/self/fd/0 \
    --label autobuilder-2 --id 02
  openssl rsa -in ${CA_DEV}/private/autobuilder-2.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y privkey -w /proc/self/fd/0 \
    --label autobuilder-2 --id 02

  pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 --list-objects

  export RAUC_PKCS11_PIN=1111
  # setting the module is needed only if p11-kit doesn't work
  export RAUC_PKCS11_MODULE=${SOFTHSM2_MOD}
}

# Prerequisite: JSON support enabled [JSON]
grep -q "ENABLE_JSON 1" $SHARNESS_BUILD_DIRECTORY/config.h && \
  test_set_prereq JSON

# Prerequisite: background service support enabled [SERVICE]
grep -q "ENABLE_SERVICE 1" $SHARNESS_BUILD_DIRECTORY/config.h &&
  test_set_prereq SERVICE &&
  select_system_or_session_bus

# Prerequisite: openssl available [OPENSSL]
openssl asn1parse -help &&
  test_set_prereq OPENSSL

# Prerequisite: HTTP server available [HTTP]
test -n "$RAUC_TEST_HTTP_SERVER" &&
  test_set_prereq HTTP

# Prerequisite: streaming support enabled [STREAMING]
grep -q "ENABLE_STREAMING 1" $SHARNESS_BUILD_DIRECTORY/config.h &&
  test -n "$RAUC_TEST_HTTP_SERVER" &&
  test_set_prereq STREAMING

# Prerequisite: casync available [CASYNC]
casync --version &&
  test_set_prereq CASYNC

# Prerequisite: desync available [DESYNC]
desync --help &&
  test_set_prereq DESYNC

# Prerequisite: softhsm2 installed [PKCS11]
test -f ${SOFTHSM2_MOD} &&
  prepare_softhsm2 &&
  test_set_prereq PKCS11

# Prerequisite: faketime available [FAKETIME]
# On some platforms faketime is broken, see e.g. https://github.com/wolfcw/libfaketime/issues/418
# Only use it if it works for date
faketime "2018-01-01" date &&
faketime "2018-01-01" date -R | grep "Jan 2018" &&
  test_set_prereq FAKETIME

# Prerequisite: grub-editenv available [GRUB]
grub-editenv -V &&
  test_set_prereq GRUB

# Prerequisite: root available [ROOT]
whoami | grep -q root &&
  test_set_prereq ROOT

test_expect_success "rauc install invalid local paths" "
  test_must_fail rauc install foo &&
  test_must_fail rauc install foo.raucb &&
  test_must_fail rauc install /path/to/foo.raucb
"

test_expect_success "rauc write-slot invalid local paths" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot system0 foo &&
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot system0 foo.raucb &&
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot system0 /path/to/foo.raucb
"

test_expect_success "rauc write-slot invalid slot" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot system0 foo &&
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot system0 foo.img &&
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot system0 /path/to/foo.img
"

test_expect_success "rauc write-slot readonly" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot rescue.0 $SHARNESS_TEST_DIRECTORY/install-content/appfs.img
"

test_expect_success OPENSSL "rauc replace signature (plain)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/out1.raucb && rm -f ${TEST_TMPDIR}/out2.raucb &&
  rm -f $TEST_TMPDIR/bundle.sig &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/out1.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  rauc \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-only-ca.pem \
    extract-signature ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out2.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success OPENSSL "rauc replace signature (verity)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-verity-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-verity-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/out1.raucb && rm -f ${TEST_TMPDIR}/out2.raucb &&
  rm -f $TEST_TMPDIR/bundle.sig &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-verity-bundle.raucb ${TEST_TMPDIR}/out1.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  rauc \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-only-ca.pem \
    extract-signature ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-verity-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out2.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success OPENSSL "rauc replace signature (crypt)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-crypt-bundle-unencrypted.raucb &&
  rm -f ${TEST_TMPDIR}/out1.raucb && rm -f ${TEST_TMPDIR}/out2.raucb &&
  rm -f $TEST_TMPDIR/bundle.sig &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/out1.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  rauc \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-only-ca.pem \
    extract-signature ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out2.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success OPENSSL "rauc replace signature (output exists)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/out1.raucb && rm -f ${TEST_TMPDIR}/out2.raucb &&
  rm -f $TEST_TMPDIR/bundle.sig &&
  touch ${TEST_TMPDIR}/out2.raucb &&
  rauc \
    --cert ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev/autobuilder-1.cert.pem \
    --key ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/out1.raucb &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    extract-signature ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  test_must_fail rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out2.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success OPENSSL "rauc replace signature (bad keyring)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/out1.raucb && rm -f ${TEST_TMPDIR}/out2.raucb &&
  rm -f $TEST_TMPDIR/bundle.sig &&
  rauc \
    --cert ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev/autobuilder-1.cert.pem \
    --key ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/out1.raucb &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    extract-signature ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  test_must_fail rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out2.raucb &&
  test ! -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success OPENSSL "rauc replace signature (no-verify)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/out1.raucb && rm -f ${TEST_TMPDIR}/out2.raucb &&
  rm -f $TEST_TMPDIR/bundle.sig &&
  rauc \
    --cert ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev/autobuilder-1.cert.pem \
    --key ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/out1.raucb &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    extract-signature ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem \
    --no-verify \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out2.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-only-ca.pem &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success OPENSSL "rauc replace signature (invalid bundle/signature/output)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/invalid.raucb ${TEST_TMPDIR}/invalid.sig \
    ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out.raucb &&
  touch ${TEST_TMPDIR}/invalid.raucb ${TEST_TMPDIR}/invalid.sig
  rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    extract-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig &&
  test -f ${TEST_TMPDIR}/bundle.sig &&
  openssl asn1parse -inform DER -in ${TEST_TMPDIR}/bundle.sig -noout > /dev/null 2>&1 &&
  test_must_fail rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/invalid.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/out.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem &&
  test ! -f ${TEST_TMPDIR}/out.raucb &&
  test_must_fail rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/invalid.sig ${TEST_TMPDIR}/out.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem &&
  test ! -f ${TEST_TMPDIR}/out.raucb &&
  test_must_fail rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/notexisting/out.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem &&
  test ! -f ${TEST_TMPDIR}/notexisting/out.raucb &&
  test_must_fail rauc \
    --keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem \
    replace-signature ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/bundle.sig ${TEST_TMPDIR}/good-bundle.raucb \
    --signing-keyring ${SHARNESS_TEST_DIRECTORY}/openssl-ca/dev-ca.pem &&
  test -f ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success "rauc bundle (crypt bundle)" "
  test_when_finished rm -rf ${TEST_TMPDIR}/install-content &&
  test_when_finished rm -f ${TEST_TMPDIR}/out.raucb &&
  cp -rL ${SHARNESS_TEST_DIRECTORY}/install-content ${TEST_TMPDIR}/ &&
  cp -fL ${SHARNESS_TEST_DIRECTORY}/install-content/manifest.raucm.crypt ${TEST_TMPDIR}/install-content/manifest.raucm &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    bundle ${TEST_TMPDIR}/install-content ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success "rauc encrypt (multiple single-cert PEM files)" "
  test_when_finished rm -f ${TEST_TMPDIR}/encrypted.raucb &&
  rauc encrypt \
    --to $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/rsa-4096/cert-000.pem \
    --to $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/rsa-4096/cert-001.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    ${SHARNESS_TEST_DIRECTORY}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/encrypted.raucb &&
  test -f ${TEST_TMPDIR}/encrypted.raucb
"

test_expect_success "rauc encrypt (single multiple-cert PEM file)" "
  test_when_finished rm -f ${TEST_TMPDIR}/encrypted.raucb &&
  rauc encrypt \
    --to $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/rsa-4096/certs.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    ${SHARNESS_TEST_DIRECTORY}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/encrypted.raucb &&
  test -f ${TEST_TMPDIR}/encrypted.raucb
"

test_expect_success "rauc encrypt (single multiple-cert PEM file, RSA+ECC mixed)" "
  test_when_finished rm -f ${TEST_TMPDIR}/encrypted.raucb &&
  rauc encrypt \
    --to $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/rsa-4096/certs.pem \
    --to $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/ecc/certs.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    ${SHARNESS_TEST_DIRECTORY}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/encrypted.raucb &&
  test -f ${TEST_TMPDIR}/encrypted.raucb
"

test_expect_success "rauc encrypt (broken multiple-cert PEM file)" "
  test_when_finished rm -f ${TEST_TMPDIR}/encrypted.raucb &&
  test_when_finished rm -f ${TEST_TMPDIR}/certs.pem &&
  head -n -5 $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/rsa-4096/certs.pem > ${TEST_TMPDIR}/certs.pem &&
  test_must_fail rauc encrypt \
    --to ${TEST_TMPDIR}/certs.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    ${SHARNESS_TEST_DIRECTORY}/good-crypt-bundle-unencrypted.raucb ${TEST_TMPDIR}/encrypted.raucb &&
  test ! -f ${TEST_TMPDIR}/encrypted.raucb
"

test_expect_success "rauc encrypt (verity bundle)" "
  test_must_fail rauc encrypt \
    --to $SHARNESS_TEST_DIRECTORY/openssl-enc/keys/rsa-4096/cert-000.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    ${SHARNESS_TEST_DIRECTORY}/good-verity-bundle.raucb ${TEST_TMPDIR}/encrypted.raucb &&
  test ! -f ${TEST_TMPDIR}/encrypted.raucb
"

rm -rf $TEST_TMPDIR

test_done
