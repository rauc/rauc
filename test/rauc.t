#!/bin/sh

test_description="rauc binary tests"

. ./sharness.sh

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

# If running under user mode linux use the prepared system bus otherwise start a
# dedicated session bus
select_system_or_session_bus ()
{
  if grep -q "init=[^ ]*/uml-test-init" /proc/cmdline; then
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
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y cert -w /dev/stdin \
    --label autobuilder-1 --id 01
  openssl rsa -in ${CA_DEV}/private/autobuilder-1.pem -inform pem -pubout -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y pubkey -w /dev/stdin \
    --label autobuilder-1 --id 01
  openssl rsa -in ${CA_DEV}/private/autobuilder-1.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y privkey -w /dev/stdin \
    --label autobuilder-1 --id 01

  openssl x509 -in ${CA_DEV}/autobuilder-2.cert.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y cert -w /dev/stdin \
    --label autobuilder-2 --id 02
  openssl rsa -in ${CA_DEV}/private/autobuilder-2.pem -inform pem -pubout -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y pubkey -w /dev/stdin \
    --label autobuilder-2 --id 02
  openssl rsa -in ${CA_DEV}/private/autobuilder-2.pem -inform pem -outform der | \
    pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 -y privkey -w /dev/stdin \
    --label autobuilder-2 --id 02

  pkcs11-tool --module ${SOFTHSM2_MOD} -l --pin 1111 --list-objects

  export RAUC_PKCS11_PIN=1111
  # setting the module is needed only if p11-kit doesn't work
  export RAUC_PKCS11_MODULE=${SOFTHSM2_MOD}
}

# Prerequisite: JSON support enabled [JSON]
grep -q "ENABLE_JSON 1" $SHARNESS_TEST_DIRECTORY/../config.h && \
  test_set_prereq JSON

# Prerequisite: background service support enabled [SERVICE]
grep -q "ENABLE_SERVICE 1" $SHARNESS_TEST_DIRECTORY/../config.h &&
  test_set_prereq SERVICE &&
  select_system_or_session_bus

# Prerequisite: softhsm2 installed [PKCS11]
test -f ${SOFTHSM2_MOD} &&
  prepare_softhsm2 &&
  test_set_prereq PKCS11

test_expect_success "rauc noargs" "
  test_must_fail rauc
"

test_expect_success "rauc invalid arg" "
  test_must_fail rauc --foobar baz
"

test_expect_success "rauc invalid cmd" "
  test_must_fail rauc dothis
"

test_expect_success "rauc missing arg" "
  test_must_fail rauc install &&
  test_must_fail rauc write-slot &&
  test_must_fail rauc info &&
  test_must_fail rauc bundle &&
  test_must_fail rauc checksum &&
  test_must_fail rauc resign &&
  test_must_fail rauc install &&
  test_must_fail rauc info
"

test_expect_success "rauc version" "
  rauc --version
"

test_expect_success "rauc help" "
  rauc --help
"

test_expect_success "rauc checksum without argument" "
  test_expect_code 1 rauc checksum
"

test_expect_success "rauc checksum with signing" "
  mkdir $SHARNESS_TEST_DIRECTORY/tmp
  cp -t $SHARNESS_TEST_DIRECTORY/tmp -a $SHARNESS_TEST_DIRECTORY/install-content/*
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    checksum $SHARNESS_TEST_DIRECTORY/tmp
  test -f $SHARNESS_TEST_DIRECTORY/tmp/manifest.raucm.sig
  rm -r $SHARNESS_TEST_DIRECTORY/tmp
"

test_expect_success "rauc checksum with extra args" "
  mkdir $SHARNESS_TEST_DIRECTORY/tmp
  cp -t $SHARNESS_TEST_DIRECTORY/tmp -a $SHARNESS_TEST_DIRECTORY/install-content/*
  rauc \
    --handler-args '--dummy'\
    checksum $SHARNESS_TEST_DIRECTORY/tmp
  grep args $SHARNESS_TEST_DIRECTORY/tmp/manifest.raucm | grep dummy
  rm -r $SHARNESS_TEST_DIRECTORY/tmp
"

test_expect_success "rauc info" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
"

test_expect_success "rauc info shell" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --output-format=shell \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb | sh
"

test_expect_success JSON "rauc info json" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --output-format=json \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
"

test_expect_success JSON "rauc info json-pretty" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --output-format=json-pretty \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
"

test_expect_success "rauc info invalid" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --output-format=invalid \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
"

test_expect_success "rauc bundle" "
  rm -f out.raucb &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info out.raucb &&
  test -f out.raucb &&
  rm out.raucb
"

test_expect_success PKCS11 "rauc bundle with PKCS11 (key 1)" "
  rm -f out.raucb &&
  rauc \
    --cert 'pkcs11:token=rauc;object=autobuilder-1' \
    --key 'pkcs11:token=rauc;object=autobuilder-1' \
    bundle $SHARNESS_TEST_DIRECTORY/install-content out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info out.raucb
"

test_expect_success PKCS11 "rauc bundle with PKCS11 (key 2)" "
  rm -f out.raucb &&
  rauc \
    --cert 'pkcs11:token=rauc;object=autobuilder-2' \
    --key 'pkcs11:token=rauc;object=autobuilder-2' \
    bundle $SHARNESS_TEST_DIRECTORY/install-content out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info out.raucb
"

test_expect_success PKCS11 "rauc bundle with PKCS11 (key mismatch)" "
  rm -f out.raucb &&
  test_must_fail rauc \
    --cert 'pkcs11:token=rauc;object=autobuilder-1' \
    --key 'pkcs11:token=rauc;object=autobuilder-2' \
    bundle $SHARNESS_TEST_DIRECTORY/install-content out.raucb
"

test_expect_success !SERVICE "rauc --override-boot-slot=system0 status: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status
"

test_expect_success !SERVICE "rauc status readable: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status --output-format=readable
"

test_expect_success !SERVICE "rauc status shell: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status --output-format=shell \
  | sh
"

test_expect_success !SERVICE,JSON "rauc status json: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status --output-format=json
"

test_expect_success !SERVICE,JSON "rauc status json-pretty: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status --output-format=json-pretty
"

test_expect_success !SERVICE "rauc status invalid: internally" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status --output-format=invalid
"

test_expect_success SERVICE "rauc --override-boot-slot=system0 status: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 \
    status
"

test_expect_success SERVICE "rauc status readable: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 \
    status --output-format=readable
"

test_expect_success SERVICE "rauc status shell: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 \
    status --output-format=shell \
  | sh
"

test_expect_success SERVICE,JSON "rauc status json: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 \
    status --output-format=json
"

test_expect_success SERVICE,JSON "rauc status json-pretty: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 \
    status --output-format=json-pretty
"

test_expect_success SERVICE "rauc status invalid: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  test_must_fail rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 \
    status --output-format=invalid
"

test_expect_success !SERVICE "rauc status mark-good: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status mark-good
"

test_expect_success !SERVICE "rauc status mark-bad: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status mark-bad
"

test_expect_success !SERVICE "rauc status mark-active: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status mark-active
"

test_expect_success SERVICE "rauc status mark-good: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 \
    status mark-good
"

test_expect_success SERVICE "rauc status mark-bad: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 \
    status mark-bad
"

test_expect_success SERVICE "rauc status mark-active: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 \
    status mark-active
"

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

test_done
