#!/bin/sh

test_description="rauc binary tests"

. ./sharness.sh

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

# Prerequisite: JSON support enabled [JSON]
grep -q "ENABLE_JSON 1" $SHARNESS_TEST_DIRECTORY/../config.h && \
  test_set_prereq JSON

# Prerequisite: background service support enabled [SERVICE]
grep -q "ENABLE_SERVICE 1" $SHARNESS_TEST_DIRECTORY/../config.h &&
  test_set_prereq SERVICE &&
  select_system_or_session_bus

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
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info out.raucb
"

cp $SHARNESS_TEST_DIRECTORY/test.conf $SHARNESS_TEST_DIRECTORY/test-temp.conf
sed -i "s!bootname=system0!bootname=$(cat /proc/cmdline | sed 's/.*root=\([^ ]*\).*/\1/')!g" $SHARNESS_TEST_DIRECTORY/test-temp.conf

test_expect_success "rauc status" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status
"

test_expect_success "rauc --override-boot-slot=system0 status" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status
"

test_expect_success "rauc status readable" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status --output-format=readable
"

test_expect_success "rauc status shell" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status --output-format=shell \
  | sh
"

test_expect_success JSON "rauc status json" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status --output-format=json
"

test_expect_success JSON "rauc status json-pretty" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status --output-format=json-pretty
"

test_expect_success "rauc status invalid" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status --output-format=invalid
"

test_expect_success !SERVICE "rauc status mark-good: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status mark-good
"

test_expect_success !SERVICE "rauc status mark-bad: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status mark-bad
"

test_expect_success !SERVICE "rauc status mark-active: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status mark-active
"

test_expect_success SERVICE "rauc status mark-good: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test-temp.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test-temp.conf \
    --override-boot-slot=system1 \
    status mark-good
"

test_expect_success SERVICE "rauc status mark-bad: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test-temp.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test-temp.conf \
    --override-boot-slot=system1 \
    status mark-bad
"

test_expect_success SERVICE "rauc status mark-active: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test-temp.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test-temp.conf \
    --override-boot-slot=system1 \
    status mark-active
"

test_expect_success "rauc install invalid local paths" "
  test_must_fail rauc install foo &&
  test_must_fail rauc install foo.raucb &&
  test_must_fail rauc install /path/to/foo.raucb
"

test_done
