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
grep -q "ENABLE_JSON 1" $SHARNESS_TEST_DIRECTORY/../config.h && \
  test_set_prereq JSON

# Prerequisite: background service support enabled [SERVICE]
grep -q "ENABLE_SERVICE 1" $SHARNESS_TEST_DIRECTORY/../config.h &&
  test_set_prereq SERVICE &&
  select_system_or_session_bus

# Prerequisite: casync available [CASYNC]
casync --version &&
  test_set_prereq CASYNC

# Prerequisite: softhsm2 installed [PKCS11]
test -f ${SOFTHSM2_MOD} &&
  prepare_softhsm2 &&
  test_set_prereq PKCS11

# Prerequisite: faketime available [FAKETIME]
faketime "2018-01-01" date &&
  test_set_prereq FAKETIME

# Prerequisite: grub-editenv available [GRUB]
grub-editenv -V &&
  test_set_prereq GRUB

# Prerequisite: root available [ROOT]
whoami | grep -q root &&
  test_set_prereq ROOT

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
  test_expect_code 1 rauc install &&
  test_expect_code 1 rauc write-slot &&
  test_expect_code 1 rauc write-slot slot &&
  test_expect_code 1 rauc info &&
  test_expect_code 1 rauc bundle &&
  test_expect_code 1 rauc bundle input &&
  test_expect_code 1 rauc resign input &&
  test_expect_code 1 rauc info
"

test_expect_success "rauc excess args" "
  test_expect_code 1 rauc install bundle excess &&
  test_expect_code 1 rauc write-slot source target excess &&
  test_expect_code 1 rauc info bundle excess &&
  test_expect_code 1 rauc bundle indir outbundle excess &&
  test_expect_code 1 rauc resign inbundle outbundle excess &&
  test_expect_code 1 rauc info bundle excess
"

test_expect_success "rauc version" "
  rauc --version
"

test_expect_success "rauc help" "
  rauc --help &&
  rauc install --help &&
  rauc write-slot --help &&
  rauc info --help &&
  rauc bundle --help &&
  rauc resign --help &&
  rauc info --help
"

test_expect_success "rauc info" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    info ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success "rauc info verification failure" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/invalid-sig-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/invalid-sig-bundle.raucb &&
  test_must_fail rauc --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    info ${TEST_TMPDIR}/invalid-sig-bundle.raucb
"

test_expect_success "rauc info dump-cert unverified" "
  ls -ld ${TEST_TMPDIR}/ &&
  ls -l ${TEST_TMPDIR}/ &&
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc --no-verify --dump-cert \
    info ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success "rauc info valid file URI" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc info --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem file://${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success "rauc info invalid file URI" "
  test_must_fail rauc info --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem file:/$SHARNESS_TEST_DIRECTORY/good-bundle.raucb &&
  test_must_fail rauc info --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem file://$SHARNESS_TEST_DIRECTORY/good-bundle.rauc
"

test_expect_success "rauc info shell" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem --output-format=shell \
    info ${TEST_TMPDIR}/good-bundle.raucb | sh
"

test_expect_success JSON "rauc info json" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem --output-format=json \
    info ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success JSON "rauc info json-pretty" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem --output-format=json-pretty \
    info ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success "rauc info invalid" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  test_must_fail rauc --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem --output-format=invalid \
    info ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success "rauc bundle" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success "rauc bundle mksquashfs extra args" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    bundle \
    --mksquashfs-args=\"-comp xz -info -progress\" \
    $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info ${TEST_TMPDIR}/out.raucb
"

test_expect_success PKCS11 "rauc bundle with PKCS11 (key 1)" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  rauc \
    --cert 'pkcs11:token=rauc;object=autobuilder-1' \
    --key 'pkcs11:token=rauc;object=autobuilder-1' \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info ${TEST_TMPDIR}/out.raucb
"

test_expect_success PKCS11 "rauc bundle with PKCS11 (key 2, revoked)" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  rauc \
    --cert 'pkcs11:token=rauc;object=autobuilder-2' \
    --key 'pkcs11:token=rauc;object=autobuilder-2' \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info ${TEST_TMPDIR}/out.raucb
"

test_expect_success PKCS11 "rauc bundle with PKCS11 (key mismatch)" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  test_must_fail rauc \
    --cert 'pkcs11:token=rauc;object=autobuilder-1' \
    --key 'pkcs11:token=rauc;object=autobuilder-2' \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb
"

test_expect_success SERVICE "rauc service double-init failure" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  test_must_fail rauc service
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
  rauc status
"

test_expect_success SERVICE "rauc status (detailed) readable: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc status --detailed --output-format=readable
"

test_expect_success SERVICE "rauc status (detailed) shell: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc status --detailed --output-format=shell \
  | sh
"

test_expect_success SERVICE,JSON "rauc status (detailed) json: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc status --detailed --output-format=json
"

test_expect_success SERVICE,JSON "rauc status (detailed) json-pretty: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc status --detailed --output-format=json-pretty
"

test_expect_success SERVICE "rauc status invalid: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service &&
  test_must_fail rauc status --output-format=invalid
"

test_expect_success !SERVICE,GRUB "rauc status mark-good: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status mark-good
"

test_expect_success !SERVICE,GRUB "rauc status mark-bad: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status mark-bad
"

test_expect_success !SERVICE,GRUB "rauc status mark-active: internally" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --override-boot-slot=system0 status mark-active
"

test_expect_success SERVICE,GRUB "rauc status mark-good: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    status mark-good
"

test_expect_success SERVICE,GRUB "rauc status mark-bad: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    status mark-bad
"

test_expect_success SERVICE,GRUB "rauc status mark-active: via D-Bus" "
  start_rauc_dbus_service \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
    --override-boot-slot=system1 &&
  test_when_finished stop_rauc_dbus_service &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/test.conf \
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

test_expect_success "rauc write-slot readonly" "
  test_must_fail rauc -c $SHARNESS_TEST_DIRECTORY/test.conf write-slot rescue.0 $SHARNESS_TEST_DIRECTORY/install-content/appfs.img
"

echo "\
[system]
compatible=Test Config
bootloader=grub
grubenv=grubenv.test

[keyring]
path=openssl-ca/dev-ca.pem
use-bundle-signing-time=true
" > $SHARNESS_TEST_DIRECTORY/use-bundle-signing-time.conf
cleanup rm $SHARNESS_TEST_DIRECTORY/use-bundle-signing-time.conf

test_expect_success FAKETIME "rauc verify with 'use-bundle-signing-time': valid signing time, invalid current time" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  faketime "2018-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb &&
  faketime "2022-01-01" rauc --conf $SHARNESS_TEST_DIRECTORY/use-bundle-signing-time.conf info ${TEST_TMPDIR}/out.raucb
"

test_expect_success FAKETIME "rauc verfiy with 'use-bundle-signing-time': invalid signing time, valid current time" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  faketime "2022-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb &&
  test_must_fail faketime "2018-01-01" rauc --conf $SHARNESS_TEST_DIRECTORY/use-bundle-signing-time.conf info ${TEST_TMPDIR}/out.raucb
"

test_expect_success FAKETIME "rauc sign bundle with expired certificate" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  test_must_fail faketime "2019-07-02" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test ! -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success FAKETIME "rauc sign bundle with not yet valid certificate" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  test_must_fail faketime "2017-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
  bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test ! -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success FAKETIME "rauc sign bundle with almost expired certificate" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  faketime "2019-06-15" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success FAKETIME "rauc sign bundle with valid certificate" "
  rm -f ${TEST_TMPDIR}/out.raucb &&
  faketime "2019-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb
"


test_expect_success "rauc extract" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rauc \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    extract ${TEST_TMPDIR}/good-bundle.raucb $TEST_TMPDIR/bundle-extract &&
  test -f $TEST_TMPDIR/bundle-extract/appfs.img &&
  test -f $TEST_TMPDIR/bundle-extract/custom_handler.sh &&
  test -f $TEST_TMPDIR/bundle-extract/hook.sh &&
  test -f $TEST_TMPDIR/bundle-extract/manifest.raucm &&
  test -f $TEST_TMPDIR/bundle-extract/rootfs.img &&
  rm -rf $TEST_TMPDIR/bundle-extract
"

test_expect_success CASYNC "rauc convert" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f casync.raucb &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    convert ${TEST_TMPDIR}/good-bundle.raucb casync.raucb &&
  test -f casync.raucb
"

test_expect_success CASYNC "rauc convert (output exists)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  touch casync.raucb &&
  test_must_fail rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    convert ${TEST_TMPDIR}/good-bundle.raucb casync.raucb &&
  test -f casync.raucb
"

test_expect_success CASYNC "rauc convert (error)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f casync.raucb &&
  test_must_fail rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    convert ${TEST_TMPDIR}/good-bundle.raucb casync.raucb &&
  test ! -f casync.raucb
"

test_expect_success CASYNC "rauc convert casync extra args" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f casync-extra-args.raucb &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    convert \
    --casync-args=\"--chunk-size=64000\" \
    ${TEST_TMPDIR}/good-bundle.raucb casync-extra-args.raucb &&
  test -f casync-extra-args.raucb
"

test_expect_success "rauc resign" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -f ${TEST_TMPDIR}/out.raucb &&
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success "rauc resign (output exists)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  touch ${TEST_TMPDIR}/out.raucb &&
  test_must_fail rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/dev-ca.pem \
    resign ${TEST_TMPDIR}/good-bundle.raucb ${TEST_TMPDIR}/out.raucb &&
  test -f ${TEST_TMPDIR}/out.raucb
"

test_expect_success FAKETIME "rauc resign extend (not expired)" "
  rm -f ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/out2.raucb &&
  faketime "2018-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out1.raucb &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  faketime "2018-10-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    resign ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/out2.raucb &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success FAKETIME "rauc resign extend (expired)" "
  rm -f ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/out2.raucb &&
  faketime "2018-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out1.raucb &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  test_must_fail faketime "2020-10-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    resign ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/out2.raucb &&
  test ! -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success FAKETIME "rauc resign extend (expired, no-verify)" "
  rm -f ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/out2.raucb &&
  faketime "2018-01-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-2018.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-2018.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content ${TEST_TMPDIR}/out1.raucb &&
  test -f ${TEST_TMPDIR}/out1.raucb &&
  faketime "2020-10-01" \
    rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/release-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/rel/private/release-1.pem \
    --keyring $SHARNESS_TEST_DIRECTORY/openssl-ca/rel-ca.pem \
    --no-verify \
    resign ${TEST_TMPDIR}/out1.raucb ${TEST_TMPDIR}/out2.raucb &&
  test -f ${TEST_TMPDIR}/out2.raucb
"

test_expect_success ROOT,SERVICE "rauc install" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  start_rauc_dbus_service_with_system \
    --conf=${SHARNESS_TEST_DIRECTORY}/minimal-test.conf \
    --mount=${SHARNESS_TEST_DIRECTORY}/mnt \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service_with_system &&
  rauc \
    install ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success ROOT,SERVICE "rauc install --progress" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  start_rauc_dbus_service_with_system \
    --conf=${SHARNESS_TEST_DIRECTORY}/minimal-test.conf \
    --mount=${SHARNESS_TEST_DIRECTORY}/mnt \
    --override-boot-slot=system0 &&
  test_when_finished stop_rauc_dbus_service_with_system &&
  rauc \
    install --progress ${TEST_TMPDIR}/good-bundle.raucb
"

test_expect_success ROOT,!SERVICE "rauc install (no service)" "
  cp -L ${SHARNESS_TEST_DIRECTORY}/good-bundle.raucb ${TEST_TMPDIR}/ &&
  test_when_finished rm -f ${TEST_TMPDIR}/good-bundle.raucb &&
  rm -rf ${SHARNESS_TEST_DIRECTORY}/images &&
  mkdir ${SHARNESS_TEST_DIRECTORY}/images &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/rootfs-0 &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/rootfs-1 &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/appfs-0 &&
  touch ${SHARNESS_TEST_DIRECTORY}/images/appfs-1 &&
  rauc \
    --conf=${SHARNESS_TEST_DIRECTORY}/minimal-test.conf \
    install ${TEST_TMPDIR}/good-bundle.raucb
"

rm -rf $TEST_TMPDIR

test_done
