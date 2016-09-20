#!/bin/sh

test_description="rauc binary tests"

. ./sharness.sh

# Prerequisite: JSON support enabled [JSON]
grep -q "ENABLE_JSON 1" $SHARNESS_TEST_DIRECTORY/../config.h && \
  test_set_prereq JSON

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
  cp -a $SHARNESS_TEST_DIRECTORY/install-content/ tmp/
  rauc \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    checksum tmp/
  test -f tmp/manifest.raucm.sig
"

test_expect_success "rauc checksum with extra args" "
  cp -a $SHARNESS_TEST_DIRECTORY/install-content/ tmp/
  rauc \
    --handler-args '--dummy'\
    checksum tmp/
  grep args tmp/manifest.raucm | grep dummy
"

test_expect_success "rauc info" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
"

test_expect_success "rauc info shell" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf --output-format=shell \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
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


TMPDIR=$(mktemp -d)
export TMPDIR
mkdir $TMPDIR/images
touch $TMPDIR/images/rescue-0
touch $TMPDIR/images/rootfs-0
touch $TMPDIR/images/rootfs-1
touch $TMPDIR/images/appfs-0
touch $TMPDIR/images/appfs-1

test_expect_success "rauc status" "
  cp $SHARNESS_TEST_DIRECTORY/test.conf $SHARNESS_TEST_DIRECTORY/test-temp.conf
  sed -i 's!bootname=system0!bootname=$(cat /proc/cmdline | sed 's/.*root=\([^ ]*\).*/\1/')!g' $SHARNESS_TEST_DIRECTORY/test-temp.conf
  sed -i 's!images!$TMPDIR/images!g' $SHARNESS_TEST_DIRECTORY/test-temp.conf
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status mark-good &&
  rauc -c $SHARNESS_TEST_DIRECTORY/test-temp.conf status mark-bad
"

test_expect_success "rauc install invalid local paths" "
  test_must_fail rauc install foo &&
  test_must_fail rauc install foo.raucb &&
  test_must_fail rauc install /path/to/foo.raucb
"

rm -r $TMPDIR

test_done
