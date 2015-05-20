#!/bin/sh

test_description="rauc binary tests"

. ./sharness.sh

test_expect_success "rauc version" "
  rauc --version
"

test_expect_success "rauc help" "
  rauc --help
"

test_expect_success "rauc checksum without argument" "
  test_expect_code 133 rauc checksum
"

test_expect_success "rauc checksum with signing" "
  cp -a $SHARNESS_TEST_DIRECTORY/install-content/ tmp/
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    checksum tmp/
  test -f tmp/manifest.raucm.sig
"

test_expect_success "rauc checksum with extra args" "
  cp -a $SHARNESS_TEST_DIRECTORY/install-content/ tmp/
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf \
    --handler-args '--dummy'\
    checksum tmp/
  grep args tmp/manifest.raucm | grep dummy
"

test_expect_success "rauc info" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf \
    info $SHARNESS_TEST_DIRECTORY/good-bundle.raucb
"

test_expect_success "rauc bundle" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf \
    --cert $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/autobuilder-1.cert.pem \
    --key $SHARNESS_TEST_DIRECTORY/openssl-ca/dev/private/autobuilder-1.pem \
    bundle $SHARNESS_TEST_DIRECTORY/install-content out.raucb
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info out.raucb
"

test_done
