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

test_expect_success "rauc checksum" "
  rauc -c $SHARNESS_TEST_DIRECTORY/test.conf info good-bundle.raucb
"

test_done
