#!/bin/bash

set -e

NAME="$0"

die_error() {
	echo "$NAME ERROR: $1"
	exit 1
}

test "$1" = "slot-post-install" || exit 0

test -n "$RAUC_SLOT_NAME" || die_error "missing RAUC_SLOT_NAME"
test -n "$RAUC_SLOT_CLASS" || die_error "missing RAUC_SLOT_CLASS"

# only rootfs needs to be handled
test "$RAUC_SLOT_CLASS" = "rootfs" || exit 0

test -d "$RAUC_SLOT_MOUNT_POINT" || die_error "missing RAUC_SLOT_MOUNT_POINT"

echo "$RAUC_SLOT_MOUNT_POINT/hook-stamp"
touch "$RAUC_SLOT_MOUNT_POINT/hook-stamp"
