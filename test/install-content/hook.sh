#!/bin/bash

set -e

NAME="$0"

die_error() {
	echo "$NAME ERROR: $1"
	exit 2
}


case "$1" in
	install-check)
		test -n "$RAUC_MF_COMPATIBLE" || die_error "missing RAUC_MF_COMPATIBLE"
		test -n "$RAUC_SYSTEM_COMPATIBLE" || die_error "missing RAUC_SYSTEM_COMPATIBLE"
		echo "No, I won't install this!" 1>&2
		exit 10
		;;
	global-post-install)
		test -n "$RAUC_MF_COMPATIBLE" || die_error "missing RAUC_MF_COMPATIBLE"
		test -n "$RAUC_SYSTEM_COMPATIBLE" || die_error "missing RAUC_SYSTEM_COMPATIBLE"
		
		test -d "$RAUC_MOUNT_PREFIX" || die_error "missing RAUC_MOUNT_PREFIX"

		echo "$RAUC_MOUNT_PREFIX/global-post-install-stamp"
		touch "$RAUC_MOUNT_PREFIX/global-post-install-stamp"
		;;
	slot-post-install)
		test -n "$RAUC_SLOT_NAME" || die_error "missing RAUC_SLOT_NAME"
		test -n "$RAUC_SLOT_CLASS" || die_error "missing RAUC_SLOT_CLASS"
		test -n "$RAUC_SLOT_TYPE" || die_error "missing RAUC_SLOT_TYPE"
		if [ "$RAUC_SLOT_CLASS" == "bootloader" ]; then
			echo "$NAME: no bootname expected for $RAUC_SLOT_NAME"
		else
			test -n "$RAUC_SLOT_BOOTNAME" || die_error "missing RAUC_SLOT_BOOTNAME for $RAUC_SLOT_NAME"
		fi

		# only rootfs needs to be handled
		test "$RAUC_SLOT_CLASS" = "rootfs" || exit 0

		test -d "$RAUC_SLOT_MOUNT_POINT" || die_error "missing RAUC_SLOT_MOUNT_POINT"

		echo "$RAUC_SLOT_MOUNT_POINT/hook-stamp"
		touch "$RAUC_SLOT_MOUNT_POINT/hook-stamp"
		;;
	slot-install)
		test -n "$RAUC_SLOT_NAME" || die_error "missing RAUC_SLOT_NAME"
		test -n "$RAUC_SLOT_CLASS" || die_error "missing RAUC_SLOT_CLASS"
		test -n "$RAUC_SLOT_TYPE" || die_error "missing RAUC_SLOT_TYPE"
		if [ "$RAUC_SLOT_CLASS" == "bootloader" ]; then
			echo "$NAME: no bootname expected for $RAUC_SLOT_NAME"
		else
			test -n "$RAUC_SLOT_BOOTNAME" || die_error "missing RAUC_SLOT_BOOTNAME for $RAUC_SLOT_NAME"
		fi

		echo "RAUC_IMAGE_NAME: $RAUC_IMAGE_NAME"
		echo "RAUC_SLOT_DEVICE: $RAUC_SLOT_DEVICE"
		echo "RAUC_SLOT_MOUNT_POINT: $RAUC_SLOT_MOUNT_POINT"
		echo "RAUC_MOUNT_PREFIX: $RAUC_MOUNT_PREFIX"
		if [ -z "$RAUC_SLOT_MOUNT_POINT" ] ; then
		    echo "$RAUC_MOUNT_PREFIX/hook-slot"
		    mkdir "$RAUC_MOUNT_PREFIX/hook-slot"
		    mount "$RAUC_SLOT_DEVICE" "$RAUC_MOUNT_PREFIX/hook-slot"
		    echo "$RAUC_MOUNT_PREFIX/hook-slot/hook-install"
		    touch "$RAUC_MOUNT_PREFIX/hook-slot/hook-install"
		    umount "$RAUC_MOUNT_PREFIX/hook-slot"
		    rmdir  "$RAUC_MOUNT_PREFIX/hook-slot"
		else
		    touch "$RAUC_SLOT_MOUNT_POINT/hook-install-mounted"
		fi
		;;
	*)
		exit 1
		;;
esac
