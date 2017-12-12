#!/bin/bash

set -e

echo "<< handler [STARTED]"

function exit_if_empty {
	if [ -z "$1" ]; then exit 1; fi
}

rootrun=""
if [ "$EUID" != 0 ]; then
	rootrun="sudo"
fi

# Sanity check
for i in $(env | grep "^RAUC_"); do
	echo $i
	exit_if_empty $i
done


# Create mount point
exit_if_empty $RAUC_MOUNT_PREFIX
mkdir -p $RAUC_MOUNT_PREFIX/image

# This is only for testing
export BAREBOX_STATE_VARS_PRE="\
bootstate.system0.priority=20 \
bootstate.system0.remaining_attempts=3 \
bootstate.system1.priority=10 \
bootstate.system1.remaining_attempts=3 \
"

# deactivate current slot
barebox-state -s bootstate.$RAUC_CURRENT_BOOTNAME.priority=0

# Update slots
exit_if_empty $RAUC_MOUNT_PREFIX
for i in $RAUC_TARGET_SLOTS; do
	eval RAUC_SLOT_DEVICE=\$RAUC_SLOT_DEVICE_${i}
	eval RAUC_IMAGE_NAME=\$RAUC_IMAGE_NAME_${i}
	eval RAUC_IMAGE_DIGEST=\$RAUC_IMAGE_DIGEST_${i}
	exit_if_empty $RAUC_SLOT_DEVICE

	# If we do not have an image for this slot, skip
	if [ -z "$RAUC_IMAGE_NAME" ]; then
		continue
	fi

	# Get absolute image path
	if [[ "$RAUC_IMAGE_NAME" = /* ]]; then
		IMAGE_PATH=$RAUC_IMAGE_NAME
	else
		IMAGE_PATH=$RAUC_UPDATE_SOURCE/$RAUC_IMAGE_NAME
	fi

	# XXX skip up-to-date slots

	# Copy image
	echo "<< image $RAUC_IMAGE_NAME [START]"
	cp $IMAGE_PATH $RAUC_SLOT_DEVICE
	echo "<< image $RAUC_IMAGE_NAME [DONE]"

	# Write slot status file
	$rootrun mount $RAUC_SLOT_DEVICE $RAUC_MOUNT_PREFIX/image
	echo [slot] > $RAUC_MOUNT_PREFIX/image/slot.raucs
	echo status=ok >> $RAUC_MOUNT_PREFIX/image/slot.raucs
	echo sha256=$RAUC_IMAGE_DIGEST >> $RAUC_MOUNT_PREFIX/image/slot.raucs
	$rootrun umount $RAUC_MOUNT_PREFIX/image
done

# Update boot priority
for i in $RAUC_SLOTS; do
	eval RAUC_SLOT_CLASS=\$RAUC_SLOT_CLASS_${i}
	eval RAUC_SLOT_BOOTNAME=\$RAUC_SLOT_BOOTNAME_${i}
	eval RAUC_SLOT_NAME=\$RAUC_SLOT_NAME_${i}

	# skip non-bootable slots
	if [ -z "$RAUC_SLOT_BOOTNAME" ]; then
		continue
	fi

	# check if in target group
	for j in $RAUC_TARGET_SLOTS; do
		eval TARGET_CLASS=\$RAUC_SLOT_CLASS_${j}
		eval TARGET_NAME=\$RAUC_SLOT_NAME_${j}

		# If we do not have an image for this slot, skip
		if [ -z "$RAUC_IMAGE_NAME" ]; then
			continue
		fi

		if [ "$RAUC_SLOT_CLASS" != "$TARGET_CLASS" ]; then
			continue
		fi

		# Set highest priority for currently updated, set lower prio for other
		if [ "$RAUC_SLOT_NAME" = "$TARGET_NAME" ]; then
			barebox-state -s bootstate.$RAUC_SLOT_BOOTNAME.priority=20
		else
			barebox-state -s bootstate.$RAUC_SLOT_BOOTNAME.priority=10
		fi
	done
done
echo "<< bootloader [DONE]"


echo "<< handler [DONE]"

exit 0
