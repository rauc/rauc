#!/bin/bash

echo "<< handler [STARTED]"

echo "SYSTEM_CONFIG: $SYSTEM_CONFIG"
echo "CURRENT_BOOTNAME: $CURRENT_BOOTNAME"
echo "TARGET_SLOTS: $TARGET_SLOTS"
echo "UPDATE_SOURCE: $UPDATE_SOURCE"
echo "MOUNT_PREFIX: $MOUNT_PREFIX"

sleep 0.5

echo "<< image rootfs [DONE]"

sleep 0.5

echo "<< image appfs [DONE]"

echo "<< image foofs [SKIPPED]"

echo "<< handler [DONE]"

exit 0
