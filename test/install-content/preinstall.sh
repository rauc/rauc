#!/bin/sh

[ -z "$RAUC_CURRENT_BOOTNAME" ] && exit 1
[ "x$RAUC_TRANSACTION_ID" = "x" ] && exit 1

if [ -n "$RAUC_PYTEST_TMP" ]; then
    env | sort > "$RAUC_PYTEST_TMP/preinstall-env-manifest"
fi

exit 0
