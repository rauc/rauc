#!/bin/sh

[ "x$RAUC_CURRENT_BOOTNAME" != "xsystem0" ] && exit 1
[ "x$RAUC_TRANSACTION_ID" = "x" ] && exit 1

if [ -n "$RAUC_PYTEST_TMP" ]; then
    env | sort > "$RAUC_PYTEST_TMP/postinstall-env"
fi

exit 0
