#!/bin/sh

[ "x$RAUC_CURRENT_BOOTNAME" != "xsystem0" ] && exit 1
[ "x$RAUC_TRANSACTION_ID" = "x" ] && exit 1

exit 0
