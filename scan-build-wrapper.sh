#!/bin/sh

scan-build -v --status-bugs -disable-checker unix.Malloc "$@"
