#!/bin/sh

set -ex

pipx run --spec pip-tools pip-compile requirements.in -U | tee requirements.txt
