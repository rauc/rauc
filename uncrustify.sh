#!/bin/sh

set -ex

cd `dirname $0`

uncrustify -c .uncrustify.cfg -l C --replace src/*.c include/*.h test/*.[ch]
