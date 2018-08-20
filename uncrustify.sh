#!/bin/sh

set -ex

cd `dirname $0`

if [ ! -e .uncrustify/build/uncrustify ]; then
	./build-uncrustify.sh
fi

.uncrustify/build/uncrustify -c .uncrustify.cfg -l C --replace src/*.c include/*.h test/*.[ch] contrib/cgi/src/*.[ch]
