#!/bin/sh

set -ex

cd `dirname $0`

git clone https://github.com/uncrustify/uncrustify.git --branch uncrustify-0.68.1 .uncrustify
cd .uncrustify
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
