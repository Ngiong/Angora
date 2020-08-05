#!/bin/bash
BIN_PATH=$(readlink -f "$0")
ROOT_DIR=$(dirname $(dirname $BIN_PATH))

set -euxo pipefail

PREFIX=${PREFIX:-${ROOT_DIR}/bin/}

cargo build --release

rm -f ${PREFIX}/fuzzer
rm -f ${PREFIX}/*.a
cp target/release/fuzzer ${PREFIX}
cp target/release/*.a ${PREFIX}/lib

# cd llvm_mode
# rm -rf build
# mkdir -p build
# cd build
# cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} -DCMAKE_BUILD_TYPE=Release ..
# make # VERBOSE=1 
# make install # VERBOSE=1

