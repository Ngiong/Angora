find . -name "FInfo*" -exec rm {} \;
find . -name "*.tt" -exec rm {} \;
find . -name "*.fast" -exec rm {} \;

ANGORA_LOC="/home/cheong/Angora_func"

CC=gclang CFLAGS=-O0 ./configure --prefix=`pwd`/../build --disable-shared
make clean
make
make install

cd ../build/bin
get-bc xmlwf
${ANGORA_LOC}/bin/angora-clang xmlwf.bc -o xmlwf.fast
USE_TRACK=1 ${ANGORA_LOC}/bin/angora-clang xmlwf.bc -o xmlwf.tt
cp FInfo-cmp-llvm-link.txt ${ANGORA_LOC}/FInfos/FInfo-cmp-xmlwf.txt
cp xmlwf.* ${ANGORA_LOC}/subjects/
