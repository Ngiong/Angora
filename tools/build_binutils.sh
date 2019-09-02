#located in binutils
find . -name "*.tt" -exec rm {} \;
find . -name "*.fast" -exec rm {} \;
find . -name "FInfo*" -exec rm {} \;

ANGORA_LOC="~/Angora_func"
rm -rf ${ANGORA_LOC}/subjects
rm -rf ${ANGORA_LOC}/FInfos

mkdir ${ANGORA_LOC}/subjects
mkdir ${ANGORA_LOC}/FInfos

CC=gclang CFLAGS=-O0 ./configure --disable-shared

make clean
make

cd binutils

get-bc size
get-bc objdump
get-bc nm-new

~/Angora_func/bin/angora-clang size.bc -o ~/Angora_func/subjects/size.fast
USE_TRACK=1 ~/Angora_func/bin/angora-clang size.bc -o ~/Angora_func/subjects/size.tt
mv FInfo-cmp-llvm-link.txt ~/Angora_func/FInfos/FInfo-cmp-size.txt

~/Angora_func/bin/angora-clang objdump.bc -o ~/Angora_func/subjects/objdump.fast
USE_TRACK=1 ~/Angora_func/bin/angora-clang objdump.bc -o ~/Angora_func/subjects/objdump.tt
mv FInfo-cmp-llvm-link.txt ~/Angora_func/FInfos/FInfo-cmp-objdump.txt

~/Angora_func/bin/angora-clang nm-new.bc -o ~/Angora_func/subjects/nm-new.fast
USE_TRACK=1 ~/Angora_func/bin/angora-clang nm-new.bc -o ~/Angora_func/subjects/nm-new.tt
mv FInfo-cmp-llvm-link.txt ~/Angora_func/FInfos/FInfo-cmp-nm-new.txt
