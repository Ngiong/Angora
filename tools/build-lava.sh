#located in LAVA-M
ANGORA_LOC="${ANGORA_LOC}"
rm -rf ${ANGORA_LOC}/subjects
rm -rf ${ANGORA_LOC}/FInfos

mkdir ${ANGORA_LOC}/subjects
mkdir ${ANGORA_LOC}/FInfos

cd base64/coreutils-8.24-lava-safe/
rm base64.*
make clean
rm FInfo*
CC=gclang CFLAGS="-g -O0" ./configure --disable-shared --prefix=`pwd`/lava-install
make -j
cp src/base64 ./
get-bc base64
${ANGORA_LOC}/bin/angora-clang base64.bc -o base64.fast
USE_TRACK=1 ${ANGORA_LOC}/bin/angora-clang base64.bc -o base64.tt
cd ../..
cd uniq/coreutils-8.24-lava-safe/
rm uniq.*
make clean
rm FInfo*
CC=gclang CFLAGS="-g -O0" ./configure --disable-shared --prefix=`pwd`/lava-install
make -j
cp src/uniq ./
get-bc uniq
${ANGORA_LOC}/bin/angora-clang uniq.bc -o uniq.fast
USE_TRACK=1 ${ANGORA_LOC}/bin/angora-clang uniq.bc -o uniq.tt
cd ../..
cd md5sum/coreutils-8.24-lava-safe/
rm md5sum.*
make clean
rm FInfo*
CC=gclang CFLAGS="-g -O0" ./configure --disable-shared --prefix=`pwd`/lava-install
make -j
cp src/md5sum ./
get-bc md5sum
${ANGORA_LOC}/bin/angora-clang md5sum.bc -o md5sum.fast
USE_TRACK=1 ${ANGORA_LOC}/bin/angora-clang md5sum.bc -o md5sum.tt
cd ../..
cd who/coreutils-8.24-lava-safe/
rm who.*
make clean
rm FInfo*
CC=gclang CFLAGS="-g -O0" ./configure --disable-shared --prefix=`pwd`/lava-install
make -j
cp src/who ./
get-bc who
${ANGORA_LOC}/bin/angora-clang who.bc -o who.fast
USE_TRACK=1 ${ANGORA_LOC}/bin/angora-clang who.bc -o who.tt
cd ../..
echo "moving executables and FInfo.txt"
mv base64/coreutils-8.24-lava-safe/base64.fast ${ANGORA_LOC}/subjects/
mv base64/coreutils-8.24-lava-safe/base64.tt ${ANGORA_LOC}/subjects/
mv md5sum/coreutils-8.24-lava-safe/md5sum.fast ${ANGORA_LOC}/subjects/
mv md5sum/coreutils-8.24-lava-safe/md5sum.tt ${ANGORA_LOC}/subjects/
mv uniq/coreutils-8.24-lava-safe/uniq.fast ${ANGORA_LOC}/subjects/
mv uniq/coreutils-8.24-lava-safe/uniq.tt ${ANGORA_LOC}/subjects/
mv who/coreutils-8.24-lava-safe/who.fast ${ANGORA_LOC}/subjects/
mv who/coreutils-8.24-lava-safe/who.tt ${ANGORA_LOC}/subjects/
mv base64/coreutils-8.24-lava-safe/FInfo-cmp-llvm-link.txt ${ANGORA_LOC}/FInfos/FInfo-cmp-base64.txt
mv md5sum/coreutils-8.24-lava-safe/FInfo-cmp-llvm-link.txt ${ANGORA_LOC}/FInfos/FInfo-cmp-md5sum.txt
mv uniq/coreutils-8.24-lava-safe/FInfo-cmp-llvm-link.txt ${ANGORA_LOC}/FInfos/FInfo-cmp-uniq.txt
mv who/coreutils-8.24-lava-safe/FInfo-cmp-llvm-link.txt ${ANGORA_LOC}/FInfos/FInfo-cmp-who.txt
echo "Done"
