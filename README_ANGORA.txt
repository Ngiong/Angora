1. Installtion
  1-1. Get Angora from git
    git clone https://github.com/AngoraFuzzer/Angora.git
  1-2. Install LLVM v4.0.0 (It doesn't work on other versions)
    Pre-built binary link : http://releases.llvm.org/4.0.0/clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
  1-3. Install Rust (with cargo)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  1-4. Environemnt setting
    export PATH="/path-to-llvm4/bin:$PATH"
    export LD_LIBRARY_PATH="/path-to-llvm4/lib:/path-to-Angora/bin/lib"
    export PATH="$HOME/.cargo/bin:$PATH"
  1-5. Build Angora
    /path-to-Angora/build/build.sh

  1-6. Install Go
    pre-built link : https://dl.google.com/go/go1.12.7.linux-amd64.tar.gz
    export PATH="/path-to-go/bin:$PATH"
    export GOPATH="/where ever you want"  (GOPATH need to be different with path of Go)
    export PATH="$GOPATH/bin:$PATH"
  1-7. Install gllvm
    go get github.com/SRI-CSL/gllvm/cmd/...
    (This command will install gclang, gclang++, get-bc in $GOPATH/bin directory)

2. Use Angora to build target program
Angora needs two executable of target program :
  1. One without taint analysis instrumentation (fast), and  
  2. One with taint analysis instrumentation (taint)
so you need to build target program with angora twice.

  CC=gclang CFLAGS="-g -O0" ./configure --disable-shared
  make
  get-bc xx   #xx = target executable
  /path-to-angora/bin/angora-clang xx.bc -o xx.fast
  USE_TRACK=1 /path-to-angora/bin/angora-clang xx.bc -o xx.taint

we will get two executable : xx.fast and xx.taint.

3. Run Angora (Similiar to AFL)
  /path-to-Angora/angora-fuzzer -i /initial seed path/ -o /path to output/ -t xx.taint -- xx.fast [argv]
  (use @@ for input file argv like AFL)
