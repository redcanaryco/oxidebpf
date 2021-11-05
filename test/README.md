# Build

Run `docker-compose run --rm test-builder` from this (test/) directory to build the BPF test application.

On a RHEL instance of VM, you can try:
* `yum install llvm-toolset`
* `yum install kernel-devel`
* `make CC=clang LLC=llc OPT=opt LLVM_DIS=llvm-dis KERNEL_HEADERS_ROOT=/usr/src/kernels/$(uname -r)` 
