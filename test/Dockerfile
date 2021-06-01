FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y llvm-6.0 clang-6.0 libclang-6.0-dev \
    linux-headers-4.4.0-98-generic linux-headers-4.10.0-14-generic \
    make binutils curl coreutils

WORKDIR /src
CMD make clean all