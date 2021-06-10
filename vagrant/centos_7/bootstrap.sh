#!/usr/bin/env bash

export DEBIAN_FRONTEND=noninteractive
yum -y upgrade
yum -y install epel-release
yum -y install gcc gcc-c++ make clang llvm bpftool

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
# Installing cargo-with allows for `cargo with "strace -fe bpf" -- test` while testing
source /root/.cargo/env
rustup install stable
rustup default stable
cargo install cargo-with
