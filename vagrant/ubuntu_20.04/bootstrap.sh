#!/usr/bin/env bash

apt-get update
apt-get upgrade -y
apt-get install -y build-essential clang llvm libclang-dev linux-tools-oem \
  linux-tools-5.4.0-58-generic

su vagrant << EOF
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # Installing cargo-with allows for `cargo with "strace -fe bpf" -- test` while testing
  source /home/vagrant/.cargo/env
  cargo install cargo-with
EOF
