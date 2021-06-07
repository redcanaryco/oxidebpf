# oxidebpf

oxidebpf is a fully MIT licensed Rust library for managing eBPF programs.

# Overview

TODO

# Requirements

TODO

*  Linux environment provided

# Getting Started

TODO: Quick steps to get started

## Usage

TODO: Usage goes here.

## Building

The project includes several Vagrantfiles which are set up to build and test the library.

```
$ cd vagrant/ubuntu_20.04
$ vagrant up
$ vagrant ssh
$ cd oxidebpf
$ cargo build
```

## Testing

1. Run `docker-compose run --rm test-builder` to build the eBPF test application.
2. Run tests with `cargo test`. To trace BPF syscalls as they occur, run 
   the tests with `cargo with "strace -fe bpf" -- test` (depends on `cargo-with`, included in 
   vagrant bootstrap by default).