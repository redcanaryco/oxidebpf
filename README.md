# oxidebpf

`oxidebpf` is a fully MIT licensed Rust library for managing eBPF programs.

# Overview

Motivation: 

*  fully MIT licensed library that will 
*  run anywhere and 
*  spawn long running BPF programs, 
*  minimize dependencies, 

Goals:

*  fully MIT licensed, no GPL dependencies
*  Pure Rust, or as much as possible
*  Minimize dependencies, try to pull in as little as possible

# Requirements

A set of Linux environments are provided for building and testing, with 
dependencies listed in their `bootstrap.sh` scripts. In general, you will
want:

```
$ sudo apt-get install build-essential clang llvm libclang-dev linux-tools-oem \
  linux-tools-(kernel version)-generic
```

Additionally, you will need cargo installed. The `cargo-with` package is 
recommended for debugging and testing. It allows you to trace BPF calls
during tests by running `cargo with "strace -fe bpf" -- test`.


# Getting Started

TODO: Quick steps to get started

*  Add oxidebpf to your Cargo.toml
*  Three main components: Programs/Maps (bpf objects), ProgramVersions, and ProgramGroups
*  The idea is to run anywhere, so you can put a bunch of different bpf programs in there
*  You create Programs and Maps and perfmaps, compose ProgramVersions from the programs
and maps
*  Create a ProgramGroup from ProgramVersions and it will attempt to load versions until
one works!

## Usage

TODO: Usage goes here.

Same thing as above but with more details.

## Building

The project includes several Vagrantfiles which are set up to build and test the library.

```
$ cd vagrant/ubuntu_20.04
$ vagrant up
$ vagrant ssh
$ cd oxidebpf
$ cargo build
```

If you want to build locally, check the `bootstrap.sh` file for the Vagrantfile
most similar to your system

## Testing

You can run tests with `cargo test`. To trace BPF syscalls as they occur, run 
the tests with `cargo with "strace -fe bpf" -- test` (depends on `cargo-with`, included in
vagrant bootstrap by default).
