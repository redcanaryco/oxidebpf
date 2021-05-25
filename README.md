# oxidebpf

`oxidebpf` is a fully MIT licensed Rust library for managing eBPF programs.

## Motivation

The motivation behind `oxidebpf` is to create a fully MIT licensed Rust library
for managing long-running eBPF programs that run in as many places as possible.
There are a number of fantastic libraries for interfacing with eBPF already,
but they either have GPL dependencies, are not in Rust, or are primarily designed 
short-running programs.

## Goals

We want `oxidebpf` to meet the following goals.

*  Fully MIT licensed with no GPL dependencies.
*  Written in pure Rust, or as close to pure Rust as possible.
*  Minimal dependencies, pull in the bare minimum set of dependencies
required to achieve our desired functionality.

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

Here's some quick steps to get yu started right away.

1.  Add `oxidebpf` to your `Cargo.toml`
2.  Use the `ProgramBlueprint` to load your compiled eBPF object file with
maps and programs.
3.  Create a `Program` for each program you intend to load. Create a `Map`
for each map and a `PerfMap` for any perfmap.
4.  Create a `ProgramVersion` with your programs and maps. You may create
multiple `ProgramVersion`s, representing different sets of
programs and maps.
5.  Create a `ProgramGroup` with your `ProgramVersion`s. 
6.  Tell the `ProgramGroup` to start loading. It will attempt each `ProgramVersion`
in order until one successfully loads on the current kernel. If it cannot

TODO: Rust code snippet showing above steps goes here

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
most similar to your system. This file will include build and test dependencies
for the distribution.

## Testing

You can run tests with `cargo test`. To trace BPF syscalls as they occur, run 
the tests with `cargo with "strace -fe bpf" -- test` (depends on `cargo-with`, included in
vagrant bootstrap by default).
