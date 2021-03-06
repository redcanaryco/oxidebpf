# oxidebpf

`oxidebpf` is a permissive licensed Rust library for managing eBPF programs.

## Motivation

The motivation behind `oxidebpf` is to create a permissive licensed Rust library
for managing long-running eBPF programs that operate in as many environments
as possible. Doing this required breaking some pre-set patterns on how eBPF
applications are developed and deployed. We wanted to be able to easily deploy
an eBPF solution that worked on as many distributions as possible; without forcing
the user to have a tool-chain present. Users typically just want a product to do
the thing - without a bunch of additional setup or maintenance. This library
helped us realize that goal - and we are sharing it openly.

Initially this library meets our current eBPF requirements, so its not a fully
flushed out eBPF implementation. Contributions are very much welcome, and we will
slowly be adding to the feature list over time.

## Goals

We want `oxidebpf` to meet the following goals.

*  Permissive licensed with no GPL dependencies.
*  Support custom CO-RE eBPF
*  Run eBPF programs on Linux 4.4+
*  Written in pure Rust, or as close to pure Rust as possible.
*  Minimal dependencies, pull in the bare minimum set of dependencies required
to achieve our desired functionality.

# Requirements

A set of Linux environments are provided for building and testing, with dependencies
listed in their `bootstrap.sh` scripts. In general, you will want:

```
$ sudo apt-get install build-essential clang llvm libclang-dev linux-tools-oem \
  linux-tools-(kernel version)-generic
```

Additionally, you will need cargo installed. The `cargo-with` package is recommended
for debugging and testing. It allows you to trace BPF calls during tests by running
`cargo with "strace -vfe bpf" -- test`.

# Getting Started

Here's some quick steps to get you started right away.

1. Add `oxidebpf` to your `Cargo.toml`, if you wish to use perfmaps you should
also add `crossbeam-channel`.
2. Use the `ProgramBlueprint` to load your compiled eBPF object file with
maps and programs.
3. Create a `Program` for each program you intend to load, with options set.
4. Create a `ProgramVersion` with your programs. You may create
multiple `ProgramVersion`s, representing different sets of
programs. For example, programs intended to run on different kernel versions.
5. Create a `ProgramGroup`.
6. Give the `ProgramGroup` your `ProgramVersions` and `ProgramBlueprint`, and
tell it to start loading. It will attempt each `ProgramVersion` in order until
one successfully loads on the current kernel. If it cannot load any program
version, it will return an error composed of the underlying errors for each
`ProgramVersion`.

```rust
let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .join("test")
    .join(format!("test_program_{}", std::env::consts::ARCH));
let program_blueprint =
    ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
        .expect("Could not open test object file");
let mut program_group = ProgramGroup::new();
let (tx, rx) = crossbeam_channel::bounded(1024);

program_group.load(
    program_blueprint,
    vec![ProgramVersion::new(vec![
        Program::new(
            "test_program_map_update",
            vec!["do_mount"],
        )
        .syscall(true),
        Program::new("test_program", vec!["do_mount"]).syscall(true),
    ])],
    || (tx, PerfBufferSize::Total(4096))),
).expect("Could not load programs");

// read from rx any events from a perfmap in the loaded program version

```

Note: this expects the presence of a `test_program_[arch]` binary in a `test` subfolder
of your project, where `[arch]` is the architecture of your system.

## Building

The project includes several Vagrantfiles which are set up to build and test the library.

```
$ cd vagrant/ubuntu_20.04
$ vagrant up
$ vagrant ssh
$ cd oxidebpf
$ cargo build
```

If you want to build locally, check the `bootstrap.sh` file for the Vagrantfile most
similar to your system. This file will include build and test dependencies for the
distribution.

## Testing

1. Run `docker-compose run --rm test-builder` from the `test/` directory to build the BPF test application. For additional options for RHEL builds, see `test/README.md`.
2. Run tests with `cargo test`. To trace BPF syscalls as they occur, run
   the tests with `cargo with "strace -fe bpf" -- test` (depends on `cargo-with`, included in
   vagrant bootstrap by default).

Note: some tests will require root privileges to pass. Other tests require a single-threaded context
to pass. To test consistently, try running: `sudo -E /path/to/your/.cargo/bin/cargo test -- --test-threads=1`.
For convenience, you can alias this as `alias scargo="sudo -E $HOME/.cargo/bin/cargo"` and run tests with
`scargo test -- --test-threads=`.

# Features

## Metrics

`oxidebpf` has a (disabled by default) feature called `metrics`. When
enabled it will use the [metrics] crate to propagate internal metrics
related to the ebpf maps. These are the `metrics` that `oxidebpf`
currently reports on:

* `perfmap.unread_size_pct`: A histogram of how much of the perfmap
  buffer has not been read. This is emitted right after polling the
  perf map file descriptors but before reading from them. This is only
  emitted by perfmaps that woke up during the epoll, if a perfmap
  never gets data then it will not report by this metric. The map name
  and cpu are reported as labels. A `describe_histogram!` is also
  emitted for this metric to tell reporters that this is a percentage
  unit. This can be used to set up histogram buckets.

* `perfmap.buffer_size_kb`: A gauge of how much memory (in KB) is
  being allocated for the data portion of the perfmap buffer. Note
  that an extra page is always allocated for metadata. This is emitted
  immediately prior to the creation of the map. The map name is
  reported as a label.

* `perfmap.num_buffers`: A gauge of how many buffers are being
  allocated for a perfmap. This is also the number of online cpus that
  oxidebpf detected. This is emitted immediately prior to the creation
  of the perf map. The map name is reported as a label.

* `perfmap.channel.full`: A counter of how many times we tried to send
  a dropped message across the user provided channel for perfmaps but
  failed due to it being full. The map name is reported as a label.

Adding or removing metrics will not be considered a breaking change at
this point but we may reconsider this decision in the future as we
stabilize what metrics seem the most useful

[metrics]: https://docs.rs/metrics/latest/metrics/
