use std::{
    collections::{HashMap, HashSet},
    io::{BufRead, BufReader, BufWriter, Write},
    os::unix::prelude::RawFd,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use crossbeam_channel::Sender;
use libc::c_int;
use slog::{crit, error, info};

use crate::{
    blueprint::ProgramObject,
    bpf::{
        constant::bpf_map_type,
        syscall::{self, bpf_map_update_elem},
    },
    cpu_info, debugfs,
    maps::{perf_map_poller::PerfMapPoller, ArrayMap, BpfHashMap, PerCpu, PerfMap, ProgMap},
    perf::{
        constant::{perf_event_sample_format, perf_sw_ids, perf_type_id},
        PerfEventAttr, PerfSample, PerfWakeup,
    },
    DebugfsMountOpts, OxidebpfError, PerfChannelMessage, Program, ProgramBlueprint,
    SchedulingPolicy, LOGGER,
};

/// A group of eBPF [`Program`](struct@Program)s that a user wishes to load.
#[derive(Default)]
pub struct ProgramVersion<'a> {
    programs: Vec<Program<'a>>,
    fds: HashSet<RawFd>,
    ev_names: HashSet<String>,
    pub(crate) array_maps: HashMap<String, ArrayMap>,
    pub(crate) hash_maps: HashMap<String, BpfHashMap>,
    polling_delay: u64,
    polling_thread_policy: Option<SchedulingPolicy>,
}

/// Determines how to set the size of the perf buffer
///
/// Perf buffers are internally all sized individually and there is
/// one per online CPU. This enum gives you the flexibility to decide
/// if you want to size each CPU to a given size, or if you would like
/// oxidebpf to calculate the per buffer size for you.
///
/// Note that in either case the actual size will be rounded up to the
/// nearest whole page number, and then rounded down so the number of
/// pages fit a power of two.
#[derive(Debug, Clone, Copy)]
pub enum PerfBufferSize {
    /// Sizes each buffer to the given maximum.
    PerCpu(usize),
    /// Sizes each buffer by dividing the given maximum across the
    /// online CPUs. For example if the total size is 1MB, and we have
    /// 4 CPUS, each CPU will get a maximum of 256KB to work with.
    Total(usize),
}

impl<'a> Clone for ProgramVersion<'a> {
    fn clone(&self) -> Self {
        Self {
            programs: self.programs.clone(),
            ev_names: self.ev_names.clone(),
            array_maps: self.array_maps.clone(),
            hash_maps: self.hash_maps.clone(),
            fds: self
                .fds
                .iter()
                .map(|fd| unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 3) })
                .collect(),
            polling_delay: self.polling_delay,
            polling_thread_policy: self.polling_thread_policy,
        }
    }
}

impl<'a> ProgramVersion<'a> {
    /// Create a new `ProgramVersion` from a vector of [`Program`](struct@Program)s.
    ///
    /// The newly created `ProgramVersion` should be given to a
    /// [`ProgramGroup`](struct@ProgramGroup) for loading. The `ProgramVersion` encapsulates
    /// all the logic for loading, attaching, and returning events from a single clustering
    /// of eBPF [`Program`](struct@Program)s. Each `ProgramVersion` should be intended to act
    /// as an independent unit, in the absence of other `ProgramVersion`s.
    ///
    /// # Panics
    ///
    /// *  When dropping a `ProgramVersion` that uses debugfs, if the drop routine cannot
    /// reach the correct files in debugfs it will panic.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::{ProgramVersion, Program, ProgramType};
    ///
    /// let program_vec = vec![
    ///     Program::new(
    ///         "sys_ptrace_write",
    ///         &["sys_ptrace"],
    ///     ).syscall(true),
    ///     Program::new(
    ///         "sys_process_vm_writev",
    ///         &["sys_process_vm_writev"],
    ///     ).syscall(true)
    /// ];
    ///
    /// ProgramVersion::new(program_vec);
    /// ```
    pub fn new(programs: Vec<Program<'a>>) -> Self {
        ProgramVersion {
            programs,
            fds: HashSet::new(),
            ev_names: HashSet::new(),
            array_maps: HashMap::new(),
            hash_maps: HashMap::new(),
            polling_delay: 100,
            polling_thread_policy: None,
        }
    }

    /// Manually specify the perfmap polling interval for this `ProgramVersion`.
    pub fn polling_delay(mut self, delay: u64) -> Self {
        self.polling_delay = delay;
        self
    }

    pub(crate) fn set_debugfs_mount_point(&mut self, debugfs_mount: DebugfsMountOpts) {
        for program in self.programs.iter_mut() {
            program.set_debugfs_mount_point(debugfs_mount.clone());
        }
    }

    pub(crate) fn set_polling_policy(&mut self, policy: Option<SchedulingPolicy>) {
        self.polling_thread_policy = policy;
    }

    fn event_poller(
        &self,
        perfmaps: Vec<PerfMap>,
        tx: Sender<PerfChannelMessage>,
    ) -> Result<(), OxidebpfError> {
        let polling_delay = Duration::from_millis(self.polling_delay);
        let polling_policy = self
            .polling_thread_policy
            .unwrap_or(SchedulingPolicy::Other(0));

        // the PerfMapPoller thread will use this to signal when
        // it is ready to receive events.
        let perf_poller_signal = Arc::new((Mutex::new(false), Condvar::new()));
        let perf_poller_signal_clone = perf_poller_signal.clone();

        let _ = std::thread::Builder::new()
            .name("PerfMapPoller".to_string())
            .spawn(move || {
                perf_map_poller(
                    perfmaps,
                    tx,
                    polling_delay,
                    polling_policy,
                    perf_poller_signal_clone,
                )
            })
            .map_err(|e| {
                crit!(LOGGER.0, "event_poller(); error in thread polling: {:?}", e);
                OxidebpfError::ThreadPollingError
            })?;

        // Wait until PerfMapPoller is ready.
        let max_wait = Duration::from_secs(1);
        let (lock, cvar) = &*perf_poller_signal;
        let wait_result = cvar
            .wait_timeout_while(
                lock.lock().map_err(|_| OxidebpfError::LockError)?,
                max_wait,
                |&mut pending| !pending,
            )
            .map_err(|_| OxidebpfError::LockError)?
            .1;

        if wait_result.timed_out() {
            info!(
                LOGGER.0,
                "event_poller(); PerfMapPoller is not ready to receive events"
            );
        }

        Ok(())
    }

    pub(crate) fn load_program_version(
        &mut self,
        mut program_blueprint: ProgramBlueprint,
        mut perfmap_opts_fn: impl FnMut() -> (Sender<PerfChannelMessage>, PerfBufferSize),
    ) -> Result<(), OxidebpfError> {
        let mut matching_blueprints: Vec<ProgramObject> = self
            .programs
            .iter()
            .map(|p| {
                program_blueprint
                    .programs
                    .get(p.name)
                    .cloned()
                    .ok_or_else(|| {
                        info!(
                            LOGGER.0,
                            "Failed to find eBPF program: {}",
                            p.name.to_string()
                        );
                        OxidebpfError::ProgramNotFound(p.name.to_string())
                    })
            })
            .collect::<Result<_, OxidebpfError>>()?;

        let mut perfmaps = vec![];
        // load maps and save fds and apply relocations
        let mut loaded_maps = HashSet::new();
        let mut tailcall_tables = HashMap::new();

        let mut perfmap_opts = None;

        let perfmap_entries = cpu_info::max_possible_index()? as u32 + 1;

        for program_object in matching_blueprints.iter_mut() {
            for name in program_object.required_maps().iter() {
                let map = program_blueprint
                    .maps
                    .get_mut(name)
                    .ok_or_else(|| {
                        info!(
                            LOGGER.0,
                            "load_program_version(); map not found while iterating through required maps, map name: {}; program name: {}",
                            name,
                            program_object.name
                        );
                        OxidebpfError::MapNotFound(name.to_string())
                    })?;

                if !loaded_maps.contains(&map.name) {
                    match map.definition.map_type {
                        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => {
                            if map.definition.max_entries == 0 {
                                map.definition.max_entries = perfmap_entries
                            };

                            let fd = unsafe {
                                syscall::bpf_map_create_with_sized_attr(map.definition.into())?
                            };
                            self.fds.insert(fd);
                            map.set_loaded(fd);
                            program_object.fixup_map_relocation(fd, map)?;

                            let event_attr = PerfEventAttr {
                                config: perf_sw_ids::PERF_COUNT_SW_BPF_OUTPUT as u64,
                                size: std::mem::size_of::<PerfEventAttr>() as u32,
                                p_type: perf_type_id::PERF_TYPE_SOFTWARE,
                                sample_type: perf_event_sample_format::PERF_SAMPLE_RAW as u64,
                                sample_union: PerfSample { sample_period: 1 },
                                wakeup_union: PerfWakeup { wakeup_events: 1 },
                                ..Default::default()
                            };

                            let buffer_size = match perfmap_opts {
                                Some((_, buffer_size)) => buffer_size,
                                None => {
                                    let opts = perfmap_opts_fn();
                                    let size = opts.1;
                                    perfmap_opts = Some(opts);
                                    size
                                }
                            };

                            let perfmap = PerfMap::new_group(&map.name, event_attr, buffer_size)?;

                            perfmap
                                .iter()
                                .try_for_each(|p| -> Result<(), OxidebpfError> {
                                    self.fds.insert(unsafe {
                                        libc::fcntl(p.ev_fd as RawFd, libc::F_DUPFD_CLOEXEC, 3)
                                    });
                                    bpf_map_update_elem::<i32, i32>(fd, p.cpuid(), p.ev_fd as i32)
                                })?;

                            perfmaps.extend(perfmap);
                        }
                        bpf_map_type::BPF_MAP_TYPE_ARRAY => {
                            // Create the new array Map
                            unsafe {
                                match ArrayMap::new(
                                    name,
                                    map.definition.value_size as u32,
                                    map.definition.max_entries,
                                ) {
                                    Ok(new_map) => {
                                        let fd = libc::fcntl(
                                            *new_map.get_fd(),
                                            libc::F_DUPFD_CLOEXEC,
                                            3,
                                        );
                                        self.fds.insert(fd);
                                        map.set_loaded(fd);
                                        program_object.fixup_map_relocation(fd, map)?;
                                        self.array_maps.insert(name.to_string(), new_map);
                                    }
                                    Err(err) => return Err(err),
                                };
                            }
                        }
                        bpf_map_type::BPF_MAP_TYPE_HASH => unsafe {
                            match BpfHashMap::new(
                                name,
                                map.definition.key_size as u32,
                                map.definition.value_size as u32,
                                map.definition.max_entries,
                            ) {
                                Ok(new_map) => {
                                    let fd =
                                        libc::fcntl(*new_map.get_fd(), libc::F_DUPFD_CLOEXEC, 3);
                                    self.fds.insert(fd);
                                    map.set_loaded(fd);
                                    program_object.fixup_map_relocation(fd, map)?;
                                    self.hash_maps.insert(name.to_string(), new_map);
                                }
                                Err(err) => return Err(err),
                            };
                        },
                        bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY => {
                            match ProgMap::new(name, map.definition.max_entries) {
                                Ok(new_map) => {
                                    let fd = unsafe {
                                        libc::fcntl(*new_map.get_fd(), libc::F_DUPFD_CLOEXEC, 3)
                                    };
                                    self.fds.insert(fd);
                                    map.set_loaded(fd);
                                    program_object.fixup_map_relocation(fd, map)?;
                                    tailcall_tables.insert(new_map.base.name.to_string(), new_map);
                                }
                                Err(err) => return Err(err),
                            };
                        }
                        _ => {
                            let fd = unsafe {
                                syscall::bpf_map_create_with_sized_attr(map.definition.into())?
                            };
                            self.fds.insert(fd);
                            map.set_loaded(fd);
                            program_object.fixup_map_relocation(fd, map)?;
                        }
                    }
                    loaded_maps.insert(map.name.to_string());
                } else {
                    program_object.fixup_map_relocation(map.get_fd()?, map)?;
                }
            }
        }

        // load and attach programs
        for blueprint in matching_blueprints.into_iter() {
            // Programs are kept separate from ProgramBlueprints to allow users to specify
            // different blueprints/files for the same set of programs, should they choose.
            // This means we need to do ugly filters like this
            let name = blueprint.name;
            let programs = self.programs.iter_mut().filter(|p| p.name == name);

            for p in programs {
                // check if the user specified a kind, otherwise set it based on the blueprint
                let program_type = match &p.kind {
                    Some(k) => k,
                    None => {
                        p.kind = Some(blueprint.program_type);
                        &blueprint.program_type
                    }
                };
                let fd = match syscall::bpf_prog_load(
                    u32::from(program_type),
                    &blueprint.code,
                    blueprint.license.clone(),
                    blueprint.kernel_version,
                ) {
                    Ok(fd) => fd,
                    Err(e) => {
                        // if this program is optional, go to the next one
                        if p.optional {
                            continue;
                        }

                        // If it's not optional, fail out of the whole Version
                        info!(
                            LOGGER.0,
                            "load_program_version(); failed out of version with error {:?}", e
                        );
                        return Err(e);
                    }
                };

                // fix up any tail call mapping that might exist
                if let Some(tcm) = &p.tail_call_mapping {
                    match tailcall_tables.get(&tcm.map) {
                        Some(map) => bpf_map_update_elem(*map.get_fd(), tcm.index, fd)?,
                        None => {
                            info!(
                                LOGGER.0,
                                "load_program_version(); tail call mapping not found, could not update: {:?}",
                                tcm.map.clone()
                            );
                            return Err(OxidebpfError::MapNotFound(tcm.map.clone()));
                        }
                    }
                }

                // SAFETY: Program object `p` takes the `fd` here, but does NOT manage its lifetime
                p.loaded_as(fd);
                match p.attach() {
                    Err(e) => {
                        if !p.optional {
                            info!(
                                LOGGER.0,
                                "load_program_version(); failed mandatory program load: {}; error: {:?}",
                                p.name,
                                e,
                            );
                            return Err(e);
                        }
                    }
                    Ok(s) => {
                        self.ev_names.extend(s.0);
                        // SAFETY: these fds that came from `p.attach()` are not managed by `p`
                        self.fds.extend(s.1);
                    }
                }
                self.fds.insert(fd);
            }
        }

        // start perfmap event poller, if one exists
        if let Some((tx, _)) = perfmap_opts {
            self.event_poller(perfmaps, tx)?;
        }

        Ok(())
    }
}

impl<'a> Drop for ProgramVersion<'a> {
    fn drop(&mut self) {
        // Detach everything, close remaining attachpoints
        // SAFETY: these fds must be wholly owned by `ProgramVersion`.
        for fd in self.fds.iter() {
            unsafe {
                libc::close(*fd as c_int);
            }
        }

        // We are intentionally enumerating and closing _all_ debugfs created
        // probes here, on the off chance that one gets missed somehow. Otherwise,
        // we might end up stuck with a bunch of unused probes clogging the namespace.
        // If it has oxidebpf_ it's probably one of ours. This avoids conflicting
        // with customer user probes or probes from other frameworks.
        if let Some(debugfs_mount) = debugfs::mount_point().as_deref() {
            drop_debugfs_uprobes(debugfs_mount);
            drop_debugfs_kprobes(debugfs_mount);
        }
    }
}

fn drop_debugfs_uprobes(debugfs_mount: &str) {
    let up_file = match std::fs::OpenOptions::new()
        .append(true)
        .write(true)
        .read(true)
        .open(format!("{}/tracing/uprobe_events", debugfs_mount))
    {
        Ok(f) => f,
        Err(e) => {
            info!(
                LOGGER.0,
                "ProgramVersion::drop(); could not modify {}/tracing/uprobe_events: {:?}",
                debugfs_mount,
                e
            );
            return;
        }
    };
    let up_reader = BufReader::new(&up_file);
    let mut up_writer = BufWriter::new(&up_file);
    for line in up_reader.lines() {
        let line = line.unwrap();
        if line.contains("oxidebpf_") {
            if let Err(e) = up_writer.write_all(format!("-:{}\n", &line[2..]).as_bytes()) {
                info!(
                    LOGGER.0,
                    "ProgramVersion::drop(); could not close uprobe [{}]: {:?}", line, e
                );
                return;
            }
        }
    }
}

fn drop_debugfs_kprobes(debugfs_mount: &str) {
    let kp_file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .open(format!("{}/tracing/uprobe_events", debugfs_mount))
    {
        Ok(f) => f,
        Err(e) => {
            info!(
                LOGGER.0,
                "ProgramVersion::drop(); could not modify {}/tracing/kprobe_events: {:?}",
                debugfs_mount,
                e
            );
            return;
        }
    };
    let kp_reader = BufReader::new(&kp_file);
    let mut kp_writer = BufWriter::new(&kp_file);
    for line in kp_reader.lines() {
        let line = line.unwrap();
        if line.contains("oxidebpf_") {
            if let Err(e) = kp_writer.write_all(format!("-:{}\n", &line[2..]).as_bytes()) {
                info!(
                    LOGGER.0,
                    "ProgramVersion::drop(); could not close kprobe [{}]: {:?}", line, e
                );
                return;
            }
        }
    }
}

fn perf_map_poller(
    perfmaps: Vec<PerfMap>,
    tx: Sender<PerfChannelMessage>,
    polling_delay: Duration,
    polling_policy: SchedulingPolicy,
    polling_signal: Arc<(Mutex<bool>, Condvar)>,
) {
    prioritize_thread(polling_policy);

    let poller = match PerfMapPoller::new(perfmaps.into_iter(), polling_signal) {
        Ok(poller) => poller,
        Err(e) => {
            crit!(LOGGER.0, "perf_map_poller(); {}", e);
            return;
        }
    };

    if let Err(e) = poller.poll(tx, polling_delay) {
        crit!(
            LOGGER.0,
            "perf_map_poller(); unrecoverable polling error: {}",
            e
        );
    }
}

/// Sets thread priority according to the given policy and then sets a
/// niceness value when relevant. Errors are logged but otherwise
/// ignored.
fn prioritize_thread(polling_policy: SchedulingPolicy) {
    let native_id = match polling_policy {
        SchedulingPolicy::Deadline(_, _, _) => {
            // SAFETY: this syscall is always successful
            unsafe { libc::syscall(libc::SYS_gettid) as libc::pthread_t }
        }
        _ => thread_priority::thread_native_id(),
    };
    let priority = polling_policy.into();
    let policy = polling_policy.into();

    // This call throws errors if the passed in priority and policies don't match, so we need
    // to ensure that it's what's expected (1 to 99 inclusive for realtime, set of 3 nanosecond
    // counts for realtime deadline, 0 for all others).
    if let Err(e) = thread_priority::set_thread_priority_and_policy(native_id, priority, policy) {
        error!(
            LOGGER.0,
            "perf_map_poller(); could not set thread priority, continuing at inherited: {:?}", e
        );
    };

    // Once we've set our scheduling policy and priority, we'll want to set the niceness value
    // (if relevant).
    match polling_policy {
        SchedulingPolicy::Other(polling_priority) | SchedulingPolicy::Batch(polling_priority) => {
            // SAFETY: continuing at the default is not fatal, casting i8 to i32 is safe, clamp
            unsafe {
                let polling_priority = polling_priority.clamp(-20, 19);
                if libc::nice(polling_priority as i32) < 0 {
                    let errno = nix::errno::Errno::from_i32(nix::errno::errno());
                    error!(
                        LOGGER.0,
                        "perf_map_poller(); could not set niceness, continuing at 0: {:?}", errno
                    );
                }
            };
        }
        // we don't need to set a niceness value for anything else
        _ => {}
    }
}
