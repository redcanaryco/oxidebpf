use std::collections::HashMap;

use crossbeam_channel::Sender;
use slog::info;

use crate::{
    set_memlock_limit, ArrayMap, BpfHashMap, DebugfsMountOpts, OxidebpfError, PerfChannelMessage,
    ProgramBlueprint, ProgramVersion, SchedulingPolicy, LOGGER,
};

/// A group of eBPF [`ProgramVersion`](struct@ProgramVersion)s that a user
/// wishes to load from a blueprint. The loader will attempt each `ProgramVersion`
/// in order until one successfully loads, or none do.
pub struct ProgramGroup<'a> {
    loaded_version: Option<ProgramVersion<'a>>,
    mem_limit: Option<usize>,
    loaded: bool,
    debugfs_mount: DebugfsMountOpts,
    polling_thread_policy: Option<SchedulingPolicy>,
}

impl<'a> ProgramGroup<'a> {
    /// Create a program group that will manage multiple
    /// [`ProgramVersion`](struct@ProgramVersion)s.
    ///
    /// Together with [`load()`](fn.load.html), this is the primary
    /// public interface of the oxidebpf library. You feed your
    /// `ProgramGroup` a collection of `ProgramVersion`s, each with
    /// their own set of `Program`s. Note that you must provide your
    /// `ProgramGroup` with a
    /// [`ProgramBlueprint`](struct@ProgramBlueprint). The blueprint
    /// contains the parsed object file with all the eBPF programs and
    /// maps you may load.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::ProgramBlueprint;
    /// use oxidebpf::{ProgramGroup, Program, ProgramVersion, ProgramType};
    /// use std::path::PathBuf;
    ///
    /// let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    ///             .join("test")
    ///             .join(format!("test_program_{}", std::env::consts::ARCH));
    /// let program_blueprint =
    ///     ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
    ///         .expect("Could not open test object file");
    ///
    /// ProgramGroup::new();
    /// ```
    pub fn new() -> ProgramGroup<'a> {
        ProgramGroup {
            loaded_version: None,
            mem_limit: None,
            debugfs_mount: DebugfsMountOpts::MountDisabled,
            loaded: false,
            polling_thread_policy: None,
        }
    }

    /// Manually set the memlock ulimit for this `ProgramGroup`. The limit will be applied
    /// when calling `load()`.
    pub fn mem_limit(mut self, limit: usize) -> Self {
        self.mem_limit = Some(limit);
        self
    }

    /// Controls whether `debugfs` is mounted before attaching {k,u}probes. This operation only
    /// occurs if `perf_event_open` is not supported and debugfs is not mounted. The
    /// [DebugfsMountOpts](enum@DebugfsMountOpts) enum determines where `debugfs` gets mounted to.
    pub fn auto_mount_debugfs(mut self, mount_options: DebugfsMountOpts) -> Self {
        self.debugfs_mount = mount_options;
        self
    }

    /// Sets the thread priority for the thread that polls perfmaps for events coming from eBPF
    /// to userspace. The priority number specified should be valid for the scheduling policy you
    /// provide (documented in the enum). This may be useful if you find you're missing messages
    /// that you expect to be present, or are dropping more messages than seems reasonable.
    pub fn polling_thread_priority(mut self, scheduling_policy: SchedulingPolicy) -> Self {
        self.polling_thread_policy = Some(scheduling_policy);
        self
    }

    /// Attempt to load [`ProgramVersion`](struct@ProgramVersion)s until one
    /// successfully loads.
    ///
    /// This function attempts to load each `ProgramVersion` in the order given until
    /// one successfully loads. When one loads, if that version had a perfmap channel,
    /// a [`PerfChannelMessage`](struct@PerfChannelMessage) receiver crossbeam channel
    /// is available after loading by calling `get_receiver()` on the `ProgramGroup`.
    /// If none load, a `NoProgramVersionLoaded` error is returned, along with all the
    /// internal errors generated during attempted loading.
    ///
    /// If the program version contain any perfmaps,
    /// perfmap_opts_fn(), will be called on each one until a version
    /// suceeds to load. perfmap_opts_fn() returns a channel from
    /// which to send perf messages, and a size (in bytes) for the per
    /// cpu perf buffer. When the perfmap is created the buffer will
    /// take at most the specified number of bytes but it will shrink
    /// to fit a page size that is a multiple of two.
    ///
    /// NOTE: Once you call `load()`, it cannot be called again without re-creating
    /// the `ProgramGroup`.
    ///
    /// # Example
    ///
    /// ```
    /// use oxidebpf::ProgramBlueprint;
    /// use oxidebpf::{ProgramGroup, Program, ProgramVersion, ProgramType};
    /// use std::path::PathBuf;
    ///
    /// let program = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    ///             .join("test")
    ///             .join(format!("test_program_{}", std::env::consts::ARCH));
    /// let program_blueprint =
    ///     ProgramBlueprint::new(&std::fs::read(program).expect("Could not open file"), None)
    ///         .expect("Could not open test object file");
    /// let mut program_group = ProgramGroup::new();
    ///
    /// let (tx, rx) = crossbeam_channel::bounded(1024);
    ///
    /// program_group.load(
    ///     program_blueprint,
    ///     vec![ProgramVersion::new(vec![Program::new(
    ///         "test_program",
    ///         &["do_mount"],
    ///     ).syscall(true)])],
    ///     || (tx.clone(), 1024 * 8),
    /// ).expect("Could not load programs");
    /// ```
    pub fn load(
        &mut self,
        program_blueprint: ProgramBlueprint,
        program_versions: Vec<ProgramVersion<'a>>,
        mut perfmap_opts_fn: impl FnMut() -> (Sender<PerfChannelMessage>, usize),
    ) -> Result<(), OxidebpfError> {
        if self.loaded {
            info!(
                LOGGER.0,
                "ProgramGroup::load(); error: attempting to load a program group that was already loaded"
            );
            return Err(OxidebpfError::ProgramGroupAlreadyLoaded);
        }

        if let Some(limit) = self.mem_limit {
            set_memlock_limit(limit)?;
        }
        let mut errors = vec![];
        for mut program_version in program_versions {
            program_version.set_debugfs_mount_point(self.debugfs_mount.clone());
            program_version.set_polling_policy(self.polling_thread_policy);

            match program_version
                .load_program_version(program_blueprint.clone(), &mut perfmap_opts_fn)
            {
                Ok(()) => {
                    self.loaded_version = Some(program_version);
                    break;
                }
                Err(e) => {
                    errors.push(e);
                }
            };
        }

        match &self.loaded_version {
            None => {
                info!(
                    LOGGER.0,
                    "ProgramGroup::load(); error: no program version was able to load for {:?}, errors: {:?}",
                    match std::env::current_exe() {
                        Ok(p) => p,
                        Err(_) => std::path::PathBuf::from("unknown"),
                    },
                    errors
                );
                Err(OxidebpfError::NoProgramVersionLoaded(errors))
            }
            Some(_) => {
                self.loaded = true;
                Ok(())
            }
        }
    }

    /// Get a reference to the array maps in the [`Program`](struct@ProgramGroup)s.
    pub fn get_array_maps(&self) -> Option<&HashMap<String, ArrayMap>> {
        self.loaded_version.as_ref().map(|ver| &ver.array_maps)
    }

    /// Get a reference to the hash maps in the ['Program'](struct@ProgramGroup)s.
    pub fn get_hash_maps(&self) -> Option<&HashMap<String, BpfHashMap>> {
        self.loaded_version.as_ref().map(|ver| &ver.hash_maps)
    }
}
