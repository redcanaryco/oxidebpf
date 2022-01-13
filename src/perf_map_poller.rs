use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

use crossbeam_channel::Sender;
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use nix::errno::Errno;
use slog::{crit, error, info};

use crate::{
    maps::{PerCpu, PerfEvent, PerfMap},
    OxidebpfError, PerfChannelMessage, SchedulingPolicy, LOGGER,
};

pub fn perf_map_poller(
    perfmaps: Vec<PerfMap>,
    tx: Sender<PerfChannelMessage>,
    polling_delay: Duration,
    polling_policy: SchedulingPolicy,
    polling_signal: Arc<(Mutex<bool>, Condvar)>,
) {
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

    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            crit!(
                LOGGER.0,
                "perf_map_poller(); error creating poller: {:?}",
                e
            );
            return;
        }
    };

    let tokens: HashMap<Token, PerfMap> = match perfmaps
        .into_iter()
        .map(|p| {
            let token = Token(p.ev_fd as usize);
            poll.registry()
                .register(&mut SourceFd(&p.ev_fd), token, Interest::READABLE)
                .map(|_| (token, p))
        })
        .collect()
    {
        Ok(tokens) => tokens,
        Err(e) => {
            crit!(
                LOGGER.0,
                "perf_map_poller(); error registering poller: {:?}",
                e
            );
            return;
        }
    };

    {
        // now that the perfmap fd's are registered, we can signal to the main thread that
        // event polling is ready.
        let (lock, cvar) = &*polling_signal;
        match lock.lock() {
            Ok(mut polling_is_ready) => {
                *polling_is_ready = true;
                cvar.notify_one();
            }
            Err(e) => {
                info!(
                    LOGGER.0,
                    "perf_map_poller(); error grabbing cond mutex: {:?}", e
                );
            }
        }
    }

    let mut events = Events::with_capacity(1024);

    // for tracking dropped event statistics inside the loop
    'outer: loop {
        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(_) => {}
            Err(e) => match nix::errno::Errno::from_i32(nix::errno::errno()) {
                Errno::EINTR => continue,
                _ => {
                    crit!(
                        LOGGER.0,
                        "perf_map_poller(); unrecoverable polling error: {:?}",
                        e
                    );
                    return;
                }
            },
        }
        let mut perf_events: Vec<(String, i32, Option<PerfEvent>)> = Vec::new();

        events
            .iter()
            .filter_map(|e| tokens.get(&e.token()))
            .for_each(|perfmap| loop {
                match perfmap.read() {
                    Ok(perf_event) => {
                        perf_events.push((
                            perfmap.name.to_string(),
                            perfmap.cpuid() as i32,
                            perf_event,
                        ));
                    }
                    Err(OxidebpfError::NoPerfData) => {
                        // we're done reading
                        return;
                    }
                    Err(e) => {
                        crit!(LOGGER.0, "perf_map_poller(); perfmap read error: {:?}", e);
                        return;
                    }
                }
            });

        for event in perf_events.into_iter() {
            let message = match event.2 {
                None => continue,
                Some(PerfEvent::Lost(l)) => PerfChannelMessage::Dropped(l.count),
                Some(PerfEvent::Sample(e)) => PerfChannelMessage::Event {
                    map_name: event.0,
                    cpuid: event.1,
                    data: e.data,
                },
            };

            match tx.send(message) {
                Ok(_) => {}
                Err(_) => break 'outer,
            };
        }

        thread::sleep(polling_delay);
    }
}
