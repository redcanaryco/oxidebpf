use std::{
    collections::HashMap,
    fmt::{self, Formatter},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

use crossbeam_channel::{Sender, TrySendError};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use nix::errno::Errno;
use slog::crit;

use crate::{
    maps::{PerCpu, PerfEvent, PerfMap},
    PerfChannelMessage, LOGGER,
};

pub struct PerfMapPoller {
    poll: Poll,
    tokens: HashMap<Token, PerfMap>,
}

impl PerfMapPoller {
    pub fn new(
        perfmaps: impl Iterator<Item = PerfMap>,
        polling_signal: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<Self, InitError> {
        let poll = Poll::new().map_err(InitError::Creation)?;
        let registry = poll.registry();

        let tokens = perfmaps
            .map(|p| {
                let token = Token(p.ev_fd as usize);
                registry
                    .register(&mut SourceFd(&p.ev_fd), token, Interest::READABLE)
                    .map(|_| (token, p))
            })
            .collect::<Result<_, _>>()
            .map_err(InitError::Registration)?;

        {
            // now that the perfmap fd's are registered, we can signal to the main thread that
            // event polling is ready.
            let (lock, cvar) = &*polling_signal;
            let mut locked_signal = lock
                .lock()
                .map_err(|e| InitError::ReadySignal(e.to_string()))?;
            *locked_signal = true;
            cvar.notify_one();
        }

        Ok(Self { poll, tokens })
    }

    pub fn poll(
        mut self,
        tx: Sender<PerfChannelMessage>,
        polling_delay: Duration,
    ) -> Result<(), std::io::Error> {
        let mut events = Events::with_capacity(self.tokens.len());

        loop {
            match self.poll_once(&mut events, &tx) {
                Ok(_) => thread::sleep(polling_delay),
                Err(RunError::Disconnected) => return Ok(()),
                Err(RunError::Poll(e)) => return Err(e),
            }
        }
    }

    fn poll_once(
        &mut self,
        events: &mut Events,
        tx: &Sender<PerfChannelMessage>,
    ) -> Result<(), RunError> {
        if let Err(e) = self.poll.poll(events, Some(Duration::from_millis(100))) {
            match nix::errno::Errno::from_i32(nix::errno::errno()) {
                Errno::EINTR => return Ok(()),
                _ => return Err(RunError::Poll(e)),
            }
        }

        let perf_events = events
            .iter()
            .filter_map(|e| self.tokens.get(&e.token()))
            .flat_map(|perfmap| {
                let name = &perfmap.name;
                let cpuid = perfmap.cpuid() as i32;

                // SAFETY: events should be 0 or 1 per token->buffer
                // meaning that no perfbuffer is running read_all more
                // than once hence meeting the safety requirements of
                // `read_all`
                unsafe {
                    perfmap
                        .read_all()
                        .map(move |e| e.map(|e| (name.clone(), cpuid, e)))
                }
            })
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    crit!(LOGGER.0, "perf_map_poller(); perfmap read error: {:?}", e);
                    None
                }
            });

        let mut dropped = 0;
        for (map_name, cpuid, event) in perf_events {
            match event {
                PerfEvent::Lost(count) => {
                    dropped += count;
                    // it's okay if the channel is full try again
                    // later so we aren't blocking on sending droppped
                    // messages
                    match tx.try_send(PerfChannelMessage::Dropped(dropped)) {
                        Ok(_) => dropped = 0,
                        Err(TrySendError::Disconnected(_)) => return Err(RunError::Disconnected),
                        #[cfg(feature = "metrics")]
                        Err(TrySendError::Full(_)) => {
                            metrics::increment_counter!("perfmap.channel.full", "map_name" => map_name)
                        }
                        #[cfg(not(feature = "metrics"))]
                        Err(TrySendError::Full(_)) => {}
                    }
                }
                PerfEvent::Sample(data) => tx
                    .send(PerfChannelMessage::Event {
                        map_name,
                        cpuid,
                        data,
                    })
                    .map_err(|_| RunError::Disconnected)?,
            };
        }

        Ok(())
    }
}

pub enum InitError {
    Creation(std::io::Error),
    Registration(std::io::Error),
    ReadySignal(String),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InitError::Creation(e) => write!(f, "error creating poller: {}", e),
            InitError::Registration(e) => write!(f, "error registering poller: {}", e),
            InitError::ReadySignal(e) => write!(f, "error grabbing cond mutex: {}", e),
        }
    }
}

enum RunError {
    Poll(std::io::Error),
    Disconnected,
}
