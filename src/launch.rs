//! Linux: session processes started the embedding program's way.

use crate::SpawnRequest;
use std::io;
use std::process::Command;

/// Starts session processes in place of tinyssh's own account handling
/// (see [`Config::launcher`](crate::Config::launcher)).
///
/// The launcher decides what runs and as whom: the program, its arguments,
/// environment, working directory and credentials (for example with
/// [`CommandExt::uid`](std::os::unix::process::CommandExt::uid) or a
/// [`pre_exec`](std::os::unix::process::CommandExt::pre_exec) hook). tinyssh
/// does the rest as for its own sessions: it connects the process to the
/// terminal or to pipes, sets `TERM` to the client's, makes the process a
/// session leader with the terminal as its controlling terminal (in a
/// `pre_exec` hook of its own, which runs after the command's), and waits for
/// it and hangs it up.
///
/// Implemented for closures `Fn(&SpawnRequest) -> io::Result<Launch>`.
pub trait Launcher: Send + Sync {
    /// Prepares the process for `request`. An error ends the session: the
    /// client sees it on stderr, with exit status 127.
    fn launch(&self, request: &SpawnRequest<'_>) -> io::Result<Launch>;
}

impl<F: Fn(&SpawnRequest<'_>) -> io::Result<Launch> + Send + Sync> Launcher for F {
    fn launch(&self, request: &SpawnRequest<'_>) -> io::Result<Launch> {
        self(request)
    }
}

/// A session process prepared by a [`Launcher`].
#[derive(Debug)]
pub struct Launch {
    /// The process to start. tinyssh replaces its standard input, output
    /// and error.
    pub command: Command,
    /// The user the process runs as, if not the server's. Like `login`,
    /// tinyssh gives this user the terminal (keeping the group devpts gave
    /// it): programs that reopen it would fail otherwise.
    pub terminal_owner: Option<u32>,
}
