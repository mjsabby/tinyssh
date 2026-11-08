# tinyssh

A minimal, panic-free SSHv2 **server** library for interactive shell access,
built to be embedded (for example in a Linux distribution's init). It
implements the subset of RFC 4253, RFC 4252 and RFC 4254 with a single cryptographic suite:

| Purpose          | Algorithm                                                  |
|------------------|------------------------------------------------------------|
| Key exchange     | `curve25519-sha256` (plus OpenSSH strict KEX)              |
| Host / user keys | `ssh-ed25519`                                              |
| Cipher + MAC     | `aes128-gcm@openssh.com` (no separate MAC is advertised)   |
| Compression      | `none`                                                     |

Supported: `publickey` authentication (query and signed forms), one `session`
channel at a time with `pty-req`, `shell`, `exec`, `window-change` and
`exit-status`, window flow control, and rekeying in both directions.

Requires x86-64 with AVX2, BMI2, ADX, AES-NI, PCLMULQDQ, VAES, VPCLMULQDQ
and SHA-NI (AMD Zen 3+, Intel Ice Lake+). tinyssh is compiled for exactly
that, with no run-time check or fallback, and refuses to build unless the
features are enabled. This repository's `.cargo/config.toml` enables them; a
program that depends on tinyssh needs the same flags, for example:

```sh
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+aes,+pclmulqdq,+vaes,+vpclmulqdq,+sha,+adx" cargo build --release
```

Not supported, by design: passwords and other auth methods, port/agent/X11
forwarding, subsystems (so modern `scp` needs `scp -O`; SFTP is unavailable),
more than one simultaneous channel, terminal modes from `pty-req` (the pty's
defaults are used), and key files: keys are raw 32-byte Ed25519 values, and
storing them is up to the embedding program.

## Properties

* **Sans-IO core.** `Connection` is a state machine over byte buffers;
  `serve`/`serve_connection` drive it with tokio and a pseudo-terminal
  (Linux `/dev/ptmx`, Windows ConPTY) or pipes.
* **No steady-state allocation.** Each connection gets one `Arena` (receive,
  send, deferred-reply and stdin buffers). Packets are decrypted and parsed in
  place; replies are built and encrypted in place. Once a session is running,
  neither the protocol core (including rekeys) nor the tokio driver allocates.
* **Panic-free.** Library code is linted with `clippy::indexing_slicing`,
  `arithmetic_side_effects`, `unwrap_used`, `expect_used`, `panic` and friends
  denied. Malformed input becomes an `Error` plus `SSH_MSG_DISCONNECT`.
* **Simple ownership.** No `Arc`, `Rc`, `RefCell` or locks. One task owns a
  connection and its process; the `Config` is shared by reference.
* **Bounded.** Fixed buffers, a capped number of replies queued during key
  exchange, `max_connections`, `max_auth_attempts` and `login_timeout`.
* **One dependency.** Only `tokio`. The SSH wire encoding and all of the
  cryptography are written here, and OS randomness, PTYs and ConPTY use small
  FFI declarations against libraries `std` already links.
* **AVX2 crypto.** AES-128-GCM uses the 256-bit VAES and VPCLMULQDQ
  instructions (`src/cipher/vaes.rs`), about 2.5x faster than the `aes-gcm`
  crate here, whose GHASH has no 256-bit backend and whose CPU detection
  mistakes VAES for an AVX-512 feature. SHA-256 uses SHA-NI
  (`src/sha256.rs`).
* **Curve25519** (`src/curve25519/`). X25519 runs the Montgomery ladder four
  field elements at a time in AVX2 registers (radix 2^25.5, hand-allocated
  VPMULUDQ assembly); inversions and square roots use MULX/ADCX/ADOX
  assembly, with the limbs kept in registers across runs of squarings. Both
  are ported from a C++ implementation and match its speed. Fixed-base
  multiplications (ephemeral keys, signing) use a constant-time comb over a
  precomputed table (ref10-style, 24 KiB), selecting each entry with AVX2
  compares and blends. The server's ephemeral public key and the shared
  secret share one inversion (Montgomery's trick). Verification computes
  `[s]B - [k]A` with the four coordinates of an Edwards point in the four
  AVX2 lanes (a width-5 NAF for `k`, width 6 for `s` with a precomputed
  10 KiB table of odd multiples of B; subtraction needs no negated entries),
  and keeps the usual cofactorless check: the result's encoding must equal
  R. SHA-512 for Ed25519 is plain scalar code (`src/sha512.rs`). On Zen 3,
  against `x25519-dalek` and `ed25519-dalek` with their precomputed tables
  (and decoding the public key for each verification, as SSH does):

  | Operation | tinyssh | dalek |
  |---|---|---|
  | X25519 shared secret | 20.8 µs | 39.1 µs |
  | X25519 public key | 6.7 µs | 11.3 µs |
  | Server key exchange (both) | 25.5 µs | 50.4 µs |
  | Ed25519 sign | 7.3 µs | 12.2 µs |
  | Ed25519 verify | 21.1 µs | 26.9 µs |
* **Batched I/O.** Process output is read up to 128 KiB at a time, sent as
  several packets in one write, and session pipes are enlarged to 1 MiB.

## Usage

```rust
// seed, admin_key: [u8; 32], stored however the embedding program likes.
let host_key = tinyssh::HostKey::from_seed(&seed);
let keys = tinyssh::AuthorizedKeys::from(vec![tinyssh::PublicKey::from_bytes(admin_key)]);
let mut config = tinyssh::Config::new(host_key, keys);
config.rekey_limit = 1 << 30; // defaults: 4 GiB, 2 MiB window, 6 auth attempts, 60 s login
let config: &'static tinyssh::Config = Box::leak(Box::new(config));
let listener = tokio::net::TcpListener::bind("0.0.0.0:22").await?;
tinyssh::serve(listener, config).await // never returns
```

`HostKey::generate()` creates a host key from OS randomness; `to_seed()`
returns the 32 bytes to store. `Config::authorizer` accepts anything
implementing `Authorizer`, including closures `Fn(&str, &PublicKey) -> bool`;
`AuthorizedKeys` is a plain list of keys allowed for every user. On Linux,
`Config::launcher` likewise accepts a `Launcher`, including closures
`Fn(&SpawnRequest) -> io::Result<Launch>`, to start sessions the embedding
program's way (see [Processes](#processes)).

To run your own event loop, use `Arena`, `Connection` and `Event` directly:
copy socket input into `read_buf()`, call `poll()` until it returns `None`,
write `write_buf()` to the socket, and move session data with `stdin()`,
`output()` and `exited()`.

### Processes

* **Linux, as root:** the requested user is looked up in `/etc/passwd`, its
  groups in `/etc/group`; the shell runs with those credentials, in a new
  session with the pty as controlling terminal, as a login shell (`-sh`).
* **Linux, unprivileged:** the shell runs as the server's own user.
* **Linux, with a launcher:** `Config::launcher` replaces both of the above.
  It returns the `std::process::Command` to run (program, arguments,
  environment, working directory and credentials, for example through
  `CommandExt::uid` or a `pre_exec` hook); tinyssh connects it to the
  terminal or to pipes, sets `TERM`, makes it a session leader with the
  terminal as its controlling terminal (in a `pre_exec` hook that runs after
  the command's), and gives the terminal to `Launch::terminal_owner`. An init
  can run sessions as the accounts of its own configuration this way, with
  no `/etc/passwd` entries.
* **Windows:** the shell (`Config::shell` or `%COMSPEC%`) runs as the server's
  own account, in a ConPTY when a terminal was requested and with pipes
  otherwise. `exec` commands run as `cmd.exe /s /c "<command>"`, so quoted
  program paths survive CMD's quote handling; other shells get `-c` and the
  command quoted as one argument.

Terminal dimensions of zero are unspecified (RFC 4254): a ConPTY then starts
at 80x24, and a `window-change` keeps the current value of a zero field.
Process output is read one chunk ahead of the client's window, so the end of
a session (EOF, `exit-status`, close) is reported even while the window is
full.

When a client disconnects or closes the session before it is over, the
process group receives `SIGHUP` (and `SIGCONT`), even if the shell has
already exited: the shell is not reaped until then, so the group's ID cannot
have been reused. A session that runs to completion (the shell exited and
its output was sent) signals nothing, so a job that let go of the session's
output (`cmd > log 2>&1 &`) keeps running, as with OpenSSH. tinyssh reaps
its session processes itself, by PID; a host program that also reaps children
it did not start (`waitpid(-1)`, as an init running as PID 1 does for orphans)
takes their exit status (the client then sees 255), and tinyssh no longer
signals a group it cannot be sure is still the session's. On Windows every
session runs in its own job object, and the whole job (including anything
the shell started) is terminated when the session ends.

### Example daemon

The daemon stores keys as hex: the host key file holds the seed (generated on
first start), and the authorized keys file holds one public key per line.
The raw key of an OpenSSH `.pub` file is the end of its base64 blob:

```sh
cut -d' ' -f2 ~/.ssh/id_ed25519.pub | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n' > keys
cargo run --release --example tinysshd -- --listen 0.0.0.0:2222 \
    --host-key ./host_key --authorized-keys ./keys
ssh -p 2222 localhost
```

OpenSSH 10.1+ clients warn that `curve25519-sha256` is not post-quantum;
`-o WarnWeakCrypto=no` silences it.

Every commit to `main` that passes CI is published as a GitHub release with
static `tinysshd` binaries for x86-64 Linux (musl) and Windows, their debug
information in separate files that debuggers find next to the binaries (a
`.dbg` file with the Linux binary's DWARF, and the Windows `.pdb`), and
`SHA256SUMS`. They are built with `cargo build --profile dist --example
tinysshd`, a release build with full debug information.

## Testing

```sh
cargo test             # everything; OpenSSH interop tests skip if ssh is absent
cargo clippy --all-targets
cargo clippy --target x86_64-pc-windows-msvc
taskset -c 2 cargo test --release --lib -- --ignored --nocapture bench   # curve25519 timings
```

CI (`.github/workflows/ci.yml`) runs clippy and the tests on Linux and
Windows, and the tests again as release builds for the published binaries'
targets.

* `src/tests/` drives the server with an in-memory client that reuses the
  transport code: full sessions, server- and client-initiated rekeys (down to
  one exchange per packet; at most four before authentication), replies
  deferred during key exchange, window violations, tampered packets, strict
  KEX, wrong KEX guesses, auth limits, and the wire codec against the RFC
  4251 examples. The same client also runs over TCP against the real driver
  and processes, checking that a session's end is reported while the window
  is closed, that input stops when the shell exits, that closing a session
  hangs up the jobs its shell left behind and reaps the shell, that a
  session that runs to completion leaves its jobs alone, and that a
  launcher's process gets its environment and working directory, leads its
  session with the terminal as its controlling terminal, and reports a
  failed launch. `tests/driver.rs`
  checks the login timeout (also against a client flooding a
  current-thread runtime) and the connection limit.
* `src/cipher/` checks the VAES AES-GCM against the GCM specification's test
  vectors and against the `aes-gcm` crate (a dev-dependency) for every length
  up to 600 bytes and larger
  ones, including rejection of tampered tags, ciphertext and associated data.
  `src/sha256.rs` and `src/sha512.rs` check the hashes against the FIPS 180-4
  examples and against the `sha2` crate (a dev-dependency) for every length
  up to 300 bytes, split at every point.
* `src/curve25519/` checks the field arithmetic against a big-integer
  reference (including carry edge cases), the AVX2 ladder step with extreme
  limbs against its overflow bounds, scalar reduction against long division,
  X25519 against the RFC 7748 vectors and `x25519-dalek` (non-canonical and
  small-order points included), and Ed25519 against the RFC 8032 vectors and
  `ed25519-dalek` (identical keys and signatures; tampered, malleable and
  small-order cases rejected). Both dalek crates are dev-dependencies only.
  The ignored `rfc7748_million_iterations` test runs the long RFC vector, and
  `constant_time` marks the secrets as undefined for Valgrind's memcheck,
  which then reports any secret-dependent branch or memory address:

  ```sh
  cargo test --release --lib -- --ignored rfc7748_million_iterations
  valgrind --error-exitcode=1 target/release/deps/tinyssh-<hash> \
      --ignored --exact curve25519::tests::constant_time
  ```
* `steady_state_does_not_allocate` (debug builds) counts allocations while
  megabytes stream through the core with dozens of rekeys.
* `tests/driver_alloc.rs` (debug builds) counts allocations on every thread
  but the client's (the server's runtime thread and the threads that report
  I/O completions to it) while OpenSSH streams 64 MiB through a binary echo
  process after 16 MiB of warm-up, with rekeys from both sides. On Windows
  the echo pauses after each MiB, so that writes to it have to wait.
* `tests/openssh.rs` runs the system `ssh` client against the server: exec,
  stderr and exit codes, rejected keys, a 12 MiB round trip with rekeys, a
  40 MB download, and an interactive pty session.
