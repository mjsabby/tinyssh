//! Windows: ConPTY for terminal sessions and pipes for plain `exec`.
//!
//! Our ends of all pipes are overlapped named pipes; the child's ends are
//! ordinary synchronous handles, as ConPTY requires. Output is read through
//! tokio's named pipes, which reuse one buffer per pipe. Input is written
//! from a fixed buffer with overlapped I/O that the system thread pool
//! completes, because tokio's named pipes allocate for nearly every write
//! (see [`Writer`]). The process runs as the server's own account (Windows
//! cannot switch users without credentials).

use super::{Chunk, windows_command_line};
use crate::Config;
use crate::conn::{SpawnRequest, WinSize};
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::ManuallyDrop;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{NonNull, null, null_mut};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

type Handle = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct Coord {
    x: i16,
    y: i16,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct StartupInfoExW {
    startup_info: StartupInfoW,
    attribute_list: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: Handle,
}

impl Overlapped {
    const ZERO: Self = Self {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: null_mut(),
    };
}

/// `PTP_WIN32_IO_CALLBACK`.
type IoCallback = unsafe extern "system" fn(
    instance: *mut c_void,
    context: *mut c_void,
    overlapped: *mut c_void,
    result: u32,
    transferred: usize,
    io: Handle,
);

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreatePseudoConsole(
        size: Coord,
        input: Handle,
        output: Handle,
        flags: u32,
        console: *mut Handle,
    ) -> i32;
    fn ResizePseudoConsole(console: Handle, size: Coord) -> i32;
    fn ClosePseudoConsole(console: Handle);
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: u32,
        flags: u32,
        size: *mut usize,
    ) -> i32;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: u32,
        attribute: usize,
        value: *const c_void,
        size: usize,
        previous: *mut c_void,
        returned: *mut usize,
    ) -> i32;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateProcessW(
        application: *const u16,
        command_line: *mut u16,
        process_attributes: *const c_void,
        thread_attributes: *const c_void,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoW,
        information: *mut ProcessInformation,
    ) -> i32;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: Handle, code: *mut u32) -> i32;
    fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
    fn TerminateJobObject(job: Handle, code: u32) -> i32;
    fn SetHandleInformation(handle: Handle, mask: u32, flags: u32) -> i32;
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_timeout: u32,
        security_attributes: *const c_void,
    ) -> Handle;
    fn WriteFile(
        file: Handle,
        buffer: *const u8,
        len: u32,
        written: *mut u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn GetOverlappedResult(
        file: Handle,
        overlapped: *const Overlapped,
        transferred: *mut u32,
        wait: i32,
    ) -> i32;
    fn CancelIoEx(file: Handle, overlapped: *const Overlapped) -> i32;
    fn SetFileCompletionNotificationModes(file: Handle, flags: u8) -> i32;
    fn CreateThreadpoolIo(
        file: Handle,
        callback: IoCallback,
        context: *mut c_void,
        environment: *const c_void,
    ) -> Handle;
    fn StartThreadpoolIo(io: Handle);
    fn CancelThreadpoolIo(io: Handle);
    fn WaitForThreadpoolIoCallbacks(io: Handle, cancel_pending: i32);
    fn CloseThreadpoolIo(io: Handle);
}

#[link(name = "bcryptprimitives", kind = "raw-dylib")]
unsafe extern "system" {
    fn ProcessPrng(data: *mut u8, len: usize) -> i32;
}

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;
const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
const INFINITE: u32 = u32::MAX;
const WAIT_FAILED: u32 = u32::MAX;
const ERROR_BROKEN_PIPE: i32 = 109;
const ERROR_IO_INCOMPLETE: i32 = 996;
const ERROR_IO_PENDING: i32 = 997;
const INVALID_HANDLE_VALUE: Handle = std::ptr::without_provenance_mut(usize::MAX);
const PIPE_ACCESS_OUTBOUND: u32 = 0x0000_0002;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// With the byte type, byte read mode and blocking wait mode, which are zero.
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
const FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: u8 = 0x01;
/// The pipe buffer size, which tokio's named pipes use as well.
const PIPE_BUFFER: u32 = 65_536;
/// The most input passed to the process in one write.
const INPUT_CHUNK: usize = 64 * 1024;

/// Fills `buf` from the system CSPRNG.
pub(crate) fn os_random(buf: &mut [u8]) -> io::Result<()> {
    // SAFETY: ProcessPrng writes exactly `len` bytes and cannot fail.
    unsafe { ProcessPrng(buf.as_mut_ptr(), buf.len()) };
    Ok(())
}

fn coord(size: WinSize) -> Coord {
    let clamp = |v: u16| i16::try_from(v.max(1)).unwrap_or(i16::MAX);
    Coord {
        x: clamp(size.cols),
        y: clamp(size.rows),
    }
}

/// The size of a terminal whose request leaves it unspecified.
const DEFAULT_SIZE: WinSize = WinSize {
    cols: 80,
    rows: 24,
    width: 0,
    height: 0,
};

/// A unique name for a session pipe.
fn pipe_name() -> io::Result<String> {
    let mut id = [0u8; 16];
    os_random(&mut id)?;
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(r"\\.\pipe\tinyssh-{hex}"))
}

/// A pipe for output from the child: our end is a tokio named pipe, the
/// child's a synchronous handle.
async fn output_pipe() -> io::Result<(NamedPipeServer, File)> {
    let name = pipe_name()?;
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(1)
        .reject_remote_clients(true)
        .access_inbound(true)
        .access_outbound(false)
        .create(&name)?;
    let client = OpenOptions::new().write(true).open(&name)?;
    server.connect().await?;
    Ok((server, client))
}

/// A pipe for input to the child: our end is a [`Writer`], the child's a
/// synchronous handle. Opening the child's end connects the pipe.
fn input_pipe() -> io::Result<(Writer, File)> {
    let name = pipe_name()?;
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // SAFETY: the name is NUL-terminated; default security attributes.
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            null(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle that we now own.
    let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
    let client = OpenOptions::new().read(true).open(&name)?;
    Ok((Writer::new(pipe)?, client))
}

/// Owned pseudoconsole handle, and its current size.
pub(crate) struct PseudoConsole {
    handle: Handle,
    size: WinSize,
}

/// A pseudoconsole handle on its way to a blocking thread, which closes it
/// with [`close`](Self::close). If that never happens (shutdown can discard a
/// blocking task before it starts), dropping it closes the handle on a
/// thread of its own.
///
/// Never on the executor: before Windows 11 24H2, closing waits for the
/// final output to be read, which the task that drains it (see
/// `Output::exited`) then could not do.
struct RawConsole(Handle);

// SAFETY: pseudoconsole handles may be used from any thread.
unsafe impl Send for PseudoConsole {}
// SAFETY: as above.
unsafe impl Send for RawConsole {}

impl PseudoConsole {
    fn resize(&mut self, size: WinSize) {
        self.size = self.size.apply(size);
        // SAFETY: `self.handle` is a live pseudoconsole.
        unsafe { ResizePseudoConsole(self.handle, coord(self.size)) };
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        let raw = RawConsole(self.handle);
        // ClosePseudoConsole may block until conhost's final output has been
        // read, so it must not run on the async executor. Off the runtime
        // the whole `Output` is being dropped, its pipe (declared first)
        // already closed, so nothing waits for a reader.
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => drop(runtime.spawn_blocking(move || raw.close())),
            Err(_) => raw.close(),
        }
    }
}

impl RawConsole {
    fn close(self) {
        let raw = ManuallyDrop::new(self);
        // SAFETY: the handle is live, and with `Drop` skipped closed once.
        unsafe { ClosePseudoConsole(raw.0) };
    }
}

impl Drop for RawConsole {
    fn drop(&mut self) {
        // If no thread can start, the console is left open rather than
        // closed here, where it could wait forever (see above); the copy is
        // not dropped, so there is no recursion.
        let raw = ManuallyDrop::new(Self(self.0));
        let _ = std::thread::Builder::new().spawn(move || ManuallyDrop::into_inner(raw).close());
    }
}

/// A process thread attribute list (`STARTUPINFOEXW::lpAttributeList`).
struct Attributes(Vec<usize>);

impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0usize;
        // SAFETY: a null list queries the required size (and "fails").
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        let words = size.div_ceil(size_of::<usize>()).max(1);
        let mut list = Self(vec![0usize; words]);
        // SAFETY: the buffer is at least `size` bytes and pointer-aligned.
        if unsafe { InitializeProcThreadAttributeList(list.ptr(), count, 0, &mut size) } == 0 {
            list.0.clear();
            return Err(io::Error::last_os_error());
        }
        Ok(list)
    }

    /// Adds an attribute.
    ///
    /// # Safety
    ///
    /// `value` must stay valid until the list is dropped: Windows keeps the
    /// pointer, not a copy.
    unsafe fn set(
        &mut self,
        attribute: usize,
        value: *const c_void,
        size: usize,
    ) -> io::Result<()> {
        // SAFETY: the list is initialized; the caller keeps `value` alive.
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.ptr(),
                0,
                attribute,
                value,
                size,
                null_mut(),
                null_mut(),
            )
        };
        match ok {
            0 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }

    fn ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            // SAFETY: the list was initialized.
            unsafe { DeleteProcThreadAttributeList(self.ptr()) };
        }
    }
}

/// A job object that groups every process of one session.
fn new_job() -> io::Result<OwnedHandle> {
    // SAFETY: default security attributes and no name.
    let job = unsafe { CreateJobObjectW(null(), null()) };
    match job.is_null() {
        true => Err(io::Error::last_os_error()),
        // SAFETY: a fresh handle that we now own.
        false => Ok(unsafe { OwnedHandle::from_raw_handle(job) }),
    }
}

/// Marks a pipe end inheritable so it can become a child's std handle.
fn inheritable(file: &File) -> io::Result<Handle> {
    let handle = file.as_raw_handle();
    // SAFETY: `handle` is owned by `file` and therefore valid.
    match unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(handle),
    }
}

/// What the child's standard handles are connected to.
enum ChildIo<'a> {
    Console(&'a PseudoConsole),
    /// Inheritable stdin, stdout and stderr pipe ends.
    Pipes([Handle; 3]),
}

/// Starts `command_line` inside `job` (which then also holds every process
/// it starts), attached to a pseudoconsole or to pipes.
fn create_process(
    command_line: &str,
    job: &OwnedHandle,
    io: ChildIo<'_>,
) -> io::Result<OwnedHandle> {
    // The attribute list refers to these arrays, so they must outlive it.
    let jobs = [job.as_raw_handle()];
    let (std_handles, inherit, flags) = match io {
        // Invalid std handles keep a ConPTY child from inheriting ours (for
        // example when the server's output is redirected to a log).
        ChildIo::Console(_) => ([INVALID_HANDLE_VALUE; 3], 0, EXTENDED_STARTUPINFO_PRESENT),
        ChildIo::Pipes(handles) => (handles, 1, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW),
    };
    let mut attributes = Attributes::new(2)?;
    // SAFETY: `jobs` and `std_handles` outlive `attributes`; the
    // pseudoconsole attribute takes the HPCON value itself.
    unsafe {
        attributes.set(
            PROC_THREAD_ATTRIBUTE_JOB_LIST,
            jobs.as_ptr().cast(),
            size_of_val(&jobs),
        )?;
        match io {
            ChildIo::Console(console) => attributes.set(
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                console.handle.cast_const(),
                size_of::<Handle>(),
            )?,
            // Inherit exactly the three pipe ends and nothing else.
            ChildIo::Pipes(_) => attributes.set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                std_handles.as_ptr().cast(),
                size_of_val(&std_handles),
            )?,
        }
    }
    let [std_input, std_output, std_error] = std_handles;
    let startup = StartupInfoExW {
        startup_info: StartupInfoW {
            cb: u32::try_from(size_of::<StartupInfoExW>()).unwrap_or(u32::MAX),
            reserved: null_mut(),
            desktop: null_mut(),
            title: null_mut(),
            x: 0,
            y: 0,
            x_size: 0,
            y_size: 0,
            x_count_chars: 0,
            y_count_chars: 0,
            fill_attribute: 0,
            flags: STARTF_USESTDHANDLES,
            show_window: 0,
            reserved2_len: 0,
            reserved2: null_mut(),
            std_input,
            std_output,
            std_error,
        },
        attribute_list: attributes.ptr(),
    };
    let mut command_line: Vec<u16> = command_line.encode_utf16().chain([0]).collect();
    let mut info = ProcessInformation {
        process: null_mut(),
        thread: null_mut(),
        process_id: 0,
        thread_id: 0,
    };
    // SAFETY: all pointers are valid for the duration of the call; the
    // command line buffer is mutable and NUL-terminated as required.
    let ok = unsafe {
        CreateProcessW(
            null(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            inherit,
            flags,
            null(),
            null(),
            (&raw const startup).cast(),
            &mut info,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateProcessW returned fresh handles that we now own.
    drop(unsafe { OwnedHandle::from_raw_handle(info.thread) });
    Ok(unsafe { OwnedHandle::from_raw_handle(info.process) })
}

/// The session's process.
pub(crate) struct Process {
    pub(crate) input: Input,
    pub(crate) output: Output,
    pub(crate) waiter: Waiter,
    job: OwnedHandle,
}

impl Process {
    /// Starts the shell or `exec` command for `req`.
    pub(crate) async fn spawn(req: &SpawnRequest<'_>, config: &Config) -> io::Result<Self> {
        let shell = config
            .shell
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("COMSPEC").ok())
            .unwrap_or_else(|| "cmd.exe".into());
        let command_line = windows_command_line(&shell, req.command);
        let job = new_job()?;
        let (input, output, process) = match &req.pty {
            Some(pty) => {
                let (input, input_client) = input_pipe()?;
                let (output, output_client) = output_pipe().await?;
                let size = DEFAULT_SIZE.apply(pty.size);
                let mut console = null_mut();
                // SAFETY: both handles are valid synchronous pipe ends;
                // conhost duplicates them, so ours can be closed afterwards.
                let hr = unsafe {
                    CreatePseudoConsole(
                        coord(size),
                        input_client.as_raw_handle(),
                        output_client.as_raw_handle(),
                        0,
                        &mut console,
                    )
                };
                if hr < 0 {
                    return Err(io::Error::other(format!(
                        "CreatePseudoConsole failed: {hr:#x}"
                    )));
                }
                let console = PseudoConsole {
                    handle: console,
                    size,
                };
                drop((input_client, output_client));
                let process = create_process(&command_line, &job, ChildIo::Console(&console))?;
                let input = Input {
                    pipe: Some(input),
                    pty: true,
                };
                (
                    input,
                    Output::Pty {
                        pipe: output,
                        console: Some(console),
                    },
                    process,
                )
            }
            None => {
                let (stdin, stdin_client) = input_pipe()?;
                let (stdout, stdout_client) = output_pipe().await?;
                let (stderr, stderr_client) = output_pipe().await?;
                let handles = [
                    inheritable(&stdin_client)?,
                    inheritable(&stdout_client)?,
                    inheritable(&stderr_client)?,
                ];
                let process = create_process(&command_line, &job, ChildIo::Pipes(handles))?;
                // The child has its own copies now.
                drop((stdin_client, stdout_client, stderr_client));
                let input = Input {
                    pipe: Some(stdin),
                    pty: false,
                };
                let output = Output::Pipes {
                    stdout: Some(stdout),
                    stderr: Some(stderr),
                };
                (input, output, process)
            }
        };
        Ok(Self {
            input,
            output,
            waiter: Waiter::new(process),
            job,
        })
    }

    /// Applies a `window-change` request.
    pub(crate) fn resize(&mut self, size: WinSize) {
        if let Output::Pty {
            console: Some(console),
            ..
        } = &mut self.output
        {
            console.resize(size);
        }
    }

    /// Ends a session that ran to completion. On Windows this, too,
    /// terminates the job (see `Drop`).
    pub(crate) fn finish(self) {
        drop(self);
    }

    /// Terminates the session (see `Drop`).
    pub(crate) fn hangup(self) {
        drop(self);
    }
}

impl Drop for Process {
    /// Terminates the session: every process in its job, including anything
    /// the shell started. Dropping rather than an explicit call also covers a
    /// cancelled connection.
    fn drop(&mut self) {
        // SAFETY: the job handle is live.
        unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) };
    }
}

/// Writing side.
pub(crate) struct Input {
    pipe: Option<Writer>,
    pty: bool,
}

impl Input {
    pub(crate) fn is_open(&self) -> bool {
        self.pipe.is_some()
    }

    /// See [`Writer::write`].
    pub(crate) async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match &mut self.pipe {
            Some(pipe) => pipe.write(data).await,
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    /// Client EOF closes the stdin pipe; a terminal ignores it.
    pub(crate) fn close(&mut self) {
        if !self.pty {
            self.pipe = None;
        }
    }

    pub(crate) fn broken(&mut self) {
        self.pipe = None;
    }
}

/// Our end of the pipe for the process's input.
///
/// tokio's named pipes (mio's) copy each write into a pooled buffer but drop
/// that buffer when the write completes at once, so nearly every write
/// allocates. This one writes from a fixed buffer with overlapped I/O, and
/// the system thread pool reports writes that have to wait for the process.
struct Writer {
    /// Closed before `io`, as `CloseThreadpoolIo` requires.
    pipe: OwnedHandle,
    io: PoolIo,
    buf: Vec<u8>,
    /// A write was started and its result not yet collected.
    in_flight: bool,
}

impl Writer {
    fn new(pipe: OwnedHandle) -> io::Result<Self> {
        let io = PoolIo::new(&pipe)?;
        Ok(Self {
            pipe,
            io,
            buf: vec![0; INPUT_CHUNK],
            in_flight: false,
        })
    }

    /// Writes from `data`, returning how much of it the pipe took.
    ///
    /// Cancel-safe the way the driver needs: a write keeps going when the
    /// future is dropped and the next call reports it, so that call must be
    /// given the same data (the driver passes the unconsumed stdin).
    async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if !self.in_flight {
            let n = data.len().min(self.buf.len());
            match (self.buf.get_mut(..n), data.get(..n)) {
                (Some(buf), Some(data)) if n > 0 => buf.copy_from_slice(data),
                // A zero-byte write would read as end of file to the process.
                _ => return Ok(0),
            }
            self.start(n)?;
        }
        loop {
            if let Some(result) = self.result() {
                self.in_flight = false;
                return result;
            }
            self.io.done().notified().await;
        }
    }

    /// Starts writing the first `len` bytes of the buffer.
    fn start(&mut self, len: usize) -> io::Result<()> {
        let overlapped = self.io.overlapped();
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        // SAFETY: no write is in flight, so nothing else uses the OVERLAPPED.
        // It and the buffer stay in place until the write is over (see
        // `Drop`).
        let error = unsafe {
            overlapped.write(Overlapped::ZERO);
            StartThreadpoolIo(self.io.raw);
            let ok = WriteFile(
                self.pipe.as_raw_handle(),
                self.buf.as_ptr(),
                len,
                null_mut(),
                overlapped,
            );
            (ok == 0).then(io::Error::last_os_error)
        };
        match error {
            Some(e) if e.raw_os_error() == Some(ERROR_IO_PENDING) => {}
            // Finished or failed at once: no callback follows.
            error => {
                // SAFETY: cancels the notification started above.
                unsafe { CancelThreadpoolIo(self.io.raw) };
                if let Some(e) = error {
                    return Err(e);
                }
            }
        }
        self.in_flight = true;
        Ok(())
    }

    /// The result of the write in flight, or `None` while it lasts.
    fn result(&self) -> Option<io::Result<usize>> {
        let mut written = 0u32;
        // SAFETY: the OVERLAPPED of the write in flight on this handle.
        let ok = unsafe {
            GetOverlappedResult(
                self.pipe.as_raw_handle(),
                self.io.overlapped(),
                &mut written,
                0,
            )
        };
        if ok != 0 {
            return Some(Ok(written as usize));
        }
        let e = io::Error::last_os_error();
        (e.raw_os_error() != Some(ERROR_IO_INCOMPLETE)).then_some(Err(e))
    }
}

impl Drop for Writer {
    /// A write in flight is canceled and waited for: the kernel must be done
    /// with the buffer and the OVERLAPPED before they are freed.
    fn drop(&mut self) {
        if self.in_flight {
            let mut written = 0u32;
            let overlapped = self.io.overlapped();
            // SAFETY: the handle is open and the OVERLAPPED is the write's.
            unsafe {
                CancelIoEx(self.pipe.as_raw_handle(), overlapped);
                GetOverlappedResult(self.pipe.as_raw_handle(), overlapped, &mut written, 1);
            }
        }
    }
}

/// A handle's binding to the system thread pool, which wakes `done` when an
/// overlapped operation on the handle completes asynchronously. It also
/// holds the OVERLAPPED for those operations (one at a time); both stay at
/// a fixed address until the binding is closed.
struct PoolIo {
    raw: Handle,
    state: NonNull<IoState>,
}

struct IoState {
    overlapped: UnsafeCell<Overlapped>,
    done: Notify,
}

// SAFETY: thread pool objects may be used from any thread, and the callback
// touches only `done`, which is `Sync`.
unsafe impl Send for PoolIo {}

impl PoolIo {
    /// Binds `handle`. Operations that complete at once get no callback.
    fn new(handle: &OwnedHandle) -> io::Result<Self> {
        // SAFETY: a live handle.
        let ok = unsafe {
            SetFileCompletionNotificationModes(
                handle.as_raw_handle(),
                FILE_SKIP_COMPLETION_PORT_ON_SUCCESS,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let state = NonNull::from(Box::leak(Box::new(IoState {
            overlapped: UnsafeCell::new(Overlapped::ZERO),
            done: Notify::new(),
        })));
        // SAFETY: the callback's context, `done`, lives until the binding is
        // closed (see `Drop`).
        let raw = unsafe {
            let done = &raw const (*state.as_ptr()).done;
            CreateThreadpoolIo(
                handle.as_raw_handle(),
                io_done,
                done.cast_mut().cast(),
                null(),
            )
        };
        if raw.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: allocated above and never shared.
            drop(unsafe { Box::from_raw(state.as_ptr()) });
            return Err(e);
        }
        Ok(Self { raw, state })
    }

    fn overlapped(&self) -> *mut Overlapped {
        self.state().overlapped.get()
    }

    fn done(&self) -> &Notify {
        &self.state().done
    }

    fn state(&self) -> &IoState {
        // SAFETY: allocated in `new` and freed only on drop.
        unsafe { self.state.as_ref() }
    }
}

impl Drop for PoolIo {
    fn drop(&mut self) {
        // SAFETY: the owner waited for its last operation, so once the
        // callbacks already queued have run, nothing refers to the state.
        unsafe {
            WaitForThreadpoolIoCallbacks(self.raw, 0);
            CloseThreadpoolIo(self.raw);
            drop(Box::from_raw(self.state.as_ptr()));
        }
    }
}

/// Thread pool callback: an operation completed asynchronously.
unsafe extern "system" fn io_done(
    _instance: *mut c_void,
    context: *mut c_void,
    _overlapped: *mut c_void,
    _result: u32,
    _transferred: usize,
    _io: Handle,
) {
    // SAFETY: the context is the binding's `done`, which outlives the
    // binding's callbacks (see `PoolIo`).
    let done = unsafe { &*context.cast::<Notify>() };
    done.notify_one();
}

/// Reading side.
pub(crate) enum Output {
    Pty {
        pipe: NamedPipeServer,
        console: Option<PseudoConsole>,
    },
    Pipes {
        stdout: Option<NamedPipeServer>,
        stderr: Option<NamedPipeServer>,
    },
}

impl Output {
    /// Reads the next chunk of output into `buf`. Cancel-safe.
    pub(crate) async fn read(&mut self, buf: &mut [u8]) -> io::Result<Chunk> {
        match self {
            Self::Pty { pipe, .. } => loop {
                pipe.readable().await?;
                match read(pipe, buf) {
                    Ok(Some(0)) => return Ok(Chunk::Eof),
                    Ok(Some(n)) => return Ok(Chunk::Stdout(n)),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            },
            Self::Pipes { stdout, stderr } => loop {
                if stdout.is_none() && stderr.is_none() {
                    return Ok(Chunk::Eof);
                }
                let (is_stderr, pipe) = tokio::select! {
                    ready = readable(stdout.as_ref()) => (false, ready?),
                    ready = readable(stderr.as_ref()) => (true, ready?),
                };
                match read(pipe, buf) {
                    Ok(Some(0)) => {
                        *(if is_stderr {
                            &mut *stderr
                        } else {
                            &mut *stdout
                        }) = None
                    }
                    Ok(Some(n)) if is_stderr => return Ok(Chunk::Stderr(n)),
                    Ok(Some(n)) => return Ok(Chunk::Stdout(n)),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            },
        }
    }

    /// The process exited: closing the pseudoconsole flushes conhost's last
    /// output and then ends the output pipe.
    pub(crate) fn exited(&mut self) {
        if let Self::Pty { console, .. } = self
            && let Some(console) = console.take()
        {
            drop(console);
        }
    }
}

/// Non-blocking read: `Some(0)` at end of stream, `None` if nothing is ready.
fn read(pipe: &NamedPipeServer, buf: &mut [u8]) -> io::Result<Option<usize>> {
    match pipe.try_read(buf) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE) => Ok(Some(0)),
        Err(e) => Err(e),
    }
}

async fn readable(pipe: Option<&NamedPipeServer>) -> io::Result<&NamedPipeServer> {
    match pipe {
        Some(pipe) => pipe.readable().await.map(|()| pipe),
        None => std::future::pending().await,
    }
}

/// Waits for the process to exit.
pub(crate) struct Waiter(JoinHandle<io::Result<u32>>);

impl Waiter {
    fn new(process: OwnedHandle) -> Self {
        Self(tokio::task::spawn_blocking(move || {
            let handle = process.as_raw_handle();
            let mut code = 0u32;
            // SAFETY: `process` keeps the handle open for both calls.
            unsafe {
                if WaitForSingleObject(handle, INFINITE) == WAIT_FAILED
                    || GetExitCodeProcess(handle, &mut code) == 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(code)
        }))
    }

    pub(crate) async fn wait(&mut self) -> io::Result<u32> {
        (&mut self.0).await.map_err(io::Error::other)?
    }
}
