//! Randomness from the operating system and secret hygiene.

use crate::Error;

/// Fills `buf` with cryptographically secure random bytes from the OS.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), Error> {
    crate::sys::os_random(buf).map_err(Error::Io)
}

/// Returns `N` random bytes.
pub(crate) fn array<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0; N];
    fill(&mut out)?;
    Ok(out)
}

/// A small reserve of OS randomness for packet padding, so sending a packet
/// does not cost a system call.
pub(crate) struct Pool {
    buf: [u8; 256],
    used: usize,
}

impl Pool {
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; 256],
            used: 256,
        }
    }

    pub(crate) fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for byte in out {
            if self.used >= self.buf.len() {
                fill(&mut self.buf)?;
                self.used = 0;
            }
            *byte = self.buf.get(self.used).copied().unwrap_or_default();
            self.used = self.used.saturating_add(1);
        }
        Ok(())
    }
}

/// Overwrites secret material with zeros in a way the optimizer cannot elide.
pub(crate) fn wipe<T: Copy + Default>(buf: &mut [T]) {
    for item in buf.iter_mut() {
        // SAFETY: `item` is a valid, exclusive reference.
        unsafe { core::ptr::write_volatile(item, T::default()) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
