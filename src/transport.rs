//! Binary packet protocol (RFC 4253 §6): framing, padding, sequence numbers
//! and in-place AEAD over caller-provided fixed buffers.

use crate::Error;
use crate::cipher::{Aead, BLOCK, TAG};
use crate::rng::Pool;
use crate::wire::{Buf, Res};
use core::ops::Range;

/// Largest `packet_length` accepted (RFC 4253 §6.1 requires 35000 bytes).
pub(crate) const MAX_PACKET: usize = 35_000;
/// Largest packet on the wire: length field, `packet_length` bytes, tag.
const MAX_WIRE_PACKET: usize = 4 + MAX_PACKET + TAG;
/// Longest identification line, including CR LF (RFC 4253 §4.2).
const MAX_LINE: usize = 255;
/// Block size before encryption is enabled.
const PLAIN_BLOCK: usize = 8;
/// Bytes a packet adds around its payload, at most: length, padding length,
/// up to 19 bytes of padding and the tag.
pub(crate) const OVERHEAD: usize = 4 + 1 + 4 + BLOCK - 1 + TAG;

/// Per-direction packet counters and keys.
pub(crate) struct Keys {
    pub(crate) aead: Option<Aead>,
    /// Sequence number of the next packet.
    pub(crate) seq: u32,
    /// Bytes and packets since the last NEWKEYS (rekey accounting).
    pub(crate) bytes: u64,
    pub(crate) packets: u64,
}

impl Keys {
    pub(crate) const fn new() -> Self {
        Self {
            aead: None,
            seq: 0,
            bytes: 0,
            packets: 0,
        }
    }

    /// Switches to new keys after NEWKEYS; strict KEX also resets `seq`.
    /// Installs the keys in `next` by swapping them with the current ones,
    /// which `next` then holds (to be wiped when it is dropped).
    pub(crate) fn install_swap(&mut self, next: &mut Option<Aead>, reset_seq: bool) {
        core::mem::swap(&mut self.aead, next);
        self.bytes = 0;
        self.packets = 0;
        if reset_seq {
            self.seq = 0;
        }
    }

    pub(crate) fn install(&mut self, aead: Aead, reset_seq: bool) {
        self.aead = Some(aead);
        self.bytes = 0;
        self.packets = 0;
        if reset_seq {
            self.seq = 0;
        }
    }

    fn count(&mut self, total: usize) {
        self.seq = self.seq.wrapping_add(1);
        self.packets = self.packets.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(total).unwrap_or(u64::MAX));
    }
}

/// Receive buffer: raw socket bytes in, decrypted payloads out.
pub(crate) struct RxBuf<'a> {
    buf: &'a mut [u8],
    start: usize,
    end: usize,
}

impl<'a> RxBuf<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            start: 0,
            end: 0,
        }
    }

    /// Free space for socket reads. Unprocessed bytes (at most a partial
    /// packet) are moved to the front only once the space behind them could
    /// no longer hold a whole packet, so most reads copy nothing.
    pub(crate) fn space(&mut self) -> &mut [u8] {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.buf.len().saturating_sub(self.end) < MAX_WIRE_PACKET
            && self.start > 0
            && self.start <= self.end
            && self.end <= self.buf.len()
        {
            self.buf.copy_within(self.start..self.end, 0);
            self.end = self.end.saturating_sub(self.start);
            self.start = 0;
        }
        self.buf.get_mut(self.end..).unwrap_or_default()
    }

    pub(crate) fn has_space(&self) -> bool {
        self.end.saturating_sub(self.start) < self.buf.len()
    }

    pub(crate) fn filled(&mut self, n: usize) {
        self.end = self.end.saturating_add(n).min(self.buf.len());
    }

    pub(crate) fn get(&self, range: Range<usize>) -> &[u8] {
        self.buf.get(range).unwrap_or_default()
    }

    fn pending(&self) -> &[u8] {
        self.buf.get(self.start..self.end).unwrap_or_default()
    }

    /// Takes the peer's identification line, without CR LF.
    pub(crate) fn line(&mut self) -> Result<Option<Range<usize>>, Error> {
        let pending = self.pending();
        let Some(newline) = pending.iter().take(MAX_LINE).position(|&b| b == b'\n') else {
            return match pending.len() >= MAX_LINE {
                true => Err(Error::Protocol("identification line too long")),
                false => Ok(None),
            };
        };
        let line = pending.get(..newline).unwrap_or_default();
        let len = line.strip_suffix(b"\r").unwrap_or(line).len();
        let start = self.start;
        self.start = start.saturating_add(newline).saturating_add(1);
        Ok(Some(start..start.saturating_add(len)))
    }

    /// Authenticates and decrypts the next complete packet in place and
    /// returns the range of its payload, or `None` if more bytes are needed.
    pub(crate) fn packet(&mut self, keys: &mut Keys) -> Result<Option<Range<usize>>, Error> {
        let Some(&head) = self.pending().first_chunk::<4>() else {
            return Ok(None);
        };
        let len = usize::try_from(u32::from_be_bytes(head)).unwrap_or(usize::MAX);
        let (aligned, tag) = match keys.aead {
            Some(_) => (len.checked_rem(BLOCK) == Some(0), TAG),
            None => (
                len.checked_add(4).and_then(|n| n.checked_rem(PLAIN_BLOCK)) == Some(0),
                0,
            ),
        };
        if !aligned || !(8..=MAX_PACKET).contains(&len) {
            return Err(Error::Protocol("bad packet length"));
        }
        let total = len.saturating_add(4).saturating_add(tag);
        if self.pending().len() < total {
            return Ok(None);
        }
        let start = self.start;
        let end = start.saturating_add(total);
        let packet = self
            .buf
            .get_mut(start..end)
            .ok_or(Error::Protocol("bad packet length"))?;
        if let Some(aead) = keys.aead.as_mut() {
            aead.open(packet)?;
        }
        let padding = usize::from(packet.get(4).copied().unwrap_or_default());
        let payload = len.checked_sub(padding).and_then(|n| n.checked_sub(1));
        let payload = payload.filter(|&n| n > 0 && padding >= 4);
        let payload = payload.ok_or(Error::Protocol("bad padding"))?;
        self.start = end;
        keys.count(total);
        let first = start.saturating_add(5);
        Ok(Some(first..first.saturating_add(payload)))
    }
}

/// Send buffer: packets are built, padded and encrypted in place.
pub(crate) struct TxBuf<'a> {
    buf: &'a mut [u8],
    sent: usize,
    end: usize,
    pad: Pool,
}

impl<'a> TxBuf<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            sent: 0,
            end: 0,
            pad: Pool::new(),
        }
    }

    /// Bytes waiting to be written to the socket.
    pub(crate) fn pending(&self) -> &[u8] {
        self.buf.get(self.sent..self.end).unwrap_or_default()
    }

    pub(crate) fn advance(&mut self, n: usize) {
        self.sent = self.sent.saturating_add(n).min(self.end);
        if self.sent == self.end {
            self.sent = 0;
            self.end = 0;
        }
    }

    /// Space available for new packets (after compaction).
    pub(crate) fn free(&self) -> usize {
        self.buf
            .len()
            .saturating_sub(self.end.saturating_sub(self.sent))
    }

    /// Returns where `need` bytes can be appended, compacting if necessary.
    fn reserve(&mut self, need: usize) -> Result<usize, Error> {
        if self.buf.len().saturating_sub(self.end) < need && self.sent > 0 {
            self.buf.copy_within(self.sent..self.end, 0);
            self.end = self.end.saturating_sub(self.sent);
            self.sent = 0;
        }
        match self.buf.len().saturating_sub(self.end) >= need {
            true => Ok(self.end),
            false => Err(Error::Protocol("send buffer exhausted")),
        }
    }

    /// Appends unframed bytes (the identification line).
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let at = self.reserve(bytes.len())?;
        let end = at.saturating_add(bytes.len());
        let dst = self
            .buf
            .get_mut(at..end)
            .ok_or(Error::Protocol("send buffer exhausted"))?;
        dst.copy_from_slice(bytes);
        self.end = end;
        Ok(())
    }

    /// Appends one packet whose payload (at most `max` bytes) is written by
    /// `body`.
    pub(crate) fn packet(
        &mut self,
        keys: &mut Keys,
        max: usize,
        body: impl FnOnce(&mut Buf<'_>) -> Res,
    ) -> Result<(), Error> {
        const FULL: Error = Error::Protocol("send buffer exhausted");
        let at = self.reserve(max.saturating_add(OVERHEAD))?;
        let region = self.buf.get_mut(at..).ok_or(FULL)?;
        let (header, rest) = region.split_at_mut_checked(5).ok_or(FULL)?;
        let payload = {
            let mut w = Buf::new(rest.get_mut(..max).ok_or(FULL)?);
            body(&mut w).map_err(|_| Error::Protocol("message too large"))?;
            w.len()
        };
        // AEAD: padding_length || payload || padding is a multiple of 16.
        // Plain: the whole packet including the length field is a multiple of 8.
        let (block, unpadded, tag) = match keys.aead {
            Some(_) => (BLOCK, payload.saturating_add(1), TAG),
            None => (PLAIN_BLOCK, payload.saturating_add(5), 0),
        };
        let mut padding = block.saturating_sub(unpadded.checked_rem(block).unwrap_or_default());
        if padding < 4 {
            padding = padding.saturating_add(block);
        }
        let length = payload.saturating_add(1).saturating_add(padding);
        let pad = rest
            .get_mut(payload..payload.saturating_add(padding))
            .ok_or(FULL)?;
        self.pad.fill(pad)?;
        let (len_field, pad_field) = header.split_at_mut_checked(4).ok_or(FULL)?;
        len_field.copy_from_slice(&u32::try_from(length).map_err(|_| FULL)?.to_be_bytes());
        pad_field.copy_from_slice(&[u8::try_from(padding).map_err(|_| FULL)?]);
        let total = length.saturating_add(4).saturating_add(tag);
        let packet = region.get_mut(..total).ok_or(FULL)?;
        if let Some(aead) = keys.aead.as_mut() {
            aead.seal(packet)?;
        }
        self.end = at.saturating_add(total);
        keys.count(total);
        Ok(())
    }
}
