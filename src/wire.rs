//! SSH wire encoding (RFC 4251 §5) on borrowed slices and fixed buffers.
//! Only `byte`, `boolean`, `uint32`, `string` and non-negative `mpint` are
//! needed. Nothing here allocates.

use crate::Error;
use crate::sha256::Sha256;

/// Message numbers (RFC 4250 §4.1).
pub(crate) mod msg {
    pub(crate) const DISCONNECT: u8 = 1;
    pub(crate) const IGNORE: u8 = 2;
    pub(crate) const UNIMPLEMENTED: u8 = 3;
    pub(crate) const DEBUG: u8 = 4;
    pub(crate) const SERVICE_REQUEST: u8 = 5;
    pub(crate) const SERVICE_ACCEPT: u8 = 6;
    pub(crate) const KEXINIT: u8 = 20;
    pub(crate) const NEWKEYS: u8 = 21;
    pub(crate) const KEX_ECDH_INIT: u8 = 30;
    pub(crate) const KEX_ECDH_REPLY: u8 = 31;
    pub(crate) const USERAUTH_REQUEST: u8 = 50;
    pub(crate) const USERAUTH_FAILURE: u8 = 51;
    pub(crate) const USERAUTH_SUCCESS: u8 = 52;
    pub(crate) const USERAUTH_PK_OK: u8 = 60;
    pub(crate) const GLOBAL_REQUEST: u8 = 80;
    pub(crate) const REQUEST_FAILURE: u8 = 82;
    pub(crate) const CHANNEL_OPEN: u8 = 90;
    pub(crate) const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub(crate) const CHANNEL_OPEN_FAILURE: u8 = 92;
    pub(crate) const CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub(crate) const CHANNEL_DATA: u8 = 94;
    pub(crate) const CHANNEL_EXTENDED_DATA: u8 = 95;
    pub(crate) const CHANNEL_EOF: u8 = 96;
    pub(crate) const CHANNEL_CLOSE: u8 = 97;
    pub(crate) const CHANNEL_REQUEST: u8 = 98;
    pub(crate) const CHANNEL_SUCCESS: u8 = 99;
    pub(crate) const CHANNEL_FAILURE: u8 = 100;
}

/// `SSH_MSG_DISCONNECT` reason codes (RFC 4253 §11.1).
pub(crate) mod reason {
    pub(crate) const PROTOCOL_ERROR: u32 = 2;
    pub(crate) const KEY_EXCHANGE_FAILED: u32 = 3;
    pub(crate) const MAC_ERROR: u32 = 5;
    pub(crate) const SERVICE_NOT_AVAILABLE: u32 = 7;
    pub(crate) const BY_APPLICATION: u32 = 11;
    pub(crate) const NO_MORE_AUTH_METHODS: u32 = 14;
}

const MALFORMED: Error = Error::Protocol("malformed message");

/// Cursor over a received message.
pub(crate) struct Msg<'a>(&'a [u8]);

impl<'a> Msg<'a> {
    pub(crate) fn new(payload: &'a [u8]) -> Self {
        Self(payload)
    }

    /// Bytes consumed so far, relative to `start`.
    pub(crate) fn offset_in(&self, start: &[u8]) -> usize {
        start.len().saturating_sub(self.0.len())
    }

    pub(crate) fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(MALFORMED)?;
        self.0 = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.bytes()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.bytes()?))
    }

    /// RFC 4251: any non-zero value is TRUE.
    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        Ok(self.u8()? != 0)
    }

    /// `string`: uint32 length followed by that many bytes.
    pub(crate) fn string(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::try_from(self.u32()?).map_err(|_| MALFORMED)?;
        let (head, rest) = self.0.split_at_checked(len).ok_or(MALFORMED)?;
        self.0 = rest;
        Ok(head)
    }

    /// A string that must be exactly `N` bytes long.
    pub(crate) fn fixed_string<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        <[u8; N]>::try_from(self.string()?).map_err(|_| MALFORMED)
    }

    pub(crate) fn end(&self) -> Result<(), Error> {
        match self.0.is_empty() {
            true => Ok(()),
            false => Err(MALFORMED),
        }
    }
}

/// Whether the comma-separated `list` contains `name`.
pub(crate) fn has_name(list: &[u8], name: &[u8]) -> bool {
    list.split(|&b| b == b',').any(|n| n == name)
}

/// The first entry of a comma-separated name-list.
pub(crate) fn first_name(list: &[u8]) -> &[u8] {
    list.split(|&b| b == b',').next().unwrap_or_default()
}

/// The encoded data does not fit (in the buffer, or in a uint32 length).
#[derive(Debug)]
pub(crate) struct Overflow;

pub(crate) type Res = Result<(), Overflow>;

/// Encoder over any byte sink (fixed buffers, hashes, length counters).
pub(crate) trait Put {
    /// Appends bytes as they are.
    fn put_raw(&mut self, bytes: &[u8]) -> Res;

    fn put_u8(&mut self, v: u8) -> Res {
        self.put_raw(&[v])
    }

    fn put_u32(&mut self, v: u32) -> Res {
        self.put_raw(&v.to_be_bytes())
    }

    fn put_bool(&mut self, v: bool) -> Res {
        self.put_u8(u8::from(v))
    }

    /// `string`: uint32 length followed by the bytes.
    fn put_string(&mut self, s: &[u8]) -> Res {
        self.put_u32(u32::try_from(s.len()).map_err(|_| Overflow)?)?;
        self.put_raw(s)
    }

    /// `mpint` of a non-negative big-endian integer: no leading zero bytes,
    /// plus one zero byte if the top bit is set.
    fn put_mpint(&mut self, be: &[u8]) -> Res {
        let skip = be.iter().take_while(|&&b| b == 0).count();
        let digits = be.get(skip..).unwrap_or_default();
        let pad = digits.first().is_some_and(|&b| b & 0x80 != 0);
        let len = digits.len().checked_add(usize::from(pad)).ok_or(Overflow)?;
        self.put_u32(u32::try_from(len).map_err(|_| Overflow)?)?;
        if pad {
            self.put_u8(0)?;
        }
        self.put_raw(digits)
    }
}

/// Bounded writer into a fixed slice.
pub(crate) struct Buf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Buf<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl Put for Buf<'_> {
    fn put_raw(&mut self, bytes: &[u8]) -> Res {
        let end = self.len.checked_add(bytes.len()).ok_or(Overflow)?;
        let dst = self.buf.get_mut(self.len..end).ok_or(Overflow)?;
        dst.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

/// Feeds encoded data straight into a SHA-256 computation.
pub(crate) struct Hash<'a>(pub(crate) &'a mut Sha256);

impl Put for Hash<'_> {
    fn put_raw(&mut self, bytes: &[u8]) -> Res {
        self.0.update(bytes);
        Ok(())
    }
}

/// Measures encoded length without storing anything.
pub(crate) struct Count(pub(crate) usize);

impl Put for Count {
    fn put_raw(&mut self, bytes: &[u8]) -> Res {
        self.0 = self.0.checked_add(bytes.len()).ok_or(Overflow)?;
        Ok(())
    }
}
