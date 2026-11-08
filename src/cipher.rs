//! `aes128-gcm@openssh.com` packet protection (RFC 5647 with OpenSSH's
//! amendments): the 4-byte `packet_length` travels in clear as associated
//! data, everything after it is encrypted, and a 16-byte tag follows. The
//! 12-byte nonce is a 4-byte fixed field plus a 64-bit invocation counter
//! that increments once per packet.
//!
//! AES-128-GCM itself is implemented in [`vaes`].

mod vaes;

use crate::Error;

/// Authentication tag length.
pub(crate) const TAG: usize = 16;
/// Cipher block size; `packet_length` must be a multiple of it.
pub(crate) const BLOCK: usize = 16;

/// Keys and nonce state for one direction.
pub(crate) struct Aead {
    gcm: vaes::Gcm,
    iv: [u8; 12],
}

impl Aead {
    pub(crate) fn new(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            gcm: vaes::Gcm::new(key),
            iv,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let nonce = self.iv;
        if let Some(counter) = self.iv.last_chunk_mut::<8>() {
            *counter = u64::from_be_bytes(*counter).wrapping_add(1).to_be_bytes();
        }
        nonce
    }

    /// Encrypts `packet` = `length(4) || plaintext || tag space(16)` in place.
    pub(crate) fn seal(&mut self, packet: &mut [u8]) -> Result<(), Error> {
        let (aad, rest) = packet.split_at_mut_checked(4).ok_or(Error::Mac)?;
        let body_len = rest.len().checked_sub(TAG).ok_or(Error::Mac)?;
        let (body, tag_out) = rest.split_at_mut_checked(body_len).ok_or(Error::Mac)?;
        let tag_out = <&mut [u8; TAG]>::try_from(tag_out).map_err(|_| Error::Mac)?;
        let nonce = self.next_nonce();
        *tag_out = self.gcm.seal(&nonce, aad, body).ok_or(Error::Mac)?;
        Ok(())
    }

    /// Authenticates and decrypts `packet` = `length(4) || ciphertext || tag`
    /// in place.
    pub(crate) fn open(&mut self, packet: &mut [u8]) -> Result<(), Error> {
        let (aad, rest) = packet.split_at_mut_checked(4).ok_or(Error::Mac)?;
        let body_len = rest.len().checked_sub(TAG).ok_or(Error::Mac)?;
        let (body, tag) = rest.split_at_mut_checked(body_len).ok_or(Error::Mac)?;
        let tag = <[u8; TAG]>::try_from(&*tag).map_err(|_| Error::Mac)?;
        let nonce = self.next_nonce();
        match self.gcm.open(&nonce, aad, body, &tag) {
            true => Ok(()),
            false => Err(Error::Mac),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Aead, TAG};
    use aes_gcm::aead::array::Array;
    use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};

    /// Packets match `aes-gcm` with OpenSSH's framing: the length field as
    /// associated data and the invocation counter in the nonce's last 8
    /// bytes, starting from the derived IV.
    #[test]
    fn packets_match_aes_gcm() {
        let (key, iv) = ([0x42; 16], [0xA5; 12]);
        let (mut tx, mut rx) = (Aead::new(&key, iv), Aead::new(&key, iv));
        let reference = Aes128Gcm::new(&Array::from(key));
        for (i, len) in [16, 32, 48, 256, 4096, 32_784].into_iter().enumerate() {
            let mut packet: Vec<u8> = (0..4 + len + TAG).map(|j| (j * 7) as u8).collect();
            let plain = packet.clone();
            tx.seal(&mut packet).unwrap();

            let mut nonce = iv;
            let counter = u64::from_be_bytes(nonce[4..].try_into().unwrap()) + i as u64;
            nonce[4..].copy_from_slice(&counter.to_be_bytes());
            let mut expected = plain.clone();
            let (aad, rest) = expected.split_at_mut(4);
            let (body, tag) = rest.split_at_mut(len);
            let t = reference
                .encrypt_inout_detached(&Array::from(nonce), aad, body.into())
                .unwrap();
            tag.copy_from_slice(&t);
            assert_eq!(packet, expected, "packet {i}");

            rx.open(&mut packet).unwrap();
            assert_eq!(packet[..4 + len], plain[..4 + len]);
        }
    }
}
