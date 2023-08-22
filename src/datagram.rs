use crate::AesCipher;
use crate::Result;
use aes::cipher::StreamCipher;
use bytes::Buf;
use rand::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;

#[derive(Debug)]
pub enum DatagramKind {
    Empty,
    Data(Datagram),
}

fn get_buf_len(datagram_len: usize) -> usize {
    datagram_len - NONCE_LEN - HASH_LEN
}

impl DatagramKind {
    pub fn check(src: &Cursor<&[u8]>) -> bool {
        src.remaining() >= LENGTH_LEN + NONCE_LEN + HASH_LEN
    }

    pub fn parse(src: &mut Cursor<&[u8]>, decryptor: &mut AesCipher) -> Result<DatagramKind> {
        let mut length_bytes = [0u8; LENGTH_LEN];
        src.copy_to_slice(&mut length_bytes);
        decryptor.apply_keystream(&mut length_bytes);

        let len = u32::from_le_bytes(length_bytes) as usize;
        if len < NONCE_LEN + HASH_LEN {
            return Err("invalid datagram length".into());
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        src.copy_to_slice(&mut nonce_bytes);
        decryptor.apply_keystream(&mut nonce_bytes);

        if len == NONCE_LEN + HASH_LEN {
            let mut hash_bytes = [0u8; HASH_LEN];
            src.copy_to_slice(&mut hash_bytes);
            decryptor.apply_keystream(&mut hash_bytes);

            let nonce_hash = Sha256::new().chain_update(&nonce_bytes).finalize();
            if nonce_hash[..] != hash_bytes[..] {
                return Err("corrupted datagram".into());
            }

            return Ok(DatagramKind::Empty);
        }

        let mut buf = [0u8; BUFFER_LEN];
        let mut buf_data = &mut buf[..get_buf_len(len)];
        src.copy_to_slice(&mut buf_data);
        decryptor.apply_keystream(&mut buf_data);

        let mut hash_bytes = [0u8; HASH_LEN];
        src.copy_to_slice(&mut hash_bytes);
        decryptor.apply_keystream(&mut hash_bytes);

        let datagram_hash = Sha256::new()
            .chain_update(&nonce_bytes)
            .chain_update(&buf_data)
            .finalize();

        if datagram_hash[..] != hash_bytes[..] {
            return Err("corrupted datagram".into());
        }

        Ok(DatagramKind::Data(Datagram::new(
            len,
            nonce_bytes,
            buf,
            hash_bytes,
        )))
    }
}

const LENGTH_LEN: usize = 4;
const NONCE_LEN: usize = 32;
const BUFFER_LEN: usize = 64;
const HASH_LEN: usize = 32;

/// Represents a Datagram for secure communication.
///
/// | Parameter  | Size              | Notes                                                     |
/// |------------|-------------------|-----------------------------------------------------------|
/// | `length`   | 4 bytes (LE)      | Length of the whole datagram, excluding the length field  |
/// | `nonce`    | 32 bytes          | Random value                                              |
/// | `buffer`   | length - 64 bytes | Actual data to be sent to the other side                  |
/// | `hash`     | 32 bytes          | SHA-256(nonce || buffer) to ensure integrity              |
///
/// More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#datagram.
#[derive(Debug)]
pub struct Datagram {
    pub length: usize,
    pub nonce: [u8; NONCE_LEN],
    pub buffer: [u8; BUFFER_LEN],
    pub hash: [u8; HASH_LEN],
}

impl Datagram {
    pub fn new(
        len: usize,
        nonce: [u8; NONCE_LEN],
        buf: [u8; BUFFER_LEN],
        hash: [u8; HASH_LEN],
    ) -> Self {
        let new_datagram = Datagram {
            length: len,
            nonce,
            buffer: buf,
            hash,
        };
        new_datagram
    }

    pub fn from_buf(buf: &[u8]) -> Result<Datagram> {
        let len = buf.len();

        if len > BUFFER_LEN {
            return Err("datagram size exceeded".into());
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut buf_bytes = [0u8; BUFFER_LEN];
        buf_bytes[..len].copy_from_slice(buf);

        let hash: [u8; HASH_LEN] = Sha256::new()
            .chain_update(&nonce_bytes)
            .chain_update(&buf)
            .finalize()
            .into();

        Ok(Datagram::new(
            NONCE_LEN + len + HASH_LEN,
            nonce_bytes,
            buf_bytes,
            hash,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(LENGTH_LEN + NONCE_LEN + BUFFER_LEN + HASH_LEN);

        bytes.extend_from_slice(&(self.length as u32).to_le_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.buffer[..get_buf_len(self.length)]);
        bytes.extend_from_slice(&self.hash);

        bytes
    }
}
