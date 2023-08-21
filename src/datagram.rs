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

impl DatagramKind {
    pub fn parse(src: &mut Cursor<&[u8]>, decryptor: &mut AesCipher) -> Result<DatagramKind> {
        let mut length_bytes = [0u8; 4];
        src.copy_to_slice(&mut length_bytes);
        decryptor.apply_keystream(&mut length_bytes);

        let len = u32::from_le_bytes(length_bytes);
        if len < 64 {
            return Err("invalid datagram length".into());
        }

        let mut nonce_bytes = [0u8; 32];
        src.copy_to_slice(&mut nonce_bytes);
        decryptor.apply_keystream(&mut nonce_bytes);

        if len == 64 {
            let mut hash_bytes = [0u8; 32];
            src.copy_to_slice(&mut hash_bytes);
            decryptor.apply_keystream(&mut hash_bytes);

            let nonce_hash = Sha256::new().chain_update(&nonce_bytes).finalize();
            if nonce_hash[..] != hash_bytes[..] {
                return Err("corrupted datagram".into());
            }

            return Ok(DatagramKind::Empty);
        }

        let mut buf = [0u8; 64];
        src.copy_to_bytes(len as usize).copy_to_slice(&mut buf);
        decryptor.apply_keystream(&mut buf[..len as usize]);

        let mut hash_bytes = [0u8; 32];
        src.copy_to_slice(&mut hash_bytes);
        decryptor.apply_keystream(&mut hash_bytes);

        let datagram_hash = Sha256::new()
            .chain_update(&nonce_bytes)
            .chain_update(&buf[..len as usize])
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
    pub length: u32,
    pub nonce: [u8; 32],
    pub buffer: [u8; 64],
    pub hash: [u8; 32],
}

impl Datagram {
    pub fn new(len: u32, nonce: [u8; 32], buf: [u8; 64], hash: [u8; 32]) -> Self {
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

        if len > 64 {
            return Err("datagram size exceeded".into());
        }

        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let mut buf_bytes = [0u8; 64];
        buf_bytes.clone_from_slice(buf);

        let hash: [u8; 32] = Sha256::new()
            .chain_update(&nonce_bytes)
            .chain_update(&buf_bytes)
            .finalize()
            .into();

        Ok(Datagram::new(len as u32, nonce_bytes, buf_bytes, hash))
    }

    pub fn to_enc_bytes(mut self, encryptor: &mut AesCipher) -> Vec<u8> {
        let mut enc_bytes = Vec::with_capacity(64);

        let mut length_bytes = self.length.to_le_bytes();
        encryptor.apply_keystream(&mut length_bytes);
        enc_bytes.extend_from_slice(&length_bytes);

        encryptor.apply_keystream(&mut self.nonce);
        enc_bytes.extend_from_slice(&self.nonce);

        encryptor.apply_keystream(&mut self.buffer[..self.length as usize]);
        enc_bytes.extend_from_slice(&self.buffer[..self.length as usize]);

        encryptor.apply_keystream(&mut self.hash);
        enc_bytes.extend_from_slice(&self.hash);

        enc_bytes
    }
}
