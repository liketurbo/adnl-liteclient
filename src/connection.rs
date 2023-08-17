use crate::Result;
use aes::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::MontgomeryPoint;
use rand::prelude::*;
use sha2::{Digest, Sha256};
use tokio::io::BufWriter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use x25519_dalek::{EphemeralSecret, PublicKey};

type Aes256Ctr128BE = ctr::Ctr128BE<aes::Aes256>;

pub(crate) struct InitConnection {
    stream: BufWriter<TcpStream>,
}

/// Get Key ID: SHA256 hash of serialized TL schema.
/// Common TL schemas and IDs:
///
/// - `pub.ed25519 key:int256 = PublicKey` -- ID c6b41348
/// - `pub.aes key:int256 = PublicKey` -- ID d4adbc2d
/// - `pub.overlay name:bytes = PublicKey` -- ID cb45ba34
/// - `pub.unenc data:bytes = PublicKey` -- ID 0a451fb6
/// - `pk.aes key:int256` = PrivateKey` -- ID 3751e8a5
///
/// More details: https://docs.ton.org/develop/network/adnl-tcp#getting-key-id
fn gen_key_id(key: &[u8; 32]) -> [u8; 32] {
    let prefix: [u8; 4] = [0xc6, 0xb4, 0x13, 0x48];
    Sha256::new()
        .chain_update(prefix)
        .chain_update(key)
        .finalize()
        .into()
}

/// Encrypt session parameters.
///
/// Hash, key, and nonce for AES-256 cipher in CTR mode with a 128-bit big-endian counter:
/// - `hash`: SHA-256(aes_params)
/// - `key`: secret[0..16] || hash[16..32]
/// - `nonce`: hash[0..4] || secret[20..32]
///
/// More details: https://docs.ton.org/learn/networking/low-level-adnl#handshake.
fn encrypt_aes_params(
    aes_params: &mut [u8; 160],
    aes_params_hash: &[u8; 32],
    shared_key: &[u8; 32],
) {
    let mut key = [0u8; 32];
    key[0..16].copy_from_slice(&shared_key[0..16]);
    key[16..32].copy_from_slice(&aes_params_hash[16..32]);

    let mut nonce = [0u8; 16];
    nonce[0..4].copy_from_slice(&aes_params_hash[0..4]);
    nonce[4..16].copy_from_slice(&shared_key[20..32]);

    let mut cipher = Aes256Ctr128BE::new(
        key.as_slice().try_into().unwrap(),
        nonce.as_slice().try_into().unwrap(),
    );
    cipher.apply_keystream(aes_params);
}

/// To perform x25519, the public key must be in x25519 format.
///
/// More details: https://docs.ton.org/learn/networking/low-level-adnl#public-key-cryptosystems-list
fn ed25519_to_x25519(ed25519_public_key: &[u8; 32]) -> Result<[u8; 32]> {
    let x25519_public_key = CompressedEdwardsY::from_slice(ed25519_public_key)?
        .decompress()
        .ok_or("decompression failed")?
        .to_montgomery();
    Ok(*x25519_public_key.as_bytes())
}

/// Public key must be transmitted over the network in ed25519 format
///
/// More details: https://docs.ton.org/learn/networking/low-level-adnl#public-key-cryptosystems-list
fn x25519_to_ed25519(x25519_public_key: &[u8; 32]) -> Result<[u8; 32]> {
    let ed25519_public_key = MontgomeryPoint(*x25519_public_key)
        .to_edwards(0)
        .ok_or("conversion failed")?
        .compress();
    Ok(*ed25519_public_key.as_bytes())
}

impl InitConnection {
    pub fn new(socket: TcpStream) -> Self {
        InitConnection {
            stream: BufWriter::new(socket),
        }
    }

    pub async fn handshake(mut self, receiver_public: &[u8; 32]) -> Result<EstablishedConnection> {
        let my_secret = EphemeralSecret::random();
        let my_public = PublicKey::from(&my_secret);
        let receiver_public_x25519 = PublicKey::from(ed25519_to_x25519(receiver_public)?);
        let shared_key = my_secret.diffie_hellman(&receiver_public_x25519);

        // Represents AES-CTR session parameters.
        //
        // | Parameter  | Size     |
        // |------------|----------|
        // | `rx_key`   | 32 bytes |
        // | `tx_key`   | 32 bytes |
        // | `rx_nonce` | 16 bytes |
        // | `tx_nonce` | 16 bytes |
        // | `padding`  | 64 bytes |
        //
        // More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#handshake.
        let mut aes_params = [0u8; 160];
        rand::thread_rng().fill_bytes(&mut aes_params);

        let rx_cipher = Aes256Ctr128BE::new(
            aes_params[0..32].try_into().unwrap(),
            aes_params[64..80].try_into().unwrap(),
        );
        let tx_cipher = Aes256Ctr128BE::new(
            aes_params[32..64].try_into().unwrap(),
            aes_params[80..96].try_into().unwrap(),
        );

        // Represents a 256-bytes handshake packet for secure communication.
        //
        // | Parameter             | Size      | Notes                                                          |
        // |-----------------------|-----------|----------------------------------------------------------------|
        // | `receiver_address`    | 32 bytes  | Server peer identity as described in the corresponding section |
        // | `sender_public`       | 32 bytes  | Client public key                                              |
        // | `sha256_aes_params`   | 32 bytes  | Integrity proof of session parameters using SHA-256            |
        // | `encrypted_aes_params`| 160 bytes | Encrypted session parameters using AES encryption              |
        //
        // More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#handshake.
        let key_id = gen_key_id(&receiver_public);
        self.stream.write(&key_id).await?;
        let my_public_ed25519 = x25519_to_ed25519(my_public.as_bytes())?;
        self.stream.write(&my_public_ed25519).await?;
        let aes_params_hash = Sha256::new().chain_update(aes_params).finalize();
        self.stream.write(&aes_params_hash).await?;
        encrypt_aes_params(
            &mut aes_params,
            &aes_params_hash.into(),
            shared_key.as_bytes(),
        );
        self.stream.write(&aes_params).await?;
        self.stream.flush().await?;

        let mut est_connection = EstablishedConnection {
            stream: self.stream,
            rx_cipher,
            tx_cipher,
        };

        let datagram = est_connection.receive().await?;

        match datagram {
            Datagram::Empty => return Ok(est_connection),
            _ => return Err("handshake not accepted".into()),
        }
    }
}

pub(crate) struct EstablishedConnection {
    stream: BufWriter<TcpStream>,
    rx_cipher: Aes256Ctr128BE,
    tx_cipher: Aes256Ctr128BE,
}

impl EstablishedConnection {
    pub async fn receive(&mut self) -> Result<Datagram> {
        // Represents a Datagram for secure communication.
        //
        // | Parameter  | Size              | Notes                                                     |
        // |------------|-------------------|-----------------------------------------------------------|
        // | `length`   | 4 bytes (LE)      | Length of the whole datagram, excluding the length field  |
        // | `nonce`    | 32 bytes          | Random value                                              |
        // | `buffer`   | length - 64 bytes | Actual data to be sent to the other side                  |
        // | `hash`     | 32 bytes          | SHA-256(nonce || buffer) to ensure integrity              |
        //
        // More information can be found in the https://docs.ton.org/learn/networking/low-level-adnl#datagram.
        let mut length_bytes = [0u8; 4];
        self.stream.read_exact(&mut length_bytes).await?;
        self.rx_cipher.apply_keystream(&mut length_bytes);

        let length = u32::from_le_bytes(length_bytes);
        if length < 64 {
            return Err("too short datagram".into());
        }

        let mut nonce_bytes = [0u8; 32];
        self.stream.read_exact(&mut nonce_bytes).await?;
        self.rx_cipher.apply_keystream(&mut nonce_bytes);

        if length == 64 {
            let mut hash_bytes = [0u8; 32];
            self.stream.read_exact(&mut hash_bytes).await?;
            self.rx_cipher.apply_keystream(&mut hash_bytes);

            let nonce_hash = Sha256::new().chain_update(&nonce_bytes).finalize();
            if nonce_hash[..] != hash_bytes[..] {
                return Err("corrupted datagram".into());
            }

            return Ok(Datagram::Empty);
        }

        return Err("didn't write the rest yet".into());
    }
}

pub enum Datagram {
    Empty,
}
