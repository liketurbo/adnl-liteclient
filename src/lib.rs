use base64::{engine::general_purpose, Engine as _};

pub mod client;
pub mod connection;
pub mod datagram;
pub mod tl_types;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;
pub type AesCipher = ctr::Ctr128BE<aes::Aes256>;

pub trait ToBytes {
    fn to_bytes(&self) -> Result<[u8; 32]>;
}

impl ToBytes for &str {
    fn to_bytes(&self) -> Result<[u8; 32]> {
        let bytes: [u8; 32] = general_purpose::STANDARD
            .decode(self)
            .map_err(|_| "invalid base64")?
            .try_into()
            .map_err(|_| "invalid byte array size")?;
        Ok(bytes)
    }
}

impl ToBytes for String {
    fn to_bytes(&self) -> Result<[u8; 32]> {
        self.as_str().to_bytes()
    }
}
