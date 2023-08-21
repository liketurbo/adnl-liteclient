pub mod client;
pub mod connection;
pub mod datagram;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;
pub type AesCipher = ctr::Ctr128BE<aes::Aes256>;
