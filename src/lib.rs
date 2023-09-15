mod client;
mod tl_types;

pub use client::Client;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;
