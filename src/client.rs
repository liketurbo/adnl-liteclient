use crate::connection::EstablishedConnection;
use crate::connection::InitConnection;
use crate::Result;
use base64::{engine::general_purpose, Engine as _};
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs as ToSocketAddr;

pub struct Client {
    connection: EstablishedConnection,
}

pub trait ToBytes {
    fn to_bytes(&self) -> Result<[u8; 32]>;
}

impl ToBytes for String {
    fn to_bytes(&self) -> Result<[u8; 32]> {
        let bytes: [u8; 32] = general_purpose::STANDARD
            .decode(self)
            .map_err(|_| "invalid base64")?
            .try_into()
            .map_err(|_| "invalid byte array size")?;
        Ok(bytes)
    }
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

impl Client {
    pub async fn connect<T: ToSocketAddr, S: ToBytes>(addr: T, public: S) -> Result<Client> {
        let socket = TcpStream::connect(addr).await?;
        let init_connection = InitConnection::new(socket);
        let est_connection = init_connection
            .handshake(&public.to_bytes().unwrap())
            .await?;
        Ok(Client {
            connection: est_connection,
        })
    }

    // In future I need to setup automatic generation from tl
    pub async fn ping(&mut self) -> Result<()> {
        let mut frame: Vec<u8> = vec![];
        frame.extend_from_slice(&76u32.to_le_bytes());
        frame.extend_from_slice(&vec![0u8; 32]);
        Ok(())
    }
}
