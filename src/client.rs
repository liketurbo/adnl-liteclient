use std::io::Cursor;

use crate::connection::EstablishedConnection;
use crate::connection::InitConnection;
use crate::datagram::Datagram;
use crate::datagram::DatagramKind;
use crate::Result;
use base64::{engine::general_purpose, Engine as _};
use crc32fast;
use hex;
use rand::prelude::*;
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

    pub async fn ping(&mut self) -> Result<()> {
        let mut buffer = Vec::with_capacity(64);

        let checksum = crc32fast::hash(b"tcp.ping random_id:long = tcp.Pong");
        let id_tl_schema = hex::encode(checksum.to_le_bytes());
        let id_tl_schema_bytes = id_tl_schema.as_bytes();
        buffer.extend_from_slice(id_tl_schema_bytes);

        let random_num = rand::thread_rng().next_u64();
        let random_bytes = random_num.to_le_bytes();
        buffer.extend_from_slice(&random_bytes);

        self.connection.send(&buffer).await?;

        if let Some(DatagramKind::Data(datagram)) = self.connection.receive().await? {
            println!("{:?}", datagram);
            return Ok(());
        }

        Err("ping failed".into())
    }
}
