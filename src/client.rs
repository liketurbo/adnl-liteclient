use crate::connection::EstablishedConnection;
use crate::connection::InitConnection;
use crate::datagram::DatagramKind;
use crate::{Result, ToBytes};
use crc32fast;
use rand::prelude::*;
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs as ToSocketAddr;

pub struct Client {
    connection: EstablishedConnection,
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
        let checksum_bytes = checksum.to_le_bytes();
        buffer.extend_from_slice(&checksum_bytes);

        let random_num = rand::thread_rng().next_u64();
        let random_bytes = random_num.to_le_bytes();
        buffer.extend_from_slice(&random_bytes);

        self.connection.send(&buffer).await?;

        if let Some(DatagramKind::Data(datagram)) = self.connection.receive().await? {
            println!("received datagram: {:?}", datagram);
            return Ok(());
        }

        Err("ping failed".into())
    }
}
