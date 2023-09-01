use crate::connection::EstablishedConnection;
use crate::connection::InitConnection;
use crate::datagram::Datagram;
use crate::tl_types::Query;
use crate::tl_types::{CurrentTime, GetTime, Int256, Message};
use crate::{Result, ToBytes};
use rand::RngCore;
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

    pub async fn get_time(&mut self) -> Result<CurrentTime> {
        let mut query_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut query_id);

        let buf = tl_proto::serialize(Message::Query {
            query_id: Int256(&query_id),
            query: tl_proto::serialize(Query {
                data: tl_proto::serialize(GetTime),
            }),
        });
        let datagram = Datagram::from_buf(&buf)?;
        self.connection.write_datagram(&datagram).await?;

        if let Some(datagram) = self.connection.read_datagram().await? {
            let buf = datagram.get_buf()?;
            let message = tl_proto::deserialize::<Message>(&buf)?;
            match message {
                Message::Answer {
                    query_id: q_id,
                    answer,
                } => {
                    if q_id.0[..] != query_id[..] {
                        return Err("query_id didn't match".into());
                    }
                    let current_time = tl_proto::deserialize::<CurrentTime>(&answer)?;
                    return Ok(current_time);
                }
                Message::Query { .. } => return Err("returned query instead of answer".into()),
            }
        }

        Err("liteServer.getTime failed".into())
    }
}
