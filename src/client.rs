use crate::tl_types::Query;
use crate::tl_types::{CurrentTime, GetTime};
use adnl_tcp::Client as AdnlClient;
use adnl_tcp::ToPublicKey;
use anyhow::Result;
use tokio::net::ToSocketAddrs as ToSocketAddr;

pub struct Client {
    adnl_client: AdnlClient,
}

impl Client {
    pub async fn connect<T: ToSocketAddr, S: ToPublicKey>(addr: T, public: S) -> Result<Client> {
        let adnl_client = AdnlClient::connect(addr, public).await?;
        Ok(Client { adnl_client })
    }

    pub async fn get_time(&mut self) -> Result<CurrentTime> {
        let query_bytes = tl_proto::serialize(Query {
            data: tl_proto::serialize(GetTime),
        });

        let answer = self.adnl_client.query(&query_bytes).await?;
        let current_time = tl_proto::deserialize::<CurrentTime>(&answer.answer)?;

        Ok(current_time)
    }
}
