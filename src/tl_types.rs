use tl_proto::{TlRead, TlWrite};

/// int256 8*[ int ] = Int256;
#[derive(TlRead, TlWrite, Debug)]
#[tl(size_hint = 32)]
pub struct Int256<'tl>(pub &'tl [u8; 32]);

/// adnl.message.query query_id:int256 query:bytes = adnl.Message;
/// adnl.message.answer query_id:int256 answer:bytes = adnl.Message;
#[derive(TlRead, TlWrite, Debug)]
#[tl(boxed, scheme = "lite_api.tl")]
pub enum Message<'tl> {
    /// adnl.message.query query_id:int256 query:bytes = adnl.Message;
    #[tl(id = "adnl.message.query")]
    Query {
        query_id: Int256<'tl>,
        query: Vec<u8>,
    },
    /// adnl.message.answer query_id:int256 answer:bytes = adnl.Message;
    #[tl(id = "adnl.message.answer")]
    Answer {
        query_id: Int256<'tl>,
        answer: Vec<u8>,
    },
}

/// liteServer.query data:bytes = Object;
#[derive(TlRead, TlWrite, Debug)]
#[tl(boxed, id = "liteServer.query", scheme = "lite_api.tl")]
pub struct Query {
    pub data: Vec<u8>,
}

/// liteServer.currentTime now:int = liteServer.CurrentTime;
#[derive(TlRead, TlWrite, Debug)]
#[tl(boxed, id = "liteServer.currentTime", scheme = "lite_api.tl")]
pub struct CurrentTime {
    pub now: i32,
}

/// liteServer.getTime = liteServer.CurrentTime;
#[derive(TlRead, TlWrite)]
#[tl(boxed, id = "liteServer.getTime", scheme = "lite_api.tl")]
pub struct GetTime;
