use tl_proto::{TlRead, TlWrite};

#[derive(TlRead, TlWrite, Debug)]
#[tl(
    boxed,
    id = "liteServer.query",
    scheme_inline = "liteServer.query data:bytes = Object;"
)]
pub struct Query {
    pub data: Vec<u8>,
}

#[derive(TlRead, TlWrite, Debug)]
#[tl(
    boxed,
    id = "liteServer.currentTime",
    scheme_inline = "liteServer.currentTime now:int = liteServer.CurrentTime;"
)]
pub struct CurrentTime {
    pub now: u32,
}

#[derive(TlRead, TlWrite)]
#[tl(
    boxed,
    id = "liteServer.getTime",
    scheme_inline = "liteServer.getTime = liteServer.CurrentTime;"
)]
pub struct GetTime;
