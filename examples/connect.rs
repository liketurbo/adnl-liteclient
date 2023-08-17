use adnl_liteclient::client::Client;

#[tokio::main]
async fn main() {
    let client = Client::connect(
        "65.21.141.233:30131",
        "wrQaeIFispPfHndEBc0s0fx7GSp8UFFvebnytQQfc6A=",
    )
    .await
    .unwrap();
}
