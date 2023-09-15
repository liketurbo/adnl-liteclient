use adnl_liteclient::Client;

#[tokio::main]
async fn main() {
    let mut client = Client::connect(
        "65.21.141.233:30131",
        "wrQaeIFispPfHndEBc0s0fx7GSp8UFFvebnytQQfc6A=",
    )
    .await
    .unwrap();
    let current_time = client.get_time().await.unwrap();
    println!("{:?}", current_time);
}
