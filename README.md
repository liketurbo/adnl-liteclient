# ADNL Liteclient

This is an unfinished ADNL Liteclient built upon [liketurbo/adnl-tcp](https://github.com/liketurbo/adnl-tcp).

At the moment, only the `get_time` function is implemented, but you can use it as a template to implement the rest of the specification from [lite_api.tl](https://github.com/ton-blockchain/ton/blob/e1197b13d43a082a48402bdbdeadab472087ad09/tl/generate/scheme/lite_api.tl). However, it's worth noting that a more complete ADNL Liteclient already exists at [tonstack/lite-client](https://github.com/tonstack/lite-client). Therefore, it's probably better for you to use that instead.

## Usage

```rust
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
