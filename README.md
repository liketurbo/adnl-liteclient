# ADNL Liteclient

This is an unfinished, simplified implementation of the ADNL Liteclient, built using [Tokio](https://tokio.rs/).

This project was never intended for production use but rather as a learning experience for working with [Tokio](https://tokio.rs/) and gaining a deeper understanding of the  [TON](https://ton.org) protocols.

If you are looking for a more complete ADNL Liteclient, consider checking out [tonstack/lite-client](https://github.com/tonstack/lite-client). If you want to learn more about programming with [Tokio](https://tokio.rs/), you can explore [tokio-rs/mini-redis](https://github.com/tokio-rs/mini-redis).

## Usage

```rust
use adnl_liteclient::client::Client;

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
```
