use std::error::Error;
use tokio::stream::StreamExt;

extern crate erbium;

use erbium::dhcp;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut services = futures::stream::FuturesUnordered::new();

    services.push(tokio::spawn(dhcp::run()));

    while let Some(x) = services.next().await {
        println!("Service complete: {:?}", x)
    }

    Ok(())
}


