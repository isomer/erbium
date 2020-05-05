use std::error::Error;
use tokio::stream::StreamExt;

mod dhcp;
mod dns;
mod net;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut services = futures::stream::FuturesUnordered::new();

    services.push(tokio::spawn(dhcp::run()));
    services.push(tokio::spawn(dns::run()));

    loop {
        match services.next().await {
            Some(x) => println!("Service complete: {:?}", x),
            None => break,
        }
    }

    Ok(())
}
