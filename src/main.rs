//mod net;
use std::error::Error;

mod dhcp;
mod dns;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tokio::spawn(dhcp::run());

    tokio::spawn(dns::run());

    Ok(())
}
