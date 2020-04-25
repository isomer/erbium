//mod net;
use std::error::Error;

mod dhcp;
mod dns;
mod net;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let dhcp = tokio::spawn(dhcp::run());

    let dns = tokio::spawn(dns::run());

    let dhcp_result = dhcp.await;
    let dns_result = dns.await;

    match dhcp_result {
        Ok(_) => (),
        Err(e) => println!("DHCP Error: {:?}", e),
    }

    match dns_result {
        Ok(_) => (),
        Err(e) => println!("DNS Error: {:?}", e),
    }
    Ok(())
}
