use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync;

mod dhcppkt;
mod pool;

type Pools = Arc<sync::Mutex<pool::Pools>>;
type LockedPools<'a> = sync::MutexGuard<'a, pool::Pools>;

#[derive(Debug)]
enum DhcpError {
    UnknownMessageType(dhcppkt::MessageType),
}

impl std::error::Error for DhcpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for DhcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpError::UnknownMessageType(m) => write!(f, "Unknown Message Type: {:?}", m),
        }
    }
}

fn handle_discover(pools: LockedPools, _req: &dhcppkt::DHCP) -> Result<dhcppkt::DHCP, DhcpError> {
    let addr = pools.allocate_address("default");
    return Err(DhcpError::UnknownMessageType(dhcppkt::DHCPDISCOVER));
}

fn handle_pkt(pools: LockedPools, req: dhcppkt::DHCP) -> Result<dhcppkt::DHCP, DhcpError> {
    match &req.options.messagetype {
        &dhcppkt::DHCPDISCOVER => handle_discover(pools, &req),
        &x => Err(DhcpError::UnknownMessageType(x)),
    }
}

async fn recvdhcp(pools: Pools, pkt: &[u8], from: std::net::SocketAddr) {
    let pool = pools.lock().await;
    match dhcppkt::parse(pkt) {
        Ok(d) => match handle_pkt(pool, d) {
            Err(e) => println!("Error processing DHCP Packet from {:?}: {:?}", from, e),
            _ => (),
        },
        Err(e) => println!("Failed to parse DHCP Packet: {:?}", e),
    }
}

async fn run_internal() -> Result<(), Box<dyn std::error::Error>> {
    let pools = Arc::new(sync::Mutex::new(pool::Pools::new()?));
    let mut listener = UdpSocket::bind("[::]:1067").await?;
    println!("Listening for DHCP on {}", listener.local_addr()?);

    loop {
        let mut buf = [0; 65536];
        let (n, sa) = listener.recv_from(&mut buf).await?;
        let p = pools.clone();
        tokio::spawn(async move { recvdhcp(p, &buf[0..n], sa).await });
    }
}

pub async fn run() -> Result<(), String> {
    match run_internal().await {
        Ok(o) => Ok(o),
        Err(e) => Err(e.to_string()),
    }
}
