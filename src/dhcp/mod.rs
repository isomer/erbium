use std::collections;
use std::net;
use std::sync::Arc;
use tokio::sync;

use crate::net::packet;
use crate::net::raw;
use crate::net::udp;

/* We don't want a conflict between nix libc and whatever we use, so use nix's libc */
use nix::libc as libc;

mod dhcppkt;
mod pool;

type Pools = Arc<sync::Mutex<pool::Pools>>;
type LockedPools<'a> = sync::MutexGuard<'a, pool::Pools>;
type UdpSocket = udp::UdpSocket;

#[derive(Debug)]
enum DhcpError {
    UnknownMessageType(dhcppkt::MessageType),
    NoAddressesAvailable,
    ParseError(dhcppkt::ParseError),
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
            DhcpError::NoAddressesAvailable => write!(f, "No Addresses Available"),
            DhcpError::ParseError(e) => write!(f, "Parse Error: {:?}", e),
        }
    }
}

fn handle_discover(pools: LockedPools, req: &dhcppkt::DHCP) -> Result<dhcppkt::DHCP, DhcpError> {
    match pools.allocate_address("default") {
        Some(lease) => Ok(dhcppkt::DHCP {
            op: dhcppkt::OP_BOOTREPLY,
            htype: dhcppkt::HWTYPE_ETHERNET,
            hlen: 6,
            hops: 0,
            xid: req.xid,
            secs: 0,
            flags: req.flags,
            ciaddr: net::Ipv4Addr::UNSPECIFIED,
            yiaddr: lease.ip,
            siaddr: net::Ipv4Addr::UNSPECIFIED,
            giaddr: req.giaddr,
            chaddr: req.chaddr.clone(),
            sname: vec![],
            file: vec![],
            options: dhcppkt::DhcpOptions {
                messagetype: dhcppkt::DHCPOFFER,
                hostname: req.options.hostname.clone(),
                parameterlist: None,
                leasetime: None,
                other: collections::HashMap::new(),
            },
        }),
        _ => Err(DhcpError::NoAddressesAvailable),
    }
}

fn handle_request(pools: LockedPools, req: &dhcppkt::DHCP) -> Result<dhcppkt::DHCP, DhcpError> {
    match pools.allocate_address("default") {
        Some(lease) => Ok(dhcppkt::DHCP {
            op: dhcppkt::OP_BOOTREPLY,
            htype: dhcppkt::HWTYPE_ETHERNET,
            hlen: 6,
            hops: 0,
            xid: req.xid,
            secs: 0,
            flags: req.flags,
            ciaddr: req.ciaddr,
            yiaddr: lease.ip,
            siaddr: net::Ipv4Addr::UNSPECIFIED,
            giaddr: req.giaddr,
            chaddr: req.chaddr.clone(),
            sname: vec![],
            file: vec![],
            options: dhcppkt::DhcpOptions {
                messagetype: dhcppkt::DHCPACK,
                hostname: req.options.hostname.clone(),
                parameterlist: None,
                leasetime: Some(lease.lease),
                other: collections::HashMap::new(),
            },
        }),
        _ => Err(DhcpError::NoAddressesAvailable),
    }
}

fn handle_pkt(pools: LockedPools, buf: &[u8]) -> Result<dhcppkt::DHCP, DhcpError> {
    let dhcp = dhcppkt::parse(buf);
    match dhcp {
        Ok(req) => {
            println!("Parse: {:?}", req);
            match req.options.messagetype {
                dhcppkt::DHCPDISCOVER => handle_discover(pools, &req),
                dhcppkt::DHCPREQUEST => handle_request(pools, &req),
                x => Err(DhcpError::UnknownMessageType(x)),
            }
        }
        Err(e) => Err(DhcpError::ParseError(e)),
    }
}

async fn send_raw(raw: Arc<raw::RawSocket>, buf: &[u8], intf: i32) -> Result<(), std::io::Error> {
    raw.send_msg(
        buf,
        &mut raw::ControlMessage::new(),
        raw::MsgFlags::empty(),
        /* Wow this is ugly, some wrappers here might help */
        Some(&nix::sys::socket::SockAddr::Link(
            nix::sys::socket::LinkAddr(nix::libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: 0,
                sll_ifindex: intf,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            }),
        )),
    )
    .await
    .map(|_| ())
}

async fn recvdhcp(
    raw: Arc<raw::RawSocket>,
    pools: Pools,
    pkt: &[u8],
    from: std::net::SocketAddr,
    intf: i32,
) {
    let pool = pools.lock().await;
    let ip4 = if let net::SocketAddr::V4(f) = from {
        f
    } else {
        //net::SocketAddrV4(net::Ipv4Addr::UNSPECIFIED)
        println!("from={:?}", from);
        unimplemented!()
    };
    match handle_pkt(pool, pkt) {
        Ok(mut r) => {
            println!("Reply: {:?}", r);
            let buf = r.serialise();
            let etherbuf = packet::Fragment::new_udp(
                "192.0.2.2:2".parse().unwrap(), /* TODO */
                &[2, 0, 0, 0, 0, 1],            /* TODO */
                ip4,
                &[2, 0, 0, 0, 0, 2], /* TODO */
                packet::Tail::Payload(&buf),
            )
            .flatten();

            match send_raw(raw, &etherbuf, intf).await {
                Err(e) => println!("Failed to send reply to {:?}: {:?}", from, e),
                Ok(_) => (),
            }
        }
        Err(e) => println!("Error processing DHCP Packet from {:?}: {:?}", from, e),
    }
}

enum RunError {
    Io(std::io::Error),
    Nix(nix::Error),
    PoolError(pool::Error),
}

impl ToString for RunError {
    fn to_string(&self) -> String {
        match self {
            RunError::Io(e) => e.to_string(),
            RunError::Nix(e) => e.to_string(),
            RunError::PoolError(e) => e.to_string(),
        }
    }
}

async fn run_internal() -> Result<(), RunError> {
    println!("Starting DHCP service");
    let raw = Arc::new(raw::RawSocket::new().map_err(RunError::Io)?);
    println!("Raw socket created");
    let pools = Arc::new(sync::Mutex::new(
        pool::Pools::new().map_err(RunError::PoolError)?,
    ));
    let listener = UdpSocket::bind("0.0.0.0:1067")
        .await
        .map_err(RunError::Io)?;
    listener
        .set_opt_ipv4_packet_info(true)
        .map_err(RunError::Io)?;
    println!(
        "Listening for DHCP on {}",
        listener.local_addr().map_err(RunError::Io)?
    );

    loop {
        let rm = listener
            .recv_msg(65536, udp::MsgFlags::empty())
            .await
            .map_err(RunError::Io)?;
        let p = pools.clone();
        let r = raw.clone();
        tokio::spawn(async move {
            recvdhcp(
                r,
                p,
                &rm.buffer,
                rm.address.unwrap(),
                rm.local_intf().unwrap(),
            )
            .await
        });
    }
}

pub async fn run() -> Result<(), String> {
    match run_internal().await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
