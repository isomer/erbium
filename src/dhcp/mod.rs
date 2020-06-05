/*   Copyright 2020 Perry Lorier
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Main DHCP Code.
 */
use std::collections;
use std::convert::TryInto;
use std::net;
use std::sync::Arc;
use tokio::sync;

use crate::net::packet;
use crate::net::raw;
use crate::net::udp;

/* We don't want a conflict between nix libc and whatever we use, so use nix's libc */
use nix::libc;

mod dhcppkt;
mod pool;

#[cfg(test)]
mod test;

type Pools = Arc<sync::Mutex<pool::Pools>>;
type UdpSocket = udp::UdpSocket;
type ServerIds = std::collections::HashSet<net::Ipv4Addr>;
type SharedServerIds = Arc<sync::Mutex<ServerIds>>;

#[derive(Debug, PartialEq, Eq)]
enum DhcpError {
    UnknownMessageType(dhcppkt::MessageType),
    NoLeasesAvailable,
    ParseError(dhcppkt::ParseError),
    InternalError(String),
    OtherServer,
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
            DhcpError::NoLeasesAvailable => write!(f, "No Leases Available"),
            DhcpError::ParseError(e) => write!(f, "Parse Error: {:?}", e),
            DhcpError::InternalError(e) => write!(f, "Internal Error: {:?}", e),
            DhcpError::OtherServer => write!(f, "Packet for a different DHCP server"),
        }
    }
}

fn handle_discover(
    pools: &mut pool::Pools,
    req: &dhcppkt::DHCP,
    dst: net::IpAddr,
    _serverids: ServerIds,
) -> Result<dhcppkt::DHCP, DhcpError> {
    if let net::IpAddr::V4(addr) = dst {
        match pools.allocate_address(
            "default",
            &req.get_client_id(),
            req.options.get_address_request(),
        ) {
            Ok(lease) => Ok(dhcppkt::DHCP {
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
                    serveridentifier: Some(addr),
                    clientidentifier: req.options.clientidentifier.clone(),
                    other: collections::HashMap::new(),
                },
            }),
            Err(pool::Error::NoAssignableAddress) => Err(DhcpError::NoLeasesAvailable),
            Err(e) => Err(DhcpError::InternalError(e.to_string())),
        }
    } else {
        Err(DhcpError::InternalError(
            "Missing v4 addresses on received packet".to_string(),
        ))
    }
}

fn handle_request(
    pools: &mut pool::Pools,
    req: &dhcppkt::DHCP,
    _dst: net::IpAddr,
    serverids: ServerIds,
) -> Result<dhcppkt::DHCP, DhcpError> {
    if let Some(si) = req.options.serveridentifier {
        if !serverids.contains(&si) {
            return Err(DhcpError::OtherServer);
        }
    }
    match pools.allocate_address(
        "default",
        &req.get_client_id(),
        req.options.get_address_request(),
    ) {
        Ok(lease) => Ok(dhcppkt::DHCP {
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
                leasetime: Some(lease.expire),
                serveridentifier: req.options.serveridentifier,
                clientidentifier: req.options.clientidentifier.clone(),
                other: collections::HashMap::new(),
            },
        }),
        Err(pool::Error::NoAssignableAddress) => Err(DhcpError::NoLeasesAvailable),
        Err(e) => Err(DhcpError::InternalError(e.to_string())),
    }
}

fn handle_pkt(
    mut pools: &mut pool::Pools,
    buf: &[u8],
    dst: net::IpAddr,
    serverids: ServerIds,
) -> Result<dhcppkt::DHCP, DhcpError> {
    let dhcp = dhcppkt::parse(buf);
    match dhcp {
        Ok(req) => {
            println!("Parse: {:?}", req);
            match req.options.messagetype {
                dhcppkt::DHCPDISCOVER => handle_discover(&mut pools, &req, dst, serverids),
                dhcppkt::DHCPREQUEST => handle_request(&mut pools, &req, dst, serverids),
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

async fn get_serverids(s: &SharedServerIds) -> ServerIds {
    s.lock().await.clone()
}

fn to_array(mac: &[u8]) -> Option<[u8; 6]> {
    mac[0..6].try_into().ok()
}

async fn recvdhcp(
    raw: Arc<raw::RawSocket>,
    pools: Pools,
    serverids: SharedServerIds,
    pkt: &[u8],
    src: std::net::SocketAddr,
    netinfo: crate::net::netinfo::SharedNetInfo,
    intf: i32,
) {
    let mut pool = pools.lock().await;
    let ip4 = if let net::SocketAddr::V4(f) = src {
        f
    } else {
        println!("from={:?}", src);
        unimplemented!()
    };
    let dst = netinfo
        .get_ipv4_by_ifidx(intf.try_into().unwrap())
        .await
        .unwrap(); /* TODO: Error? */
    match handle_pkt(
        &mut pool,
        pkt,
        std::net::IpAddr::V4(dst),
        get_serverids(&serverids).await,
    ) {
        Ok(r) => {
            if let Some(si) = r.options.serveridentifier {
                serverids.lock().await.insert(si);
            }
            println!("Reply: {:?}", r);
            let buf = r.serialise();
            let srcip = std::net::SocketAddrV4::new(dst, 67);
            if let Some(crate::net::netinfo::LinkLayer::Ethernet(srcll)) = netinfo
                .get_linkaddr_by_ifidx(intf.try_into().unwrap())
                .await
            {
                let etherbuf = packet::Fragment::new_udp(
                    srcip,
                    &srcll,
                    ip4,
                    &to_array(&r.chaddr).unwrap(), /* TODO: Error handling */
                    packet::Tail::Payload(&buf),
                )
                .flatten();

                if let Err(e) = send_raw(raw, &etherbuf, intf).await {
                    println!("Failed to send reply to {:?}: {:?}", src, e);
                }
            } else {
                println!("Not a usable LinkLayer?!");
            }
        }
        Err(e) => println!("Error processing DHCP Packet from {:?}: {:?}", src, e),
    }
}

enum RunError {
    Io(std::io::Error),
    PoolError(pool::Error),
}

impl ToString for RunError {
    fn to_string(&self) -> String {
        match self {
            RunError::Io(e) => e.to_string(),
            RunError::PoolError(e) => e.to_string(),
        }
    }
}

async fn run_internal(netinfo: crate::net::netinfo::SharedNetInfo) -> Result<(), RunError> {
    println!("Starting DHCP service");
    let rawsock = Arc::new(raw::RawSocket::new().map_err(RunError::Io)?);
    let pools = Arc::new(sync::Mutex::new(
        pool::Pools::new().map_err(RunError::PoolError)?,
    ));
    {
        let mut lockedpools = pools.lock().await;
        lockedpools
            .add_pool("default")
            .map_err(RunError::PoolError)?;
        lockedpools
            .add_subnet(
                "default",
                pool::Netblock {
                    addr: "192.168.0.0".parse().expect("Failed to parse IPv4 Addr"),
                    prefixlen: 24,
                },
            )
            .map_err(RunError::PoolError)?;
    }
    let serverids: SharedServerIds = Arc::new(sync::Mutex::new(std::collections::HashSet::new()));
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
        let rs = rawsock.clone();
        let s = serverids.clone();
        let ni = netinfo.clone();
        tokio::spawn(async move {
            recvdhcp(
                rs,
                p,
                s,
                &rm.buffer,
                rm.address.unwrap(),
                ni,
                rm.local_intf().unwrap(),
            )
            .await
        });
    }
}

pub async fn run(netinfo: crate::net::netinfo::SharedNetInfo) -> Result<(), String> {
    match run_internal(netinfo).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
