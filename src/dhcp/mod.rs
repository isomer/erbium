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
use std::iter::FromIterator;
use std::net;
use std::sync::Arc;
use tokio::sync;

use crate::net::packet;
use crate::net::raw;
use crate::net::udp;

/* We don't want a conflict between nix libc and whatever we use, so use nix's libc */
use nix::libc;

pub mod config;
mod dhcppkt;
pub mod pool;

#[cfg(test)]
mod test;

type Pool = Arc<sync::Mutex<pool::Pool>>;
type UdpSocket = udp::UdpSocket;
type ServerIds = std::collections::HashSet<net::Ipv4Addr>;
pub type SharedServerIds = Arc<sync::Mutex<ServerIds>>;

#[derive(Debug, PartialEq, Eq)]
pub enum DhcpError {
    UnknownMessageType(dhcppkt::MessageType),
    NoLeasesAvailable,
    ParseError(dhcppkt::ParseError),
    InternalError(String),
    OtherServer,
    NoPolicyConfigured,
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
            DhcpError::NoPolicyConfigured => write!(f, "No policy configured for client"),
        }
    }
}

#[derive(Debug)]
struct DHCPRequest {
    /// The DHCP request packet.
    pkt: dhcppkt::DHCP,
    /// The IP address that the request was received on.
    serverip: std::net::Ipv4Addr,
    /// The interface index that the request was received on.
    ifindex: u32,
}

#[cfg(test)]
impl std::default::Default for DHCPRequest {
    fn default() -> Self {
        DHCPRequest {
            pkt: dhcppkt::DHCP {
                op: dhcppkt::OP_BOOTREQUEST,
                htype: dhcppkt::HWTYPE_ETHERNET,
                hlen: 6,
                hops: 0,
                xid: 0,
                secs: 0,
                flags: 0,
                ciaddr: net::Ipv4Addr::UNSPECIFIED,
                yiaddr: net::Ipv4Addr::UNSPECIFIED,
                siaddr: net::Ipv4Addr::UNSPECIFIED,
                giaddr: net::Ipv4Addr::UNSPECIFIED,
                chaddr: vec![
                    0x00, 0x00, 0x5E, 0x00, 0x53,
                    0x00, /* Reserved for documentation, per RFC7042 */
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                sname: vec![],
                file: vec![],
                options: Default::default(),
            },
            serverip: "0.0.0.0".parse().unwrap(),
            ifindex: 0,
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
enum PolicyMatch {
    NoMatch,
    MatchFailed,
    MatchSucceeded,
}

fn check_policy(req: &DHCPRequest, policy: &config::Policy) -> PolicyMatch {
    let mut outcome = PolicyMatch::NoMatch;
    //if let Some(policy.match_interface ...
    if let Some(match_chaddr) = &policy.match_chaddr {
        outcome = PolicyMatch::MatchSucceeded;
        if req.pkt.chaddr != *match_chaddr {
            return PolicyMatch::MatchFailed;
        }
    }
    if let Some(match_subnet) = &policy.match_subnet {
        outcome = PolicyMatch::MatchSucceeded;
        if !match_subnet.contains(req.serverip) {
            return PolicyMatch::MatchFailed;
        }
    }

    for (k, m) in policy.match_other.iter() {
        if let Some(v) = req.pkt.options.other.get(k) {
            outcome = PolicyMatch::MatchSucceeded;
            if &m.as_bytes() != v {
                return PolicyMatch::MatchFailed;
            }
        } else {
            return PolicyMatch::MatchFailed;
        }
    }

    outcome
}

fn apply_policy(req: &DHCPRequest, policy: &config::Policy, response: &mut Response) -> bool {
    let policymatch = check_policy(req, policy);
    if policymatch == PolicyMatch::MatchFailed {
        return false;
    }

    if policymatch == PolicyMatch::NoMatch && !check_policies(req, &policy.policies) {
        return false;
    }

    if let Some(address) = &policy.apply_address {
        response.address = Some(address.clone()); /* HELP: I tried to make the lifetimes worked, and failed */
    }

    // TODO: This should probably just be a u128 bitvector
    let pl: std::collections::HashSet<
        dhcppkt::DhcpOption,
        std::collections::hash_map::RandomState,
    > = std::collections::HashSet::from_iter(
        req.pkt
            .options
            .get_option::<Vec<u8>>(&dhcppkt::OPTION_PARAMLIST)
            .unwrap_or_else(Vec::new)
            .iter()
            .cloned()
            .map(dhcppkt::DhcpOption::from),
    );

    for (k, v) in &policy.apply_other {
        if pl.contains(k) {
            response.options.mutate_option(k, v);
        }
    }

    /* And check to see if a subpolicy also matches */
    apply_policies(req, &policy.policies, response);
    true
}

fn check_policies(req: &DHCPRequest, policies: &[config::Policy]) -> bool {
    for policy in policies {
        match check_policy(req, policy) {
            PolicyMatch::MatchSucceeded => return true,
            PolicyMatch::MatchFailed => continue,
            PolicyMatch::NoMatch => {
                if check_policies(req, &policy.policies) {
                    return true;
                } else {
                    continue;
                }
            }
        }
    }
    false
}

fn apply_policies(req: &DHCPRequest, policies: &[config::Policy], response: &mut Response) -> bool {
    for policy in policies {
        if apply_policy(req, policy, response) {
            return true;
        }
    }
    false
}

#[derive(Default)]
struct Response {
    options: dhcppkt::DhcpOptions,
    address: Option<pool::PoolAddresses>,
    minlease: Option<std::time::Duration>,
    maxlease: Option<std::time::Duration>,
}

fn handle_discover<'l>(
    pools: &mut pool::Pool,
    req: &DHCPRequest,
    _serverids: ServerIds,
    conf: &'l super::config::Config,
) -> Result<dhcppkt::DHCP, DhcpError> {
    let mut response: Response = Response {
        options: dhcppkt::DhcpOptions {
            other: collections::HashMap::new(),
        }
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPOFFER)
        .set_option(&dhcppkt::OPTION_SERVERID, &req.serverip)
        .maybe_set_option(
            &dhcppkt::OPTION_CLIENTID,
            req.pkt.options.get_clientid().as_ref(),
        ),
        ..Default::default()
    };
    if !apply_policies(req, &conf.dhcp.policies, &mut response) {
        Err(DhcpError::NoPolicyConfigured)
    } else if let Some(addresses) = response.address {
        match pools.allocate_address(
            &req.pkt.get_client_id(),
            req.pkt.options.get_address_request(),
            &addresses,
        ) {
            Ok(lease) => Ok(dhcppkt::DHCP {
                op: dhcppkt::OP_BOOTREPLY,
                htype: dhcppkt::HWTYPE_ETHERNET,
                hlen: 6,
                hops: 0,
                xid: req.pkt.xid,
                secs: 0,
                flags: req.pkt.flags,
                ciaddr: net::Ipv4Addr::UNSPECIFIED,
                yiaddr: lease.ip,
                siaddr: net::Ipv4Addr::UNSPECIFIED,
                giaddr: req.pkt.giaddr,
                chaddr: req.pkt.chaddr.clone(),
                sname: vec![],
                file: vec![],
                options: response
                    .options
                    .clone()
                    .set_option(&dhcppkt::OPTION_SERVERID, &req.serverip),
            }),
            Err(pool::Error::NoAssignableAddress) => Err(DhcpError::NoLeasesAvailable),
            Err(e) => Err(DhcpError::InternalError(e.to_string())),
        }
    } else {
        Err(DhcpError::NoLeasesAvailable)
    }
}

fn handle_request(
    pools: &mut pool::Pool,
    req: &DHCPRequest,
    serverids: ServerIds,
    conf: &super::config::Config,
) -> Result<dhcppkt::DHCP, DhcpError> {
    if let Some(si) = req.pkt.options.get_serverid() {
        if !serverids.contains(&si) {
            return Err(DhcpError::OtherServer);
        }
    }
    let mut response: Response = Response {
        options: dhcppkt::DhcpOptions {
            other: collections::HashMap::new(),
        }
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPOFFER)
        .set_option(&dhcppkt::OPTION_SERVERID, &req.serverip)
        .maybe_set_option(
            &dhcppkt::OPTION_CLIENTID,
            req.pkt.options.get_clientid().as_ref(),
        ),
        ..Default::default()
    };
    if !apply_policies(req, &conf.dhcp.policies, &mut response) {
        Err(DhcpError::NoPolicyConfigured)
    } else if let Some(addresses) = response.address {
        match pools.allocate_address(
            &req.pkt.get_client_id(),
            req.pkt.options.get_address_request(),
            &addresses,
        ) {
            Ok(lease) => Ok(dhcppkt::DHCP {
                op: dhcppkt::OP_BOOTREPLY,
                htype: dhcppkt::HWTYPE_ETHERNET,
                hlen: 6,
                hops: 0,
                xid: req.pkt.xid,
                secs: 0,
                flags: req.pkt.flags,
                ciaddr: req.pkt.ciaddr,
                yiaddr: lease.ip,
                siaddr: net::Ipv4Addr::UNSPECIFIED,
                giaddr: req.pkt.giaddr,
                chaddr: req.pkt.chaddr.clone(),
                sname: vec![],
                file: vec![],
                options: response
                    .options
                    .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPACK)
                    .set_option(
                        &dhcppkt::OPTION_SERVERID,
                        &req.pkt.options.get_serverid().unwrap_or(req.serverip),
                    )
                    .maybe_set_option(
                        &dhcppkt::OPTION_CLIENTID,
                        req.pkt.options.get_clientid().as_ref(),
                    )
                    .set_option(&dhcppkt::OPTION_LEASETIME, &(lease.expire.as_secs() as u32)),
            }),
            Err(pool::Error::NoAssignableAddress) => Err(DhcpError::NoLeasesAvailable),
            Err(e) => Err(DhcpError::InternalError(e.to_string())),
        }
    } else {
        Err(DhcpError::NoLeasesAvailable)
    }
}

fn format_mac(v: &[u8]) -> String {
    v.iter()
        .map(|b| format!("{:0>2x}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn format_client(req: &dhcppkt::DHCP) -> String {
    format!(
        "{} ({})",
        format_mac(&req.chaddr),
        String::from_utf8_lossy(
            &req.options
                .get_option::<Vec<u8>>(&dhcppkt::OPTION_HOSTNAME)
                .unwrap_or(vec![])
        ),
    )
}

pub fn handle_pkt(
    mut pools: &mut pool::Pool,
    buf: &[u8],
    dst: net::Ipv4Addr,
    serverids: ServerIds,
    intf: u32,
    conf: &super::config::Config,
) -> Result<dhcppkt::DHCP, DhcpError> {
    let dhcp = dhcppkt::parse(buf);
    match dhcp {
        Ok(req) => {
            println!(
                "{}: {} on {}",
                format_client(&req),
                req.options
                    .get_messagetype()
                    .map(|x| x.to_string())
                    .unwrap_or("[unknown]".into()),
                intf
            );
            println!(
                "{}: Options: {}",
                format_client(&req),
                req.options
                    .other
                    .iter()
                    // We already decode MSGTYPE and PARAMLIST elsewhere, so don't try and decode
                    // them here.  It just leads to confusing looking messages.
                    .filter(|(&k, _)| k != dhcppkt::OPTION_MSGTYPE && k != dhcppkt::OPTION_PARAMLIST)
                    .map(|(k, v)| format!(
                        "{}({})",
                        k.to_string(),
                        k.get_type()
                            .and_then(|x| x.decode(v))
                            .map(|x| format!("{}", x))
                            .unwrap_or("<unknown>".into())
                    ))
                    .collect::<Vec<String>>()
                    .join(" "),
            );
            println!(
                "{}: Requested: {}",
                format_client(&req),
                req.options
                    .get_option::<Vec<u8>>(&dhcppkt::OPTION_PARAMLIST)
                    .map(|v| v
                        .iter()
                        .map(|&x| dhcppkt::DhcpOption::new(x))
                        .map(|o| o.to_string())
                        .collect::<Vec<String>>()
                        .join(" "))
                    .unwrap_or("<none>".into())
            );

            let request = DHCPRequest {
                pkt: req,
                serverip: dst,
                ifindex: intf,
            };
            match request.pkt.options.get_messagetype() {
                Some(dhcppkt::DHCPDISCOVER) => {
                    handle_discover(&mut pools, &request, serverids, conf)
                }
                Some(dhcppkt::DHCPREQUEST) => handle_request(&mut pools, &request, serverids, conf),
                Some(x) => Err(DhcpError::UnknownMessageType(x)),
                None => Err(DhcpError::ParseError(dhcppkt::ParseError::InvalidPacket)),
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
    pools: Pool,
    serverids: SharedServerIds,
    pkt: &[u8],
    src: std::net::SocketAddr,
    netinfo: crate::net::netinfo::SharedNetInfo,
    intf: u32,
    conf: super::config::SharedConfig,
) {
    let mut pool = pools.lock().await;
    let ip4 = if let net::SocketAddr::V4(f) = src {
        f
    } else {
        println!("from={:?}", src);
        unimplemented!()
    };
    let optional_dst = netinfo.get_ipv4_by_ifidx(intf).await;
    if optional_dst.is_none() {
        println!("No IPv4 found on interface {}", intf);
        return;
    }
    let dst = optional_dst.unwrap();
    let lockedconf = conf.lock().await;
    match handle_pkt(
        &mut pool,
        pkt,
        dst,
        get_serverids(&serverids).await,
        intf,
        &lockedconf,
    ) {
        Ok(r) => {
            if let Some(si) = r.options.get_serverid() {
                serverids.lock().await.insert(si);
            }
            println!(
                "Sending {} for {} ({}) on {} with {} for {}",
                r.options
                    .get_messagetype()
                    .map(|x| x.to_string())
                    .unwrap_or("[unknown]".into()),
                r.chaddr
                    .iter()
                    .map(|b| format!("{:0>2x}", b))
                    .collect::<Vec<String>>()
                    .join(":"),
                String::from_utf8_lossy(
                    &r.options
                        .get_option::<Vec<u8>>(&dhcppkt::OPTION_HOSTNAME)
                        .unwrap_or(vec![])
                ),
                netinfo
                    .get_name_by_ifidx(intf)
                    .await
                    .unwrap_or("<unknown if>".into()),
                r.yiaddr,
                r.options
                    .get_option::<u32>(&dhcppkt::OPTION_LEASETIME)
                    .unwrap_or(0)
            );
            //println!("Reply: {:?}", r);
            let buf = r.serialise();
            let srcip = std::net::SocketAddrV4::new(dst, 67);
            if let Some(crate::net::netinfo::LinkLayer::Ethernet(srcll)) = netinfo
                .get_linkaddr_by_ifidx(intf.try_into().unwrap())
                .await
            {
                if let Some(chaddr) = to_array(&r.chaddr) {
                    let etherbuf = packet::Fragment::new_udp(
                        srcip,
                        &srcll,
                        ip4,
                        &chaddr,
                        packet::Tail::Payload(&buf),
                    )
                    .flatten();

                    if let Err(e) = send_raw(raw, &etherbuf, intf.try_into().unwrap()).await {
                        println!("Failed to send reply to {:?}: {:?}", src, e);
                    }
                } else {
                    println!("Cannot send reply to invalid address {:?}", r.chaddr);
                }
            } else {
                println!("Not a usable LinkLayer?!");
            }
        }
        Err(e) => println!("Error processing DHCP Packet to {:?}: {:?}", dst, e),
    }
}

enum RunError {
    Io(std::io::Error),
    PoolError(pool::Error),
}

impl ToString for RunError {
    fn to_string(&self) -> String {
        match self {
            RunError::Io(e) => format!("I/O Error in DHCP: {}", e),
            RunError::PoolError(e) => format!("DHCP Pool Error: {}", e),
        }
    }
}

async fn run_internal(
    netinfo: crate::net::netinfo::SharedNetInfo,
    conf: super::config::SharedConfig,
) -> Result<(), RunError> {
    println!("Starting DHCP service");
    let rawsock = Arc::new(raw::RawSocket::new().map_err(RunError::Io)?);
    let pools = Arc::new(sync::Mutex::new(
        pool::Pool::new().map_err(RunError::PoolError)?,
    ));
    let serverids: SharedServerIds = Arc::new(sync::Mutex::new(std::collections::HashSet::new()));
    let listener = UdpSocket::bind("0.0.0.0:67").await.map_err(RunError::Io)?;
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
        let c = conf.clone();
        tokio::spawn(async move {
            recvdhcp(
                rs,
                p,
                s,
                &rm.buffer,
                rm.address.unwrap(),
                ni,
                rm.local_intf().unwrap().try_into().unwrap(),
                c,
            )
            .await
        });
    }
}

pub async fn run(
    netinfo: crate::net::netinfo::SharedNetInfo,
    conf: super::config::SharedConfig,
) -> Result<(), String> {
    match run_internal(netinfo, conf).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[test]
fn test_policy() {
    let cfg = config::Policy {
        match_subnet: Some(crate::net::Ipv4Subnet::new("192.0.2.0".parse().unwrap(), 24).unwrap()),
        ..Default::default()
    };
    let req = DHCPRequest {
        serverip: "192.0.2.67".parse().unwrap(),
        ..Default::default()
    };
    let mut resp = Default::default();
    let policies = vec![cfg];

    assert_eq!(apply_policies(&req, policies.as_slice(), &mut resp), true);
}

#[tokio::test]
async fn test_config_parse() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = crate::config::load_config_from_string_for_test(
        "---
dhcp:
    Policies:
      - match-subnet: 192.168.0.0/24
        apply-dns-server: ['8.8.8.8', '8.8.4.4']
        apply-subnet: 192.168.0.0/24
        apply-time-offset: 3600
        apply-domain-name: erbium.dev
        apply-forward: false
        apply-mtu: 1500
        apply-broadcast: 192.168.255.255
        apply-rebind-time: 120
        apply-renewal-time: 90s
        apply-arp-timeout: 1w


        Policies:
           - { match-hostname: myhost, apply-address: 192.168.0.1 }
           - { match-hardware-address: 00:01:02:03:04:05, apply-address: 192.168.0.2 }


      - match-interface: dmz
        apply-dns-server: ['8.8.8.8']
        apply-subnet: 192.0.2.0/24

        # Reserve some space from the pool for servers
        Policies:
          - apply-range: {start: 192.0.2.10, end: 192.0.2.20}

            # From the reserved pool, assign a static address.
            Policies:
              - { match-hardware-address: 00:01:02:03:04:05, apply-address: 192.168.0.2 }

          # Reserve space for VPN endpoints
          - match-user-class: VPN
            apply-subnet: 192.0.2.128/25
        ",
    )?;

    let mut resp = Response {
        ..Default::default()
    };
    if !apply_policies(
        &DHCPRequest {
            pkt: dhcppkt::DHCP {
                op: dhcppkt::OP_BOOTREQUEST,
                htype: dhcppkt::HWTYPE_ETHERNET,
                hlen: 6,
                hops: 0,
                xid: 0,
                secs: 0,
                flags: 0,
                ciaddr: net::Ipv4Addr::UNSPECIFIED,
                yiaddr: net::Ipv4Addr::UNSPECIFIED,
                siaddr: net::Ipv4Addr::UNSPECIFIED,
                giaddr: net::Ipv4Addr::UNSPECIFIED,
                chaddr: vec![0, 1, 2, 3, 4, 5],
                sname: vec![],
                file: vec![],
                options: dhcppkt::DhcpOptions {
                    ..Default::default()
                },
            },
            serverip: "192.168.0.67".parse().unwrap(),
            ifindex: 1,
        },
        &cfg.lock().await.dhcp.policies,
        &mut resp,
    ) {
        panic!("No policies applied");
    }

    println!("{:?}", cfg.lock().await);

    assert_eq!(
        resp.address,
        Some(std::collections::HashSet::from_iter(
            [std::net::Ipv4Addr::new(192, 168, 0, 2)].iter().cloned()
        ))
    );

    Ok(())
}
