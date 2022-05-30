/*   Copyright 2021 Perry Lorier
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
use std::convert::TryInto as _;
use std::net;
use std::ops::Sub as _;
use std::sync::Arc;
use tokio::sync;

use crate::dhcp::dhcppkt::Serialise;
use crate::net::packet;
use crate::net::raw;
use crate::net::udp;

/* We don't want a conflict between nix libc and whatever we use, so use nix's libc */
use nix::libc;

pub mod config;
pub mod dhcppkt;
pub mod pool;
#[cfg(test)]
mod test;

type UdpSocket = udp::UdpSocket;
type ServerIds = std::collections::HashSet<net::Ipv4Addr>;
pub type SharedServerIds = Arc<sync::Mutex<ServerIds>>;

lazy_static::lazy_static! {
    static ref DHCP_RX_PACKETS: prometheus::IntCounter =
        prometheus::register_int_counter!("dhcp_received_packets", "Number of DHCP packets received")
            .unwrap();
    static ref DHCP_TX_PACKETS: prometheus::IntCounter =
        prometheus::register_int_counter!("dhcp_sent_packets", "Number of DHCP packets sent")
            .unwrap();
    static ref DHCP_ERRORS: prometheus::IntCounterVec = prometheus::register_int_counter_vec!(
        "dhcp_errors",
        "Counts of reasons that replies cannot be sent",
        &["reason"]
    )
    .unwrap();
    static ref DHCP_ALLOCATIONS: prometheus::IntCounterVec = prometheus::register_int_counter_vec!(
        "dhcp_allocations",
        "Counts of address allocation types",
        &["reason"]
    )
    .unwrap();
    static ref DHCP_ACTIVE_LEASES: prometheus::IntGauge = prometheus::register_int_gauge!(
        "dhcp_active_leases",
        "Counts of leases that are currently in use"
    )
    .unwrap();
    static ref DHCP_EXPIRED_LEASES: prometheus::IntGauge = prometheus::register_int_gauge!(
        "dhcp_expired_leases",
        "Counts of leases that are currently expired"
    )
    .unwrap();
}

#[derive(Debug, PartialEq, Eq)]
pub enum DhcpError {
    UnknownMessageType(dhcppkt::MessageType),
    NoLeasesConfigured,
    ParseError(dhcppkt::ParseError),
    PoolError(pool::Error),
    InternalError(String),
    OtherServer(std::net::Ipv4Addr),
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
            DhcpError::NoLeasesConfigured => write!(f, "No Leases Configured"),
            DhcpError::ParseError(e) => write!(f, "Parse Error: {:?}", e),
            DhcpError::InternalError(e) => write!(f, "Internal Error: {:?}", e),
            DhcpError::OtherServer(s) => write!(f, "Packet for a different DHCP server: {}", s),
            DhcpError::NoPolicyConfigured => write!(f, "No policy configured for client"),
            DhcpError::PoolError(p) => write!(f, "Pool Error: {:?}", p),
        }
    }
}

impl DhcpError {
    const fn get_variant_name(&self) -> &'static str {
        use DhcpError::*;
        match self {
            UnknownMessageType(_) => "UNKNOWN_MESSAGE_TYPE",
            NoLeasesConfigured => "NO_LEASES_CONFIGURED",
            ParseError(_) => "PARSE_ERROR",
            InternalError(_) => "INTERNAL_ERROR",
            OtherServer(_) => "OTHER_SERVER",
            NoPolicyConfigured => "NO_POLICY",
            PoolError(pool::Error::NoAssignableAddress) => "NO_ADDRESS",
            PoolError(pool::Error::RequestedAddressInUse) => "ADDRESS_IN_USE",
            PoolError(_) => "INTERNAL_POOL_ERROR",
        }
    }
}

#[derive(Debug)]
pub struct DHCPRequest {
    /// The DHCP request packet.
    pub pkt: dhcppkt::Dhcp,
    /// The IP address that the request was received on.
    pub serverip: std::net::Ipv4Addr,
    /// The interface index that the request was received on.
    pub ifindex: u32,
    pub if_mtu: Option<u32>,
    pub if_router: Option<std::net::Ipv4Addr>,
}

#[cfg(test)]
impl std::default::Default for DHCPRequest {
    fn default() -> Self {
        DHCPRequest {
            pkt: dhcppkt::Dhcp {
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
                ],
                sname: vec![],
                file: vec![],
                options: Default::default(),
            },
            serverip: "0.0.0.0".parse().unwrap(),
            ifindex: 0,
            if_mtu: None,
            if_router: None,
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
    if policy.match_all {
        outcome = PolicyMatch::MatchSucceeded;
    }
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
        if match (m, req.pkt.options.other.get(k)) {
            (None, None) => true, /* Required that option doesn't exist, option doesn't exist */
            (None, Some(_)) => false, /* Required that option doesn't exist, option exists */
            (Some(mat), Some(opt)) if &mat.as_bytes() == opt => true, /* Required it has value, and matches */
            (Some(_), Some(_)) => false, /* Required it has a value, option has some other value */
            (Some(_), None) => false, /* Required that option has a value, option doesn't exist */
        } {
            /* If at least one thing matches, then this is a MatchSucceded */
            outcome = PolicyMatch::MatchSucceeded;
        } else {
            /* If any fail, then fail everything */
            return PolicyMatch::MatchFailed;
        }
    }
    outcome
}

fn apply_policy(req: &DHCPRequest, policy: &config::Policy, response: &mut Response) -> bool {
    /* Check if our policy should match.
     */
    match check_policy(req, policy) {
        /* If the match failed, do not apply. */
        PolicyMatch::MatchFailed => return false,
        /* If there are no matches applied for this policy, check if any subpolicies match, and if
         * so, apply this policy too, otherwise fail.
         */
        PolicyMatch::NoMatch => {
            if !check_policies(req, &policy.policies) {
                return false;
            }
        }
        /* If there were matchers, and we matched them all, then continue with applying the policy.
         */
        PolicyMatch::MatchSucceeded => (),
    }

    /* If there are addresses provided here, override any from the parent */
    if let Some(address) = &policy.apply_address {
        response.address = Some(address.clone()); /* HELP: I tried to make the lifetimes worked, and failed */
    }

    /* Now get the list of parameters we will apply from the parameter list from the client.
     */
    // TODO: This should probably just be a u128 bitvector
    let pl: std::collections::HashSet<
        dhcppkt::DhcpOption,
        std::collections::hash_map::RandomState,
    > = req
        .pkt
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_PARAMLIST)
        .unwrap_or_default()
        .iter()
        .copied()
        .map(dhcppkt::DhcpOption::from)
        .collect();

    for (k, v) in &policy.apply_other {
        if pl.contains(k) {
            response.options.mutate_option(k, v.as_ref());
        }
    }

    /* And check to see if a subpolicy also matches */
    apply_policies(req, &policy.policies, response);

    /* Some of the defaults depend on what other options end up being set, so apply them here. */
    if let Some(subnet) = &policy.match_subnet {
        if pl.contains(&dhcppkt::OPTION_NETMASK) {
            response
                .options
                .mutate_option_default(&dhcppkt::OPTION_NETMASK, &subnet.netmask());
        }
        if pl.contains(&dhcppkt::OPTION_BROADCAST) {
            response
                .options
                .mutate_option_default(&dhcppkt::OPTION_BROADCAST, &subnet.broadcast());
        }
    }

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

#[derive(Default, Clone)]
struct ResponseOptions {
    /* Options can be unset (not specified), set to "None" (do not send), or set to a specific
     * value.
     */
    option: collections::HashMap<dhcppkt::DhcpOption, Option<Vec<u8>>>,
}

impl ResponseOptions {
    fn set_raw_option(mut self, option: &dhcppkt::DhcpOption, value: &[u8]) -> Self {
        self.option.insert(*option, Some(value.to_vec()));
        self
    }

    fn set_option<T: dhcppkt::Serialise>(self, option: &dhcppkt::DhcpOption, value: &T) -> Self {
        let mut v = Vec::new();
        value.serialise(&mut v);
        self.set_raw_option(option, &v)
    }

    pub fn mutate_option<T: dhcppkt::Serialise>(
        &mut self,
        option: &dhcppkt::DhcpOption,
        maybe_value: Option<&T>,
    ) {
        match maybe_value {
            Some(value) => {
                let mut v = Vec::new();
                value.serialise(&mut v);
                self.option.insert(*option, Some(v));
            }
            None => {
                self.option.insert(*option, None);
            }
        }
    }

    pub fn mutate_option_default<T: dhcppkt::Serialise>(
        &mut self,
        option: &dhcppkt::DhcpOption,
        value: &T,
    ) {
        if self.option.get(option).is_none() {
            self.mutate_option(option, Some(value));
        }
    }

    pub fn to_options(&self) -> dhcppkt::DhcpOptions {
        let mut opt = dhcppkt::DhcpOptions {
            ..Default::default()
        };
        for (k, v) in &self.option {
            if let Some(d) = v {
                opt.other.insert(*k, d.to_vec());
            }
        }
        opt
    }
}

#[derive(Default)]
struct Response {
    options: ResponseOptions,
    address: Option<pool::PoolAddresses>,
    minlease: Option<std::time::Duration>,
    maxlease: Option<std::time::Duration>,
}

fn handle_discover<'l>(
    pools: &mut pool::Pool,
    req: &DHCPRequest,
    _serverids: &ServerIds,
    base: &[config::Policy],
    conf: &'l super::config::Config,
) -> Result<dhcppkt::Dhcp, DhcpError> {
    /* Build the default response we are about to reply with, it will be filled in later */
    let mut response: Response = Response {
        options: ResponseOptions {
            ..Default::default()
        }
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPOFFER)
        .set_option(&dhcppkt::OPTION_SERVERID, &req.serverip),
        ..Default::default()
    };

    /* Now attempt to apply all the policies.*/
    let base_policy = apply_policies(req, base, &mut response);
    let conf_policy = apply_policies(req, &conf.dhcp.policies, &mut response);
    if !base_policy && !conf_policy {
        /* If none of the policies applied at all, then provide a warning back to the caller */
        Err(DhcpError::NoPolicyConfigured)
    } else if let Some(addresses) = response.address {
        /* At least one policy matched, and provided addresses.  So now go allocate an address */
        let mut raw_options = Vec::new();
        req.pkt.options.serialise(&mut raw_options);
        match pools.allocate_address(
            &req.pkt.get_client_id(),
            req.pkt.options.get_address_request(),
            &addresses,
            response.minlease.unwrap_or(pool::DEFAULT_MIN_LEASE),
            response.maxlease.unwrap_or(pool::DEFAULT_MAX_LEASE),
            &raw_options,
        ) {
            /* Now we have an address, build the reply */
            Ok(lease) => {
                DHCP_ALLOCATIONS
                    .with_label_values(&[&format!("{:?}", lease.lease_type)])
                    .inc();
                log::info!(
                    "Allocated Lease: {} for {:?} ({:?})",
                    lease.ip,
                    lease.expire,
                    lease.lease_type
                );

                Ok(dhcppkt::Dhcp {
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
                        .set_option(&dhcppkt::OPTION_SERVERID, &req.serverip)
                        .to_options(),
                })
            }
            /* Some error occurred, document it. */
            Err(e) => Err(DhcpError::PoolError(e)),
        }
    } else {
        /* There were no addresses assigned to this match */
        Err(DhcpError::NoLeasesConfigured)
    }
}

fn handle_request(
    pools: &mut pool::Pool,
    req: &DHCPRequest,
    serverids: &ServerIds,
    base: &[config::Policy],
    conf: &super::config::Config,
) -> Result<dhcppkt::Dhcp, DhcpError> {
    if let Some(si) = req.pkt.options.get_serverid() {
        if !serverids.contains(&si) {
            return Err(DhcpError::OtherServer(si));
        }
    }
    let mut response: Response = Response {
        options: ResponseOptions {
            ..Default::default()
        }
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPOFFER)
        .set_option(&dhcppkt::OPTION_SERVERID, &req.serverip),
        ..Default::default()
    };
    let base_policy = apply_policies(req, base, &mut response);
    let conf_policy = apply_policies(req, &conf.dhcp.policies, &mut response);
    if !base_policy && !conf_policy {
        Err(DhcpError::NoPolicyConfigured)
    } else if let Some(addresses) = response.address {
        let mut raw_options = Vec::new();
        req.pkt.options.serialise(&mut raw_options);
        match pools.allocate_address(
            &req.pkt.get_client_id(),
            if !req.pkt.ciaddr.is_unspecified() {
                Some(req.pkt.ciaddr)
            } else {
                req.pkt.options.get_address_request()
            },
            &addresses,
            response.minlease.unwrap_or(pool::DEFAULT_MIN_LEASE),
            response.maxlease.unwrap_or(pool::DEFAULT_MAX_LEASE),
            &raw_options,
        ) {
            Ok(lease) => {
                DHCP_ALLOCATIONS
                    .with_label_values(&[&format!("{:?}", lease.lease_type)])
                    .inc();
                log::info!(
                    "Allocated Lease: {} for {:?} ({:?})",
                    lease.ip,
                    lease.expire,
                    lease.lease_type
                );
                Ok(dhcppkt::Dhcp {
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
                        .set_option(&dhcppkt::OPTION_LEASETIME, &(lease.expire.as_secs() as u32))
                        .to_options(),
                })
            }
            Err(e) => Err(DhcpError::PoolError(e)),
        }
    } else {
        Err(DhcpError::NoLeasesConfigured)
    }
}

fn format_mac(v: &[u8]) -> String {
    v.iter()
        .map(|b| format!("{:0>2x}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn format_client(req: &dhcppkt::Dhcp) -> String {
    format!(
        "{} ({})",
        format_mac(&req.chaddr),
        String::from_utf8_lossy(
            &req.options
                .get_option::<Vec<u8>>(&dhcppkt::OPTION_HOSTNAME)
                .unwrap_or_default()
        ),
    )
}

fn log_options(req: &dhcppkt::Dhcp) {
    log::info!(
        "{}: Options: {}",
        format_client(req),
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
                    .unwrap_or_else(|| "<decode-failed>".into())
            ))
            .collect::<Vec<String>>()
            .join(" "),
    );
}

async fn log_pkt(request: &DHCPRequest, netinfo: &crate::net::netinfo::SharedNetInfo) {
    use std::fmt::Write as _;
    let mut s = "".to_string();
    write!(
        s,
        "{}: {} on {}",
        format_client(&request.pkt),
        request
            .pkt
            .options
            .get_messagetype()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "[unknown]".into()),
        netinfo.get_safe_name_by_ifidx(request.ifindex).await
    )
    .unwrap();
    if !request.serverip.is_unspecified() {
        write!(s, " ({})", request.serverip).unwrap();
    }
    if !request.pkt.ciaddr.is_unspecified() {
        write!(s, ", using {}", request.pkt.ciaddr).unwrap();
    }
    if !request.pkt.giaddr.is_unspecified() {
        write!(
            s,
            ", relayed via {} hops from {}",
            request.pkt.hops, request.pkt.giaddr
        )
        .unwrap();
    }
    log::info!("{}", s);
    log_options(&request.pkt);
    log::info!(
        "{}: Requested: {}",
        format_client(&request.pkt),
        request
            .pkt
            .options
            .get_option::<Vec<u8>>(&dhcppkt::OPTION_PARAMLIST)
            .map(|v| v
                .iter()
                .map(|&x| dhcppkt::DhcpOption::new(x))
                .map(|o| o.to_string())
                .collect::<Vec<String>>()
                .join(" "))
            .unwrap_or_else(|| "<none>".into())
    );
}

/// Produce a default configuration.
/// This builds a configuration that would look like:
/// ```yaml
/// # Always match the base configuration
/// match-all: true
/// # For top level settings, apply them.
/// apply-dns-servers: [ip4s]
/// apply-dns-search: [domains]
/// apply-captive-portal: captiveportal
/// policies:
///  # For each IPv4 prefix provided in the addresses top level config:
///  - match-subnet: prefix4
///    apply-subnet: prefix4 # with the current requestip removed.
/// ```
pub async fn build_default_config(
    conf: &crate::config::Config,
    request: &DHCPRequest,
) -> config::Policy {
    let mut default_policy = config::Policy {
        match_all: true, /* We always want this policy to match. */
        ..Default::default()
    };
    /* Add the default options from the top level configuration */
    default_policy.apply_other.insert(
        dhcppkt::OPTION_DOMAINSERVER,
        Some(dhcppkt::DhcpOptionTypeValue::IpList(
            conf.dns_servers
                .iter()
                .filter_map(|ip| match ip {
                    ip if *ip == config::INTERFACE4 => Some(request.serverip),
                    std::net::IpAddr::V4(ip4) => Some(*ip4),
                    _ => None,
                })
                .collect(),
        )),
    );
    default_policy.apply_other.insert(
        dhcppkt::OPTION_DOMAINSEARCH,
        Some(dhcppkt::DhcpOptionTypeValue::DomainList(
            conf.dns_search.clone(),
        )),
    );
    default_policy.apply_other.insert(
        dhcppkt::OPTION_CAPTIVEPORTAL,
        conf.captive_portal
            .clone()
            .map(dhcppkt::DhcpOptionTypeValue::String),
    );
    /* Now build some sub policies, for each address range */
    let all_addrs = conf.dhcp.get_all_used_addresses();
    default_policy.policies = conf
        .addresses
        .iter()
        .filter_map(|prefix| {
            if let super::config::Prefix::V4(p4) = prefix {
                use crate::config::Match as _;
                use crate::config::PrefixOps as _;
                let subnet = crate::net::Ipv4Subnet::new(p4.network(), p4.prefixlen).ok()?;
                let mut ret = config::Policy {
                    match_subnet: Some(subnet),
                    apply_address: Some(
                        (1..((1 << (32 - p4.prefixlen)) - 2))
                            .map(|offset| (u32::from(subnet.network()) + offset).into())
                            // TODO: This removes one IP from the list, it should also remove any
                            // others found on the local machine.  Probably fine for now, but
                            // likely to cause confusion in the future.
                            .filter(|ip4| *ip4 != request.serverip)
                            .collect::<pool::PoolAddresses>()
                            .sub(&all_addrs),
                    ),
                    ..Default::default()
                };
                /* If this is the interface the request is coming in, then we can do extra stuff */
                if p4.contains(request.serverip) {
                    // Add the MTU
                    // TODO: Perhaps don't send it if it's default?
                    if let Some(mtu) = request.if_mtu {
                        ret.apply_other.insert(
                            dhcppkt::OPTION_MTUIF,
                            Some(dhcppkt::DhcpOptionTypeValue::U16(mtu as u16)),
                        );
                    }
                    // Add the default route.
                    if let Some(route) = request.if_router {
                        ret.apply_other.insert(
                            dhcppkt::OPTION_ROUTERADDR,
                            Some(dhcppkt::DhcpOptionTypeValue::Ip(route)),
                        );
                    }
                }
                Some(ret)
            } else {
                None
            }
        })
        .collect();
    default_policy
}

pub async fn handle_pkt(
    pools: &mut pool::Pool,
    request: &DHCPRequest,
    serverids: ServerIds,
    conf: &super::config::Config,
) -> Result<dhcppkt::Dhcp, DhcpError> {
    match request.pkt.options.get_messagetype() {
        Some(dhcppkt::DHCPDISCOVER) => {
            let base = [build_default_config(conf, request).await];
            handle_discover(pools, request, &serverids, &base, conf)
        }
        Some(dhcppkt::DHCPREQUEST) => {
            let base = [build_default_config(conf, request).await];
            handle_request(pools, request, &serverids, &base, conf)
        }
        Some(x) => Err(DhcpError::UnknownMessageType(x)),
        None => Err(DhcpError::ParseError(dhcppkt::ParseError::InvalidPacket)),
    }
}

async fn send_raw(raw: Arc<raw::RawSocket>, buf: &[u8], intf: i32) -> Result<(), std::io::Error> {
    DHCP_TX_PACKETS.inc();
    raw.send_msg(
        buf,
        &raw::ControlMessage::new(),
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

enum RunError {
    ListenError(std::io::Error),
    RecvError(std::io::Error),
    Io(std::io::Error),
    PoolError(pool::Error),
}

impl ToString for RunError {
    fn to_string(&self) -> String {
        match self {
            RunError::Io(e) => format!("I/O Error in DHCP: {}", e),
            RunError::PoolError(e) => format!("DHCP Pool Error: {}", e),
            RunError::ListenError(e) => format!("Failed to listen on DHCP: {}", e),
            RunError::RecvError(e) => format!("Failed to receive a packet for DHCP: {}", e),
        }
    }
}

pub struct DhcpService {
    netinfo: crate::net::netinfo::SharedNetInfo,
    conf: crate::config::SharedConfig,
    rawsock: std::sync::Arc<crate::net::raw::RawSocket>,
    pool: std::sync::Arc<sync::Mutex<pool::Pool>>,
    serverids: SharedServerIds,
    listener: UdpSocket,
}

impl DhcpService {
    async fn recvdhcp(&self, pkt: &[u8], src: std::net::SocketAddr, intf: u32) {
        let raw = self.rawsock.clone();
        /* First, lets find the various metadata IP addresses */
        let ip4 = if let net::SocketAddr::V4(f) = src {
            f
        } else {
            DHCP_ERRORS
                .with_label_values(&["UNEXPECTED_IP_PROTOCOL"])
                .inc();
            log::warn!(
                "Query from unexpected source protocol ({:?}), ignoring.",
                src
            );
            return;
        };
        let optional_dst = self.netinfo.get_ipv4_by_ifidx(intf).await;
        if optional_dst.is_none() {
            log::warn!(
                "No IPv4 found on interface {}",
                self.netinfo.get_safe_name_by_ifidx(intf).await
            );
            DHCP_ERRORS
                .with_label_values(&["NO_IPV4_ON_INTERFACE"])
                .inc();
            return;
        }

        /* Now lets decode the packet, and if it fails decode, fail the function early */
        let req = match dhcppkt::parse(pkt) {
            Err(e) => {
                log::warn!("Failed to parse packet: {}", e);
                DHCP_ERRORS.with_label_values(&[e.get_variant_name()]).inc();
                return;
            }
            Ok(req) => req,
        };

        /* Log what we've got */
        let if_mtu = self.netinfo.get_mtu_by_ifidx(intf).await;
        let if_router = match self.netinfo.get_ipv4_default_route().await {
            /* If the default route points out a different interface, then this is the default route */
            Some((_, Some(rtridx))) if rtridx != intf => Some(optional_dst.unwrap()),
            /* If it's the same interface, then the default router should be the nexthop */
            Some((Some(nexthop), Some(rtridx))) if rtridx == intf => Some(nexthop),
            _ => None,
        };

        let request = DHCPRequest {
            pkt: req,
            serverip: optional_dst.unwrap(),
            ifindex: intf,
            if_mtu,
            if_router,
        };
        log_pkt(&request, &self.netinfo).await;

        /* Now, lets process the packet we've found */
        let reply;
        {
            /* Limit the amount of time we have these locked to just handling the packet */
            let mut pool = self.pool.lock().await;
            let lockedconf = self.conf.read().await;

            reply = match handle_pkt(
                &mut pool,
                &request,
                get_serverids(&self.serverids).await,
                &lockedconf,
            )
            .await
            {
                Err(e) => {
                    log::warn!(
                        "{}: Failed to handle {}: {}",
                        format_client(&request.pkt),
                        request
                            .pkt
                            .options
                            .get_messagetype()
                            .map(|x| x.to_string())
                            .unwrap_or_else(|| "packet".into()),
                        e
                    );
                    DHCP_ERRORS.with_label_values(&[e.get_variant_name()]).inc();
                    return;
                }
                Ok(r) => r,
            };
        }

        /* Now, we should have a packet ready to send */
        /* First, if we're claiming to be particular IP, we should remember that as an IP that is one
         * of ours
         */
        if let Some(si) = reply.options.get_serverid() {
            self.serverids.lock().await.insert(si);
        }

        /* Log what we're sending */
        log::info!(
            "{}: Sending {} on {} with {} for {}",
            format_client(&reply),
            reply
                .options
                .get_messagetype()
                .map(|x| x.to_string())
                .unwrap_or_else(|| "[unknown]".into()),
            self.netinfo
                .get_name_by_ifidx(intf)
                .await
                .unwrap_or_else(|| "<unknown if>".into()),
            reply.yiaddr,
            reply
                .options
                .get_option::<u32>(&dhcppkt::OPTION_LEASETIME)
                .unwrap_or(0)
        );
        log_options(&reply);

        /* Collect metadata ready to send */
        let srcll = if let Some(crate::net::netinfo::LinkLayer::Ethernet(srcll)) =
            self.netinfo.get_linkaddr_by_ifidx(intf).await
        {
            srcll
        } else {
            log::warn!("{}: Not a usable LinkLayer?!", format_client(&reply));
            DHCP_ERRORS.with_label_values(&["UNUSABLE_LINKLAYER"]).inc();
            return;
        };

        let chaddr = if let Some(chaddr) = to_array(&reply.chaddr) {
            chaddr
        } else {
            log::warn!(
                "{}: Cannot send reply to invalid client hardware addr {:?}",
                format_client(&reply),
                reply.chaddr
            );
            DHCP_ERRORS.with_label_values(&["INVALID_CHADDR"]).inc();
            return;
        };

        /* Construct the raw packet from the reply to send */
        let replybuf = reply.serialise();
        let etherbuf = packet::Fragment::new_udp(
            std::net::SocketAddrV4::new(request.serverip, 67),
            &srcll,
            ip4,
            &chaddr,
            packet::Tail::Payload(&replybuf),
        )
        .flatten();

        if let Err(e) = send_raw(raw, &etherbuf, intf.try_into().unwrap()).await {
            log::warn!("{}: Failed to send reply: {:?}", format_client(&reply), e);
            DHCP_ERRORS.with_label_values(&["SEND_ERROR"]).inc();
        }
    }

    async fn new_internal(
        netinfo: crate::net::netinfo::SharedNetInfo,
        conf: super::config::SharedConfig,
    ) -> Result<Self, RunError> {
        let rawsock =
            Arc::new(raw::RawSocket::new(raw::EthProto::ALL).map_err(RunError::ListenError)?);
        let pool = Arc::new(sync::Mutex::new(
            pool::Pool::new().map_err(RunError::PoolError)?,
        ));
        let serverids: SharedServerIds =
            Arc::new(sync::Mutex::new(std::collections::HashSet::new()));
        let listener = UdpSocket::bind(
            &tokio::net::lookup_host("0.0.0.0:67")
                .await
                .unwrap()
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(RunError::ListenError)?;
        listener
            .set_opt_ipv4_packet_info(true)
            .map_err(RunError::ListenError)?;
        listener
            .set_opt_reuse_port(true)
            .map_err(RunError::ListenError)?;
        log::info!(
            "Listening for DHCP on {}",
            listener.local_addr().map_err(RunError::Io)?
        );
        Ok(Self {
            netinfo,
            conf,
            rawsock,
            pool,
            serverids,
            listener,
        })
    }

    pub async fn new(
        netinfo: crate::net::netinfo::SharedNetInfo,
        conf: super::config::SharedConfig,
    ) -> Result<Self, String> {
        match Self::new_internal(netinfo, conf).await {
            Ok(x) => Ok(x),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn run_internal(
        self: &std::sync::Arc<Self>,
        listener: &UdpSocket,
    ) -> Result<(), RunError> {
        loop {
            let rm = match listener.recv_msg(65536, udp::MsgFlags::empty()).await {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(RunError::RecvError(e)),
            };
            DHCP_RX_PACKETS.inc();
            let self2 = self.clone();
            tokio::spawn(async move {
                self2
                    .recvdhcp(
                        &rm.buffer,
                        rm.address.unwrap(),
                        rm.local_intf().unwrap().try_into().unwrap(),
                    )
                    .await
            });
        }
    }

    pub async fn run(self: std::sync::Arc<Self>) -> Result<(), String> {
        match self.run_internal(&self.listener).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn update_metrics(self: &std::sync::Arc<Self>) {
        match self.pool.lock().await.get_pool_metrics() {
            Ok((in_use, expired)) => {
                DHCP_ACTIVE_LEASES.set(in_use.into());
                DHCP_EXPIRED_LEASES.set(expired.into());
            }
            Err(e) => log::warn!("Failed to update metrics: {}", e),
        }
    }

    pub async fn get_leases(self: &std::sync::Arc<Self>) -> Vec<pool::LeaseInfo> {
        let ret = self.pool.lock().await.get_leases();
        match ret {
            Ok(l) => l,
            Err(e) => {
                log::warn!("Failed to get leases: {}", e);
                Vec::new()
            }
        }
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
dhcp-policies:
  - match-subnet: 192.168.0.0/24
    apply-dns-servers: ['8.8.8.8', '8.8.4.4']
    apply-subnet: 192.168.0.0/24
    apply-time-offset: 3600
    apply-domain-name: erbium.dev
    apply-forward: false
    apply-mtu: 1500
    apply-broadcast: 192.168.255.255
    apply-rebind-time: 120
    apply-renewal-time: 90s
    apply-arp-timeout: 1w


    policies:
       - { match-host-name: myhost, apply-address: 192.168.0.1 }
       - { match-hardware-address: 00:01:02:03:04:05, apply-address: 192.168.0.2 }


  - match-interface: dmz
    apply-dns-servers: ['8.8.8.8']
    apply-subnet: 192.0.2.0/24

    # Reserve some space from the pool for servers
    policies:
      - apply-range: {start: 192.0.2.10, end: 192.0.2.20}

        # From the reserved pool, assign a static address.
        policies:
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
            pkt: dhcppkt::Dhcp {
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
            if_mtu: None,
            if_router: None,
        },
        &cfg.read().await.dhcp.policies,
        &mut resp,
    ) {
        panic!("No policies applied");
    }

    log::info!("{:?}", cfg.read().await);

    assert_eq!(
        resp.address,
        Some(
            [std::net::Ipv4Addr::new(192, 168, 0, 2)]
                .iter()
                .cloned()
                .collect()
        )
    );

    Ok(())
}

#[test]
fn test_format_client() {
    let req = dhcppkt::Dhcp {
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
    };
    assert_eq!(format_client(&req), "00:01:02:03:04:05 ()");
}

#[tokio::test]
async fn test_defaults() {
    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut pkt = test::mk_dhcp_request();
    pkt.pkt.options.mutate_option(
        &dhcppkt::OPTION_PARAMLIST,
        &vec![
            6u8, /* Domain Server */
            119, /* Domain Search */
            160, /* Captive Portal */
        ],
    );

    let serverids: ServerIds = ServerIds::new();
    let conf = crate::config::Config {
        dns_servers: vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ],
        dns_search: vec!["example.org".into()],
        captive_portal: Some("example.com".into()),
        ..test::mk_default_config()
    };
    let base = [build_default_config(&conf, &pkt).await];
    println!("base={:?}", base);
    let resp =
        handle_discover(&mut p, &pkt, &serverids, &base, &conf).expect("Failed to handle request");
    assert_eq!(
        resp.options
            .get_option::<Vec<std::net::Ipv4Addr>>(&dhcppkt::OPTION_DOMAINSERVER),
        Some(vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()])
    );
    println!(
        "{:?}",
        resp.options.get_raw_option(&dhcppkt::OPTION_CAPTIVEPORTAL)
    );
    assert_eq!(
        resp.options
            .get_option::<Vec<u8>>(&dhcppkt::OPTION_CAPTIVEPORTAL),
        Some(
            "example.com"
                .as_bytes()
                .iter()
                .copied()
                .collect::<Vec<u8>>()
        )
    );
    assert_eq!(
        resp.options
            .get_option::<Vec<String>>(&dhcppkt::OPTION_DOMAINSEARCH),
        Some(vec![String::from("example.org")])
    );
}

#[tokio::test]
async fn test_base() {
    let mut pool = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut pkt = test::mk_dhcp_request();
    pkt.pkt.options.mutate_option(
        &dhcppkt::OPTION_PARAMLIST,
        &vec![
            6u8, /* Domain Server */
            119, /* Domain Search */
            160, /* Captive Portal */
        ],
    );

    let serverids: ServerIds = ServerIds::new();
    let mut apply_address: pool::PoolAddresses = Default::default();
    apply_address.insert("192.0.2.3".parse().unwrap());
    let conf = crate::config::Config {
        dns_servers: vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ],
        dns_search: vec!["example.org".into()],
        captive_portal: Some("example.com".into()),
        addresses: vec![config::Prefix::V4(config::Prefix4 {
            addr: "192.0.2.0".parse().unwrap(),
            prefixlen: 24,
        })],
        dhcp: config::Config {
            policies: vec![config::Policy {
                match_chaddr: Some(vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5]),
                apply_address: Some(apply_address),
                ..Default::default()
            }],
        },
        ..Default::default()
    };
    let base = build_default_config(&conf, &pkt).await;
    /* The generated policy should not allocate 192.0.2.3, because that is allocated in the
     * custom dhcp policy provided.
     */
    assert!(!base.policies[0]
        .apply_address
        .as_ref()
        .unwrap()
        .contains(&"192.0.2.3".parse().unwrap()));
    println!("base={:#?}", base);
    println!("pkt={:?}", pkt);
    let resp = handle_discover(&mut pool, &pkt, &serverids, &[base], &conf)
        .expect("Failed to handle request");
    assert_eq!(
        resp.options
            .get_option::<Vec<std::net::Ipv4Addr>>(&dhcppkt::OPTION_DOMAINSERVER),
        Some(vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()])
    );
    println!(
        "{:?}",
        resp.options.get_raw_option(&dhcppkt::OPTION_CAPTIVEPORTAL)
    );
    assert_eq!(
        resp.options
            .get_option::<Vec<u8>>(&dhcppkt::OPTION_CAPTIVEPORTAL),
        Some(
            "example.com"
                .as_bytes()
                .iter()
                .copied()
                .collect::<Vec<u8>>()
        )
    );
    assert_eq!(
        resp.options
            .get_option::<Vec<String>>(&dhcppkt::OPTION_DOMAINSEARCH),
        Some(vec![String::from("example.org")])
    );
}

#[tokio::test]
/* There was a bug that if the suffix bits in the prefix were not 0, then it would silently ignore
 * the address.  Now we set them to 0 ourselves explicitly.
 */
async fn test_non_network_prefix() {
    let conf = crate::config::load_config_from_string_for_test(
        "---
addresses: [192.0.2.53/24]
",
    )
    .unwrap();

    let pkt = test::mk_dhcp_request();
    let base = build_default_config(&*conf.read().await, &pkt).await;

    let network = crate::net::Ipv4Subnet::new("192.0.2.0".parse().unwrap(), 24).unwrap();

    assert_eq!(base.policies[0].match_subnet.unwrap().addr, network.addr);
    assert_eq!(
        base.policies[0].match_subnet.unwrap().prefixlen,
        network.prefixlen
    );
}
