/*   Copyright 2024 Perry Lorier
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
 *  API for finding out information about interfaces.
 *  Currently uses netlink, but ideally should eventually be generalised for other platforms.
 */
use netlink_packet_core::constants::*;
use netlink_packet_core::NetlinkPayload::InnerMessage;
use netlink_packet_core::*;
use netlink_packet_route::RouteNetlinkMessage::*;
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    link::{LinkAttribute, LinkFlag, LinkLayerType, LinkMessage},
    route::{RouteAddress, RouteAttribute, RouteMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::TokioSocket as Socket;
use netlink_sys::{protocols, AsyncSocket as _, AsyncSocketExt as _, SocketAddr};

// These were removed in https://github.com/rust-netlink/netlink-packet-route/commit/88b1348cc0a257c55e520cae3bde3c66d5bc65a3 with no obvious replacement.
// I imagine that .add_membership() will eventually be cleaned up to require some new type and
// these will be redundant then.
const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV4_ROUTE: u32 = 7;
const RTNLGRP_IPV6_IFADDR: u32 = 9;
const RTNLGRP_IPV6_ROUTE: u32 = 11;

#[cfg(not(test))]
use log::{trace, warn};

#[cfg(test)]
use {println as trace, println as warn};

#[derive(Clone, PartialEq, Eq)]
pub enum LinkLayer {
    Ethernet([u8; 6]),
    None,
}

impl std::fmt::Debug for LinkLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            LinkLayer::Ethernet(e) => write!(
                f,
                "Ethernet({})",
                e.iter()
                    .map(|b| format!("{:0>2x}", b))
                    .collect::<Vec<String>>()
                    .join(":")
            ),
            LinkLayer::None => write!(f, "None"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IfFlags(Vec<LinkFlag>);

impl IfFlags {
    pub fn has_multicast(&self) -> bool {
        self.0.iter().any(|&x| x == LinkFlag::Multicast)
    }
}

#[derive(Debug)]
struct IfInfo {
    name: String,
    addresses: Vec<(std::net::IpAddr, u8)>,
    lladdr: LinkLayer,
    mtu: u32,
    //operstate: netlink_packet_route::rtnl::link::nlas::link_state::State, // Is private
    flags: IfFlags,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RouteInfo {
    pub addr: std::net::IpAddr,
    pub prefixlen: u8,
    pub oifidx: Option<u32>,
    pub nexthop: Option<std::net::IpAddr>,
}

impl std::fmt::Display for RouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefixlen)?;
        if let Some(nexthop) = self.nexthop {
            write!(f, " via {}", nexthop)?;
        }
        if let Some(oifidx) = self.oifidx {
            write!(f, " dev if#{}", oifidx)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct NetInfo {
    name2idx: std::collections::HashMap<String, u32>,
    intf: std::collections::HashMap<u32, IfInfo>,
    routeinfo: Vec<RouteInfo>,
}

impl NetInfo {
    fn new() -> Self {
        NetInfo {
            name2idx: std::collections::HashMap::new(),
            intf: std::collections::HashMap::new(),
            routeinfo: vec![],
        }
    }
    fn add_interface(&mut self, ifidx: u32, ifinfo: IfInfo) {
        self.name2idx.insert(ifinfo.name.clone(), ifidx);
        self.intf.insert(ifidx, ifinfo);
    }
}

#[derive(Clone)]
pub struct SharedNetInfo(std::sync::Arc<tokio::sync::RwLock<NetInfo>>);

struct NetLinkNetInfo {}

impl NetLinkNetInfo {
    fn decode_linklayer(linktype: LinkLayerType, addr: &[u8]) -> LinkLayer {
        match linktype {
            LinkLayerType::Ether => {
                LinkLayer::Ethernet([addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]])
            }
            LinkLayerType::Loopback => LinkLayer::None,
            LinkLayerType::Sit => LinkLayer::None, // Actually this is a IpAddr, but we don't do DHCP over it, so...
            l => {
                warn!("Unknown Linklayer: {:?}", l);
                LinkLayer::None
            }
        }
    }

    fn parse_addr(addr: &AddressMessage) -> (std::net::IpAddr, u8) {
        let mut ifaddr = None;
        let ifprefixlen = addr.header.prefix_len;
        for i in &addr.attributes {
            if let AddressAttribute::Address(a) = i {
                ifaddr = Some(*a)
            }
        }
        (ifaddr.unwrap(), ifprefixlen)
    }

    async fn process_newaddr(ni: &SharedNetInfo, addr: &AddressMessage) {
        let ifindex = addr.header.index;
        let ifaddr = NetLinkNetInfo::parse_addr(addr);
        let mut ni = ni.0.write().await;
        let ii = ni.intf.get_mut(&ifindex).unwrap(); // TODO: Error?
        if !ii.addresses.contains(&ifaddr) {
            /* It's common to renew IPv6 addresses, don't treat them as new if
             * the address already exists.
             */
            ii.addresses.push(ifaddr);
            let (ip, prefixlen) = ifaddr;
            trace!(
                "Found addr {}/{} for {}(#{}), now {:?}",
                ip,
                prefixlen,
                ii.name,
                ifindex,
                ii.addresses
            );
        }
    }

    async fn process_deladdr(sni: &SharedNetInfo, addr: &AddressMessage) {
        let ifindex = addr.header.index;
        let ifaddr = NetLinkNetInfo::parse_addr(addr);
        let mut ni = sni.0.write().await;
        let ii = ni.intf.get_mut(&ifindex).unwrap(); // TODO: Error?
        ii.addresses.retain(|&x| x != ifaddr);
        let (ip, prefixlen) = ifaddr;
        trace!(
            "Lost addr {}/{} for {}(#{}), now {:?}",
            ip,
            prefixlen,
            ii.name,
            ifindex,
            ii.addresses
        );
    }

    async fn process_newlink(sni: &SharedNetInfo, link: &LinkMessage) {
        let mut ifname: Option<String> = None;
        let mut ifmtu: Option<u32> = None;
        let mut ifaddr = None;
        let ifflags = link.header.flags.clone();
        let ifidx = link.header.index;
        for i in &link.attributes {
            match i {
                LinkAttribute::IfName(name) => ifname = Some(name.clone()),
                LinkAttribute::Mtu(mtu) => ifmtu = Some(*mtu),
                LinkAttribute::Address(addr) => ifaddr = Some(addr.clone()),
                _ => (),
            }
        }
        let ifaddr = ifaddr.map_or(LinkLayer::None, |x| {
            NetLinkNetInfo::decode_linklayer(link.header.link_layer_type, &x)
        });

        let mut netinfo = sni.0.write().await;
        /* This might be an update to an existing interface.
         * (eg the interface might be changing it's oper state from down/up etc.
         * So preserve some information.
         */
        let old_ifinfo = netinfo.intf.remove(&ifidx);
        let (old_name, old_addresses, old_mtu) = old_ifinfo
            .map(|x| (Some(x.name), Some(x.addresses), Some(x.mtu)))
            .unwrap_or((None, None, None));
        let ifinfo = IfInfo {
            name: ifname.or(old_name).expect("Interface with unknown name"),
            mtu: ifmtu.or(old_mtu).expect("Interface missing MTU"),
            addresses: old_addresses.unwrap_or_default(),
            lladdr: ifaddr,
            flags: IfFlags(ifflags),
        };

        trace!(
            "Found new interface {}(#{}) {:?} ({:?})",
            ifinfo.name,
            ifidx,
            ifinfo,
            link
        );
        netinfo.add_interface(ifidx, ifinfo);
    }

    fn decode_route(route: &RouteMessage) -> Option<RouteInfo> {
        let mut destination = None;
        let mut oifidx = None;
        let mut gateway = None;
        for nla in &route.attributes {
            match nla {
                RouteAttribute::Destination(dest) => {
                    destination = match dest {
                        RouteAddress::Inet(addr) => Some((*addr).into()),
                        RouteAddress::Inet6(addr) => Some((*addr).into()),
                        f => panic!("Unexpected family {:?}", f),
                    }
                }
                RouteAttribute::Gateway(via) => {
                    gateway = match via {
                        RouteAddress::Inet(addr) => Some((*addr).into()),
                        RouteAddress::Inet6(addr) => Some((*addr).into()),
                        f => panic!("Unexpected family {:?}", f),
                    }
                }
                RouteAttribute::Oif(oif) => oifidx = Some(oif),
                RouteAttribute::Table(254) => (),
                RouteAttribute::Table(_) => return None, /* Skip routes that are not in the "main" table */
                _ => (),                                 /* Ignore unknown nlas */
            }
        }
        Some(RouteInfo {
            addr: destination.unwrap_or_else(|| match route.header.address_family {
                AddressFamily::Inet => "0.0.0.0".parse().unwrap(),
                AddressFamily::Inet6 => "::".parse().unwrap(),
                _ => unreachable!(),
            }),
            prefixlen: route.header.destination_prefix_length,
            oifidx: oifidx.copied(),
            nexthop: gateway,
        })
    }

    async fn process_newroute(sni: &SharedNetInfo, route: &RouteMessage) {
        if let Some(ri) = NetLinkNetInfo::decode_route(route) {
            trace!("New Route: {}", ri);
            sni.0.write().await.routeinfo.push(ri);
        }
    }

    async fn process_delroute(sni: &SharedNetInfo, route: &RouteMessage) {
        if let Some(ri) = NetLinkNetInfo::decode_route(route) {
            trace!("Del Route: {}", ri);
            /* We basically assume there will only ever be one route for each prefix.
             * We'd have to be a lot more careful if we were to support multiple routes to a
             * particular prefix
             */
            sni.0.write().await.routeinfo.retain(|r| *r != ri);
        }
    }

    async fn send_linkdump(socket: &mut Socket, seq: &mut u32) {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        hdr.sequence_number = *seq;
        let mut packet = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetLink(LinkMessage::default())),
        );
        *seq += 1;

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        // Before calling serialize, it is important to check that the buffer in which we're emitting is big
        // enough for the packet, other `serialize()` panics.

        assert!(buf.len() == packet.buffer_len());

        packet.serialize(&mut buf[..]);

        socket.socket_mut().add_membership(RTNLGRP_LINK).unwrap();

        if let Err(e) = socket.send(&buf[..]).await {
            warn!("SEND ERROR {}", e);
        }
    }

    async fn send_routedump(socket: &mut Socket, seq: &mut u32, address_family: u8) {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        hdr.sequence_number = *seq;
        let mut rmsg = RouteMessage::default();
        rmsg.header.address_family = netlink_packet_route::AddressFamily::Other(address_family);
        let mut packet = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetRoute(rmsg)),
        );

        *seq += 1;

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        // Before calling serialize, it is important to check that the buffer in which we're emitting is big
        // enough for the packet, other `serialize()` panics.

        assert!(buf.len() == packet.buffer_len());

        packet.serialize(&mut buf[..]);

        match address_family.into() {
            AddressFamily::Inet => socket
                .socket_mut()
                .add_membership(RTNLGRP_IPV4_ROUTE)
                .unwrap(),
            AddressFamily::Inet6 => socket
                .socket_mut()
                .add_membership(RTNLGRP_IPV6_ROUTE)
                .unwrap(),
            _ => unreachable!(),
        }

        if let Err(e) = socket.send(&buf[..]).await {
            warn!("SEND ERROR {}", e);
        }
    }

    async fn send_addrdump(socket: &mut Socket, seq: &mut u32) {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        hdr.sequence_number = *seq;

        let mut amsg = AddressMessage::default();
        amsg.header.family = AddressFamily::Packet;

        let mut packet = NetlinkMessage::new(
            hdr,
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetAddress(amsg)),
        );

        *seq += 1;

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        // Before calling serialize, it is important to check that the buffer in which we're emitting is big
        // enough for the packet, other `serialize()` panics.

        assert!(buf.len() == packet.buffer_len());

        packet.serialize(&mut buf[..]);

        socket
            .socket_mut()
            .add_membership(RTNLGRP_IPV4_IFADDR)
            .unwrap();
        socket
            .socket_mut()
            .add_membership(RTNLGRP_IPV6_IFADDR)
            .unwrap();

        if let Err(e) = socket.send(&buf[..]).await {
            warn!("SEND ERROR {}", e);
        }
    }

    async fn process_message(
        sni: &SharedNetInfo,
        rx_packet: &NetlinkMessage<RouteNetlinkMessage>,
    ) -> bool {
        match &rx_packet.payload {
            InnerMessage(NewLink(link)) => {
                NetLinkNetInfo::process_newlink(sni, link).await;
                false
            }
            InnerMessage(NewAddress(addr)) => {
                NetLinkNetInfo::process_newaddr(sni, addr).await;
                false
            }
            InnerMessage(DelAddress(addr)) => {
                NetLinkNetInfo::process_deladdr(sni, addr).await;
                false
            }
            InnerMessage(NewRoute(route)) => {
                NetLinkNetInfo::process_newroute(sni, route).await;
                false
            }
            InnerMessage(DelRoute(route)) => {
                NetLinkNetInfo::process_delroute(sni, route).await;
                false
            }
            NetlinkPayload::Done(_) => true,
            e => {
                warn!("Unknown: {:?}", e);
                false
            }
        }
    }

    async fn run(sni: SharedNetInfo, chan: tokio::sync::mpsc::Sender<()>) {
        let mut socket = Socket::new(protocols::NETLINK_ROUTE).unwrap();
        let mut seq = 1;
        socket.socket_mut().connect(&SocketAddr::new(0, 0)).unwrap();

        NetLinkNetInfo::send_linkdump(&mut socket, &mut seq).await;
        enum State {
            ReadingLink,
            ReadingAddr,
            ReadingRoute4,
            ReadingRoute6,
            Done,
        }
        let mut state = State::ReadingLink;
        // we set the NLM_F_DUMP flag so we expect a multipart rx_packet in response.
        while let Ok((pkt, _)) = socket.recv_from_full().await {
            let mut offset = 0;
            while offset < pkt.len() {
                let rx_packet =
                    <NetlinkMessage<RouteNetlinkMessage>>::deserialize(&pkt[offset..]).unwrap();
                offset += rx_packet.header.length as usize;

                if NetLinkNetInfo::process_message(&sni, &rx_packet).await {
                    match state {
                        State::ReadingLink => {
                            trace!("Finished Link");
                            NetLinkNetInfo::send_addrdump(&mut socket, &mut seq).await;
                            state = State::ReadingAddr
                        }
                        State::ReadingAddr => {
                            trace!("Finished Addr");
                            NetLinkNetInfo::send_routedump(
                                &mut socket,
                                &mut seq,
                                AddressFamily::Inet.into(),
                            )
                            .await;
                            state = State::ReadingRoute4
                        }
                        State::ReadingRoute4 => {
                            trace!("Finished Route4");
                            NetLinkNetInfo::send_routedump(
                                &mut socket,
                                &mut seq,
                                AddressFamily::Inet6.into(),
                            )
                            .await;
                            state = State::ReadingRoute6
                        }
                        State::ReadingRoute6 => {
                            // Try and inform anyone listening that we have completed.
                            // But if it fails, don't worry, we'll send another one soonish.
                            trace!("Finished Route6");
                            let _ = chan.try_send(());
                            state = State::Done
                        }
                        State::Done => {}
                    }
                }
            }
        }
    }
}

impl SharedNetInfo {
    pub async fn new() -> Self {
        let (s, mut c) = tokio::sync::mpsc::channel::<()>(1);
        let shared = SharedNetInfo(std::sync::Arc::new(
            tokio::sync::RwLock::new(NetInfo::new()),
        ));
        tokio::spawn(NetLinkNetInfo::run(shared.clone(), s));
        // We want to block and wait until all the data is loaded, otherwise we'll cause confusion.
        c.recv().await;
        shared
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        let mut ni = NetInfo::new();
        ni.add_interface(
            0,
            IfInfo {
                name: "lo".into(),
                addresses: vec![("127.0.0.1".parse().unwrap(), 8)],
                lladdr: LinkLayer::None,
                mtu: 65536,
                flags: IfFlags(vec![LinkFlag::Multicast]),
            },
        );
        ni.add_interface(
            1,
            IfInfo {
                name: "eth0".into(),
                addresses: vec![("192.0.2.254".parse().unwrap(), 24)],
                lladdr: LinkLayer::Ethernet([0x00, 0x00, 0x5E, 0x00, 0x53, 0xFF]),
                mtu: 1500,
                flags: IfFlags(vec![LinkFlag::Multicast]),
            },
        );
        SharedNetInfo(std::sync::Arc::new(tokio::sync::RwLock::new(ni)))
    }

    #[allow(dead_code)]
    pub async fn get_interfaces(&self) -> Vec<String> {
        self.0
            .read()
            .await
            .intf
            .values()
            .map(|x| x.name.clone())
            .collect()
    }

    pub async fn get_ifindexes(&self) -> Vec<u32> {
        self.0.read().await.intf.keys().copied().collect()
    }

    pub async fn get_linkaddr_by_ifidx(&self, ifidx: u32) -> Option<LinkLayer> {
        self.0
            .read()
            .await
            .intf
            .get(&ifidx)
            .map(|x| x.lladdr.clone())
    }

    pub async fn get_if_prefixes(&self) -> Vec<(std::net::IpAddr, u8)> {
        self.0
            .read()
            .await
            .intf
            .iter()
            .flat_map(|(_ifidx, x)| x.addresses.clone())
            .collect()
    }

    pub async fn get_prefixes_by_ifidx(&self, ifidx: u32) -> Option<Vec<(std::net::IpAddr, u8)>> {
        self.0
            .read()
            .await
            .intf
            .get(&ifidx)
            .map(|x| x.addresses.clone())
    }

    pub async fn get_ipv4_by_ifidx(&self, ifidx: u32) -> Option<std::net::Ipv4Addr> {
        self.get_prefixes_by_ifidx(ifidx)
            .await
            .and_then(|prefixes| {
                prefixes
                    .iter()
                    .filter_map(|(prefix, _prefixlen)| {
                        if let std::net::IpAddr::V4(addr) = prefix {
                            Some(addr)
                        } else {
                            None
                        }
                    })
                    .copied()
                    .next()
            })
    }
    pub async fn get_mtu_by_ifidx(&self, ifidx: u32) -> Option<u32> {
        self.0.read().await.intf.get(&ifidx).map(|x| x.mtu)
    }
    pub async fn get_name_by_ifidx(&self, ifidx: u32) -> Option<String> {
        self.0.read().await.intf.get(&ifidx).map(|x| x.name.clone())
    }
    pub async fn get_safe_name_by_ifidx(&self, ifidx: u32) -> String {
        match self.get_name_by_ifidx(ifidx).await {
            Some(ifname) => ifname,
            None => format!("if#{}", ifidx),
        }
    }
    pub async fn get_flags_by_ifidx(&self, ifidx: u32) -> Option<IfFlags> {
        self.0
            .read()
            .await
            .intf
            .get(&ifidx)
            .map(|x| x.flags.clone())
    }

    pub async fn get_ipv4_default_route(
        &self,
    ) -> Option<(Option<std::net::Ipv4Addr>, Option<u32>)> {
        self.0.read().await.routeinfo.iter().find_map(|ri| {
            if ri.prefixlen == 0 && ri.addr.is_ipv4() {
                Some((
                    if let Some(std::net::IpAddr::V4(nexthop)) = ri.nexthop {
                        Some(nexthop)
                    } else {
                        None
                    },
                    ri.oifidx,
                ))
            } else {
                None
            }
        })
    }

    pub async fn get_ipv6_default_route(
        &self,
    ) -> Option<(Option<std::net::Ipv6Addr>, Option<u32>)> {
        self.0.read().await.routeinfo.iter().find_map(|ri| {
            if ri.prefixlen == 0 && ri.addr.is_ipv6() {
                Some((
                    if let Some(std::net::IpAddr::V6(nexthop)) = ri.nexthop {
                        Some(nexthop)
                    } else {
                        None
                    },
                    ri.oifidx,
                ))
            } else {
                None
            }
        })
    }
}

#[tokio::test]
async fn test_interface() {
    const IFIDX: u32 = 10;
    let ni = SharedNetInfo::new_for_test();
    let mut hdr = NetlinkHeader::default();
    hdr.sequence_number = 1;
    let mut lmsg = LinkMessage::default();
    lmsg.header.index = IFIDX;
    lmsg.header.link_layer_type = LinkLayerType::Ether;
    lmsg.attributes = vec![
        LinkAttribute::IfName("test1".into()),
        LinkAttribute::Mtu(1500),
        LinkAttribute::Address(vec![0x00, 0x53, 0x00, 0x00, 0x00, 0x00]),
        LinkAttribute::Broadcast(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ];
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage::new(
            hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewLink(lmsg)),
        ),
    )
    .await;
    hdr.sequence_number = 2;
    let mut amsg = AddressMessage::default();
    amsg.header.index = IFIDX;
    amsg.header.family = AddressFamily::Inet;
    amsg.header.prefix_len = 24;
    amsg.attributes = vec![AddressAttribute::Address("192.0.2.1".parse().unwrap())];
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage::new(
            hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewAddress(amsg)),
        ),
    )
    .await;
    let mut a6msg = AddressMessage::default();
    a6msg.header.index = IFIDX;
    a6msg.header.family = AddressFamily::Inet6;
    a6msg.header.prefix_len = 24;
    a6msg.attributes = vec![AddressAttribute::Address("2001:db8::".parse().unwrap())];
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage::new(
            hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewAddress(a6msg)),
        ),
    )
    .await;
    assert!(ni.get_interfaces().await.contains(&"test1".into()));
    assert_eq!(
        ni.get_ipv4_by_ifidx(IFIDX).await,
        Some(std::net::Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(ni.get_mtu_by_ifidx(IFIDX).await, Some(1500));
    assert_eq!(ni.get_name_by_ifidx(IFIDX).await, Some("test1".to_string()));
    assert_eq!(
        ni.get_linkaddr_by_ifidx(IFIDX).await,
        Some(LinkLayer::Ethernet([0x00, 0x53, 0x00, 0x00, 0x00, 0x00]))
    );
    /* It's common to get a second NewLink, make sure we preserve the addresses */
    hdr.sequence_number = 1;
    let mut lmsg = LinkMessage::default();
    lmsg.header.index = IFIDX;
    lmsg.header.link_layer_type = LinkLayerType::Ether;
    lmsg.attributes = vec![
        LinkAttribute::IfName("test1".into()),
        LinkAttribute::Mtu(1501),
        LinkAttribute::Address(vec![0x00, 0x53, 0x00, 0x00, 0x00, 0x01]),
        LinkAttribute::Broadcast(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]),
    ];
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage::new(
            hdr,
            NetlinkPayload::from(RouteNetlinkMessage::NewLink(lmsg)),
        ),
    )
    .await;
    /* Did this disturb the data that was already there? */
    assert_eq!(
        {
            let mut v = ni.get_interfaces().await;
            v.sort();
            v
        },
        vec!["eth0".to_string(), "lo".to_string(), "test1".to_string()]
    );
    assert_eq!(
        ni.get_ipv4_by_ifidx(IFIDX).await,
        Some(std::net::Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(ni.get_mtu_by_ifidx(IFIDX).await, Some(1501));
    assert_eq!(ni.get_name_by_ifidx(IFIDX).await, Some("test1".to_string()),);
    assert_eq!(
        ni.get_linkaddr_by_ifidx(IFIDX).await,
        Some(LinkLayer::Ethernet([0x00, 0x53, 0x00, 0x00, 0x00, 0x01]))
    );
}

#[tokio::test]
async fn test_netinfo_startup() {
    // Initialise netinfo and make sure it doesn't block indefinately on startup.
    println!("about to start");
    let _ = SharedNetInfo::new().await;
    println!("new complete");
}
