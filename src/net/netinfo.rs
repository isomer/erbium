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
 *  API for finding out information about interfaces.
 *  Currently uses netlink, but ideally should eventually be generalised for other platforms.
 */
use netlink_packet_route::AddressHeader;
use netlink_packet_route::NetlinkPayload::InnerMessage;
use netlink_packet_route::RtnlMessage::*;
use netlink_packet_route::{
    constants::*, AddressMessage, LinkMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    RouteMessage, RtnlMessage,
};
use netlink_sys::TokioSocket as Socket;
use netlink_sys::{protocols, SocketAddr};

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

#[derive(Debug, Clone, Copy)]
pub struct IfFlags(u32);

impl IfFlags {
    pub const fn has_multicast(&self) -> bool {
        self.0 & IFF_MULTICAST != 0
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

fn convert_address(addr: &[u8], family: u16) -> std::net::IpAddr {
    match family {
        AF_INET => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
        }
        AF_INET6 => std::net::IpAddr::V6(
            [
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], addr[8],
                addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
            ]
            .into(),
        ),
        x => panic!("Unknown address family {:?}", x),
    }
}

struct NetLinkNetInfo {}

impl NetLinkNetInfo {
    fn decode_linklayer(linktype: u16, addr: &[u8]) -> LinkLayer {
        match linktype {
            ARPHRD_ETHER => {
                LinkLayer::Ethernet([addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]])
            }
            ARPHRD_LOOPBACK => LinkLayer::None,
            ARPHRD_SIT => LinkLayer::None, // Actually this is a IpAddr, but we don't do DHCP over it, so...
            l => {
                log::warn!("Unknown Linklayer: {:?}", l);
                LinkLayer::None
            }
        }
    }

    fn parse_addr(addr: &AddressMessage) -> (std::net::IpAddr, u8) {
        use netlink_packet_route::address::nlas::Nla::*;
        let mut ifaddr = None;
        let iffamily = addr.header.family;
        let ifprefixlen = addr.header.prefix_len;
        for i in &addr.nlas {
            if let Address(a) = i {
                ifaddr = Some(convert_address(a, iffamily.into()));
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
            log::trace!(
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
        log::trace!(
            "Lost addr {}/{} for {}(#{}), now {:?}",
            ip,
            prefixlen,
            ii.name,
            ifindex,
            ii.addresses
        );
    }

    async fn process_newlink(sni: &SharedNetInfo, link: &LinkMessage) {
        use netlink_packet_route::link::nlas::Nla::*;
        let mut ifname: Option<String> = None;
        let mut ifmtu: Option<u32> = None;
        let mut ifaddr = None;
        let ifflags = link.header.flags;
        let ifidx = link.header.index;
        for i in &link.nlas {
            match i {
                IfName(name) => ifname = Some(name.clone()),
                Mtu(mtu) => ifmtu = Some(*mtu),
                Address(addr) => ifaddr = Some(addr.clone()),
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

        log::trace!(
            "Found new interface {}(#{}) {:?} ({:?})",
            ifinfo.name,
            ifidx,
            ifinfo,
            link
        );
        netinfo.add_interface(ifidx, ifinfo);
    }

    fn decode_route(route: &RouteMessage) -> Option<RouteInfo> {
        use netlink_packet_route::rtnl::nlas::route::Nla::*;
        use std::convert::TryFrom as _;
        let mut destination = None;
        let mut oifidx = None;
        let mut gateway = None;
        for nla in &route.nlas {
            match nla {
                Destination(dest) => {
                    destination = match route.header.address_family as u16 {
                        AF_INET => <[u8; 4]>::try_from(&dest[..])
                            .map(std::net::IpAddr::from)
                            .ok(),
                        AF_INET6 => <[u8; 16]>::try_from(&dest[..])
                            .map(std::net::IpAddr::from)
                            .ok(),
                        f => panic!("Unexpected family {}", f),
                    }
                }
                Gateway(via) => {
                    gateway = match route.header.address_family as u16 {
                        AF_INET => <[u8; 4]>::try_from(&via[..])
                            .map(std::net::IpAddr::from)
                            .ok(),
                        AF_INET6 => <[u8; 16]>::try_from(&via[..])
                            .map(std::net::IpAddr::from)
                            .ok(),
                        f => panic!("Unexpected family {}", f),
                    }
                }
                Oif(oif) => oifidx = Some(oif),
                Table(254) => (),
                Table(_) => return None, /* Skip routes that are not in the "main" table */
                _ => (),                 /* Ignore unknown nlas */
            }
        }
        Some(RouteInfo {
            addr: destination.unwrap_or_else(|| match route.header.address_family as u16 {
                AF_INET => "0.0.0.0".parse().unwrap(),
                AF_INET6 => "::".parse().unwrap(),
                _ => unreachable!(),
            }),
            prefixlen: route.header.destination_prefix_length,
            oifidx: oifidx.copied(),
            nexthop: gateway,
        })
    }

    async fn process_newroute(sni: &SharedNetInfo, route: &RouteMessage) {
        if let Some(ri) = NetLinkNetInfo::decode_route(route) {
            log::trace!("New Route: {}", ri);
            sni.0.write().await.routeinfo.push(ri);
        }
    }

    async fn process_delroute(sni: &SharedNetInfo, route: &RouteMessage) {
        if let Some(ri) = NetLinkNetInfo::decode_route(route) {
            log::trace!("Del Route: {}", ri);
            /* We basically assume there will only ever be one route for each prefix.
             * We'd have to be a lot more careful if we were to support multiple routes to a
             * particular prefix
             */
            sni.0.write().await.routeinfo.retain(|r| *r != ri);
        }
    }

    async fn send_linkdump(socket: &mut Socket, seq: &mut u32) {
        let mut packet = NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_DUMP,
                sequence_number: *seq,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::GetLink(LinkMessage::default())),
        };
        *seq += 1;

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        // Before calling serialize, it is important to check that the buffer in which we're emitting is big
        // enough for the packet, other `serialize()` panics.

        assert!(buf.len() == packet.buffer_len());

        packet.serialize(&mut buf[..]);

        socket.add_membership(RTNLGRP_LINK).unwrap();

        if let Err(e) = socket.send(&buf[..]).await {
            log::warn!("SEND ERROR {}", e);
        }
    }

    async fn send_routedump(socket: &mut Socket, seq: &mut u32, address_family: u8) {
        use netlink_packet_route::RouteHeader;
        let mut packet = NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_DUMP,
                sequence_number: *seq,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::GetRoute(RouteMessage {
                header: RouteHeader {
                    address_family,
                    ..Default::default()
                },
                ..Default::default()
            })),
        };

        *seq += 1;

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        // Before calling serialize, it is important to check that the buffer in which we're emitting is big
        // enough for the packet, other `serialize()` panics.

        assert!(buf.len() == packet.buffer_len());

        packet.serialize(&mut buf[..]);

        match address_family as u16 {
            AF_INET => socket.add_membership(RTNLGRP_IPV4_ROUTE).unwrap(),
            AF_INET6 => socket.add_membership(RTNLGRP_IPV6_ROUTE).unwrap(),
            _ => unreachable!(),
        }

        if let Err(e) = socket.send(&buf[..]).await {
            log::warn!("SEND ERROR {}", e);
        }
    }

    async fn send_addrdump(socket: &mut Socket, seq: &mut u32) {
        let mut packet = NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_DUMP,
                sequence_number: *seq,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::GetAddress(AddressMessage {
                header: AddressHeader {
                    family: AF_PACKET as u8,
                    ..Default::default()
                },
                ..Default::default()
            })),
        };

        *seq += 1;

        packet.finalize();

        let mut buf = vec![0; packet.header.length as usize];

        // Before calling serialize, it is important to check that the buffer in which we're emitting is big
        // enough for the packet, other `serialize()` panics.

        assert!(buf.len() == packet.buffer_len());

        packet.serialize(&mut buf[..]);

        socket.add_membership(RTNLGRP_IPV4_IFADDR).unwrap();
        socket.add_membership(RTNLGRP_IPV6_IFADDR).unwrap();

        if let Err(e) = socket.send(&buf[..]).await {
            log::warn!("SEND ERROR {}", e);
        }
    }

    async fn process_message(sni: &SharedNetInfo, rx_packet: &NetlinkMessage<RtnlMessage>) -> bool {
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
            NetlinkPayload::Done => true,
            e => {
                log::warn!("Unknown: {:?}", e);
                false
            }
        }
    }

    async fn run(sni: SharedNetInfo, chan: tokio::sync::mpsc::Sender<()>) {
        let mut socket = Socket::new(protocols::NETLINK_ROUTE).unwrap();
        let _port_number = socket.bind_auto().unwrap().port_number();
        let mut seq = 1;
        socket.connect(&SocketAddr::new(0, 0)).unwrap();

        let mut receive_buffer = vec![0; 4096];
        let mut offset = 0;

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
        while let Ok(size) = socket.recv(&mut receive_buffer[..]).await {
            loop {
                let bytes = &receive_buffer[offset..];
                let rx_packet = <NetlinkMessage<RtnlMessage>>::deserialize(bytes).unwrap();

                if NetLinkNetInfo::process_message(&sni, &rx_packet).await {
                    match state {
                        State::ReadingLink => {
                            NetLinkNetInfo::send_addrdump(&mut socket, &mut seq).await;
                            state = State::ReadingAddr
                        }
                        State::ReadingAddr => {
                            NetLinkNetInfo::send_routedump(&mut socket, &mut seq, AF_INET as u8)
                                .await;
                            state = State::ReadingRoute4
                        }
                        State::ReadingRoute4 => {
                            NetLinkNetInfo::send_routedump(&mut socket, &mut seq, AF_INET6 as u8)
                                .await;
                            state = State::ReadingRoute6
                        }
                        State::ReadingRoute6 => {
                            // Try and inform anyone listening that we have completed.
                            // But if it fails, don't worry, we'll send another one soonish.
                            let _ = chan.try_send(());
                            state = State::Done
                        }
                        State::Done => {}
                    }
                }

                offset += rx_packet.header.length as usize;
                if offset == size || rx_packet.header.length == 0 {
                    offset = 0;
                    break;
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
                flags: IfFlags(IFF_MULTICAST),
            },
        );
        ni.add_interface(
            1,
            IfInfo {
                name: "eth0".into(),
                addresses: vec![("192.0.2.254".parse().unwrap(), 24)],
                lladdr: LinkLayer::Ethernet([0x00, 0x00, 0x5E, 0x00, 0x53, 0xFF]),
                mtu: 1500,
                flags: IfFlags(IFF_MULTICAST),
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
        self.0.read().await.intf.get(&ifidx).map(|x| x.flags)
    }

    pub async fn get_ipv4_default_route(
        &self,
    ) -> Option<(Option<std::net::Ipv4Addr>, Option<u32>)> {
        self.0
            .read()
            .await
            .routeinfo
            .iter()
            .filter_map(|ri| {
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
            .next()
    }

    pub async fn get_ipv6_default_route(
        &self,
    ) -> Option<(Option<std::net::Ipv6Addr>, Option<u32>)> {
        self.0
            .read()
            .await
            .routeinfo
            .iter()
            .filter_map(|ri| {
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
            .next()
    }
}

#[tokio::test]
async fn test_interface() {
    use netlink_packet_route::rtnl;
    use netlink_packet_route::{AddressHeader, LinkHeader};
    const IFIDX: u32 = 10;
    let ni = SharedNetInfo::new_for_test();
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage {
            header: NetlinkHeader {
                sequence_number: 1,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::NewLink(LinkMessage {
                header: LinkHeader {
                    index: IFIDX,
                    link_layer_type: ARPHRD_ETHER,
                    ..Default::default()
                },
                nlas: vec![
                    rtnl::link::nlas::Nla::IfName("test1".into()),
                    rtnl::link::nlas::Nla::Mtu(1500),
                    rtnl::link::nlas::Nla::Address(vec![0x00, 0x53, 0x00, 0x00, 0x00, 0x00]),
                    rtnl::link::nlas::Nla::Broadcast(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
                ],
                ..Default::default()
            })),
        },
    )
    .await;
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage {
            header: NetlinkHeader {
                sequence_number: 2,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::NewAddress(AddressMessage {
                header: AddressHeader {
                    index: IFIDX,
                    family: AF_INET as u8,
                    prefix_len: 24,
                    ..Default::default()
                },
                nlas: vec![rtnl::address::nlas::Nla::Address(vec![192, 0, 2, 1])],
                ..Default::default()
            })),
        },
    )
    .await;
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage {
            header: NetlinkHeader {
                sequence_number: 2,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::NewAddress(AddressMessage {
                header: AddressHeader {
                    index: IFIDX,
                    family: AF_INET6 as u8,
                    prefix_len: 24,
                    ..Default::default()
                },
                nlas: vec![rtnl::address::nlas::Nla::Address(vec![
                    0x20, 0x1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ])],
                ..Default::default()
            })),
        },
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
    NetLinkNetInfo::process_message(
        &ni,
        &NetlinkMessage {
            header: NetlinkHeader {
                sequence_number: 1,
                ..Default::default()
            },
            payload: NetlinkPayload::from(RtnlMessage::NewLink(LinkMessage {
                header: LinkHeader {
                    index: IFIDX,
                    link_layer_type: ARPHRD_ETHER,
                    ..Default::default()
                },
                nlas: vec![
                    rtnl::link::nlas::Nla::IfName("test1".into()),
                    rtnl::link::nlas::Nla::Mtu(1501),
                    rtnl::link::nlas::Nla::Address(vec![0x00, 0x53, 0x00, 0x00, 0x00, 0x01]),
                    rtnl::link::nlas::Nla::Broadcast(vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]),
                ],
                ..Default::default()
            })),
        },
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
