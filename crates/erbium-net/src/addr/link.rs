/*   Copyright 2023 Perry Lorier
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
 *  We try and use the nix types here, but they're somewhat frustrating to use, for instance not
 *  providing useful safe constructors.  So we do that here.
 */

pub use nix::sys::socket::LinkAddr;
pub type IfIndex = usize;

/// physical layer protocol (Ethertype)
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct EtherType(pub u16);
impl EtherType {
    pub const UNSPECIFIED: EtherType = EtherType(0);
    pub const IP: EtherType = EtherType(0x0800);
    pub const ARP: EtherType = EtherType(0x0806);
    pub const IPV6: EtherType = EtherType(0x86DD);
    pub const LLDP: EtherType = EtherType(0x88CC);
}

impl From<EtherType> for u16 {
    fn from(e: EtherType) -> u16 {
        e.0
    }
}

impl From<u16> for EtherType {
    fn from(e: u16) -> EtherType {
        EtherType(e)
    }
}

/// Arp Hardware Type (ArpHrd)
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct ArpHrd(pub u16);
#[allow(dead_code)]
impl ArpHrd {
    const UNSPECIFIED: ArpHrd = ArpHrd(0);
    const ETHERNET: ArpHrd = ArpHrd(1);
}

impl From<ArpHrd> for u16 {
    fn from(a: ArpHrd) -> u16 {
        a.0
    }
}

impl From<u16> for ArpHrd {
    fn from(u: u16) -> Self {
        Self(u)
    }
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub struct PacketType(pub u8);
#[allow(dead_code)]
impl PacketType {
    const HOST: PacketType = PacketType(0);
    const BROADCAST: PacketType = PacketType(1);
    const MULTICAST: PacketType = PacketType(2);
    const OTHER_HOST: PacketType = PacketType(3);
    const OUTGOING: PacketType = PacketType(4);
    const LOOPBACK: PacketType = PacketType(5);
    const USER: PacketType = PacketType(6);
    const KERNEL: PacketType = PacketType(7);
    const FAST_ROUTE: PacketType = PacketType(8);
}

impl From<PacketType> for u8 {
    fn from(p: PacketType) -> u8 {
        p.0
    }
}

impl From<u8> for PacketType {
    fn from(p: u8) -> PacketType {
        Self(p)
    }
}

/// nix doesn't provide a safe way to construct LinkAddrs, so we provide our own.
pub fn new_linkaddr(
    protocol: EtherType,
    ifindex: IfIndex,
    hatype: ArpHrd,
    pkttype: PacketType,
    addr: &[u8],
) -> LinkAddr {
    let mut sll_addr = [0_u8; 8];
    sll_addr[..addr.len()].copy_from_slice(addr);
    // We are careful to use the same version of libc here as nix does to avoid type confusion.
    let ll = nix::libc::sockaddr_ll {
        sll_family: nix::libc::AF_PACKET as u16,
        sll_protocol: u16::to_be(protocol.into()),
        sll_ifindex: ifindex as i32,
        sll_hatype: hatype.into(),
        sll_pkttype: pkttype.into(),
        sll_halen: addr.len() as u8,
        sll_addr,
    };
    unsafe {
        use nix::sys::socket::SockaddrLike as _;
        LinkAddr::from_raw(
            &ll as *const _ as *const _,
            Some(
                std::mem::size_of_val(&ll) as u32, /* why doesn't from_raw take a usize? */
            ),
        )
        .unwrap()
    }
}

pub fn linkaddr_for_ifindex(ifindex: IfIndex) -> LinkAddr {
    new_linkaddr(
        EtherType::UNSPECIFIED,
        ifindex,
        ArpHrd::UNSPECIFIED,
        PacketType::HOST,
        &[0; 8],
    )
}
