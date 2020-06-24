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
 */
pub mod netinfo;
pub mod packet;
pub mod raw;
pub mod udp;

// TODO: Write better Debug or to_string() method.
#[derive(Clone, Debug)]
pub struct Ipv4Subnet {
    pub addr: std::net::Ipv4Addr,
    pub prefixlen: u8,
}

#[derive(Debug)]
pub enum Error {
    InvalidSubnet,
}

impl Ipv4Subnet {
    pub fn new(addr: std::net::Ipv4Addr, prefixlen: u8) -> Result<Self, Error> {
        let ret = Self { addr, prefixlen };
        /* If the prefix is too short, then return an error */
        if u32::from(ret.addr) & !u32::from(ret.netmask()) != 0 {
            Err(Error::InvalidSubnet)
        } else {
            Ok(ret)
        }
    }
    pub fn network(&self) -> std::net::Ipv4Addr {
        (u32::from(self.addr) & u32::from(self.netmask())).into()
    }
    pub fn netmask(&self) -> std::net::Ipv4Addr {
        (!(0xffff_ffff as u64 >> self.prefixlen) as u32).into()
    }
    pub fn contains(&self, ip: std::net::Ipv4Addr) -> bool {
        u32::from(ip) & u32::from(self.netmask()) == u32::from(self.addr)
    }
    pub fn broadcast(&self) -> std::net::Ipv4Addr {
        (u32::from(self.network()) | !u32::from(self.netmask())).into()
    }
}

#[test]
fn test_netmask() -> Result<(), Error> {
    assert_eq!(
        Ipv4Subnet::new("0.0.0.0".parse().unwrap(), 0)?.netmask(),
        "0.0.0.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        Ipv4Subnet::new("0.0.0.0".parse().unwrap(), 8)?.netmask(),
        "255.0.0.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        Ipv4Subnet::new("0.0.0.0".parse().unwrap(), 16)?.netmask(),
        "255.255.0.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        Ipv4Subnet::new("0.0.0.0".parse().unwrap(), 24)?.netmask(),
        "255.255.255.0".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        Ipv4Subnet::new("0.0.0.0".parse().unwrap(), 25)?.netmask(),
        "255.255.255.128".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        Ipv4Subnet::new("0.0.0.0".parse().unwrap(), 32)?.netmask(),
        "255.255.255.255".parse::<std::net::Ipv4Addr>().unwrap()
    );
    Ok(())
}

#[test]
fn test_broadcast() {
    assert_eq!(
        Ipv4Subnet::new("192.168.1.0".parse().unwrap(), 24)
            .unwrap()
            .broadcast(),
        std::net::Ipv4Addr::new(192, 168, 1, 255)
    );
}

#[test]
fn test_contains() {
    assert_eq!(
        Ipv4Subnet::new("192.168.0.128".parse().unwrap(), 25)
            .unwrap()
            .contains("192.168.0.200".parse().unwrap()),
        true
    );
    assert_eq!(
        Ipv4Subnet::new("192.168.0.128".parse().unwrap(), 25)
            .unwrap()
            .contains("192.168.0.100".parse().unwrap()),
        false
    );
}
