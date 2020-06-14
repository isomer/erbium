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
    pub fn netmask(&self) -> std::net::Ipv4Addr {
        (u32::from(self.addr) & (((1 << self.prefixlen) - 1) as u32).to_be()).into()
    }
    pub fn contains(&self, ip: std::net::Ipv4Addr) -> bool {
        u32::from(ip) & u32::from(self.netmask()) == u32::from(self.addr)
    }
}
