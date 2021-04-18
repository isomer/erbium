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
 *  Functions to create raw packets as a [u8]
 */
use std::net;

fn partial_netsum(current: u32, buffer: &[u8]) -> u32 {
    let mut i = 0;
    let mut sum = current;
    let mut count = buffer.len();
    while count > 1 {
        let v = ((buffer[i] as u32) << 8) | (buffer[i + 1] as u32);
        sum += v;
        i += 2;
        count -= 2;
    }
    if count > 0 {
        let v = (buffer[i] as u32) << 8;
        sum += v;
    }
    sum
}

fn finish_netsum(sum: u32) -> u16 {
    let mut sum = sum;
    while sum > 0xffff {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !(sum as u16)
}

#[derive(Clone, Debug)]
pub enum Tail<'a> {
    Payload(&'a [u8]),
    Fragment(Box<Fragment<'a>>),
    #[allow(dead_code)]
    None,
}

impl<'a> Tail<'a> {
    fn len(&self) -> usize {
        match self {
            Tail::Payload(x) => x.len(),
            Tail::Fragment(x) => x.len(),
            Tail::None => 0,
        }
    }

    fn partial_netsum(&self, current: u32) -> u32 {
        match self {
            Tail::Payload(x) => partial_netsum(current, x),
            Tail::Fragment(x) => x.partial_netsum(current),
            Tail::None => current,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Fragment<'a> {
    buffer: Vec<u8>,
    tail: Tail<'a>,
}

impl<'a> Fragment<'a> {
    fn len(&self) -> usize {
        self.buffer.len() + self.tail.len()
    }
    fn partial_netsum(&self, current: u32) -> u32 {
        self.tail
            .partial_netsum(partial_netsum(current, &self.buffer))
    }
    fn netsum(&self) -> u16 {
        finish_netsum(self.partial_netsum(0))
    }
    pub fn flatten(&self) -> Vec<u8> {
        let mut x = self;
        let mut ret = vec![];
        loop {
            ret.extend_from_slice(&x.buffer);
            match &x.tail {
                Tail::None => break,
                Tail::Payload(x) => {
                    ret.extend_from_slice(x);
                    break;
                }
                Tail::Fragment(f) => {
                    x = f.as_ref();
                }
            }
        }
        ret
    }

    fn from_tail(tail: Tail) -> Fragment {
        Fragment {
            buffer: vec![],
            tail,
        }
    }
    fn push_u8(&mut self, b: u8) {
        self.buffer.push(b);
    }
    fn push_bytes(&mut self, b: &[u8]) {
        self.buffer.extend_from_slice(b);
    }
    fn push_be16(&mut self, b: u16) {
        self.push_bytes(&b.to_be_bytes());
    }

    fn new_ethernet<'l>(
        dst: &[u8; 6],
        src: &[u8; 6],
        ethertype: u16,
        payload: Tail<'l>,
    ) -> Fragment<'l> {
        let mut f = Fragment::from_tail(payload);
        f.push_bytes(dst);
        f.push_bytes(src);
        f.push_be16(ethertype);
        f
    }

    fn new_ipv4<'l>(
        src: &net::Ipv4Addr,
        srcmac: &[u8; 6],
        dst: &net::Ipv4Addr,
        dstmac: &[u8; 6],
        protocol: u8,
        payload: Tail<'l>,
    ) -> Fragment<'l> {
        let mut f = Fragment::from_tail(payload);
        f.push_u8(0x45); /* version 4, length 5*4 bytes */
        f.push_u8(0x00); /* ToS */
        f.push_be16(20_u16 + f.tail.len() as u16); /* Total Length */
        f.push_be16(0x0000); /* Identification */
        f.push_be16(0x0000); /* Flags + Frag Offset */
        f.push_u8(0x01); /* TTL */
        f.push_u8(protocol);
        f.push_be16(0x0000); /* Checksum - filled in below*/
        f.push_bytes(&src.octets());
        f.push_bytes(&dst.octets());
        let netsum = finish_netsum(partial_netsum(0, &f.buffer));
        f.buffer[10] = (netsum >> 8) as u8;
        f.buffer[11] = (netsum & 0xFF) as u8;
        Self::new_ethernet(dstmac, srcmac, 0x0800_u16, Tail::Fragment(Box::new(f)))
    }

    pub fn new_udp<'l>(
        src: net::SocketAddrV4,
        srcmac: &[u8; 6],
        dst: net::SocketAddrV4,
        dstmac: &[u8; 6],
        payload: Tail<'l>,
    ) -> Fragment<'l> {
        let mut f = Self::from_tail(payload);
        f.push_be16(src.port());
        f.push_be16(dst.port());
        f.push_be16(8_u16 + f.tail.len() as u16); /* Length */
        f.push_be16(0x0000); /* TODO: Checksum */
        let l = f.len();
        let mut pseudohdr = Self::from_tail(Tail::Fragment(Box::new(f.clone())));
        let udp_protocol: u8 = 17;
        pseudohdr.push_bytes(&src.ip().octets());
        pseudohdr.push_bytes(&dst.ip().octets());
        pseudohdr.push_u8(0x00_u8);
        pseudohdr.push_u8(udp_protocol);
        pseudohdr.push_be16(l as u16);
        let netsum = pseudohdr.netsum();
        f.buffer[6] = (netsum >> 8) as u8;
        f.buffer[7] = (netsum & 0xFF) as u8;
        let t = Tail::Fragment(Box::new(f.clone()));
        Self::new_ipv4(src.ip(), srcmac, dst.ip(), dstmac, udp_protocol, t)
    }
}

#[test]
fn test_udp_packet() {
    let u = Fragment::new_udp(
        "192.0.2.1:1".parse().unwrap(),
        &[2, 0, 0, 0, 0, 0],
        "192.0.2.2:2".parse().unwrap(),
        &[2, 0, 0, 0, 0, 1],
        Tail::Payload(&[1, 2, 3, 4]),
    );
    println!("u={:?}", u);
}

#[test]
fn test_checksum() {
    let data = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];

    assert_eq!(finish_netsum(partial_netsum(0, &data)), 0xE5CA);
}
