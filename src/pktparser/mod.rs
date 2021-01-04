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
 *  API to make parsing packets easier.
 */

use std::convert::TryInto;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedEndOfInput,
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::UnexpectedEndOfInput => write!(f, "Unexpected End Of Input"),
        }
    }
}

pub struct Buffer<'l> {
    buffer: &'l [u8],
    offset: usize,
}

impl<'l> Buffer<'l> {
    pub fn new(buffer: &'l [u8]) -> Buffer {
        Buffer { buffer, offset: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.offset
    }

    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    pub fn empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn set_offset(mut self, o: usize) -> Option<Self> {
        if o <= self.size() {
            self.offset = o;
            Some(self)
        } else {
            None
        }
    }

    pub fn skip(self, s: usize) -> Option<Self> {
        let new_offset = self.offset + s;
        self.set_offset(new_offset)
    }

    pub fn get_u8(&mut self) -> Option<u8> {
        if self.offset < self.buffer.len() {
            let ret = self.buffer[self.offset];
            self.offset += 1;
            Some(ret)
        } else {
            None
        }
    }

    pub fn get_bytes(&mut self, b: usize) -> Option<&'l [u8]> {
        if self.offset + b <= self.buffer.len() {
            let ret = &self.buffer[self.offset..self.offset + b];
            self.offset += b;
            Some(ret)
        } else {
            None
        }
    }

    pub fn get_vec(&mut self, b: usize) -> Option<Vec<u8>> {
        Some(self.get_bytes(b)?.to_vec())
    }

    pub fn get_be16(&mut self) -> Option<u16> {
        let bytes = self.get_bytes(std::mem::size_of::<u16>())?;
        Some(u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn get_be32(&mut self) -> Option<u32> {
        let bytes = self.get_bytes(std::mem::size_of::<u32>())?;
        Some(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub fn get_ipv4(&mut self) -> Option<std::net::Ipv4Addr> {
        let bytes = self.get_bytes(std::mem::size_of::<[u8; 4]>())?;
        Some(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))
    }

    pub fn get_tlv(&mut self) -> Option<(u8, &[u8])> {
        let tl = self.get_bytes(2)?;
        let t = tl[0];
        let l = tl[1];
        Some((t, self.get_bytes(l as usize)?))
    }

    fn get_label(&mut self) -> Option<&[u8]> {
        let l = self.get_u8()?;
        self.get_bytes(l as usize)
    }

    fn get_domain(&mut self) -> Option<Vec<String>> {
        let mut d = vec![];
        loop {
            let l = self.get_label()?;
            if l.is_empty() {
                return Some(d);
            }
            d.push(String::from_utf8_lossy(l).to_string())
        }
    }

    pub fn get_domains(&mut self) -> Option<Vec<Vec<String>>> {
        let mut dl = vec![];
        while !self.empty() {
            dl.push(self.get_domain()?);
        }
        Some(dl)
    }
}

#[test]
fn test_get_u8() {
    let data = [1, 2, 3];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.get_u8(), Some(1));
    assert_eq!(buffer.get_u8(), Some(2));
    assert_eq!(buffer.get_u8(), Some(3));
    assert_eq!(buffer.get_u8(), None);
}

#[test]
fn test_get_bytes() {
    use std::convert::TryFrom;
    let data = [1, 2, 3, 4];
    let mut buffer = Buffer::new(&data);
    assert_eq!(
        <[u8; 2]>::try_from(buffer.get_bytes(2).unwrap()).unwrap(),
        [1u8, 2]
    );
    assert_eq!(
        <[u8; 2]>::try_from(buffer.get_bytes(2).unwrap()).unwrap(),
        [3u8, 4]
    );
    assert_eq!(buffer.get_bytes(2), None)
}

#[test]
fn test_get_vec() {
    let data = [1, 2, 3, 4];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.get_vec(2), Some(vec![1u8, 2]));
    assert_eq!(buffer.get_vec(2), Some(vec![3u8, 4]));
    assert_eq!(buffer.get_bytes(2), None)
}

#[test]
fn test_get_u16() {
    let data = [1, 2, 3, 4];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.get_be16(), Some(0x0102));
    assert_eq!(buffer.get_be16(), Some(0x0304));
    assert_eq!(buffer.get_be16(), None)
}

#[test]
fn test_get_u32() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.get_be32(), Some(0x01020304));
    assert_eq!(buffer.get_be32(), Some(0x05060708));
    assert_eq!(buffer.get_be32(), None)
}

#[test]
fn test_get_ipv4() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.get_ipv4(), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(buffer.get_ipv4(), Some(std::net::Ipv4Addr::new(5, 6, 7, 8)));
    assert_eq!(buffer.get_ipv4(), None)
}

#[test]
fn test_size() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.size(), 8);
    buffer.get_u8();
    assert_eq!(buffer.size(), 8);
}

#[test]
fn test_remaining() {
    let data = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut buffer = Buffer::new(&data);
    assert_eq!(buffer.remaining(), 8);
    buffer.get_u8();
    assert_eq!(buffer.remaining(), 7);
}

#[test]
fn test_domains() {
    let data = [
        3, 0x77, 0x77, 0x77, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x63, 0x6f, 0x6d, 0,
        3, 0x77, 0x77, 0x77, 7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x6f, 0x72, 0x67, 0,
    ];
    let mut buf = Buffer::new(&data);
    assert_eq!(
        buf.get_domains(),
        Some(vec![
            vec!["www".into(), "example".into(), "com".into()],
            vec!["www".into(), "example".into(), "org".into()]
        ])
    );
}
