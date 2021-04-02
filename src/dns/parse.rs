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
 *  Code to parse a DNS packet.
 */
use crate::dns::dnspkt;

pub struct EdnsParser<'l> {
    buffer: &'l [u8],
}

impl<'l> EdnsParser<'l> {
    fn new(buffer: &'l [u8]) -> EdnsParser {
        EdnsParser { buffer }
    }

    fn get_u8(&mut self) -> Result<u8, String> {
        if let Some((first, rest)) = self.buffer.split_first() {
            self.buffer = rest;
            Ok(*first)
        } else {
            Err("Truncated EDNS Option".to_string())
        }
    }

    fn get_u16(&mut self) -> Result<u16, String> {
        let upper = self.get_u8()?;
        let lower = self.get_u8()?;
        Ok((upper as u16) * 256 + (lower as u16))
    }

    fn get_option(&mut self) -> Result<dnspkt::EdnsOption, String> {
        let code = self.get_u16()?;
        let len = self.get_u16()? as usize;
        if self.buffer.len() < len {
            return Err(format!(
                "Truncated EDNS Option (got {}, wanted {})",
                self.buffer.len(),
                len
            ));
        }
        let data = self.buffer[0..len].to_vec();
        self.buffer = &self.buffer[len..];
        if data.len() < len {
            return Err("Truncated EDNS Option".into());
        }
        Ok(dnspkt::EdnsOption {
            code: dnspkt::EdnsCode(code),
            data,
        })
    }

    fn get_options(&mut self) -> Result<dnspkt::EdnsData, String> {
        let mut data = dnspkt::EdnsData::new();

        while !self.buffer.is_empty() {
            data.set_opt(self.get_option()?);
        }

        Ok(data)
    }
}

pub struct PktParser<'l> {
    buffer: &'l [u8],
    offset: usize,
}

impl<'l> PktParser<'l> {
    pub fn new(buffer: &'l [u8]) -> PktParser {
        PktParser { buffer, offset: 0 }
    }
    fn peek_u8(&mut self) -> Result<u8, String> {
        if self.offset < self.buffer.len() {
            Ok(self.buffer[self.offset])
        } else {
            Err("Truncated Packet (u8)".into())
        }
    }
    fn get_u8(&mut self) -> Result<u8, String> {
        let ret = self.peek_u8()?;
        self.offset += 1;
        Ok(ret)
    }
    fn get_u16(&mut self) -> Result<u16, String> {
        Ok((self.get_u8()? as u16) * 256 + (self.get_u8()? as u16))
    }
    fn get_u32(&mut self) -> Result<u32, String> {
        Ok((self.get_u8()? as u32) * (256 * 256 * 256)
            + (self.get_u8()? as u32) * (256 * 256)
            + (self.get_u8()? as u32) * (256)
            + (self.get_u8()? as u32))
    }

    fn get_bytes(&mut self, count: usize) -> Result<Vec<u8>, String> {
        if self.offset + count <= self.buffer.len() {
            let ret = self.buffer[self.offset..self.offset + count].to_vec();
            self.offset += count;
            Ok(ret)
        } else {
            Err(format!(
                "Truncated packet, reading {} bytes (only {} remaining)",
                count,
                self.buffer.len() - self.offset
            ))
        }
    }

    fn get_string(&mut self) -> Result<Vec<u8>, String> {
        let size = self.get_u8()? as usize;
        self.get_bytes(size)
    }

    fn get_domain_into(
        &mut self,
        domainv: &mut Vec<dnspkt::Label>,
        depth: i32,
    ) -> Result<(), String> {
        loop {
            let prefix = self.get_u8()?;
            match prefix {
                0 => {
                    // End of domain marker.
                    return Ok(());
                }
                p if p & 0b1100_0000 == 0 => {
                    // Uncompressed label
                    domainv.push(dnspkt::Label::from(self.get_bytes(prefix as usize)?));
                }
                offset_high if offset_high & 0b1100_0000 == 0b1100_0000 => {
                    if depth > 10 {
                        return Err("Compression Corruption".into());
                    }
                    // Compressed label.
                    let offset_low = self.get_u8()?;
                    let offset =
                        (((offset_high & !0b1100_0000) as usize) << 8) | (offset_low as usize);
                    let saved_offset = self.offset;
                    self.offset = offset;
                    let ret = self.get_domain_into(domainv, depth + 1);
                    self.offset = saved_offset;
                    return ret;
                }
                marker => return Err(format!("Unsupported label type ({:x})", marker)),
            }
        }
    }

    pub fn get_domain(&mut self) -> Result<dnspkt::Domain, String> {
        let mut domainv = Vec::new();
        self.get_domain_into(&mut domainv, 1)
            .map(|_| dnspkt::Domain::from(domainv))
    }

    fn get_class(&mut self) -> Result<dnspkt::Class, String> {
        Ok(dnspkt::Class(self.get_u16()?))
    }

    fn get_type(&mut self) -> Result<dnspkt::Type, String> {
        Ok(dnspkt::Type(self.get_u16()?))
    }

    fn get_rdata(&mut self, rtype: dnspkt::Type) -> Result<dnspkt::RData, String> {
        use dnspkt::RData::*;
        let rdlen = self.get_u16()? as usize;
        match rtype {
            dnspkt::RR_CNAME => {
                Ok(CName(self.get_domain()?))
                // TODO: assert the domain == rdlen.
            }
            dnspkt::RR_NS => {
                Ok(Ns(self.get_domain()?))
                // TODO: assert the domain == rdlen.
            }
            dnspkt::RR_PTR => {
                Ok(Ptr(self.get_domain()?))
                // TODO: assert the domain == rdlen.
            }
            dnspkt::RR_AFSDB => Ok(dnspkt::RData::AfsDb(dnspkt::AFSDBData {
                subtype: self.get_u16()?,
                hostname: self.get_domain()?,
            })),
            dnspkt::RR_RP => Ok(dnspkt::RData::Rp(dnspkt::RPData {
                mbox: self.get_domain()?,
                txt: self.get_domain()?,
            })),
            dnspkt::RR_RT => Ok(dnspkt::RData::Rt(dnspkt::PrefDomainData {
                pref: self.get_u16()?,
                domain: self.get_domain()?,
            })),
            dnspkt::RR_MX => Ok(dnspkt::RData::Mx(dnspkt::PrefDomainData {
                pref: self.get_u16()?,
                domain: self.get_domain()?,
            })),
            dnspkt::RR_NAPTR => {
                let order = self.get_u16()?;
                let preference = self.get_u16()?;
                let flags = self.get_string()?;
                let services = self.get_string()?;
                let regexp = self.get_string()?;
                let replacement = self.get_domain()?;
                Ok(dnspkt::RData::NaPtr(dnspkt::NAPTRData {
                    order,
                    preference,
                    flags,
                    services,
                    regexp,
                    replacement,
                }))
            }
            dnspkt::RR_OPT => {
                let rdata = self.get_bytes(rdlen)?;
                Ok(dnspkt::RData::Opt(EdnsParser::new(&rdata).get_options()?))
            }
            dnspkt::RR_SOA => Ok(dnspkt::RData::Soa(dnspkt::SoaData {
                mname: self.get_domain()?,
                rname: self.get_domain()?,
                serial: self.get_u32()?,
                refresh: self.get_u32()?,
                retry: self.get_u32()?,
                expire: self.get_u32()?,
                minimum: self.get_u32()?,
            })),
            _ => {
                let rdata = self.get_bytes(rdlen)?;
                Ok(dnspkt::RData::Other(rdata))
            }
        }
    }

    pub fn get_rr(&mut self) -> Result<dnspkt::RR, String> {
        let domain = self
            .get_domain()
            .map_err(|m| format!("{} while reading domain", m))?;
        let rrtype = self
            .get_type()
            .map_err(|m| format!("{} while reading rrtype", m))?;
        let class = self
            .get_class()
            .map_err(|m| format!("{} while reading class", m))?;
        let ttl = self
            .get_u32()
            .map_err(|m| format!("{} while reading ttl", m))?;
        let rdata = self
            .get_rdata(rrtype)
            .map_err(|m| format!("{} while reading rdata", m))?;

        Ok(dnspkt::RR {
            domain,
            class,
            rrtype,
            ttl,
            rdata,
        })
    }

    pub fn get_dns(&mut self) -> Result<dnspkt::DNSPkt, String> {
        let qid = self
            .get_u16()
            .map_err(|m| format!("{} while reading qid", m))?;
        let flag1 = self
            .get_u8()
            .map_err(|m| format!("{} while reading flag1", m))?;
        let flag2 = self
            .get_u8()
            .map_err(|m| format!("{} while reading flag2", m))?;
        let qcount = self
            .get_u16()
            .map_err(|m| format!("{} while reading qcount", m))?;

        let trunc = flag1 & 0b0000_0010 != 0;

        let opcode = dnspkt::Opcode((flag1 & 0b0111_1000) >> 3);
        let rcode = dnspkt::RCode((flag2 & 0b0000_1111) as u16);
        if qcount != 1 {
            return Err(format!(
                "Incorrect number of questions ({} / {:?} / {:?})",
                qcount, opcode, rcode
            ));
        }
        let arcount = self
            .get_u16()
            .map_err(|m| format!("{} while reading arcount", m))?;
        let nscount = self
            .get_u16()
            .map_err(|m| format!("{} while reading arcount", m))?;
        let adcount = self
            .get_u16()
            .map_err(|m| format!("{} while reading adcount", m))?;

        let qdomain = self
            .get_domain()
            .map_err(|m| format!("{} while reading qdomain", m))?;
        let qtype = self
            .get_type()
            .map_err(|m| format!("{} while reading qtype", m))?;
        let qclass = self
            .get_class()
            .map_err(|m| format!("{} while reading qclass", m))?;

        let mut answer = vec![];
        for _ in 0..arcount {
            if self.offset >= self.buffer.len() && trunc {
                break;
            }
            answer.push(
                self.get_rr()
                    .map_err(|e| format!("{} while reading {} answers", e, arcount))?,
            );
        }

        let mut nameserver = vec![];
        for _ in 0..nscount {
            if self.offset >= self.buffer.len() && trunc {
                break;
            }
            nameserver.push(
                self.get_rr()
                    .map_err(|e| format!("{} while reading {} nameservers", e, nscount))?,
            );
        }

        let mut additional = vec![];
        for _ in 0..adcount {
            if self.offset >= self.buffer.len() && trunc {
                break;
            }
            additional.push(
                self.get_rr()
                    .map_err(|e| format!("{} while reading {} additionals", e, adcount))?,
            );
        }

        let opt = additional
            .iter()
            .find(|it| it.rrtype == dnspkt::RR_OPT && ((it.ttl >> 16) & 0xFF) == 0);

        let ever = opt.map(|o| ((o.ttl >> 16) & 0xFF) as u8);
        let bufsize = std::cmp::max(opt.map_or(512, |o| o.class.0), 512);
        let ercode = opt.map_or(0, |o| o.ttl >> 24);
        let edo = opt.map_or(false, |o| {
            (o.ttl & 0b0000_0000_0000_0000_1000_0000_0000_0000) != 0
        });

        let edns = opt.map(|x| match &x.rdata {
            dnspkt::RData::Opt(o) => o.clone(),
            _ => panic!("opt record does not contain opt data"),
        });

        additional.retain(|rr| rr.rrtype != dnspkt::RR_OPT);

        Ok(dnspkt::DNSPkt {
            qid,
            rd: (flag1 & 0b0000_0001) != 0,
            tc: (flag1 & 0b0000_0010) != 0,
            aa: (flag1 & 0b0000_0100) != 0,
            qr: (flag1 & 0b1000_0000) != 0,
            opcode,

            cd: (flag2 & 0b0010_0000) != 0,
            ad: (flag2 & 0b0100_0000) != 0,
            ra: (flag2 & 0b1000_0000) != 0,
            //           0b0001_0000
            rcode: dnspkt::RCode(((flag2 & 0b0000_1111) as u16) | ((ercode as u16) << 4)),
            bufsize,
            edns_ver: ever,
            edns_do: edo,
            question: dnspkt::Question {
                qdomain,
                qclass,
                qtype,
            },
            answer,
            nameserver,
            additional,
            edns,
        })
    }
}

#[test]
fn test_parse_empty_domain() {
    let mut pkt = PktParser::new(&[0x00]);
    assert_eq!(pkt.get_domain().unwrap(), dnspkt::Domain::from(vec![]));
}
