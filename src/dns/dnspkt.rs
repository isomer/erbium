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
 *  Datastructures and serialisation of DNS packets.
 */

use std::cmp::Ordering;
use std::fmt;
use std::iter::FromIterator;
use std::string::ToString;

//#[derive(Debug)]
#[derive(Eq, PartialOrd, PartialEq, Clone, Copy)]
pub struct Class(pub u16);

pub const CLASS_IN: Class = Class(1); /* Internet */
pub const CLASS_CH: Class = Class(3); /* ChaosNet */

impl Ord for Class {
    fn cmp(&self, other: &Class) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl ToString for Class {
    fn to_string(&self) -> String {
        match self {
            &CLASS_IN => String::from("IN"),
            &CLASS_CH => String::from("CH"),
            Class(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Class({})", self.to_string())
    }
}

//#[derive(Debug)]
#[derive(PartialOrd, PartialEq, Eq, Clone, Hash, Copy)]
pub struct Type(pub u16);

pub const RR_A: Type = Type(1);
pub const RR_NS: Type = Type(2);
pub const RR_SOA: Type = Type(6);
pub const RR_PTR: Type = Type(12);
pub const RR_OPT: Type = Type(41);
pub const RR_NSEC: Type = Type(47);
pub const RR_NSEC3: Type = Type(50);

impl Ord for Type {
    fn cmp(&self, other: &Type) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl ToString for Type {
    fn to_string(&self) -> String {
        match self {
            &RR_A => String::from("A"),
            &RR_NS => String::from("NS"),
            &RR_SOA => String::from("SOA"),
            &RR_PTR => String::from("PTR"),
            &RR_OPT => String::from("OPT"),
            &RR_NSEC => String::from("NSEC"),
            &RR_NSEC3 => String::from("NSEC3"),
            Type(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Type({})", self.to_string())
    }
}

#[derive(PartialOrd, PartialEq, Eq, Clone, Copy)]
pub struct RCode(pub u16);
pub const NOERROR: RCode = RCode(0);
pub const FORMERR: RCode = RCode(1);
pub const NXDOMAIN: RCode = RCode(3);

impl Ord for RCode {
    fn cmp(&self, other: &RCode) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl ToString for RCode {
    fn to_string(&self) -> String {
        match self {
            &FORMERR => String::from("FORMERR"),
            &NOERROR => String::from("NOERROR"),
            &NXDOMAIN => String::from("NXDOMAIN"),
            RCode(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for RCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RCode({})", self.to_string())
    }
}

fn display_byte(b: u8) -> String {
    match b {
        n @ 32..=127 => char::from(n).to_string(),
        n => format!("\\{}", n),
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Hash, Debug)]
pub struct Label(Vec<u8>);

impl From<Vec<u8>> for Label {
    fn from(v: Vec<u8>) -> Self {
        Label(v)
    }
}
impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl ToString for Label {
    fn to_string(&self) -> String {
        String::from_iter((&self.0).iter().map(|&b| display_byte(b)))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Hash)]
pub struct Domain(Vec<Label>);

impl From<Vec<Label>> for Domain {
    fn from(v: Vec<Label>) -> Self {
        Domain(v)
    }
}

impl Ord for Domain {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            (&self.0)
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Domain({})", self.to_string())
    }
}

#[derive(Clone)]
pub struct Question {
    pub qdomain: Domain,
    pub qclass: Class,
    pub qtype: Type,
}

impl ToString for Question {
    fn to_string(&self) -> String {
        format!("{} {:?} {:?}", self.qdomain, self.qclass, self.qtype)
    }
}

impl fmt::Debug for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Question({})", self.to_string())
    }
}

#[derive(Ord, Eq, PartialEq, PartialOrd, Clone)]
pub struct EdnsCode(pub u16);

pub const EDNS_NSID: EdnsCode = EdnsCode(3);
pub const EDNS_CLIENT_SUBNET: EdnsCode = EdnsCode(8);
pub const EDNS_COOKIE: EdnsCode = EdnsCode(10);

impl ToString for EdnsCode {
    fn to_string(&self) -> String {
        match self {
            &EDNS_NSID => "NSID".to_string(),
            &EDNS_CLIENT_SUBNET => "CLIENT_SUBNET".to_string(),
            &EDNS_COOKIE => "COOKIE".to_string(),
            EdnsCode(c) => format!("#{}", c),
        }
    }
}

impl fmt::Debug for EdnsCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EdnsCode({})", self.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct EdnsOption {
    pub code: EdnsCode,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EdnsData {
    pub other: Vec<EdnsOption>,
}

#[derive(Debug, Clone)]
pub struct SoaData {
    pub mname: Domain,
    pub rname: Domain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone)]
pub enum RData {
    SOA(SoaData),
    OPT(EdnsData),
    Other(Vec<u8>),
}

impl ToString for RData {
    fn to_string(&self) -> String {
        match self {
            RData::SOA(v) => format!(
                "{:?} {:?} {} {} {} {} {}",
                v.mname, v.rname, v.serial, v.refresh, v.retry, v.expire, v.minimum
            ),
            RData::OPT(v) => format!("{:?}", v),
            RData::Other(v) => format!("\\#{} {:?}", v.len(), v),
        }
    }
}

#[derive(Clone)]
pub struct RR {
    pub domain: Domain,
    pub class: Class,
    pub rrtype: Type,
    pub ttl: u32,
    pub rdata: RData,
}

impl ToString for RR {
    fn to_string(&self) -> String {
        format!(
            "{} {} {:?} {:?} {:?}",
            self.domain, self.ttl, self.class, self.rrtype, self.rdata
        )
    }
}

impl fmt::Debug for RR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RR({})", self.to_string())
    }
}

#[derive(Eq, PartialOrd, PartialEq, Clone, Copy)]
pub struct Opcode(pub u8);

pub const OPCODE_QUERY: Opcode = Opcode(0);
pub const OPCODE_IQUERY: Opcode = Opcode(1);
pub const OPCODE_STATUS: Opcode = Opcode(2);
pub const OPCODE_NOTIFY: Opcode = Opcode(4);
pub const OPCODE_UPDATE: Opcode = Opcode(5);

impl Ord for Opcode {
    fn cmp(&self, other: &Opcode) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl ToString for Opcode {
    fn to_string(&self) -> String {
        match self {
            &OPCODE_QUERY => String::from("QUERY"),
            &OPCODE_IQUERY => String::from("IQUERY"),
            &OPCODE_STATUS => String::from("STATUS"),
            &OPCODE_NOTIFY => String::from("NOTIFY"),
            &OPCODE_UPDATE => String::from("UPDATE"),
            Opcode(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Opcode({})", self.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct DNSPkt {
    pub qid: u16,
    pub rd: bool,
    pub tc: bool,
    pub aa: bool,
    pub qr: bool,
    pub opcode: Opcode,

    pub cd: bool,
    pub ad: bool,
    pub ra: bool,
    pub rcode: RCode,
    pub bufsize: u16,
    pub edns_ver: Option<u8>,
    pub edns_do: bool,

    pub question: Question,

    pub answer: Vec<RR>,
    pub nameserver: Vec<RR>,
    pub additional: Vec<RR>,

    pub edns: Option<EdnsData>,
}

fn push_u16(v: &mut Vec<u8>, d: u16) {
    v.push((d >> 8) as u8);
    v.push((d & 0xFF) as u8);
}

fn push_u32(v: &mut Vec<u8>, d: u32) {
    v.push(((d >> 24) & 0xFF) as u8);
    v.push(((d >> 16) & 0xFF) as u8);
    v.push(((d >> 8) & 0xFF) as u8);
    v.push((d & 0xFF) as u8);
}

fn push_label(v: &mut Vec<u8>, l: &Label) {
    v.push(l.0.len() as u8);
    v.extend_from_slice(l.0.as_slice())
}

fn push_domain(v: &mut Vec<u8>, d: &Domain) {
    d.0.iter().for_each(|l| push_label(v, l));
    v.push(0)
}

fn make_edns_opt(v: &mut Vec<u8>, t: &EdnsOption) {
    push_u16(v, t.code.0);
    push_u16(v, t.data.len() as u16);
    v.extend_from_slice(t.data.as_slice());
}

impl EdnsData {
    fn push_opt(&self, mut v: &mut Vec<u8>) {
        self.other.iter().for_each(|o| make_edns_opt(&mut v, o));
    }
}

fn push_rr(v: &mut Vec<u8>, rr: &RR) {
    push_domain(v, &rr.domain);
    push_u16(v, rr.rrtype.0);
    push_u16(v, rr.class.0);
    push_u32(v, rr.ttl);
    match &rr.rdata {
        RData::SOA(s) => {
            let mut vs = Vec::<u8>::new();
            push_domain(&mut vs, &s.mname);
            v.extend_from_slice(vs.as_slice());
        }
        RData::OPT(o) => {
            let mut vo = Vec::<u8>::new();
            o.push_opt(&mut vo);
            push_u16(v, vo.len() as u16);
            v.extend_from_slice(vo.as_slice());
        }
        RData::Other(x) => {
            push_u16(v, x.len() as u16);
            v.extend_from_slice(x.as_slice());
        }
    }
}

impl DNSPkt {
    pub fn serialise(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        let flag1: u8 = (if self.rd { 0b0000_0001 } else { 0b0 })
            | (if self.tc { 0b0000_0010 } else { 0b0 })
            | (if self.aa { 0b0000_0100 } else { 0b0 })
            | (if self.qr { 0b1000_0000 } else { 0b0 })
            | (self.opcode.0 << 3);
        let flag2: u8 = (if self.cd { 0b0010_0000 } else { 0b0 })
            |(if self.ad { 0b0100_0000 } else { 0b0 })
            |(if self.ra { 0b1000_0000 } else { 0b0 })
            //             0b0001_0000
            |((self.rcode.0 & 0b0000_1111) as u8);
        let mut additional = self.additional.clone();

        if self.edns.is_some() && self.bufsize != 512 {
            let edns = self.edns.clone().unwrap_or(EdnsData { other: vec![] });

            additional.push(RR {
                domain: Domain::from(vec![]),
                class: Class(self.bufsize),
                rrtype: RR_OPT,
                ttl: ((self.edns_ver.unwrap_or(0) as u32) << 16)
                    | (if self.edns_do {
                        0b00000000_00000000_10000000_00000000
                    } else {
                        0b0
                    }),
                rdata: RData::OPT(edns),
            });
        }

        push_u16(&mut ret, self.qid);
        ret.push(flag1);
        ret.push(flag2);
        push_u16(&mut ret, 1); // qcount
        push_u16(&mut ret, self.answer.len() as u16);
        push_u16(&mut ret, self.nameserver.len() as u16);
        push_u16(&mut ret, additional.len() as u16);
        push_domain(&mut ret, &self.question.qdomain);
        push_u16(&mut ret, self.question.qtype.0);
        push_u16(&mut ret, self.question.qclass.0);
        self.answer.iter().for_each(|rr| push_rr(&mut ret, rr));
        self.nameserver.iter().for_each(|rr| push_rr(&mut ret, rr));
        additional.iter().for_each(|rr| push_rr(&mut ret, rr));

        ret
    }

    pub fn get_expiry(&self) -> std::time::Duration {
        self.answer
            .iter()
            .chain(self.nameserver.iter())
            .chain(self.additional.iter())
            .map(|rr| std::time::Duration::from_secs(rr.ttl as u64))
            .min()
            .unwrap_or_else(|| std::time::Duration::from_secs(0))
    }

    pub fn clone_with_ttl_decrement(&self, decrement: u32) -> DNSPkt {
        DNSPkt {
            question: self.question.clone(),
            additional: self
                .additional
                .iter()
                .map(|x| RR {
                    ttl: x.ttl - decrement,
                    ..x.clone()
                })
                .collect(),
            nameserver: self
                .nameserver
                .iter()
                .map(|x| RR {
                    ttl: x.ttl - decrement,
                    ..x.clone()
                })
                .collect(),
            answer: self
                .answer
                .iter()
                .map(|x| RR {
                    ttl: x.ttl - decrement,
                    ..x.clone()
                })
                .collect(),
            edns: self.edns.clone(),
            ..*self
        }
    }
}
