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
 *  Datastructures and serialisation of DNS packets.
 */

#[cfg(fuzzing)]
use arbitrary::Arbitrary;
use std::fmt;

#[derive(Eq, Ord, PartialOrd, PartialEq, Clone, Copy)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct Class(pub u16);

pub const CLASS_IN: Class = Class(1); /* Internet */
pub const CLASS_CH: Class = Class(3); /* ChaosNet */

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &CLASS_IN => write!(f, "IN"),
            &CLASS_CH => write!(f, "CH"),
            Class(x) => write!(f, "Class#{}", x),
        }
    }
}

impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Class({})", self)
    }
}

#[derive(Ord, PartialOrd, PartialEq, Eq, Clone, Hash, Copy)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct Type(pub u16);

pub const RR_A: Type = Type(1);
pub const RR_NS: Type = Type(2);
pub const RR_CNAME: Type = Type(5);
pub const RR_SOA: Type = Type(6);
pub const RR_PTR: Type = Type(12);
pub const RR_MX: Type = Type(15);
pub const RR_RP: Type = Type(17);
pub const RR_AFSDB: Type = Type(18);
pub const RR_RT: Type = Type(21);
pub const RR_NAPTR: Type = Type(35);
pub const RR_OPT: Type = Type(41);
pub const RR_NSEC: Type = Type(47);
pub const RR_NSEC3: Type = Type(50);
pub const RR_ANY: Type = Type(255);

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &RR_A => write!(f, "A"),
            &RR_NS => write!(f, "NS"),
            &RR_CNAME => write!(f, "CNAME"),
            &RR_SOA => write!(f, "SOA"),
            &RR_PTR => write!(f, "PTR"),
            &RR_NAPTR => write!(f, "NAPTR"),
            &RR_OPT => write!(f, "OPT"),
            &RR_NSEC => write!(f, "NSEC"),
            &RR_NSEC3 => write!(f, "NSEC3"),
            Type(x) => write!(f, "Type#{}", x),
        }
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Type({})", self)
    }
}

#[derive(Ord, PartialOrd, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct RCode(pub u16);
pub const NOERROR: RCode = RCode(0);
pub const FORMERR: RCode = RCode(1);
pub const SERVFAIL: RCode = RCode(2);
pub const NXDOMAIN: RCode = RCode(3);
pub const NOTIMP: RCode = RCode(4);
pub const REFUSED: RCode = RCode(5);
pub const YXDOMAIN: RCode = RCode(6);
pub const YXRRSET: RCode = RCode(7);
pub const NXRRSET: RCode = RCode(8);
pub const NOTAUTH: RCode = RCode(9);
pub const NOTZONE: RCode = RCode(10);
pub const DSOTYPENI: RCode = RCode(11);
pub const BADVERS: RCode = RCode(16);
pub const BADSIG: RCode = RCode(16); /* Yes, this is a dupe */
pub const BADKEY: RCode = RCode(17);
pub const BADTIME: RCode = RCode(18);
pub const BADMODE: RCode = RCode(19);
pub const BADNAME: RCode = RCode(20);
pub const BADALG: RCode = RCode(21);
pub const BADTRUNC: RCode = RCode(22);
pub const BADCOOKIE: RCode = RCode(23);

impl fmt::Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &NOERROR => write!(f, "NOERROR"),
            &FORMERR => write!(f, "FORMERR"),
            &SERVFAIL => write!(f, "SERVFAIL"),
            &NXDOMAIN => write!(f, "NXDOMAIN"),
            &NOTIMP => write!(f, "NOTIMP"),
            &REFUSED => write!(f, "REFUSED"),
            &YXDOMAIN => write!(f, "YXDOMAIN"),
            &YXRRSET => write!(f, "YXRRSET"),
            &NXRRSET => write!(f, "NXRRSET"),
            &NOTAUTH => write!(f, "NOTAUTH"),
            &NOTZONE => write!(f, "NOTZONE"),
            &DSOTYPENI => write!(f, "DSOTYPENI"),
            &BADVERS => write!(f, "BADVERS/BADSIG"),
            &BADKEY => write!(f, "BADKEY"),
            &BADTIME => write!(f, "BADTIME"),
            &BADMODE => write!(f, "BADMODE"),
            &BADNAME => write!(f, "BADNAME"),
            &BADALG => write!(f, "BADALG"),
            &BADTRUNC => write!(f, "BADTRUNC"),
            &BADCOOKIE => write!(f, "BADCOOKIE"),
            RCode(x) => write!(f, "RCode#{}", x),
        }
    }
}

impl fmt::Debug for RCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RCode({})", self)
    }
}

fn display_byte(b: u8) -> String {
    match b {
        n @ 32..=127 => char::from(n).to_string(),
        n => format!("\\{}", n),
    }
}

#[derive(Ord, Clone, PartialEq, Eq, PartialOrd, Hash, Debug)]
pub struct Label(Vec<u8>);

impl From<Vec<u8>> for Label {
    fn from(mut v: Vec<u8>) -> Self {
        assert!(!v.is_empty());
        v.shrink_to_fit();
        Label(v)
    }
}
impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0.iter().map(|&b| display_byte(b)).collect::<String>()
        )
    }
}

#[cfg(fuzzing)]
impl<'a> Arbitrary<'a> for Label {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        /* Labels cannot be empty. */
        loop {
            let v = Vec::<u8>::arbitrary(u)?;
            if v.len() > 0 && v.len() < 64 {
                return Ok(Self(v));
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Hash)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct Domain(Vec<Label>);

impl Domain {
    pub fn ends_with(&self, other: &Self) -> bool {
        self.0.ends_with(&other.0)
    }
}

impl From<Vec<Label>> for Domain {
    fn from(mut v: Vec<Label>) -> Self {
        v.shrink_to_fit();
        Domain(v)
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Domain({:?})", self.0)
    }
}

impl std::str::FromStr for Domain {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v = vec![];
        let mut l = vec![];
        for c in s.chars() {
            match c {
                '\\' => return Err("\\ not yet supported"), // TODO
                '.' => {
                    if l.is_empty() {
                        return Err("illegal empty label");
                    }
                    l.shrink_to_fit();
                    v.push(Label(l));
                    l = vec![]
                }
                ch if ch.is_ascii() => l.push(ch as u8),
                _ => return Err("illegal charactor in label"),
            }
        }
        if !l.is_empty() {
            l.shrink_to_fit();
            v.push(Label(l));
        }
        v.shrink_to_fit();
        Ok(Domain(v))
    }
}

// We want to sort longer suffixes first.
pub fn compare_longest_suffix(lhs: &Domain, rhs: &Domain) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    if lhs.0.len() != rhs.0.len() {
        if lhs.0.len() < rhs.0.len() {
            Greater // Because we want the largest first, not smallest first.
        } else {
            Less
        }
    } else {
        // If they are the same length, then just compare based on the text
        lhs.0.cmp(&rhs.0)
    }
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct Question {
    pub qdomain: Domain,
    pub qclass: Class,
    pub qtype: Type,
}

impl fmt::Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {:?} {:?}", self.qdomain, self.qclass, self.qtype)
    }
}

impl fmt::Debug for Question {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Question({:?} {:?} {:?})",
            self.qdomain, self.qclass, self.qtype
        )
    }
}

#[derive(Ord, Eq, PartialEq, PartialOrd, Clone)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct EdnsCode(pub u16);

pub const EDNS_NSID: EdnsCode = EdnsCode(3);
pub const EDNS_CLIENT_SUBNET: EdnsCode = EdnsCode(8);
pub const EDNS_COOKIE: EdnsCode = EdnsCode(10);
pub const EDNS_EDE: EdnsCode = EdnsCode(15);

impl fmt::Display for EdnsCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &EDNS_NSID => write!(f, "NSID"),
            &EDNS_CLIENT_SUBNET => write!(f, "CLIENT_SUBNET"),
            &EDNS_COOKIE => write!(f, "COOKIE"),
            &EDNS_EDE => write!(f, "EXTENDED_DNS_ERROR"),
            EdnsCode(c) => write!(f, "EDNS#{}", c),
        }
    }
}

impl fmt::Debug for EdnsCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EdnsCode({})", self)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct EdeCode(u16);

pub const EDE_OTHER: EdeCode = EdeCode(0);
pub const EDE_UNSUPPORTED_DNSKEY_ALGO: EdeCode = EdeCode(1);
pub const EDE_UNSUPPORTED_DS_DIGEST: EdeCode = EdeCode(2);
pub const EDE_STALE_ANSWER: EdeCode = EdeCode(3);
pub const EDE_FORGED_ANSWER: EdeCode = EdeCode(4);
pub const EDE_DNSSEC_INDETERMINATE: EdeCode = EdeCode(5);
pub const EDE_DNSSEC_BOGUS: EdeCode = EdeCode(6);
pub const EDE_SIGNATURE_EXPIRED: EdeCode = EdeCode(7);
pub const EDE_SIGNATURE_NOT_YET_VALID: EdeCode = EdeCode(8);
pub const EDE_DNSKEY_MISSING: EdeCode = EdeCode(9);
pub const EDE_RRSIG_MISSING: EdeCode = EdeCode(10);
pub const EDE_NO_ZONE_KEY_BIT_SET: EdeCode = EdeCode(11);
pub const EDE_NSEC_MISSING: EdeCode = EdeCode(12);
pub const EDE_CACHED_ERROR: EdeCode = EdeCode(13);
pub const EDE_NOT_READY: EdeCode = EdeCode(14);
pub const EDE_BLOCKED: EdeCode = EdeCode(15);
pub const EDE_CENSORED: EdeCode = EdeCode(16);
pub const EDE_FILTERED: EdeCode = EdeCode(17);
pub const EDE_PROHIBITED: EdeCode = EdeCode(18);
pub const EDE_STALE_NXDOMAIN: EdeCode = EdeCode(19);
pub const EDE_NOT_AUTHORITATIVE: EdeCode = EdeCode(20);
pub const EDE_NOT_SUPPORTED: EdeCode = EdeCode(21);
pub const EDE_NO_REACHABLE_AUTHORITY: EdeCode = EdeCode(22);
pub const EDE_NETWORK_ERROR: EdeCode = EdeCode(23);
pub const EDE_INVALID_DATA: EdeCode = EdeCode(24);

impl fmt::Display for EdeCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &EDE_OTHER => write!(f, "OTHER"),
            &EDE_UNSUPPORTED_DNSKEY_ALGO => write!(f, "UNSUPPORTED_DNSKEY_ALGO"),
            &EDE_UNSUPPORTED_DS_DIGEST => write!(f, "UNSUPPORTED_DS_DIGEST"),
            &EDE_STALE_ANSWER => write!(f, "STALE_ANSWER"),
            &EDE_FORGED_ANSWER => write!(f, "FORGED_ANSWER"),
            &EDE_DNSSEC_INDETERMINATE => write!(f, "DNSSEC_INDETERMINATE"),
            &EDE_DNSSEC_BOGUS => write!(f, "DNSSEC_BOGUS"),
            &EDE_SIGNATURE_EXPIRED => write!(f, "SIGNATURE_EXPIRED"),
            &EDE_SIGNATURE_NOT_YET_VALID => write!(f, "SIGNATURE_NOT_YET_VALID"),
            &EDE_DNSKEY_MISSING => write!(f, "DNSKEY_MISSING"),
            &EDE_RRSIG_MISSING => write!(f, "RRSIG_MISSING"),
            &EDE_NO_ZONE_KEY_BIT_SET => write!(f, "NO_ZONE_KEY_BIT_SET"),
            &EDE_NSEC_MISSING => write!(f, "NSEC_MISSING"),
            &EDE_CACHED_ERROR => write!(f, "CACHED_ERROR"),
            &EDE_NOT_READY => write!(f, "NOT_READY"),
            &EDE_BLOCKED => write!(f, "BLOCKED"),
            &EDE_CENSORED => write!(f, "CENSORED"),
            &EDE_FILTERED => write!(f, "FILTERED"),
            &EDE_PROHIBITED => write!(f, "PROHIBITED"),
            &EDE_STALE_NXDOMAIN => write!(f, "STALE_NXDOMAIN"),
            &EDE_NOT_AUTHORITATIVE => write!(f, "NOT_AUTHORITATIVE"),
            &EDE_NOT_SUPPORTED => write!(f, "NOT_SUPPOTED"),
            &EDE_NO_REACHABLE_AUTHORITY => write!(f, "NO_REACHABLE_AUTHORITY"),
            &EDE_NETWORK_ERROR => write!(f, "NETWORK_ERROR"),
            &EDE_INVALID_DATA => write!(f, "INVALID_DATA"),
            EdeCode(c) => write!(f, "EdeCode({})", c),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct EdnsOption {
    pub code: EdnsCode,
    pub data: Vec<u8>,
}

impl fmt::Debug for EdnsOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.code {
            EDNS_EDE => write!(
                f,
                "EdnsOption({}: {})",
                self.code,
                String::from_utf8_lossy(&self.data[..])
            ),
            EDNS_COOKIE => write!(
                f,
                "EdnsOption({}: {})",
                self.code,
                self.data[..]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join("")
            ),
            ref code => write!(f, "EdnsOption({}: {:?})", code, self.data),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct EdnsData(Vec<EdnsOption>);

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct SoaData {
    pub mname: Domain,
    pub rname: Domain,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct PrefDomainData {
    pub pref: u16,
    pub domain: Domain,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct AFSDBData {
    pub subtype: u16,
    pub hostname: Domain,
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct RPData {
    pub mbox: Domain,
    pub txt: Domain,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NAPTRData {
    pub order: u16,
    pub preference: u16,
    pub flags: Vec<u8>,
    pub services: Vec<u8>,
    pub regexp: Vec<u8>,
    pub replacement: Domain,
}

#[cfg(fuzzing)]
impl<'a> Arbitrary<'a> for NAPTRData {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let order = <_>::arbitrary(u)?;
        let preference = <_>::arbitrary(u)?;
        let mut flags: Vec<u8> = <_>::arbitrary(u)?;
        let mut services: Vec<u8> = <_>::arbitrary(u)?;
        let mut regexp: Vec<u8> = <_>::arbitrary(u)?;
        let replacement = <_>::arbitrary(u)?;
        flags.truncate(255);
        services.truncate(255);
        regexp.truncate(255);
        Ok(NAPTRData {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub enum RData {
    CName(Domain),
    Mx(PrefDomainData),
    Ns(Domain),
    Ptr(Domain),
    Soa(SoaData),
    Opt(EdnsData),
    AfsDb(AFSDBData),
    Rp(RPData),
    Rt(PrefDomainData),
    NaPtr(NAPTRData),
    Other(Vec<u8>),
}

impl std::fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RData::*;
        match self {
            CName(d) | Ns(d) | Ptr(d) => write!(f, "\"{}\"", d),
            Mx(pd) | Rt(pd) => write!(f, "{} {}", pd.pref, pd.domain),
            AfsDb(afs) => write!(f, "{} {}", afs.subtype, afs.hostname),
            Rp(rp) => write!(f, "{} {}", rp.mbox, rp.txt),
            NaPtr(na) => write!(
                f,
                "{} {} {:?} {:?} {:?} \"{}\"",
                na.order, na.preference, na.flags, na.services, na.regexp, na.replacement
            ),
            Soa(v) => write!(
                f,
                "{:?} {:?} {} {} {} {} {}",
                v.mname, v.rname, v.serial, v.refresh, v.retry, v.expire, v.minimum
            ),
            Opt(v) => write!(f, "{:?}", v),
            Other(v) => write!(f, "\\#{} {:?}", v.len(), v),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RR {
    pub domain: Domain,
    pub class: Class,
    pub rrtype: Type,
    pub ttl: u32,
    pub rdata: RData,
}

impl std::fmt::Display for RR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\"{}\" {} {:?} {:?} {}",
            self.domain, self.ttl, self.class, self.rrtype, self.rdata
        )
    }
}

impl fmt::Debug for RR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RR({})", self)
    }
}

#[cfg(fuzzing)]
impl<'a> Arbitrary<'a> for RR {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let domain = <_>::arbitrary(u)?;
        let class = <_>::arbitrary(u)?;
        let ttl = <_>::arbitrary(u)?;
        let rdata = <_>::arbitrary(u)?;
        let rrtype = match &rdata {
            RData::Ns(_) => RR_NS,
            RData::CName(_) => RR_CNAME,
            RData::Soa(_) => RR_SOA,
            RData::Ptr(_) => RR_PTR,
            RData::Mx(_) => RR_MX,
            RData::Rp(_) => RR_RP,
            RData::AfsDb(_) => RR_AFSDB,
            RData::Rt(_) => RR_RT,
            RData::NaPtr(_) => RR_NAPTR,
            RData::Opt(_) => RR_OPT,
            RData::Other(_) => loop {
                /* Don't create RR_SOA or RR_OPT */
                let rrtype = <_>::arbitrary(u)?;
                if rrtype != RR_NS
                    && rrtype != RR_CNAME
                    && rrtype != RR_SOA
                    && rrtype != RR_PTR
                    && rrtype != RR_MX
                    && rrtype != RR_RP
                    && rrtype != RR_AFSDB
                    && rrtype != RR_RT
                    && rrtype != RR_NAPTR
                    && rrtype != RR_OPT
                {
                    break rrtype;
                }
            },
        };
        return Ok(Self {
            domain,
            class,
            rrtype,
            ttl,
            rdata,
        });
    }
}

#[derive(Ord, Eq, PartialOrd, PartialEq, Clone, Copy)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct Opcode(pub u8);

pub const OPCODE_QUERY: Opcode = Opcode(0);
pub const OPCODE_IQUERY: Opcode = Opcode(1);
pub const OPCODE_STATUS: Opcode = Opcode(2);
pub const OPCODE_NOTIFY: Opcode = Opcode(4);
pub const OPCODE_UPDATE: Opcode = Opcode(5);

impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &OPCODE_QUERY => write!(f, "QUERY"),
            &OPCODE_IQUERY => write!(f, "IQUERY"),
            &OPCODE_STATUS => write!(f, "STATUS"),
            &OPCODE_NOTIFY => write!(f, "NOTIFY"),
            &OPCODE_UPDATE => write!(f, "UPDATE"),
            Opcode(x) => write!(f, "#{}", x),
        }
    }
}

impl fmt::Debug for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Opcode({})", self)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
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

#[cfg(fuzzing)]
impl<'a> Arbitrary<'a> for DNSPkt {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let qid = <_>::arbitrary(u)?;
        let rd = <_>::arbitrary(u)?;
        let tc = <_>::arbitrary(u)?;
        let aa = <_>::arbitrary(u)?;
        let qr = <_>::arbitrary(u)?;
        let opcode: u8 = <_>::arbitrary(u)?;
        let cd = <_>::arbitrary(u)?;
        let ad = <_>::arbitrary(u)?;
        let ra = <_>::arbitrary(u)?;
        let rcode = loop {
            let rcode = RCode::arbitrary(u)?;
            if rcode.0 <= 0b1111_1111_1111u16 {
                break rcode;
            }
        };
        let bufsize = <_>::arbitrary(u)?;
        let edns_ver = <_>::arbitrary(u)?;
        let edns_do = <_>::arbitrary(u)?;
        let question = <_>::arbitrary(u)?;
        let answer = <_>::arbitrary(u)?;
        let additional = <_>::arbitrary(u)?;
        let nameserver = <_>::arbitrary(u)?;
        let edns = <_>::arbitrary(u)?;

        return Ok(Self {
            qid,
            rd,
            tc,
            aa,
            qr,
            opcode: Opcode(opcode % 31),
            cd,
            ad,
            ra,
            rcode,
            bufsize,
            edns_ver,
            edns_do,
            question,
            answer,
            additional,
            nameserver,
            edns,
        });
    }
}

#[derive(Clone)]
struct DomainTree<T: Default> {
    label: Label,
    data: T,
    children: std::collections::LinkedList<Self>,
}

#[cfg(any(test, fuzzing))]
impl<T: fmt::Debug + Default> fmt::Debug for DomainTree<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "DomainTree(label: {}, data: {:?}, children: {:#?})",
            self.label, self.data, self.children
        )
    }
}

impl<T: Default> DomainTree<T> {
    fn new() -> Self {
        DomainTree {
            label: Label("root".into()),
            data: Default::default(),
            children: Default::default(),
        }
    }
}

type DomainOffsets = DomainTree<u16>;

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
    assert!(!l.0.is_empty());
    assert!(l.0.len() < 64);
    v.push(l.0.len() as u8);
    v.extend_from_slice(l.0.as_slice())
}

/* This does label compression.
 * node is Some if some node exists in the suffix tree for the suffix.
 * node is None if no node exists (and a label will need to be output).
 * this returns Some if this created a new node that needs to be appended to the tree (and also if
 * it output a label)
 * this returns None if there was an existing node, *and* it output the compression for the entire
 * suffix (so no more suffixes are needed).
 */
fn push_prefix(
    v: &mut Vec<u8>,
    l: &[Label],
    node: &mut Option<&mut DomainOffsets>,
    base_offset: usize,
) -> Option<DomainOffsets> {
    assert!(!l.is_empty());
    let label = &l[l.len() - 1];
    let prefix = &l[..l.len() - 1];
    let mut child = None;
    if let Some(ref mut node) = node {
        for it in &mut node.children {
            if it.label == *label {
                child = Some(&mut *it);
            }
        }
    }
    if !prefix.is_empty() {
        let ret = push_prefix(v, prefix, &mut child, base_offset);
        match (ret, child) {
            (None, None) => {
                /* They output a suffix, but we aren't part of that suffix?! */
                unreachable!()
            }
            (None, Some(_)) => {
                /* They output a suffix, we are part of the suffix, nothing to do. */
                None
            }
            (Some(r), None) => {
                /* They have output a label, we need to output a label. */
                let offset = v.len() + base_offset;
                push_label(v, label);
                let mut children = std::collections::LinkedList::new();
                children.push_back(r);
                Some(DomainTree {
                    label: label.clone(),
                    data: offset as u16,
                    children,
                })
            }
            (Some(r), Some(n)) => {
                /* They have output a label, we need to output a suffix */
                n.children.push_back(r);
                assert!((n.data >> 8) < 64);
                assert_ne!(n.data, 0);
                v.push(0b1100_0000u8 + (n.data >> 8) as u8);
                v.push((n.data & 0xff) as u8);
                None
            }
        }
    } else {
        match &child {
            None => {
                /* Not found - we need to output our label */
                let offset = v.len() + base_offset;
                push_label(v, label);
                Some(DomainTree {
                    label: label.clone(),
                    data: offset as u16,
                    children: std::collections::LinkedList::new(),
                })
            }
            Some(n) => {
                /* Found - we can output the entire domain as one compressed label. */
                v.push(0b1100_0000u8 + (n.data >> 8) as u8);
                v.push((n.data & 0xff) as u8);
                None
            }
        }
    }
}

fn push_compressed_domain(
    v: &mut Vec<u8>,
    d: &Domain,
    offsets: &mut DomainOffsets,
    base_offset: usize,
) {
    if d.0.is_empty() {
        v.push(0u8);
    } else {
        match push_prefix(v, &d.0, &mut Some(offsets), base_offset) {
            None => { /* Suffix compression already output */ }
            Some(n) => {
                offsets.children.push_back(n);
                v.push(0u8);
            }
        }
    }
}

fn push_str(v: &mut Vec<u8>, s: &[u8]) {
    assert!(s.len() < 256);
    v.push(s.len() as u8);
    v.extend(s);
}

fn make_edns_opt(v: &mut Vec<u8>, t: &EdnsOption) {
    push_u16(v, t.code.0);
    push_u16(v, t.data.len() as u16);
    v.extend_from_slice(t.data.as_slice());
}

impl EdnsData {
    pub const fn new() -> Self {
        Self(vec![])
    }
    fn push_opt(&self, v: &mut Vec<u8>) {
        self.0.iter().for_each(|o| make_edns_opt(v, o));
    }

    fn get_opt(&self, opt: &EdnsCode) -> Option<&EdnsOption> {
        self.0.iter().find(|o| o.code == *opt)
    }

    pub fn get_nsid(&self) -> Option<&[u8]> {
        self.get_opt(&EDNS_NSID).map(|opt| &opt.data[..])
    }

    pub fn set_nsid(&mut self, nsid: &[u8]) {
        self.set_opt(EdnsOption {
            code: EDNS_NSID,
            data: nsid.to_vec(),
        });
    }

    pub fn get_cookie(&self) -> Option<(&[u8], Option<&[u8]>)> {
        self.get_opt(&EDNS_COOKIE)
            .map(|opt| (&opt.data[..8], opt.data.get(8..)))
    }

    pub fn set_cookie(&mut self, client: &[u8], server: &[u8]) {
        assert!(client.len() == 8);
        assert!(server.len() >= 8 && server.len() <= 32);
        let mut data = Vec::with_capacity(client.len() + server.len());
        data.extend(client);
        data.extend(server);
        self.set_opt(EdnsOption {
            code: EDNS_COOKIE,
            data,
        })
    }

    pub fn get_extended_dns_error(&self) -> Option<(EdeCode, String)> {
        self.get_opt(&EDNS_EDE).map(|opt| {
            (
                EdeCode(u16::from_be_bytes([opt.data[0], opt.data[1]])),
                String::from_utf8_lossy(&opt.data[2..]).into_owned(),
            )
        })
    }

    pub fn set_opt(&mut self, opt: EdnsOption) {
        self.0.push(opt);
    }

    pub fn set_extended_dns_error(&mut self, code: EdeCode, msg: &str) {
        let mut data = vec![];
        data.extend(code.0.to_be_bytes().iter());
        data.extend(msg.bytes());
        self.set_opt(EdnsOption {
            code: EDNS_EDE,
            data,
        });
    }
}

fn push_rr(v: &mut Vec<u8>, rr: &RR, offsets: &mut DomainOffsets) {
    push_compressed_domain(v, &rr.domain, offsets, 0);
    push_u16(v, rr.rrtype.0);
    push_u16(v, rr.class.0);
    push_u32(v, rr.ttl);
    match &rr.rdata {
        RData::CName(d) | RData::Ptr(d) | RData::Ns(d) => {
            let mut vs = vec![];
            push_compressed_domain(&mut vs, d, offsets, v.len() + 2);
            push_u16(v, vs.len() as u16);
            v.extend_from_slice(vs.as_slice());
        }
        RData::Mx(pd) | RData::Rt(pd) => {
            let mut vs = vec![];
            push_u16(&mut vs, pd.pref);
            push_compressed_domain(&mut vs, &pd.domain, offsets, v.len() + 2);
            push_u16(v, vs.len() as u16);
            v.extend_from_slice(vs.as_slice());
        }
        RData::NaPtr(na) => {
            let mut vs = vec![];
            push_u16(&mut vs, na.order);
            push_u16(&mut vs, na.preference);
            push_str(&mut vs, &na.flags);
            push_str(&mut vs, &na.services);
            push_str(&mut vs, &na.regexp);
            push_compressed_domain(&mut vs, &na.replacement, offsets, v.len() + 2);
            push_u16(v, vs.len() as u16);
            v.extend_from_slice(vs.as_slice());
        }
        RData::Rp(rp) => {
            let mut vs = vec![];
            push_compressed_domain(&mut vs, &rp.mbox, offsets, v.len() + 2);
            push_compressed_domain(&mut vs, &rp.txt, offsets, v.len() + 2);
            push_u16(v, vs.len() as u16);
            v.extend_from_slice(vs.as_slice());
        }
        RData::Soa(s) => {
            assert!(rr.rrtype == RR_SOA);
            let mut vs = vec![];
            push_compressed_domain(&mut vs, &s.mname, offsets, v.len() + 2);
            push_compressed_domain(&mut vs, &s.rname, offsets, v.len() + 2);
            push_u32(&mut vs, s.serial);
            push_u32(&mut vs, s.refresh);
            push_u32(&mut vs, s.retry);
            push_u32(&mut vs, s.expire);
            push_u32(&mut vs, s.minimum);

            push_u16(v, vs.len() as u16);
            v.extend_from_slice(vs.as_slice());
        }
        RData::AfsDb(afs) => {
            let mut vs = vec![];
            push_u16(&mut vs, afs.subtype);
            push_compressed_domain(&mut vs, &afs.hostname, offsets, v.len() + 2);
            push_u16(v, vs.len() as u16);
            v.extend_from_slice(vs.as_slice());
        }
        RData::Opt(o) => {
            assert!(rr.rrtype == RR_OPT);
            let mut vo = vec![];
            o.push_opt(&mut vo);

            push_u16(v, vo.len() as u16);
            v.extend_from_slice(vo.as_slice());
        }
        RData::Other(x) => {
            use std::convert::TryFrom as _;
            assert!(rr.rrtype != RR_OPT && rr.rrtype != RR_SOA);
            push_u16(v, u16::try_from(x.len()).unwrap());
            v.extend_from_slice(x.as_slice());
        }
    }
}

impl DNSPkt {
    pub fn status(&self) -> String {
        match self
            .edns
            .as_ref()
            .and_then(|e| e.get_extended_dns_error())
            .map(|e| e.0)
        {
            Some(x) => format!("{} ({})", self.rcode, x),
            None => format!("{}", self.rcode),
        }
    }
    pub fn serialise(&self) -> Vec<u8> {
        self.serialise_with_size(65536)
    }
    pub fn serialise_with_size(&self, size: usize) -> Vec<u8> {
        assert!(size >= 512);
        let mut ret: Vec<u8> = Vec::new();
        let mut offsets = DomainOffsets::new();
        assert!(self.rcode.0 <= 0b1111_1111_1111);
        let flag1: u8 = u8::from(self.rd)
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

        if self.edns.is_some() {
            let edns = self.edns.clone().unwrap_or_default();

            additional.push(RR {
                domain: Domain::from(vec![]),
                class: Class(self.bufsize),
                rrtype: RR_OPT,
                ttl: (((self.rcode.0 >> 4) as u32) << 24)
                    | ((self.edns_ver.unwrap_or(0) as u32) << 16)
                    | (if self.edns_do {
                        0b0000_0000_0000_0000_1000_0000_0000_0000
                    } else {
                        0b0
                    }),
                rdata: RData::Opt(edns),
            });
        }

        push_u16(&mut ret, self.qid);
        ret.push(flag1);
        ret.push(flag2);
        push_u16(&mut ret, 1); // qcount
        push_u16(&mut ret, self.answer.len() as u16);
        push_u16(&mut ret, self.nameserver.len() as u16);
        push_u16(&mut ret, additional.len() as u16);
        push_compressed_domain(&mut ret, &self.question.qdomain, &mut offsets, 0);
        push_u16(&mut ret, self.question.qtype.0);
        push_u16(&mut ret, self.question.qclass.0);

        let mut trunc = false;
        let mut ancount: u16 = 0;
        let mut nscount: u16 = 0;
        let mut adcount: u16 = 0;

        for rr in &self.answer {
            let offset = ret.len();
            push_rr(&mut ret, rr, &mut offsets);
            if ret.len() > size {
                ret.truncate(offset);
                trunc = true;
                break;
            } else {
                ancount += 1;
            }
        }

        if !trunc {
            for rr in &self.nameserver {
                let offset = ret.len();
                push_rr(&mut ret, rr, &mut offsets);
                if ret.len() > size {
                    ret.truncate(offset);
                    trunc = true;
                    break;
                } else {
                    nscount += 1;
                }
            }
        }

        if !trunc {
            for rr in &additional {
                let offset = ret.len();
                push_rr(&mut ret, rr, &mut offsets);
                if ret.len() > size {
                    ret.truncate(offset);
                    trunc = true;
                    break;
                } else {
                    adcount += 1;
                }
            }
        }

        if trunc {
            // Update the header with the fact we truncated this.
            ret[2] |= 0b0000_0010;
            ret.splice(6..7, ancount.to_be_bytes().iter().copied());
            ret.splice(8..9, nscount.to_be_bytes().iter().copied());
            ret.splice(10..11, adcount.to_be_bytes().iter().copied());
        }

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

    #[must_use]
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

#[test]
fn test_compressed_domain() {
    let mut v = vec![];
    let domain = Domain(vec![]);
    let mut offsets = DomainOffsets::new();
    push_compressed_domain(&mut v, &domain, &mut offsets, 0);
    push_compressed_domain(&mut v, &"local".parse().unwrap(), &mut offsets, 0);
    push_compressed_domain(&mut v, &"c.d.example.com".parse().unwrap(), &mut offsets, 0);
    push_compressed_domain(
        &mut v,
        &"a.b.c.d.example.com".parse().unwrap(),
        &mut offsets,
        0,
    );
    assert_eq!(
        v,
        [
            0, /* empty domain */
            5, 108, 111, 99, 97, 108, 0, /* local */
            1, 99, 1, 100, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109,
            0, /* c.d.example.com */
            1, 97, 1, 98, 192, 8 /* a.b.<offset 8> */
        ]
    );
}

#[test]
fn test_compression_roundtrip() {
    let mut v = vec![];
    let mut offsets = DomainOffsets::new();
    push_compressed_domain(
        &mut v,
        &"test.example.com".parse().unwrap(),
        &mut offsets,
        0,
    );
    push_compressed_domain(
        &mut v,
        &"test2.example.com".parse().unwrap(),
        &mut offsets,
        0,
    );
    push_compressed_domain(
        &mut v,
        &"test.example.com".parse().unwrap(),
        &mut offsets,
        0,
    );
    let mut p = super::parse::PktParser::new(&v);
    assert_eq!(p.get_domain().unwrap(), "test.example.com".parse().unwrap());
    assert_eq!(
        p.get_domain().unwrap(),
        "test2.example.com".parse().unwrap()
    );
    assert_eq!(p.get_domain().unwrap(), "test.example.com".parse().unwrap());
}

#[test]
fn test_rr_roundtrip() {
    let mut v = vec![];
    let mut offsets = DomainOffsets::new();
    let orig_cname = RR {
        domain: "test.example.com".parse().unwrap(),
        class: CLASS_IN,
        rrtype: RR_CNAME,
        ttl: 300,
        rdata: RData::CName("test.example.com".parse().unwrap()),
    };
    let orig_naptr = RR {
        domain: "test.example.com".parse().unwrap(),
        class: CLASS_IN,
        rrtype: RR_NAPTR,
        ttl: 300,
        rdata: RData::NaPtr(NAPTRData {
            order: 10,
            preference: 20,
            flags: "FLAG".into(),
            services: "SERVICE SERVICE".into(),
            regexp: "REGEXP".into(),
            replacement: "test.example.com".parse().unwrap(),
        }),
    };
    push_rr(&mut v, &orig_cname, &mut offsets);
    push_rr(&mut v, &orig_naptr, &mut offsets);
    let mut p = super::parse::PktParser::new(&v);
    assert_eq!(orig_cname, p.get_rr().unwrap());
    assert_eq!(orig_naptr, p.get_rr().unwrap());
}

#[test]
fn test_pkt_roundtrip() {
    let mut orig_edns = EdnsData::new();
    orig_edns.set_extended_dns_error(EDE_OTHER, "Testing");
    let orig_pkt = DNSPkt {
        qid: 140,
        rd: false,
        tc: false,
        aa: false,
        qr: true,
        opcode: Opcode(15),
        cd: false,
        ad: false,
        ra: false,
        rcode: NOERROR,
        bufsize: 512,
        edns_ver: Some(0),
        edns_do: false,
        question: Question {
            qdomain: Domain::from(vec![]),
            qclass: Class(2570),
            qtype: Type(768),
        },
        answer: vec![
            RR {
                domain: Domain::from(vec![]),
                ttl: 16843009,
                class: Class(257),
                rrtype: RR_NAPTR,
                rdata: RData::NaPtr(NAPTRData {
                    order: 47288,
                    preference: 11960,
                    flags: "flags".into(),
                    services: "".into(),
                    regexp: "\u{1}".into(),
                    replacement: Domain::from(vec![]),
                }),
            },
            RR {
                domain: Domain::from(vec![]),
                ttl: 1234,
                class: CLASS_IN,
                rrtype: RR_SOA,
                rdata: RData::Soa(SoaData {
                    mname: "dnsmaster.example.com".parse().unwrap(),
                    rname: "ns1.example.com".parse().unwrap(),
                    serial: 1,
                    refresh: 3600,
                    retry: 300,
                    expire: 86400,
                    minimum: 600,
                }),
            },
            RR {
                domain: Domain::from(vec![]),
                ttl: 1234,
                class: CLASS_IN,
                rrtype: RR_MX,
                rdata: RData::Mx(PrefDomainData {
                    pref: 10,
                    domain: "mx.example.com".parse().unwrap(),
                }),
            },
        ],
        nameserver: vec![],
        additional: vec![],
        edns: Some(orig_edns),
    };
    let v = orig_pkt.serialise();
    let mut p = super::parse::PktParser::new(&v);
    assert_eq!(orig_pkt, p.get_dns().unwrap());
}

#[test]
fn domain_from_str() {
    assert_eq!(
        "example.com".parse(),
        Ok(Domain(vec![
            Label(vec![b'e', b'x', b'a', b'm', b'p', b'l', b'e']),
            Label(vec![b'c', b'o', b'm'])
        ]))
    );
}
