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
 *  Parsing/Serialisation for a DHCP Packet.
 */

use std::collections;
use std::fmt;
use std::net;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedEndOfInput,
    WrongMagic,
    InvalidPacket,
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
            ParseError::WrongMagic => write!(f, "Wrong Magic"),
            ParseError::InvalidPacket => write!(f, "Invalid Packet"),
        }
    }
}

fn get_u8(it: &mut dyn std::iter::Iterator<Item = &u8>) -> Result<u8, ParseError> {
    match it.next() {
        Some(v) => Ok(*v),
        None => Err(ParseError::UnexpectedEndOfInput),
    }
}

fn get_be16(it: &mut dyn std::iter::Iterator<Item = &u8>) -> Result<u16, ParseError> {
    Ok(get_u8(it)? as u16 * 256 + get_u8(it)? as u16)
}

fn get_be32(it: &mut dyn std::iter::Iterator<Item = &u8>) -> Result<u32, ParseError> {
    Ok(get_u8(it)? as u32 * (256 * 256 * 256)
        + get_u8(it)? as u32 * (256 * 256)
        + get_u8(it)? as u32 * 256
        + get_u8(it)? as u32)
}

fn get_bytes(
    it: &mut dyn std::iter::Iterator<Item = &u8>,
    l: usize,
) -> Result<Vec<u8>, ParseError> {
    let mut v = vec![];
    for _ in 0..l {
        v.push(get_u8(it)?);
    }
    Ok(v)
}

fn get_ipv4(it: &mut dyn std::iter::Iterator<Item = &u8>) -> Result<net::Ipv4Addr, ParseError> {
    let a = get_u8(it)?;
    let b = get_u8(it)?;
    let c = get_u8(it)?;
    let d = get_u8(it)?;
    Ok(net::Ipv4Addr::new(a, b, c, d))
}

#[derive(PartialEq, Eq)]
pub struct DhcpOp(u8);
pub const OP_BOOTREQUEST: DhcpOp = DhcpOp(1);
pub const OP_BOOTREPLY: DhcpOp = DhcpOp(2);

impl ToString for DhcpOp {
    fn to_string(&self) -> String {
        match self {
            &OP_BOOTREQUEST => String::from("BOOTREQUEST"),
            &OP_BOOTREPLY => String::from("BOOTREPLY"),
            DhcpOp(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for DhcpOp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "DhcpOp({})", self.to_string());
    }
}

#[derive(PartialEq, Eq)]
pub struct HwType(u8);
pub const HWTYPE_ETHERNET: HwType = HwType(1);

impl ToString for HwType {
    fn to_string(&self) -> String {
        match self {
            &HWTYPE_ETHERNET => String::from("Ethernet"),
            HwType(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for HwType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "HwType({})", self.to_string());
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct MessageType(u8);
pub const DHCPDISCOVER: MessageType = MessageType(1);
pub const DHCPOFFER: MessageType = MessageType(2);
pub const DHCPREQUEST: MessageType = MessageType(3);
pub const DHCPDECLINE: MessageType = MessageType(4);
pub const DHCPACK: MessageType = MessageType(5);
pub const DHCPNAK: MessageType = MessageType(6);
pub const DHCPRELEASE: MessageType = MessageType(7);
pub const DHCPINFORM: MessageType = MessageType(8);
pub const DHCPFORCERENEW: MessageType = MessageType(9);

impl ToString for MessageType {
    fn to_string(&self) -> String {
        match self {
            &DHCPDISCOVER => String::from("DHCPDISCOVER"),
            &DHCPOFFER => String::from("DHCPOFFER"),
            &DHCPREQUEST => String::from("DHCPREQUEST"),
            &DHCPDECLINE => String::from("DHCPDECLINE"),
            &DHCPACK => String::from("DHCPACK"),
            &DHCPNAK => String::from("DHCPNAK"),
            &DHCPRELEASE => String::from("DHCPRELEASE"),
            &DHCPINFORM => String::from("DHCPINFORM"),
            &DHCPFORCERENEW => String::from("DHCPFORCERENEW"),
            MessageType(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "{}", self.to_string());
    }
}

impl std::default::Default for MessageType {
    fn default() -> Self {
        DHCPNAK
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct DhcpOption(u8);
pub const OPTION_NETMASK: DhcpOption = DhcpOption(1);
pub const OPTION_TIMEOFFSET: DhcpOption = DhcpOption(2);
pub const OPTION_ROUTERADDR: DhcpOption = DhcpOption(3);
pub const OPTION_TIMESERVER: DhcpOption = DhcpOption(4);
pub const OPTION_NAMESERVER: DhcpOption = DhcpOption(5);
pub const OPTION_DOMAINSERVER: DhcpOption = DhcpOption(6);
pub const OPTION_LOGSERVER: DhcpOption = DhcpOption(7);
pub const OPTION_QUOTESERVER: DhcpOption = DhcpOption(8);
pub const OPTION_LPRSERVER: DhcpOption = DhcpOption(9);
pub const OPTION_IMPRESSSERVER: DhcpOption = DhcpOption(10);
pub const OPTION_RLPSERVER: DhcpOption = DhcpOption(11);
pub const OPTION_HOSTNAME: DhcpOption = DhcpOption(12);
pub const OPTION_DOMAINNAME: DhcpOption = DhcpOption(15);
pub const OPTION_ROOTPATH: DhcpOption = DhcpOption(17);
pub const OPTION_EXTFILE: DhcpOption = DhcpOption(18);
pub const OPTION_FORWARD: DhcpOption = DhcpOption(19);
pub const OPTION_SRCRT: DhcpOption = DhcpOption(20);
pub const OPTION_MAXDGASSM: DhcpOption = DhcpOption(21);
pub const OPTION_TTL: DhcpOption = DhcpOption(23);
pub const OPTION_MTUTMOUT: DhcpOption = DhcpOption(24);
pub const OPTION_MTUIF: DhcpOption = DhcpOption(26);
pub const OPTION_MTUSUB: DhcpOption = DhcpOption(27);
pub const OPTION_BROADCAST: DhcpOption = DhcpOption(28);
pub const OPTION_MASKDISCOVERY: DhcpOption = DhcpOption(29);
pub const OPTION_MASKSUPPLIER: DhcpOption = DhcpOption(30);
pub const OPTION_RTRDISCOVERY: DhcpOption = DhcpOption(31);
pub const OPTION_RTRREQ: DhcpOption = DhcpOption(32);
pub const OPTION_TRAILERS: DhcpOption = DhcpOption(34);
pub const OPTION_ARPTIMEOUT: DhcpOption = DhcpOption(35);
pub const OPTION_ETHERNET: DhcpOption = DhcpOption(36);
pub const OPTION_TCPTTL: DhcpOption = DhcpOption(37);
pub const OPTION_TCPKEEPALIVE: DhcpOption = DhcpOption(38);
pub const OPTION_TCPKEEPALIVEGARBAGE: DhcpOption = DhcpOption(39);
pub const OPTION_NISDOMAIN: DhcpOption = DhcpOption(40);
pub const OPTION_NISSERVERS: DhcpOption = DhcpOption(41);
pub const OPTION_NTPSERVERS: DhcpOption = DhcpOption(42);
pub const OPTION_NETBIOSNAMESRV: DhcpOption = DhcpOption(44);
pub const OPTION_NETBIOSDISTSRV: DhcpOption = DhcpOption(45);
pub const OPTION_NETBIOSTYPE: DhcpOption = DhcpOption(46);
pub const OPTION_NETBIOSSCOPE: DhcpOption = DhcpOption(47);
pub const OPTION_XWFONTSRVS: DhcpOption = DhcpOption(48);
pub const OPTION_XWDISPLAY: DhcpOption = DhcpOption(49);
pub const OPTION_ADDRESSREQUEST: DhcpOption = DhcpOption(50);
pub const OPTION_LEASETIME: DhcpOption = DhcpOption(51);
pub const OPTION_MSGTYPE: DhcpOption = DhcpOption(53);
pub const OPTION_SERVERID: DhcpOption = DhcpOption(54);
pub const OPTION_PARAMLIST: DhcpOption = DhcpOption(55);
pub const OPTION_MESSAGE: DhcpOption = DhcpOption(56);
pub const OPTION_MAXMSGSIZE: DhcpOption = DhcpOption(57);
pub const OPTION_RENEWALTIME: DhcpOption = DhcpOption(58);
pub const OPTION_REBINDTIME: DhcpOption = DhcpOption(59);
pub const OPTION_VENDOR_CLASS: DhcpOption = DhcpOption(60);
pub const OPTION_CLIENTID: DhcpOption = DhcpOption(61);
pub const OPTION_NIS3DOMAIN: DhcpOption = DhcpOption(64);
pub const OPTION_NIS3SERVERS: DhcpOption = DhcpOption(65);
pub const OPTION_HOMEAGENT: DhcpOption = DhcpOption(68);
pub const OPTION_SMTP: DhcpOption = DhcpOption(69);
pub const OPTION_POP3: DhcpOption = DhcpOption(70);
pub const OPTION_NNTP: DhcpOption = DhcpOption(71);
pub const OPTION_WWW: DhcpOption = DhcpOption(72);
pub const OPTION_FINGER: DhcpOption = DhcpOption(73);
pub const OPTION_IRC: DhcpOption = DhcpOption(74);
pub const OPTION_STREETTALK: DhcpOption = DhcpOption(75);
pub const OPTION_STDA: DhcpOption = DhcpOption(76);
pub const OPTION_USERCLASS: DhcpOption = DhcpOption(77); /* RFC3004 */
pub const OPTION_FQDN: DhcpOption = DhcpOption(81); /* RFC4702 */
pub const OPTION_PCODE: DhcpOption = DhcpOption(100); /* RFC4833 */
pub const OPTION_TCODE: DhcpOption = DhcpOption(101); /* RFC4833 */
pub const OPTION_AUTOCONF: DhcpOption = DhcpOption(103);
pub const OPTION_SUBNETSELECT: DhcpOption = DhcpOption(104);
//pub const OPTION_DOMAINSEARCH: DhcpOption = DhcpOption(119);
//pub const OPTION_CIDRROUTE: DhcpOption = DhcpOption(121);
pub const OPTION_CAPTIVEPORTAL: DhcpOption = DhcpOption(160);

const OPT_INFO: &[(&str, DhcpOption, DhcpOptionType)] = &[
    ("netmask", OPTION_NETMASK, DhcpOptionType::Ip),
    ("time-offset", OPTION_TIMEOFFSET, DhcpOptionType::I32),
    ("routers", OPTION_ROUTERADDR, DhcpOptionType::IpList),
    ("time-servers", OPTION_TIMESERVER, DhcpOptionType::IpList),
    ("name-servers", OPTION_NAMESERVER, DhcpOptionType::IpList),
    ("dns-servers", OPTION_DOMAINSERVER, DhcpOptionType::IpList),
    ("log-servers", OPTION_LOGSERVER, DhcpOptionType::IpList),
    ("quote-servers", OPTION_QUOTESERVER, DhcpOptionType::IpList),
    ("lpr-servers", OPTION_LPRSERVER, DhcpOptionType::IpList),
    // 10
    (
        "impress-servers",
        OPTION_IMPRESSSERVER,
        DhcpOptionType::IpList,
    ),
    ("rlp-servers", OPTION_RLPSERVER, DhcpOptionType::IpList),
    ("host-name", OPTION_HOSTNAME, DhcpOptionType::String),
    //("bootfile-size", OPTION_BOOTFILESZ, DhcpOptionType::u16),
    //("merit-dump-file", OPTION_MRTDUMPF, ...)
    ("domain-name", OPTION_DOMAINNAME, DhcpOptionType::String),
    //("swap-server", OPTION_SWAPSRV, ...)
    ("root-path", OPTION_ROOTPATH, DhcpOptionType::String),
    ("extension-file", OPTION_EXTFILE, DhcpOptionType::String),
    ("forward", OPTION_FORWARD, DhcpOptionType::Bool),
    // 20
    ("source-route", OPTION_SRCRT, DhcpOptionType::Bool),
    //("policy-filter", OPTION_POLICYFLT, DhcpOptionType::...),
    (
        "max-reassembly",
        OPTION_MAXDGASSM,
        DhcpOptionType::Seconds16,
    ),
    ("default-ttl", OPTION_TTL, DhcpOptionType::U8),
    ("mtu-timeout", OPTION_MTUTMOUT, DhcpOptionType::Seconds32),
    //("mtu-plateu", OPTION_MTUPLATEAU, DhcpOptionType::...), [u16]
    ("mtu", OPTION_MTUIF, DhcpOptionType::U16),
    ("mtu-subnet", OPTION_MTUSUB, DhcpOptionType::Bool),
    ("broadcast", OPTION_BROADCAST, DhcpOptionType::Ip),
    ("mask-discovery", OPTION_MASKDISCOVERY, DhcpOptionType::Bool),
    // 30
    ("mask-supplier", OPTION_MASKSUPPLIER, DhcpOptionType::Bool),
    (
        "router-discovery",
        OPTION_RTRDISCOVERY,
        DhcpOptionType::Bool,
    ),
    ("router-request", OPTION_RTRREQ, DhcpOptionType::Ip),
    //("static-route",  OPTION_STATICROUTE, DhcpOptionType::...), // Needs special handling.
    ("trailers", OPTION_TRAILERS, DhcpOptionType::Bool),
    ("arp-timeout", OPTION_ARPTIMEOUT, DhcpOptionType::Seconds32),
    ("ethernet", OPTION_ETHERNET, DhcpOptionType::Bool),
    ("tcp-ttl", OPTION_TCPTTL, DhcpOptionType::U16),
    (
        "tcp-keepalive",
        OPTION_TCPKEEPALIVE,
        DhcpOptionType::Seconds32,
    ),
    (
        "tcp-keepalive-garbage",
        OPTION_TCPKEEPALIVEGARBAGE,
        DhcpOptionType::Bool,
    ),
    // 40
    ("nis-domain", OPTION_NISDOMAIN, DhcpOptionType::String),
    ("nis-servers", OPTION_NISSERVERS, DhcpOptionType::IpList),
    ("ntp-servers", OPTION_NTPSERVERS, DhcpOptionType::IpList),
    // vendor specific options should be handled specially.
    (
        "netbios-namesrv",
        OPTION_NETBIOSNAMESRV,
        DhcpOptionType::IpList,
    ),
    (
        "netbios-distsrv",
        OPTION_NETBIOSDISTSRV,
        DhcpOptionType::IpList,
    ),
    ("netbios-type", OPTION_NETBIOSTYPE, DhcpOptionType::U8), /* enum? */
    ("netbios-scope", OPTION_NETBIOSSCOPE, DhcpOptionType::String),
    (
        "xwindow-font-servers",
        OPTION_XWFONTSRVS,
        DhcpOptionType::IpList,
    ),
    ("xwindow-display", OPTION_XWDISPLAY, DhcpOptionType::IpList),
    // 50
    ("address-request", OPTION_ADDRESSREQUEST, DhcpOptionType::Ip),
    ("lease-time", OPTION_LEASETIME, DhcpOptionType::Seconds32),
    // overload, handled specially.
    // dhcp msg type, handled specially.
    ("server-id", OPTION_SERVERID, DhcpOptionType::Ip),
    // parameter list, handled specially.
    ("message", OPTION_MESSAGE, DhcpOptionType::String),
    ("max-size", OPTION_MAXMSGSIZE, DhcpOptionType::U16),
    (
        "renewal-time",
        OPTION_RENEWALTIME,
        DhcpOptionType::Seconds16,
    ), // seconds
    ("rebind-time", OPTION_REBINDTIME, DhcpOptionType::Seconds16), // seconds
    // 60
    ("class-id", OPTION_VENDOR_CLASS, DhcpOptionType::String),
    ("client-id", OPTION_CLIENTID, DhcpOptionType::HwAddr),
    // netware
    // netware
    ("nisplus-domain", OPTION_NIS3DOMAIN, DhcpOptionType::String),
    (
        "nisplus-servers",
        OPTION_NIS3SERVERS,
        DhcpOptionType::IpList,
    ),
    //("tftp-server",  OPTION_TFTPSERVER, DhcpOptionType::String), handled specially.
    //bootfile name, handled specially.
    (
        "home-agent-servers",
        OPTION_HOMEAGENT,
        DhcpOptionType::IpList,
    ),
    ("smtp-servers", OPTION_SMTP, DhcpOptionType::IpList),
    // 70
    ("pop3-servers", OPTION_POP3, DhcpOptionType::IpList),
    ("nntp-servers", OPTION_NNTP, DhcpOptionType::IpList),
    ("www-servers", OPTION_WWW, DhcpOptionType::IpList),
    ("finger-servers", OPTION_FINGER, DhcpOptionType::IpList),
    ("irc-servers", OPTION_IRC, DhcpOptionType::IpList),
    (
        "streettalk-servers",
        OPTION_STREETTALK,
        DhcpOptionType::IpList,
    ),
    ("stda-servers", OPTION_STDA, DhcpOptionType::IpList),
    ("user-class", OPTION_USERCLASS, DhcpOptionType::String),
    //("directory-agent", OPTION_
    //("server-scope"
    //("rapid-commit"
    // 80
    ("fqdn", OPTION_FQDN, DhcpOptionType::String),
    // option 82 (relay agent information) needs special handling.
    // iSNS
    // NDS Servers
    // NDS Tree
    // NDS Context
    // BCMCS
    // BCMCS
    // 90
    // Authentication, needs special handling
    // client-last-transaction-time, RFC4388
    // associated-ip, RFC4388
    // client-system, RFC4578
    // client-ndi, RFC4578
    // ldap, RFC3679
    //
    //("uuid",      OPTION_UUID,       DhcpOptionType::String), RFC4578
    // userauth, RFC2485
    // geoconf civic, RFC4776
    // 100
    ("tz-rule", OPTION_PCODE, DhcpOptionType::String),
    ("tz-name", OPTION_TCODE, DhcpOptionType::String),
    // uuid/guid
    ("autoconfig", OPTION_AUTOCONF, DhcpOptionType::Bool),
    ("subnet-selection", OPTION_SUBNETSELECT, DhcpOptionType::Ip), // RFC3011 -- needs better support
    //("search-path", OPTION_DNSSEARCH, DhcpOptionType::...), // RFC3397
    //("sip-servers", OPTION_SIPSERVERS, DhcpOptionType::...), // RFC3361
    //121: classless routes, RFC3442 -- Don't intend to implement.
    //122: Cablelabs Client configuration, RFC3495
    //123: GeoConf, RFC6225
    //124: Vendor Identifying Vendor Class -- needs special support, RFC3925
    //125: Vendor Identifying Vendor Specific Information -- needs special support, RFC3925
    (
        "captive-portal",
        OPTION_CAPTIVEPORTAL,
        DhcpOptionType::String,
    ),
];

impl From<u8> for DhcpOption {
    fn from(v: u8) -> Self {
        DhcpOption(v)
    }
}

#[derive(Copy, Clone)]
pub enum DhcpOptionType {
    String,
    Ip,
    IpList,
    I32,
    U8,
    U16,
    U32,
    Bool,
    Seconds16,
    Seconds32,
    HwAddr,
}

type IpList = Vec<std::net::Ipv4Addr>;
type U8Str = Vec<u8>;

impl DhcpOptionType {
    pub fn decode(&self, v: &[u8]) -> Option<DhcpOptionTypeValue> {
        match *self {
            DhcpOptionType::String => U8Str::parse_into(v)
                .map(|x| DhcpOptionTypeValue::String(String::from_utf8_lossy(&x).to_string())),
            DhcpOptionType::Ip => std::net::Ipv4Addr::parse_into(v).map(DhcpOptionTypeValue::Ip),
            DhcpOptionType::IpList => IpList::parse_into(v).map(DhcpOptionTypeValue::IpList),
            DhcpOptionType::I32 => i32::parse_into(v).map(DhcpOptionTypeValue::I32),
            DhcpOptionType::U8 => u8::parse_into(v).map(DhcpOptionTypeValue::U8),
            DhcpOptionType::U16 => u16::parse_into(v).map(DhcpOptionTypeValue::U16),
            DhcpOptionType::U32 => u32::parse_into(v).map(DhcpOptionTypeValue::U32),
            DhcpOptionType::Bool => u8::parse_into(v).map(DhcpOptionTypeValue::U8), // ?
            DhcpOptionType::Seconds16 => u16::parse_into(v).map(DhcpOptionTypeValue::U16), // ?
            DhcpOptionType::Seconds32 => u32::parse_into(v).map(DhcpOptionTypeValue::U32), // ?
            DhcpOptionType::HwAddr => U8Str::parse_into(v).map(DhcpOptionTypeValue::HwAddr),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DhcpOptionTypeValue {
    String(String),
    IpList(Vec<std::net::Ipv4Addr>),
    Ip(std::net::Ipv4Addr),
    I32(i32),
    U8(u8),
    U16(u16),
    U32(u32),
    HwAddr(Vec<u8>),
}

impl DhcpOptionTypeValue {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            DhcpOptionTypeValue::String(s) => s.as_bytes().to_vec(),
            DhcpOptionTypeValue::IpList(v) => {
                v.iter().map(|x| x.octets()).fold(vec![], |mut acc, v| {
                    acc.extend(v.iter());
                    acc
                })
            }
            DhcpOptionTypeValue::Ip(i) => i.octets().to_vec(),
            DhcpOptionTypeValue::I32(x) => x.to_be_bytes().to_vec(),
            DhcpOptionTypeValue::U8(x) => x.to_be_bytes().to_vec(),
            DhcpOptionTypeValue::U16(x) => x.to_be_bytes().to_vec(),
            DhcpOptionTypeValue::U32(x) => x.to_be_bytes().to_vec(),
            DhcpOptionTypeValue::HwAddr(x) => x.clone(),
        }
    }
}

fn escape_char(&c: &u8) -> String {
    match c {
        b' '..=b'~' => char::from(c).to_string(),
        x => format!("\\x{:0>2x}", x),
    }
}

fn escape_str(c: &[u8]) -> String {
    c.iter().map(escape_char).collect::<Vec<String>>().join("")
}

impl std::fmt::Display for DhcpOptionTypeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpOptionTypeValue::String(s) => write!(f, "{}", escape_str(s.as_bytes())),
            DhcpOptionTypeValue::Ip(i) => i.fmt(f),
            DhcpOptionTypeValue::U8(i) => i.fmt(f),
            DhcpOptionTypeValue::U16(i) => i.fmt(f),
            DhcpOptionTypeValue::U32(i) => i.fmt(f),
            DhcpOptionTypeValue::I32(i) => i.fmt(f),
            DhcpOptionTypeValue::IpList(l) => write!(
                f,
                "{}",
                l.iter()
                    .map(|i| format!("{}", i))
                    .collect::<Vec<String>>()
                    .join(",")
            ),
            DhcpOptionTypeValue::HwAddr(x) => write!(
                f,
                "{}",
                x.iter()
                    .map(|b| format!("{:0>2x}", b))
                    .collect::<Vec<String>>()
                    .join(":")
            ),
        }
    }
}

impl DhcpOption {
    pub fn new(opt: u8) -> Self {
        DhcpOption(opt)
    }
    pub fn get_type(&self) -> Option<DhcpOptionType> {
        for (_name, option, ty) in OPT_INFO {
            if option == self {
                return Some(*ty);
            }
        }
        None
    }
}

pub fn name_to_option(lookup_name: &str) -> Option<DhcpOption> {
    for (name, option, _ty) in OPT_INFO {
        if *name == lookup_name {
            return Some(*option);
        }
    }
    None
}

impl ToString for DhcpOption {
    fn to_string(&self) -> String {
        for (name, option, _ty) in OPT_INFO {
            if option == self {
                return (*name).into();
            }
        }
        format!("#{}", self.0)
    }
}

impl fmt::Debug for DhcpOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "{}", self.to_string());
    }
}

pub trait DhcpParse {
    type Item;
    fn parse_into(v: &[u8]) -> Option<Self::Item>;
}

impl DhcpParse for std::net::Ipv4Addr {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self::Item> {
        if v.len() != 4 {
            None
        } else {
            Some(std::net::Ipv4Addr::new(v[0], v[1], v[2], v[3]))
        }
    }
}

impl DhcpParse for Vec<std::net::Ipv4Addr> {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self::Item> {
        let mut it = v.iter().copied();
        let mut ret = vec![];
        while let Some(o1) = it.next() {
            let o2 = it.next();
            let o3 = it.next();
            let o4 = it.next();
            ret.push(std::net::Ipv4Addr::new(o1, o2?, o3?, o4?));
        }
        Some(ret)
    }
}

/* HELP WANTED: I can't figure out how to make this a straight &[u8] -> Some(&[u8]) with no copies,
 * while preserving lifetimes etc.
 */
impl DhcpParse for Vec<u8> {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        Some(v.to_vec())
    }
}

/* This doesn't actually parse into a u64, this just parses as many bytes as it can find into a u64
 */
impl DhcpParse for u64 {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        Some(v.iter().fold(0u64, |acc, &v| (acc << 8) + (v as Self)))
    }
}

impl DhcpParse for u32 {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        Some(v.iter().fold(0u32, |acc, &v| (acc << 8) + (v as Self)))
    }
}

impl DhcpParse for u16 {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        Some(v.iter().fold(0u16, |acc, &v| (acc << 8) + (v as Self)))
    }
}

impl DhcpParse for i32 {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        Some(v.iter().fold(0i32, |acc, &v| (acc << 8) + (v as Self)))
    }
}

impl DhcpParse for u8 {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        if v.len() != 1 {
            None
        } else {
            v.get(0).copied()
        }
    }
}

impl DhcpParse for std::time::Duration {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        u64::parse_into(v).map(std::time::Duration::from_secs)
    }
}

impl DhcpParse for MessageType {
    type Item = Self;
    fn parse_into(v: &[u8]) -> Option<Self> {
        if v.len() != 1 {
            None
        } else {
            Some(MessageType(v[0]))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DhcpOptions {
    pub other: collections::HashMap<DhcpOption, Vec<u8>>,
}

impl DhcpOptions {
    pub fn get_raw_option(&self, option: &DhcpOption) -> Option<&[u8]> {
        self.other.get(option).map(|x| x.as_slice())
    }

    pub fn get_option<T: DhcpParse>(&self, option: &DhcpOption) -> Option<T::Item> {
        self.get_raw_option(option).and_then(|x| T::parse_into(x))
    }

    pub fn get_serverid(&self) -> Option<std::net::Ipv4Addr> {
        self.get_option::<std::net::Ipv4Addr>(&OPTION_SERVERID)
    }

    pub fn get_clientid(&self) -> Option<Vec<u8>> {
        self.get_option::<Vec<u8>>(&OPTION_CLIENTID)
    }

    pub fn get_address_request(&self) -> Option<net::Ipv4Addr> {
        self.get_option::<std::net::Ipv4Addr>(&OPTION_ADDRESSREQUEST)
    }

    pub fn get_messagetype(&self) -> Option<MessageType> {
        self.get_option::<MessageType>(&OPTION_MSGTYPE)
    }

    pub fn set_raw_option(mut self, option: &DhcpOption, value: &[u8]) -> Self {
        self.other.insert(*option, value.to_vec());
        self
    }

    pub fn set_option<T: Serialise>(self, option: &DhcpOption, value: &T) -> Self {
        let mut v = Vec::new();
        value.serialise(&mut v);
        self.set_raw_option(option, &v)
    }

    pub fn mutate_option<T: Serialise>(&mut self, option: &DhcpOption, value: &T) {
        let mut v = Vec::new();
        value.serialise(&mut v);
        self.other.insert(*option, v);
    }

    pub fn maybe_set_option<T: Serialise>(self, option: &DhcpOption, value: Option<&T>) -> Self {
        if let Some(v) = value {
            self.set_option(option, v)
        } else {
            self
        }
    }

    pub fn remove_option(mut self, option: &DhcpOption) -> Self {
        self.other.remove(option);
        self
    }
}

#[derive(PartialEq)]
pub struct DHCP {
    pub op: DhcpOp,
    pub htype: HwType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: net::Ipv4Addr,
    pub yiaddr: net::Ipv4Addr,
    pub siaddr: net::Ipv4Addr,
    pub giaddr: net::Ipv4Addr,
    pub chaddr: Vec<u8>,
    pub sname: Vec<u8>,
    pub file: Vec<u8>,
    pub options: DhcpOptions,
}

impl std::fmt::Debug for DHCP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DHCP")
            .field("op", &self.op)
            .field("htype", &self.htype)
            .field("hlen", &self.hlen)
            .field("hops", &self.hops)
            .field("xid", &self.xid)
            .field("secs", &self.secs)
            .field("flags", &self.flags)
            .field("ciaddr", &self.ciaddr)
            .field("yiaddr", &self.yiaddr)
            .field("siaddr", &self.siaddr)
            .field("giaddr", &self.giaddr)
            .field(
                "chaddr",
                &self
                    .chaddr
                    .iter()
                    .map(|&x| format!("{:x?}", x))
                    .collect::<Vec<String>>()
                    .join(""),
            )
            .field(
                "sname",
                &self
                    .sname
                    .iter()
                    .map(|&x| format!("{:x?}", x))
                    .collect::<Vec<String>>()
                    .join(""),
            )
            .field(
                "file",
                &String::from_utf8(self.file.clone())
                    .or_else::<Result<String, String>, _>(|_| Ok(format!("{:?}", self.file)))
                    .unwrap(),
            )
            .field("options", &self.options)
            .finish()
    }
}

fn null_terminated(mut v: Vec<u8>) -> Vec<u8> {
    for i in 0..v.len() {
        if v[i] == 0 {
            v.truncate(i);
            break;
        }
    }
    v
}

pub fn parse(pkt: &[u8]) -> Result<DHCP, ParseError> {
    let mut it = pkt.iter();
    let op = get_u8(&mut it)?;
    let htype = get_u8(&mut it)?;
    let hlen = get_u8(&mut it)?;
    let hops = get_u8(&mut it)?;
    let xid = get_be32(&mut it)?;
    let secs = get_be16(&mut it)?;
    let flags = get_be16(&mut it)?;
    let ciaddr = get_ipv4(&mut it)?;
    let yiaddr = get_ipv4(&mut it)?;
    let siaddr = get_ipv4(&mut it)?;
    let giaddr = get_ipv4(&mut it)?;
    let chaddr = get_bytes(&mut it, 16)?;
    if hlen as usize > chaddr.len() {
        return Err(ParseError::InvalidPacket);
    }
    let sname = null_terminated(get_bytes(&mut it, 64)?);
    let file = null_terminated(get_bytes(&mut it, 128)?);
    let mut raw_options: collections::HashMap<DhcpOption, Vec<u8>> = collections::HashMap::new();
    match get_be32(&mut it) {
        Ok(0x6382_5363) => {
            loop {
                match get_u8(&mut it) {
                    Ok(0) => (),      /* Pad byte */
                    Ok(255) => break, /* End Field */
                    Ok(x) => {
                        let l = get_u8(&mut it)?;
                        raw_options
                            .entry(DhcpOption(x))
                            .or_insert_with(Vec::new)
                            .extend(get_bytes(&mut it, l as usize)?);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(_) => return Err(ParseError::WrongMagic),
        Err(x) => return Err(x),
    }

    let options = DhcpOptions { other: raw_options };

    Ok(DHCP {
        op: DhcpOp(op),
        htype: HwType(htype),
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr: chaddr[0..hlen as usize].to_vec(),
        sname,
        file,
        options,
    })
}

pub trait Serialise {
    fn serialise(&self, v: &mut Vec<u8>);
}

impl Serialise for u8 {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.push(*self);
    }
}

impl Serialise for u16 {
    fn serialise(&self, v: &mut Vec<u8>) {
        for b in self.to_be_bytes().iter() {
            b.serialise(v);
        }
    }
}

impl Serialise for u32 {
    fn serialise(&self, v: &mut Vec<u8>) {
        for b in self.to_be_bytes().iter() {
            b.serialise(v);
        }
    }
}

impl Serialise for net::Ipv4Addr {
    fn serialise(&self, v: &mut Vec<u8>) {
        for b in self.octets().iter() {
            b.serialise(v);
        }
    }
}

impl Serialise for DhcpOption {
    fn serialise(&self, v: &mut Vec<u8>) {
        self.0.serialise(v);
    }
}

impl Serialise for &[u8] {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(*self);
    }
}

impl Serialise for MessageType {
    fn serialise(&self, v: &mut Vec<u8>) {
        self.0.serialise(v);
    }
}

impl<T: Serialise> Serialise for Vec<T> {
    fn serialise(&self, v: &mut Vec<u8>) {
        for i in self {
            i.serialise(v);
        }
    }
}

impl Serialise for String {
    fn serialise(&self, v: &mut Vec<u8>) {
        self.as_bytes().serialise(v)
    }
}

impl Serialise for i32 {
    fn serialise(&self, v: &mut Vec<u8>) {
        for i in self.to_be_bytes().iter() {
            i.serialise(v)
        }
    }
}

impl Serialise for DhcpOptionTypeValue {
    fn serialise(&self, v: &mut Vec<u8>) {
        match self {
            DhcpOptionTypeValue::String(x) => x.serialise(v),
            DhcpOptionTypeValue::IpList(x) => x.serialise(v),
            DhcpOptionTypeValue::Ip(x) => x.serialise(v),
            DhcpOptionTypeValue::I32(x) => x.serialise(v),
            DhcpOptionTypeValue::U8(x) => x.serialise(v),
            DhcpOptionTypeValue::U16(x) => x.serialise(v),
            DhcpOptionTypeValue::U32(x) => x.serialise(v),
            DhcpOptionTypeValue::HwAddr(x) => x.serialise(v),
        }
    }
}

fn serialise_option<T>(option: DhcpOption, bytes: &[T], v: &mut Vec<u8>)
where
    T: Serialise,
{
    option.serialise(v);
    (bytes.len() as u8).serialise(v);
    for i in bytes.iter() {
        i.serialise(v);
    }
}

impl Serialise for DhcpOptions {
    fn serialise(&self, v: &mut Vec<u8>) {
        for (o, p) in self.other.iter() {
            serialise_option(*o, p, v);
        }

        /* Add end of options marker */
        (255 as u8).serialise(v);
    }
}

fn serialise_fixed(out: &[u8], l: usize, v: &mut Vec<u8>) {
    let mut bytes = Vec::with_capacity(l);
    bytes.extend_from_slice(out);
    bytes.resize_with(l, Default::default);
    for b in &bytes {
        b.serialise(v);
    }
}

impl DHCP {
    pub fn serialise(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        self.op.0.serialise(&mut v);
        self.htype.0.serialise(&mut v);
        self.hlen.serialise(&mut v);
        self.hops.serialise(&mut v);
        self.xid.serialise(&mut v);
        self.secs.serialise(&mut v);
        self.flags.serialise(&mut v);
        self.ciaddr.serialise(&mut v);
        self.yiaddr.serialise(&mut v);
        self.siaddr.serialise(&mut v);
        self.giaddr.serialise(&mut v);

        serialise_fixed(&self.chaddr, 16, &mut v);
        serialise_fixed(&self.sname, 64, &mut v);
        serialise_fixed(&self.file, 128, &mut v);

        /* DHCP Magic */
        0x6382_5363u32.serialise(&mut v);

        self.options.serialise(&mut v);

        v
    }

    pub fn get_client_id(&self) -> Vec<u8> {
        self.options
            .get_clientid()
            .unwrap_or_else(|| self.chaddr.clone())
    }
}
