use std::collections;
use std::fmt;
use std::net;

#[derive(Debug)]
pub enum ParseError {
    UnexpectedEndOfInput,
    WrongMagic,
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

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct DhcpOption(u8);
pub const OPTION_SUBNETMASK: DhcpOption = DhcpOption(1);
pub const OPTION_TIMEOFFSET: DhcpOption = DhcpOption(2);
pub const OPTION_ROUTERADDR: DhcpOption = DhcpOption(3);
pub const OPTION_DOMAINSERVER: DhcpOption = DhcpOption(6);
pub const OPTION_HOSTNAME: DhcpOption = DhcpOption(12);
pub const OPTION_DOMAINNAME: DhcpOption = DhcpOption(15);
pub const OPTION_MTUIF: DhcpOption = DhcpOption(26);
pub const OPTION_BROADCASTADDR: DhcpOption = DhcpOption(28);
pub const OPTION_NTPSERVERS: DhcpOption = DhcpOption(42);
pub const OPTION_NETBIOSNAMESRV: DhcpOption = DhcpOption(44);
pub const OPTION_NETBIOSSCOPE: DhcpOption = DhcpOption(47);
pub const OPTION_ADDRESSREQUEST: DhcpOption = DhcpOption(50);
pub const OPTION_ADDRESSLEASETIME: DhcpOption = DhcpOption(51);
pub const OPTION_MSGTYPE: DhcpOption = DhcpOption(53);
pub const OPTION_PARAMLIST: DhcpOption = DhcpOption(55);
pub const OPTION_DOMAINSEARCH: DhcpOption = DhcpOption(119);
pub const OPTION_CIDRROUTE: DhcpOption = DhcpOption(121);

impl ToString for DhcpOption {
    fn to_string(&self) -> String {
        match self {
            &OPTION_SUBNETMASK => String::from("SUBNETMASK"),
            &OPTION_TIMEOFFSET => String::from("TIMEOFFSET"),
            &OPTION_ROUTERADDR => String::from("ROUTERADDR"),
            &OPTION_DOMAINSERVER => String::from("DOMAINSERVER"),
            &OPTION_HOSTNAME => String::from("Hostname"),
            &OPTION_DOMAINNAME => String::from("DOMAINNAME"),
            &OPTION_MTUIF => String::from("MTUIF"),
            &OPTION_BROADCASTADDR => String::from("BROADCASTADDR"),
            &OPTION_NTPSERVERS => String::from("NTPSERVERS"),
            &OPTION_NETBIOSNAMESRV => String::from("NETBIOSNAMESRV"),
            &OPTION_NETBIOSSCOPE => String::from("NETBIOSSCOPE"),
            &OPTION_ADDRESSREQUEST => String::from("ADDRESSREQUEST"),
            &OPTION_ADDRESSLEASETIME => String::from("ADDRESSLEASETIME"),
            &OPTION_MSGTYPE => String::from("DHCP Message Type"),
            &OPTION_PARAMLIST => String::from("Parameter List"),
            &OPTION_DOMAINSEARCH => String::from("DOMAINSEARCH"),
            &OPTION_CIDRROUTE => String::from("CIDRROUTE"),
            DhcpOption(x) => format!("#{}", x),
        }
    }
}

impl fmt::Debug for DhcpOption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "DhcpOption({})", self.to_string());
    }
}

#[derive(Debug, Clone)]
pub struct DhcpOptions {
    pub messagetype: MessageType,
    pub hostname: Option<String>,
    pub leasetime: Option<std::time::Duration>,
    pub parameterlist: Option<Vec<DhcpOption>>,
    pub other: collections::HashMap<DhcpOption, Vec<u8>>,
}

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
    let sname = get_bytes(&mut it, 64)?;
    let file = get_bytes(&mut it, 128)?;
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
        _ => return Err(ParseError::WrongMagic),
    }
    let options = DhcpOptions {
        messagetype: MessageType(raw_options.remove(&OPTION_MSGTYPE).unwrap()[0]), // TODO: better error handling if msgtype is missing
        hostname: raw_options
            .remove(&OPTION_HOSTNAME)
            .and_then(|host| String::from_utf8(host.to_vec()).ok()),
        leasetime: raw_options
            .remove(&OPTION_ADDRESSLEASETIME)
            .and_then(|dur| {
                Some(std::time::Duration::from_secs(
                    dur.iter().fold(0u64, |acc, &v| acc << 8 + (v as u64)),
                ))
            }),
        parameterlist: raw_options.remove(&OPTION_PARAMLIST).map(|l| {
            l.iter()
                .map(|&x| DhcpOption(x))
                .collect::<Vec<DhcpOption>>()
        }),

        other: raw_options,
    };

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
        chaddr,
        sname,
        file,
        options,
    })
}

trait Serialise {
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

impl Serialise for DhcpOptions {
    fn serialise(&self, v: &mut Vec<u8>) {
        /* Serialise DHCP Message Type */
        OPTION_MSGTYPE.serialise(v);
        (1 as u8).serialise(v);
        self.messagetype.0.serialise(v);

        if let Some(h) = &self.hostname {
            OPTION_HOSTNAME.serialise(v);
            (h.len() as u8).serialise(v);
            for c in h.as_bytes() {
                c.serialise(v);
            }
        }

        if let Some(l) = &self.leasetime {
            OPTION_ADDRESSLEASETIME.serialise(v);
            let lt = (l.as_secs() as u32).to_be_bytes();
            (lt.len() as u8).serialise(v);
            for c in lt.iter() {
                c.serialise(v);
            }
        }

        if let Some(p) = &self.parameterlist {
            OPTION_PARAMLIST.serialise(v);
            (p.len() as u8).serialise(v);
            for b in p {
                b.serialise(v);
            }
        }

        for (o, p) in self.other.iter() {
            o.serialise(v);
            (p.len() as u8).serialise(v);
            for b in p {
                b.serialise(v);
            }
        }

        /* Add end of options marker */
        (255 as u8).serialise(v);
    }
}

impl DHCP {
    pub fn serialise(&mut self) -> Vec<u8> {
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

        self.chaddr.resize_with(16, Default::default);
        for b in &self.chaddr {
            b.serialise(&mut v);
        }

        self.sname.resize_with(64, Default::default);
        for b in &self.sname {
            b.serialise(&mut v);
        }

        self.file.resize_with(128, Default::default);
        for b in &self.file {
            b.serialise(&mut v);
        }

        /* DHCP Magic */
        0x6382_5363u32.serialise(&mut v);

        self.options.serialise(&mut v);

        v
    }
}
