use std::collections;
use std::fmt;

#[derive(Debug)]
enum ParseError {
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

impl ToString for MessageType {
    fn to_string(&self) -> String {
        match self {
            &DHCPDISCOVER => String::from("DHCPDISCOVER"),
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
    pub ciaddr: u32,
    pub yiaddr: u32,
    pub siaddr: u32,
    pub giaddr: u32,
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

pub fn parse(pkt: &[u8]) -> Result<DHCP, Box<dyn std::error::Error>> {
    let mut it = pkt.iter();
    let op = get_u8(&mut it)?;
    let htype = get_u8(&mut it)?;
    let hlen = get_u8(&mut it)?;
    let hops = get_u8(&mut it)?;
    let xid = get_be32(&mut it)?;
    let secs = get_be16(&mut it)?;
    let flags = get_be16(&mut it)?;
    let ciaddr = get_be32(&mut it)?;
    let yiaddr = get_be32(&mut it)?;
    let siaddr = get_be32(&mut it)?;
    let giaddr = get_be32(&mut it)?;
    let chaddr = get_bytes(&mut it, 16)?;
    let sname = get_bytes(&mut it, 64)?;
    let file = get_bytes(&mut it, 128)?;
    let mut raw_options: collections::HashMap<DhcpOption, Vec<u8>> = collections::HashMap::new();
    match get_be32(&mut it) {
        Ok(0x63825363) => {
            loop {
                match get_u8(&mut it) {
                    Ok(0) => (),      /* Pad byte */
                    Ok(255) => break, /* End Field */
                    Ok(x) => {
                        let l = get_u8(&mut it)?;
                        raw_options
                            .entry(DhcpOption(x))
                            .or_insert_with(|| Vec::new())
                            .extend(get_bytes(&mut it, l as usize)?);
                    }
                    Err(e) => return Err(Box::new(e)),
                }
            }
        }
        Ok(_) => return Err(Box::new(ParseError::WrongMagic)),
        _ => return Err(Box::new(ParseError::WrongMagic)),
    }
    println!("Raw options: {:?}", raw_options);
    let options = DhcpOptions {
        messagetype: MessageType(raw_options.remove(&OPTION_MSGTYPE).unwrap()[0]), // TODO: better error handling if msgtype is missing
        hostname: raw_options
            .remove(&OPTION_HOSTNAME)
            .and_then(|host| String::from_utf8(host.to_vec()).ok()),
        parameterlist: raw_options.remove(&OPTION_PARAMLIST).and_then(|l| {
            Some(
                l.iter()
                    .map(|&x| DhcpOption(x))
                    .collect::<Vec<DhcpOption>>(),
            )
        }),
        other: raw_options,
    };

    Ok(DHCP {
        op: DhcpOp(op),
        htype: HwType(htype),
        hlen: hlen,
        hops: hops,
        xid: xid,
        secs: secs,
        flags: flags,
        ciaddr: ciaddr,
        yiaddr: yiaddr,
        siaddr: siaddr,
        giaddr: giaddr,
        chaddr: chaddr,
        sname: sname,
        file: file,
        options: options,
    })
}
