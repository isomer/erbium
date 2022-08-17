use crate::pktparser::Buffer;
#[cfg(fuzzing)]
use arbitrary::Arbitrary;
use std::time::Duration;

#[derive(Debug)]
pub enum Error {
    Truncated,
    InvalidEncoding,
    InvalidPacket,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
struct Type(u8);
const ND_ROUTER_SOLICIT: Type = Type(133);
const ND_ROUTER_ADVERT: Type = Type(134);
const ND_NEIGHBOR_SOLICIT: Type = Type(135);
const ND_NEIGHBOR_ADVERT: Type = Type(136);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct NDOption(u8);
pub const SOURCE_LL_ADDR: NDOption = NDOption(1);
pub const _TARGET_LL_ADDR: NDOption = NDOption(2);
pub const PREFIX_INFO: NDOption = NDOption(3);
pub const _REDIRECTED: NDOption = NDOption(4);
pub const MTU: NDOption = NDOption(5);
pub const _ROUTE_INFO: NDOption = NDOption(24);
pub const RDNSS: NDOption = NDOption(25);
pub const DNSSL: NDOption = NDOption(31);
pub const CAPTIVE_PORTAL: NDOption = NDOption(37);
pub const PREF64: NDOption = NDOption(38);
pub const IPV6_ONLY_PREFERRED: NDOption = NDOption(108);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NDOptionValue {
    SourceLLAddr(Vec<u8>),
    Mtu(u32),
    Prefix(AdvPrefix),
    RecursiveDnsServers((std::time::Duration, Vec<std::net::Ipv6Addr>)),
    DnsSearchList((std::time::Duration, Vec<String>)), // TODO: String is probably the wrong type here.
    CaptivePortal(String),
    Pref64((std::time::Duration, u8, std::net::Ipv6Addr)),
}

#[cfg(fuzzing)]
impl Arbitrary for NDOptionValue {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use std::convert::TryFrom as _;
        match u.int_in_range(0..=5)? {
            0 => Ok(NDOptionValue::SourceLLAddr(<[u8; 6]>::arbitrary(u)?.into())),
            1 => Ok(NDOptionValue::Mtu(<_>::arbitrary(u)?)),
            2 => Ok(NDOptionValue::Prefix(<_>::arbitrary(u)?)),
            3 => {
                let duration = Duration::from_secs(u.int_in_range(0..=2_u64.pow(32) - 1)?);
                let num_ips = u.arbitrary_len::<[u8; 16]>()?;
                let mut ips = Vec::new();
                for _ in 0..std::cmp::min(num_ips, 127) {
                    ips.push(<[u8; 16]>::arbitrary(u)?.into());
                }

                Ok(NDOptionValue::RecursiveDnsServers((duration, ips)))
            }
            4 => loop {
                let mut url: String = <_>::arbitrary(u)?;
                while url.ends_with('\0') {
                    url.pop();
                }
                return Ok(NDOptionValue::CaptivePortal(url));
            },
            5 => Ok(NDOptionValue::Pref64((
                Duration::from_secs(u.int_in_range(0..=2_u64.pow(13) - 1)? & !7),
                u.int_in_range(0..=5)? * 8 + 32,
                <[u8; 128 / 8]>::try_from(
                    [&<[u8; 96 / 8]>::arbitrary(u)?, &[0_u8; (128 - 96) / 8][..]].concat(),
                )
                .unwrap()
                .into(),
            ))),
            /* - no decoder (yet).  the domain type should be changed to support embedded '.' etc.
            6 => Ok(NDOptionValue::DnsSearchList((
                <_>::arbitrary(u)?,
                <_>::arbitrary(u)?,
            ))),
            */
            _ => unimplemented!(),
        }
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub struct NDOptions(Vec<NDOptionValue>);

impl NDOptions {
    pub fn add_option(&mut self, ov: NDOptionValue) {
        self.0.push(ov);
    }

    #[cfg(test)]
    pub fn find_option(&self, o: NDOption) -> Vec<NDOptionValue> {
        self.0
            .iter()
            .filter(|x| match (&o, &x) {
                (&RDNSS, &NDOptionValue::RecursiveDnsServers(_)) => true,
                (&RDNSS, _) => false,
                (&DNSSL, &NDOptionValue::DnsSearchList(_)) => true,
                (&DNSSL, _) => false,
                (&CAPTIVE_PORTAL, &NDOptionValue::CaptivePortal(_)) => true,
                (&CAPTIVE_PORTAL, _) => false,
                (_, _) => unimplemented!(),
            })
            .cloned()
            .collect()
    }
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(fuzzing, derive(Arbitrary))]
pub enum Icmp6 {
    Unknown,
    RtrSolicit(NDOptions),
    RtrAdvert(RtrAdvertisement),
}

#[derive(Debug, Eq, PartialEq)]
pub struct RtrAdvertisement {
    pub hop_limit: u8,
    pub flag_managed: bool,
    pub flag_other: bool,
    pub lifetime: std::time::Duration,
    pub reachable: std::time::Duration,
    pub retrans: std::time::Duration,
    pub options: NDOptions,
}

#[cfg(fuzzing)]
impl Arbitrary for RtrAdvertisement {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            hop_limit: <_>::arbitrary(u)?,
            flag_managed: <_>::arbitrary(u)?,
            flag_other: <_>::arbitrary(u)?,
            lifetime: Duration::from_secs(<u16>::arbitrary(u)?.into()),
            reachable: Duration::from_millis(<u32>::arbitrary(u)?.into()),
            retrans: Duration::from_millis(<u32>::arbitrary(u)?.into()),
            options: <_>::arbitrary(u)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvPrefix {
    pub prefixlen: u8,
    pub onlink: bool,
    pub autonomous: bool,
    pub valid: std::time::Duration,
    pub preferred: std::time::Duration,
    pub prefix: std::net::Ipv6Addr,
}

#[cfg(fuzzing)]
impl Arbitrary for AdvPrefix {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(AdvPrefix {
            prefixlen: u.int_in_range(0..=128)?,
            onlink: <_>::arbitrary(u)?,
            autonomous: <_>::arbitrary(u)?,
            valid: Duration::from_secs(<u32>::arbitrary(u)?.into()),
            preferred: Duration::from_secs(<u32>::arbitrary(u)?.into()),
            prefix: <[u8; 16]>::arbitrary(u)?.into(),
        })
    }
}

fn parse_nd_rtr_options(buf: &mut Buffer) -> Result<NDOptions, Error> {
    let mut options: NDOptions = Default::default();
    while buf.remaining() > 0 {
        let ty = buf.get_u8().map(NDOption).ok_or(Error::Truncated)?;
        let l = buf.get_u8().ok_or(Error::Truncated)? as usize;
        if l == 0 {
            // Nodes MUST silently discard an ND packet that contains an option with length zero.
            return Err(Error::Truncated);
        }
        let data = buf.get_bytes(l * 8 - 2).ok_or(Error::Truncated)?;
        match (ty, data) {
            (SOURCE_LL_ADDR, value) => {
                options.add_option(NDOptionValue::SourceLLAddr(value.to_vec()));
            }
            (CAPTIVE_PORTAL, value) => {
                options.add_option(NDOptionValue::CaptivePortal(
                    String::from_utf8(
                        value[..value
                            .iter()
                            .rposition(|b| *b != 0)
                            .map(|p| p + 1)
                            .unwrap_or(0)]
                            .into(),
                    )
                    .map_err(|_| Error::InvalidEncoding)?,
                ));
            }
            (PREF64, value) => {
                if value.len() != 2 * 8 - 2 {
                    // The receiver MUST ignore the PREF64 option if the Length field value is not 2.
                    // we ignore the entire packet instead...
                    return Err(Error::InvalidPacket);
                }
                use std::convert::{TryFrom as _, TryInto as _};
                let scaled_lifetime_plc = u16::from_be_bytes(value[0..=1].try_into().unwrap());
                let lifetime = Duration::from_secs((scaled_lifetime_plc & !7).into());
                let prefixlen = (scaled_lifetime_plc & 0x07) * 8 + 32;
                let ip_octets =
                    <[u8; 16]>::try_from([&value[2..], &[0, 0, 0, 0]].concat()).unwrap();
                let prefix = std::net::Ipv6Addr::from(ip_octets);
                options.add_option(NDOptionValue::Pref64((lifetime, prefixlen as u8, prefix)));
            }
            (MTU, value) => {
                if value.len() != 1 * 8 - 2 {
                    return Err(Error::InvalidPacket);
                }
                use std::convert::TryInto as _;
                options.add_option(NDOptionValue::Mtu(u32::from_be_bytes(
                    value[2..=5].try_into().unwrap(),
                )));
            }
            (RDNSS, value) => {
                use std::convert::{TryFrom as _, TryInto as _};
                let lifetime =
                    Duration::from_secs(u32::from_be_bytes(value[2..=5].try_into().unwrap()) as _);
                let servers = value[6..]
                    .chunks_exact(16)
                    .map(|x| std::net::Ipv6Addr::from(<[u8; 16]>::try_from(x).unwrap()))
                    .collect();
                options.add_option(NDOptionValue::RecursiveDnsServers((lifetime, servers)));
            }
            (PREFIX_INFO, value) => {
                use std::convert::{TryFrom as _, TryInto as _};
                if value.len() != 4 * 8 - 2 {
                    return Err(Error::InvalidPacket);
                }
                let prefixlen = value[0];
                let onlink = value[1] & 0x80 != 0;
                let autonomous = value[1] & 0x40 != 0;
                let valid =
                    Duration::from_secs(u32::from_be_bytes(value[2..6].try_into().unwrap()) as _);
                let preferred =
                    Duration::from_secs(u32::from_be_bytes(value[6..10].try_into().unwrap()) as _);
                /* reserved (4 bytes) */
                let prefix =
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&value[14..30]).unwrap());
                options.add_option(NDOptionValue::Prefix(AdvPrefix {
                    prefixlen,
                    onlink,
                    autonomous,
                    valid,
                    preferred,
                    prefix,
                }));
            }
            o => log::warn!("Unexpected ND RTR Solicit option {:?}", o),
        }
    }
    Ok(options)
}

fn parse_nd_rtr_solicit(buf: &mut Buffer) -> Result<Icmp6, Error> {
    let _reserved = buf.get_be32().ok_or(Error::Truncated)?;
    Ok(Icmp6::RtrSolicit(parse_nd_rtr_options(buf)?))
}

fn parse_nd_rtr_advert(buf: &mut Buffer) -> Result<Icmp6, Error> {
    let hop_limit = buf.get_u8().ok_or(Error::Truncated)?;
    let mo_byte = buf.get_u8().ok_or(Error::Truncated)?;
    let lifetime = Duration::from_secs(buf.get_be16().ok_or(Error::Truncated)?.into());
    let reachable = Duration::from_millis(buf.get_be32().ok_or(Error::Truncated)?.into());
    let retrans = Duration::from_millis(buf.get_be32().ok_or(Error::Truncated)?.into());
    let options = parse_nd_rtr_options(buf)?;
    let flag_managed = (0b1000_0000 & mo_byte) != 0;
    let flag_other = (0b0100_0000 & mo_byte) != 0;

    Ok(Icmp6::RtrAdvert(RtrAdvertisement {
        hop_limit,
        flag_managed,
        flag_other,
        lifetime,
        reachable,
        retrans,
        options,
    }))
}

pub fn parse(pkt: &[u8]) -> Result<Icmp6, Error> {
    /* Section 6.1.1: [..] MUST silently discard [.. unless .. ] length is 8 or more octets. */
    if pkt.len() < 8 {
        return Err(Error::Truncated);
    }
    let mut buf = Buffer::new(pkt);
    let ty = Type(buf.get_u8().ok_or(Error::Truncated)?);
    let code = buf.get_u8().ok_or(Error::Truncated)?;
    let _chksum = buf.get_be16().ok_or(Error::Truncated)?;

    match (ty, code) {
        (ND_ROUTER_SOLICIT, 0) => parse_nd_rtr_solicit(&mut buf),
        (ND_ROUTER_ADVERT, 0) => parse_nd_rtr_advert(&mut buf),
        (ND_NEIGHBOR_SOLICIT, 0) => Ok(Icmp6::Unknown),
        (ND_NEIGHBOR_ADVERT, 0) => Ok(Icmp6::Unknown),
        (t, c) => {
            log::warn!("Unexpected ICMP6 message: {:?}/{}", t, c);
            Ok(Icmp6::Unknown) /* Ignore other ICMP codes */
        }
    }
}

#[derive(Default)]
struct Serialise {
    v: Vec<u8>,
}

impl Serialise {
    fn serialise<T: SerialiseInto>(&mut self, value: T) {
        value.serialise(&mut self.v)
    }

    fn len(&self) -> usize {
        self.v.len()
    }
}

trait SerialiseInto {
    fn serialise(&self, v: &mut Vec<u8>);
}

impl SerialiseInto for u8 {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(self.to_be_bytes().iter())
    }
}

impl SerialiseInto for u16 {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(self.to_be_bytes().iter())
    }
}

impl SerialiseInto for u32 {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(self.to_be_bytes().iter())
    }
}

impl SerialiseInto for &Vec<u8> {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(self.iter())
    }
}

impl SerialiseInto for &std::net::Ipv6Addr {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(self.octets().iter())
    }
}

impl SerialiseInto for &str {
    fn serialise(&self, v: &mut Vec<u8>) {
        v.extend(self.as_bytes())
    }
}

fn serialise_router_advertisement(a: &RtrAdvertisement) -> Vec<u8> {
    let mut v: Serialise = Default::default();
    v.serialise(ND_ROUTER_ADVERT.0);
    v.serialise(0_u8); /* Code */
    v.serialise(0_u16); /* Checksum */
    v.serialise(a.hop_limit);
    v.serialise(
        if a.flag_managed { 0x80_u8 } else { 0x00_u8 }
            | if a.flag_other { 0x40_u8 } else { 0x00_u8 },
    );
    v.serialise(a.lifetime.as_secs() as u16);
    v.serialise(a.reachable.as_millis() as u32);
    v.serialise(a.retrans.as_millis() as u32);
    for opt in &a.options.0 {
        match opt {
            NDOptionValue::SourceLLAddr(src) => {
                use std::convert::TryFrom as _;
                v.serialise(SOURCE_LL_ADDR.0);
                v.serialise(u8::try_from((src.len() + 2 + 7) / 8).unwrap());
                v.serialise(src);
            }
            NDOptionValue::Mtu(mtu) => {
                v.serialise(MTU.0);
                v.serialise(1_u8);
                v.serialise(0_u16);
                v.serialise(*mtu);
            }
            NDOptionValue::Prefix(prefix) => {
                v.serialise(PREFIX_INFO.0);
                v.serialise(4_u8);
                v.serialise(prefix.prefixlen);
                v.serialise(
                    if prefix.onlink { 0x80_u8 } else { 0x00_u8 }
                        | if prefix.autonomous { 0x40_u8 } else { 0x00_u8 },
                );
                v.serialise(prefix.valid.as_secs() as u32);
                v.serialise(prefix.preferred.as_secs() as u32);
                v.serialise(0_u32);
                v.serialise(&prefix.prefix);
            }
            NDOptionValue::RecursiveDnsServers((lifetime, servers)) => {
                use std::convert::TryFrom as _;
                v.serialise(RDNSS.0);
                v.serialise(u8::try_from(1 + servers.len() * 2).unwrap());
                v.serialise(0_u16); // Reserved / Padding.
                v.serialise(lifetime.as_secs() as u32);
                for server in servers {
                    v.serialise(server);
                }
            }
            NDOptionValue::DnsSearchList((lifetime, suffixes)) => {
                let mut dnssl = Serialise::default();
                for suffix in suffixes {
                    for label in suffix.split('.') {
                        dnssl.serialise(label.len() as u8);
                        dnssl.serialise(label);
                    }
                    dnssl.serialise(0_u8);
                }
                // Pad with 0x00 to the full size.
                while dnssl.v.len() % 8 != 0 {
                    dnssl.serialise(0_u8);
                }
                v.serialise(DNSSL.0);
                v.serialise(1 + (dnssl.v.len() / 8) as u8);
                v.serialise(0_u16); // Reserved / Padding.
                v.serialise(lifetime.as_secs() as u32);
                v.serialise(&dnssl.v);
            }
            NDOptionValue::Pref64((lifetime, prefixlen, prefix)) => {
                v.serialise(PREF64.0);
                v.serialise(2_u8);
                let scaled_lifetime = (lifetime.as_secs() / 8) as u16;
                let plc = ((prefixlen - 32) / 8) as u16;
                v.serialise((scaled_lifetime << 3) | plc);
                for i in 0..12 {
                    v.serialise(prefix.octets()[i])
                }
            }
            NDOptionValue::CaptivePortal(url) => {
                let mut b = url.clone().into_bytes();
                // Pad with 0x00
                while (b.len() + 2) % 8 != 0 {
                    b.push(0x00_u8);
                }
                v.serialise(CAPTIVE_PORTAL.0);
                v.serialise((1 + b.len() / 8) as u8);
                v.serialise(&b);
            }
        }
    }
    assert_eq!(v.len() % 8, 0);
    v.v
}

pub fn serialise(msg: &Icmp6) -> Vec<u8> {
    match msg {
        Icmp6::RtrAdvert(a) => serialise_router_advertisement(a),
        Icmp6::Unknown => unimplemented!(),
        Icmp6::RtrSolicit(_) => unimplemented!(),
    }
}

#[test]
fn test_parse_nd_rtr_solicit() {
    let data = [133, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 3, 4, 5, 6];
    parse(&data).expect("Failed to parse");
}

#[test]
fn test_decode_ra() {
    let data = vec![
        0x86, 0x00, 0xc4, 0xfe, 0x40, 0x00, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x01, 0xc2, 0x00, 0x54, 0xf5, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x05, 0xdc, 0x03, 0x04, 0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00, 0x00, 0x09, 0x3a, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let result = parse(&data);
    assert!(result.is_ok());
    let result_value = result.unwrap();
    println!("{:?}", result_value);
}

#[test]
fn test_reflexitivity() {
    use std::time::Duration;
    let data = serialise(&Icmp6::RtrAdvert(RtrAdvertisement {
        hop_limit: 64,
        flag_managed: false,
        flag_other: false,
        lifetime: Duration::from_secs(600),
        reachable: Duration::from_secs(30),
        retrans: Duration::from_secs(1),
        options: NDOptions(vec![
            NDOptionValue::Mtu(1480),
            NDOptionValue::SourceLLAddr(vec![0, 1, 2, 3, 4, 5]),
            NDOptionValue::Prefix(AdvPrefix {
                prefixlen: 64,
                onlink: true,
                autonomous: true,
                valid: Duration::from_secs(86400),
                preferred: Duration::from_secs(3600),
                prefix: "2001:db8::".parse().unwrap(),
            }),
            NDOptionValue::RecursiveDnsServers((
                Duration::from_secs(600),
                vec!["2001:db8::53".parse().unwrap()],
            )),
            NDOptionValue::DnsSearchList((
                Duration::from_secs(600),
                vec!["example.com".into(), "example.net".into()],
            )),
            NDOptionValue::CaptivePortal("http://example.com/".into()),
        ]),
    }));
    parse(&data).unwrap();
}
