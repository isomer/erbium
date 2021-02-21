use crate::pktparser::Buffer;

#[derive(Debug)]
pub enum Error {
    Truncated,
}

#[derive(Debug, PartialEq, Eq)]
struct Type(u8);
const ND_ROUTER_SOLICIT: Type = Type(133);
const ND_ROUTER_ADVERT: Type = Type(134);
const ND_NEIGHBOR_SOLICIT: Type = Type(135);
const ND_NEIGHBOR_ADVERT: Type = Type(136);

#[derive(Debug, PartialEq, Eq, Hash)]
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

#[derive(Clone, Debug)]
pub enum NDOptionValue {
    SourceLLAddr(Vec<u8>),
    MTU(u32),
    Prefix(AdvPrefix),
    RDNSS((std::time::Duration, Vec<std::net::Ipv6Addr>)),
    DNSSL((std::time::Duration, Vec<String>)), // TODO: String is probably the wrong type here.
    CaptivePortal(String),
    Pref64((std::time::Duration, u8, std::net::Ipv6Addr)),
}

#[derive(Default, Debug)]
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
                (&RDNSS, &NDOptionValue::RDNSS(_)) => true,
                (&RDNSS, _) => false,
                (&DNSSL, &NDOptionValue::DNSSL(_)) => true,
                (&DNSSL, _) => false,
                (&CAPTIVE_PORTAL, &NDOptionValue::CaptivePortal(_)) => true,
                (&CAPTIVE_PORTAL, _) => false,
                (_, _) => unimplemented!(),
            })
            .cloned()
            .collect()
    }
}

#[derive(Debug)]
pub enum Icmp6 {
    Unknown,
    RtrSolicit(NDOptions),
    RtrAdvert(RtrAdvertisement),
}

#[derive(Debug)]
pub struct RtrAdvertisement {
    pub hop_limit: u8,
    pub flag_managed: bool,
    pub flag_other: bool,
    pub lifetime: std::time::Duration,
    pub reachable: std::time::Duration,
    pub retrans: std::time::Duration,
    pub options: NDOptions,
}

#[derive(Clone, Debug)]
pub struct AdvPrefix {
    pub prefixlen: u8,
    pub onlink: bool,
    pub autonomous: bool,
    pub valid: std::time::Duration,
    pub preferred: std::time::Duration,
    pub prefix: std::net::Ipv6Addr,
}

fn parse_nd_rtr_solicit(buf: &mut Buffer) -> Result<Icmp6, Error> {
    let _reserved = buf.get_be32().ok_or(Error::Truncated)?;
    let mut options: NDOptions = Default::default();
    while buf.remaining() > 0 {
        let ty = buf.get_u8().map(NDOption).ok_or(Error::Truncated)?;
        let l = buf.get_u8().ok_or(Error::Truncated)? as usize;
        if l == 0 {
            return Err(Error::Truncated);
        }
        let data = buf.get_bytes(l * 8 - 2).ok_or(Error::Truncated)?;
        match (ty, data) {
            (SOURCE_LL_ADDR, value) => {
                options.add_option(NDOptionValue::SourceLLAddr(value.to_vec()));
            }
            o => log::warn!("Unexpected ND RTR Solicit option {:?}", o),
        }
    }
    Ok(Icmp6::RtrSolicit(options))
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
        (ND_ROUTER_ADVERT, 0) => Ok(Icmp6::Unknown),
        (ND_NEIGHBOR_SOLICIT, 0) => Ok(Icmp6::Unknown),
        (ND_NEIGHBOR_ADVERT, 0) => Ok(Icmp6::Unknown),
        (t, c) => {
            log::warn!("Unexpected ICMP6 message: {:?}/{}", t, c);
            Ok(Icmp6::Unknown) /* Ignore other ICMP codes */
        }
    }
}

struct Serialise {
    v: Vec<u8>,
}

impl Serialise {
    fn serialise<T: SerialiseInto>(&mut self, value: T) {
        value.serialise(&mut self.v)
    }
}

impl Default for Serialise {
    fn default() -> Self {
        Serialise {
            v: Default::default(),
        }
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
                v.serialise(SOURCE_LL_ADDR.0);
                v.serialise(1_u8);
                v.serialise(src);
            }
            NDOptionValue::MTU(mtu) => {
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
            NDOptionValue::RDNSS((lifetime, servers)) => {
                v.serialise(RDNSS.0);
                v.serialise((1 + servers.len() * 2) as u8);
                v.serialise(0_u16); // Reserved / Padding.
                v.serialise(lifetime.as_secs() as u32);
                for server in servers {
                    v.serialise(server);
                }
            }
            NDOptionValue::DNSSL((lifetime, suffixes)) => {
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
                while (b.len() + 2) & 8 != 0 {
                    b.push(0x00_u8);
                }
                v.serialise(CAPTIVE_PORTAL.0);
                v.serialise((1 + b.len() / 8) as u8);
                v.serialise(&b);
            }
        }
    }
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
            NDOptionValue::MTU(1480),
            NDOptionValue::SourceLLAddr(vec![0, 1, 2, 3, 4, 5]),
            NDOptionValue::Prefix(AdvPrefix {
                prefixlen: 64,
                onlink: true,
                autonomous: true,
                valid: Duration::from_secs(86400),
                preferred: Duration::from_secs(3600),
                prefix: "2001:db8::".parse().unwrap(),
            }),
            NDOptionValue::RDNSS((
                Duration::from_secs(600),
                vec!["2001:db8::53".parse().unwrap()],
            )),
            NDOptionValue::DNSSL((
                Duration::from_secs(600),
                vec!["example.com".into(), "example.net".into()],
            )),
            NDOptionValue::CaptivePortal("http://example.com/".into()),
        ]),
    }));
    parse(&data).expect("Failed to parse");
}
