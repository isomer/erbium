use yaml_rust::yaml;

#[derive(Debug)]
pub enum Error {
    InvalidConfig(String),
}

impl Error {
    fn annotate(&self, prefix: &str) -> Error {
        Error::InvalidConfig(format!("{}: {}", prefix, self))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidConfig(x) => write!(f, "{}", x),
        }
    }
}

#[derive(Debug)]
pub enum HexError {
    InvalidDigit(u8),
    OddLength,
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::InvalidDigit(x) => write!(f, "Unexpected hex digit {}", x),
            HexError::OddLength => write!(f, "Hex number has odd length"),
        }
    }
}

fn hexdigit(c: u8) -> Result<u8, HexError> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0' + 10),
        _ => Err(HexError::InvalidDigit(c)),
    }
}

fn hexstring(s: &[u8]) -> Result<Vec<u8>, HexError> {
    let mut v = Vec::new();
    let mut it = s.iter();
    loop {
        let mut byte;
        if let Some(hi) = it.next() {
            byte = hexdigit(*hi)? << 4;
        } else {
            return Ok(v);
        }
        if let Some(lo) = it.next() {
            byte |= hexdigit(*lo)?;
        } else {
            return Err(HexError::OddLength);
        }
        v.push(byte)
    }
}

#[derive(Clone, Debug)]
pub struct PoolConfig {
    pub name: String,
    pub netblock: Vec<super::pool::Netblock>,
    pub ipaddr: Vec<std::net::Ipv4Addr>,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub match_interface: Option<String>,
    pub match_clientid: Option<String>,
    pub match_chaddr: Option<Vec<u8>>,
    pub match_subnet: Option<crate::net::Ipv4Subnet>,
    pub apply_dnsserver: Option<Vec<std::net::Ipv4Addr>>,
    pub apply_address: Option<Vec<std::net::Ipv4Addr>>,
    pub policies: Vec<Policy>,
}

#[derive(Debug)]
pub struct Config {
    pub policies: Vec<Policy>,
}

impl Config {
    fn parse_string(fragment: &yaml::Yaml) -> Result<String, Error> {
        Ok(fragment
            .as_str()
            .ok_or_else(|| Error::InvalidConfig(format!("Expected String, got '{:?}'", fragment)))?
            .into())
    }

    fn parse_mac(fragment: &yaml::Yaml) -> Result<Vec<u8>, Error> {
        Ok(fragment
            .as_str()
            .ok_or_else(|| Error::InvalidConfig("hardware addresses should be a string".into()))?
            .split(':')
            .map(|x| hexstring(x.as_bytes()))
            .flatten()
            .flatten()
            .collect())
    }

    fn parse_ip(fragment: &yaml::Yaml) -> Result<std::net::Ipv4Addr, Error> {
        fragment
            .as_str()
            .ok_or_else(|| Error::InvalidConfig(format!("Expected String, got '{:?}'", fragment)))?
            .parse()
            .map_err(|x| Error::InvalidConfig(format!("Expected IP address: {}", x)))
    }

    fn parse_iplist(fragment: &yaml::Yaml) -> Result<Vec<std::net::Ipv4Addr>, Error> {
        if let Some(yiplist) = fragment.as_vec() {
            let mut iplist = Vec::new();
            for ip in yiplist {
                iplist.push(
                    ip.as_str()
                        .ok_or_else(|| {
                            Error::InvalidConfig(format!(
                                "dns-server is not a string, got '{:?}'",
                                ip
                            ))
                        })?
                        .parse()
                        .map_err(|err| {
                            Error::InvalidConfig(format!(
                                "dns-server contains an invalid IP: {:?}",
                                err
                            ))
                        })?,
                )
            }
            Ok(iplist)
        } else {
            Err(Error::InvalidConfig(format!(
                "Expected IP list, got {:?}",
                fragment
            )))
        }
    }

    fn parse_subnet(fragment: &yaml::Yaml) -> Result<crate::net::Ipv4Subnet, Error> {
        let s: String = fragment
            .as_str()
            .ok_or_else(|| Error::InvalidConfig(format!("Expected String, got '{:?}'", fragment)))?
            .into();
        let sections: Vec<&str> = s.split('/').collect();
        if sections.len() != 2 {
            Err(Error::InvalidConfig(format!(
                "Expected IP prefix, but '{}'",
                s
            )))
        } else {
            Ok(crate::net::Ipv4Subnet::new(
                sections[0]
                    .parse()
                    .map_err(|x| Error::InvalidConfig(format!("{}", x)))?,
                sections[1]
                    .parse()
                    .map_err(|x| Error::InvalidConfig(format!("{}", x)))?,
            )
            .map_err(|_| Error::InvalidConfig("Prefix length too short".into()))?)
        }
    }

    fn parse_policy(fragment: &yaml::Yaml) -> Result<Policy, Error> {
        if let Some(h) = fragment.as_hash() {
            let mut policy: Policy = Default::default();
            for (k, v) in h {
                match k.as_str() {
                    Some("match-interface") => {
                        policy.match_interface = Some(
                            Config::parse_string(v)
                                .map_err(|x| x.annotate("Failed to parse match-interface"))?,
                        );
                    }
                    Some("match-clientid") => {
                        policy.match_clientid = Some(
                            Config::parse_string(v)
                                .map_err(|x| x.annotate("Failed to parse clientid"))?,
                        );
                    }
                    Some("match-chaddr") => {
                        policy.match_chaddr = Some(
                            Config::parse_mac(v)
                                .map_err(|x| x.annotate("Failed to parse hardware-address"))?,
                        );
                    }
                    Some("match-subnet") => {
                        policy.match_subnet = Some(
                            Config::parse_subnet(v)
                                .map_err(|x| x.annotate("Failed to parse subnet"))?,
                        );
                    }
                    Some("apply-dnsserver") => {
                        policy.apply_dnsserver = Some(
                            Config::parse_iplist(v)
                                .map_err(|x| x.annotate("Failed to parse dnsserver"))?,
                        );
                    }
                    Some("apply-address") => {
                        policy.apply_address = Some(
                            Config::parse_iplist(v)
                                .map_err(|x| x.annotate("Failed to parse address"))?,
                        );
                    }
                    Some(x) => {
                        return Err(Error::InvalidConfig(format!(
                            "Policy contains unknown field '{}'",
                            x
                        )))
                    }
                    None => return Err(Error::InvalidConfig("Policy is not hash".into())),
                }
            }
            Ok(policy)
        } else {
            Err(Error::InvalidConfig("Policy should be a hash".into()))
        }
    }

    fn parse_policies(fragment: &yaml::Yaml) -> Result<Vec<Policy>, Error> {
        if let Some(l) = fragment.as_vec() {
            let mut policies = Vec::new();
            for i in l {
                policies.push(Config::parse_policy(i)?);
            }
            Ok(policies)
        } else {
            Err(Error::InvalidConfig(
                "Policies should be a list of policies".into(),
            ))
        }
    }

    fn parse_dhcp(fragment: &yaml::Yaml) -> Result<Vec<Policy>, Error> {
        if let Some(h) = fragment.as_hash() {
            let mut policies = Vec::new();
            for (k, v) in h {
                match k.as_str() {
                    Some("Policies") => policies = Config::parse_policies(v)?,
                    Some(x) => return Err(Error::InvalidConfig(format!("Unexpected item {}", x))),
                    None => return Err(Error::InvalidConfig(format!("Unexpected key {:?}", k))),
                }
            }
            Ok(policies)
        } else {
            Err(Error::InvalidConfig("dhcp is expected to be a hash".into()))
        }
    }

    pub fn new(y: &mut yaml::Yaml) -> Result<Self, Error> {
        if let Some(dhcpconf) = y
            .as_hash()
            .and_then(|h| h.get(&yaml::Yaml::from_str("dhcp")))
        {
            let policies = Config::parse_dhcp(dhcpconf)?;
            Ok(Config { policies })
        } else {
            Err(Error::InvalidConfig("Missing dhcp section".into()))
        }
    }
}
