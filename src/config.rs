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
 *  Erbium Configuration parsing.
 */
use std::convert::TryFrom;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncReadExt;
use yaml_rust::yaml;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
    YamlError(yaml_rust::scanner::ScanError),
    MissingConfig,
    MultipleConfigs,
    ConfigProcessFailed,
    InvalidConfig(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "{}", e),
            Error::Utf8Error(e) => {
                write!(f, "UTF8 Decoding error reading configuration file: {}", e)
            }
            Error::YamlError(e) => write!(f, "Yaml parse error while reading configuration: {}", e),
            Error::MissingConfig => write!(f, "Configuration is empty/missing"),
            Error::MultipleConfigs => {
                write!(f, "Configuration file contains multiple configurations")
            }
            Error::ConfigProcessFailed => write!(f, "Configuration process failed"),
            Error::InvalidConfig(e) => write!(f, "Invalid Configuration: {}", e),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn annotate(self, s: &str) -> Error {
        Error::InvalidConfig(format!("{}: {}", self, s))
    }
}

#[derive(Debug, Clone)]
pub enum ConfigValue<T: Clone> {
    NotSpecified,
    DontSet,
    Value(T),
}

impl<T: Clone> ConfigValue<T> {
    pub fn from_option(v: Option<T>) -> Self {
        match v {
            None => ConfigValue::DontSet,
            Some(x) => ConfigValue::Value(x),
        }
    }
    /// Converts an ConfigValue into an Option, leaving DontSet as None.
    pub fn unwrap_or(&self, n: T) -> Option<T> {
        match self {
            ConfigValue::NotSpecified => Some(n),
            ConfigValue::DontSet => None,
            ConfigValue::Value(v) => Some(v.clone()),
        }
    }
    pub fn or(&self, n: Option<T>) -> Option<T> {
        match self {
            ConfigValue::NotSpecified => n,
            ConfigValue::DontSet => None,
            ConfigValue::Value(v) => Some(v.clone()),
        }
    }
    pub fn as_ref(&self) -> ConfigValue<&T> {
        match self {
            ConfigValue::NotSpecified => ConfigValue::NotSpecified,
            ConfigValue::DontSet => ConfigValue::DontSet,
            ConfigValue::Value(v) => ConfigValue::Value(&v),
        }
    }
    // Converts a ConfigValue into an Option, leaving NotSpecified as None.
    // This is useful if "don't set" has a default value that must be applied anyway.
    pub fn base_default(&self, n: T) -> Option<T> {
        match self {
            ConfigValue::NotSpecified => None,
            ConfigValue::DontSet => Some(n),
            ConfigValue::Value(v) => Some(v.clone()),
        }
    }
    // This return T, setting the default, and unspecified to a value.
    // This is useful if the unspecified value has an obvious required default.
    pub fn always_unwrap_or(&self, n: T) -> T {
        match self {
            ConfigValue::NotSpecified => n,
            ConfigValue::DontSet => n,
            ConfigValue::Value(v) => v.clone(),
        }
    }
    pub fn apply_default(&self, n: ConfigValue<T>) -> ConfigValue<T> {
        match (self, n) {
            (ConfigValue::NotSpecified, ConfigValue::NotSpecified) => ConfigValue::NotSpecified,
            (ConfigValue::NotSpecified, ConfigValue::DontSet) => ConfigValue::DontSet,
            (ConfigValue::NotSpecified, ConfigValue::Value(v)) => ConfigValue::Value(v),
            (ConfigValue::DontSet, _) => ConfigValue::DontSet,
            (ConfigValue::Value(v), _) => ConfigValue::Value(v.clone()),
        }
    }
}

impl<T: Clone> Default for ConfigValue<T> {
    fn default() -> Self {
        ConfigValue::NotSpecified
    }
}

pub fn type_to_name(fragment: &yaml::Yaml) -> String {
    match fragment {
        yaml::Yaml::Real(_) => "Real".into(),
        yaml::Yaml::Integer(_) => "Integer".into(),
        yaml::Yaml::String(_) => "String".into(),
        yaml::Yaml::Boolean(_) => "Boolean".into(),
        yaml::Yaml::Array(a) => format!("Array of {}", type_to_name(&a[0])),
        yaml::Yaml::Hash(_) => "Hash".into(),
        yaml::Yaml::Alias(_) => "Alias".into(),
        yaml::Yaml::Null => "Null".into(),
        yaml::Yaml::BadValue => "Bad Value".into(),
    }
}

pub fn parse_i64(name: &str, fragment: &yaml::Yaml) -> Result<Option<i64>, Error> {
    match fragment {
        yaml::Yaml::Null => Ok(None),
        yaml::Yaml::Integer(i) => Ok(Some(*i)),
        e => Err(Error::InvalidConfig(format!(
            "{} should be of type Integer, not {}",
            name,
            type_to_name(e)
        ))),
    }
}

pub fn parse_num<N: TryFrom<i64>>(name: &str, fragment: &yaml::Yaml) -> Result<Option<N>, Error> {
    match parse_i64(name, fragment) {
        Ok(None) => Ok(None),
        Err(e) => Err(e),
        Ok(Some(v)) => Ok(Some(N::try_from(v).map_err(|_| {
            Error::InvalidConfig(format!("{} out of range for {}", v, name))
        })?)),
    }
}

pub fn parse_string(name: &str, fragment: &yaml::Yaml) -> Result<Option<String>, Error> {
    match fragment {
        yaml::Yaml::Null => Ok(None),
        yaml::Yaml::String(s) => Ok(Some(s.into())),
        e => Err(Error::InvalidConfig(format!(
            "{} should be of type String, not {}",
            name,
            type_to_name(e)
        ))),
    }
}

pub fn parse_boolean(name: &str, fragment: &yaml::Yaml) -> Result<Option<bool>, Error> {
    match fragment {
        yaml::Yaml::Null => Ok(None),
        yaml::Yaml::Boolean(b) => Ok(Some(*b)),
        e => Err(Error::InvalidConfig(format!(
            "{} should be of type Boolean, not {}",
            name,
            type_to_name(e)
        ))),
    }
}

pub fn parse_array<T, F>(
    name: &str,
    fragment: &yaml::Yaml,
    mut parser: F,
) -> Result<Option<Vec<T>>, Error>
where
    F: FnMut(&str, &yaml::Yaml) -> Result<Option<T>, Error>,
{
    match fragment {
        yaml::Yaml::Null => Ok(None),
        yaml::Yaml::Array(a) => {
            let v = a
                .iter()
                .map(|it| parser(name, it))
                .collect::<Result<Vec<_>, _>>()?
                .drain(..)
                .map(|it| {
                    it.ok_or_else(|| {
                        Error::InvalidConfig(format!("Cannot have a Null value in array {}", name))
                    })
                })
                .collect::<Result<Vec<T>, _>>()?;

            Ok(Some(v))
        }
        e => Err(Error::InvalidConfig(format!(
            "{} should be of type Array, not {}",
            name,
            type_to_name(e)
        ))),
    }
}

pub const INTERFACE4: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
pub const INTERFACE6: std::net::IpAddr =
    std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

fn str_ip(ost: Option<String>) -> Result<Option<std::net::IpAddr>, Error> {
    match ost {
        Some(st) if st == "$self4" => Ok(Some(INTERFACE4)),
        Some(st) if st == "$self6" => Ok(Some(INTERFACE6)),
        Some(st) => Some(
            st.parse()
                .map_err(|e| Error::InvalidConfig(format!("{}", e))),
        )
        .transpose(),
        None => Ok(None),
    }
}

fn str_ip4(ost: Option<String>) -> Result<Option<std::net::Ipv4Addr>, Error> {
    match str_ip(ost) {
        Err(e) => Err(e),
        Ok(None) => Ok(None),
        Ok(Some(std::net::IpAddr::V4(ip4))) => Ok(Some(ip4)),
        Ok(Some(std::net::IpAddr::V6(ip6))) => Err(Error::InvalidConfig(format!(
            "Expected v4 address, got v6 address ({})",
            ip6,
        ))),
    }
}

fn str_ip6(ost: Option<String>) -> Result<Option<std::net::Ipv6Addr>, Error> {
    match str_ip(ost) {
        Err(e) => Err(e),
        Ok(None) => Ok(None),
        Ok(Some(std::net::IpAddr::V6(ip6))) => Ok(Some(ip6)),
        Ok(Some(std::net::IpAddr::V4(ip4))) => Err(Error::InvalidConfig(format!(
            "Expected v6 address, got v4 address ({})",
            ip4,
        ))),
    }
}

#[derive(Debug)]
enum HexError {
    InvalidDigit(u8),
    WrongLength,
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HexError::InvalidDigit(x) => write!(f, "Unexpected hex digit {}", x),
            HexError::WrongLength => write!(f, "Hex byte is not two digits long"),
        }
    }
}

fn hexdigit(c: u8) -> Result<u8, HexError> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(HexError::InvalidDigit(c)),
    }
}

fn hexbyte(st: &str) -> Result<u8, HexError> {
    let mut it = st.bytes();
    if let Some(n1) = it.next() {
        if let Some(n2) = it.next() {
            if it.next().is_none() {
                return Ok((hexdigit(n1)? << 4) | hexdigit(n2)?);
            }
        }
    }
    Err(HexError::WrongLength)
}

fn str_hwaddr(ost: Option<String>) -> Result<Option<Vec<u8>>, Error> {
    ost.map(|st| {
        st.split(':') /* Vec<String> */
            .map(hexbyte) /* Vec<Result<u8>> */
            .collect()
    })
    .transpose()
    .map_err(|e| Error::InvalidConfig(e.to_string()))
}

/// Parses a prefix of the form IP/prefixlen.
/// IP can be v4 or v6.
/// Currently no error handling on prefixlen is done.
fn str_prefix(ost: Option<String>) -> Result<Option<Prefix>, Error> {
    Ok(ost
        .map(|st| {
            let sections = st.split('/').collect::<Vec<_>>();
            if sections.len() != 2 {
                Err(Error::InvalidConfig(format!(
                    "Expected IP prefix, but '{}'",
                    st
                )))
            } else {
                let prefixlen = sections[1]
                    .parse()
                    .map_err(|x| Error::InvalidConfig(format!("{}", x)))?;
                match str_ip(Some(sections[0].into())) {
                    Ok(Some(std::net::IpAddr::V4(ip4))) => Ok(Some(Prefix::V4(Prefix4 {
                        addr: ip4,
                        prefixlen,
                    }))),
                    Ok(Some(std::net::IpAddr::V6(ip6))) => Ok(Some(Prefix::V6(Prefix6 {
                        addr: ip6,
                        prefixlen,
                    }))),
                    Err(e) => Err(e),
                    Ok(None) => Ok(None),
                }
            }
        })
        .transpose()?
        .flatten())
}

/// Parses a prefix of the form IPv4/prefixlen.
/// Currently no error handling on prefixlen is done.
fn str_prefix4(ost: Option<String>) -> Result<Option<Prefix4>, Error> {
    Ok(ost
        .map(|st| {
            let sections = st.split('/').collect::<Vec<_>>();
            if sections.len() != 2 {
                Err(Error::InvalidConfig(format!(
                    "Expected IPv4 prefix, but '{}'",
                    st
                )))
            } else {
                let prefixlen = sections[1]
                    .parse()
                    .map_err(|x| Error::InvalidConfig(format!("{}", x)))?;
                match str_ip4(Some(sections[0].into())) {
                    Ok(Some(ip4)) => Ok(Some(Prefix4 {
                        addr: ip4,
                        prefixlen,
                    })),
                    Err(e) => Err(e),
                    Ok(None) => Ok(None),
                }
            }
        })
        .transpose()?
        .flatten())
}

/// Parses a prefix of the form IPv6/prefixlen.
/// Currently no error handling on prefixlen is done.
fn str_prefix6(ost: Option<String>) -> Result<Option<Prefix6>, Error> {
    Ok(ost
        .map(|st| {
            let sections = st.split('/').collect::<Vec<_>>();
            if sections.len() != 2 {
                Err(Error::InvalidConfig(format!(
                    "Expected IPv6 prefix, but '{}'",
                    st
                )))
            } else {
                let prefixlen = sections[1]
                    .parse()
                    .map_err(|x| Error::InvalidConfig(format!("{}", x)))?;
                match str_ip6(Some(sections[0].into())) {
                    Ok(Some(ip6)) => Ok(Some(Prefix6 {
                        addr: ip6,
                        prefixlen,
                    })),
                    Err(e) => Err(e),
                    Ok(None) => Ok(None),
                }
            }
        })
        .transpose()?
        .flatten())
}

fn str_duration(ost: Option<String>) -> Result<Option<std::time::Duration>, Error> {
    ost.map(|st| {
        let mut num = None;
        let mut ret = Default::default();
        for c in st.chars() {
            match c {
                '0'..='9' => {
                    if let Some(n) = num {
                        num = Some(n * 10 + c as u64 - '0' as u64);
                    } else {
                        num = Some(c as u64 - '0' as u64);
                    }
                }
                's' => {
                    ret += std::time::Duration::from_secs(num.take().unwrap());
                }
                'm' => {
                    ret += std::time::Duration::from_secs(num.take().unwrap() * 60);
                }
                'h' => {
                    ret += std::time::Duration::from_secs(num.take().unwrap() * 3600);
                }
                'd' => {
                    ret += std::time::Duration::from_secs(num.take().unwrap() * 86400);
                }
                'w' => {
                    ret += std::time::Duration::from_secs(num.take().unwrap() * 7 * 86400);
                }
                x if x.is_whitespace() => (),
                '_' => (),
                _ => {
                    return Err(Error::InvalidConfig(format!(
                        "Unexpected {} in duration",
                        c
                    )))
                }
            }
        }
        if let Some(n) = num {
            ret += std::time::Duration::from_secs(n);
        }
        Ok(ret)
    })
    .transpose()
}

pub fn parse_string_hwaddr(name: &str, fragment: &yaml::Yaml) -> Result<Option<Vec<u8>>, Error> {
    parse_string(name, fragment).and_then(str_hwaddr)
}

pub fn parse_string_ip(
    name: &str,
    fragment: &yaml::Yaml,
) -> Result<Option<std::net::IpAddr>, Error> {
    parse_string(name, fragment).and_then(str_ip)
}

pub fn parse_string_ip4(
    name: &str,
    fragment: &yaml::Yaml,
) -> Result<Option<std::net::Ipv4Addr>, Error> {
    parse_string(name, fragment).and_then(str_ip4)
}

pub fn parse_string_ip6(
    name: &str,
    fragment: &yaml::Yaml,
) -> Result<Option<std::net::Ipv6Addr>, Error> {
    parse_string(name, fragment).and_then(str_ip6)
}

pub fn parse_string_prefix(name: &str, fragment: &yaml::Yaml) -> Result<Option<Prefix>, Error> {
    parse_string(name, fragment).and_then(str_prefix)
}

pub fn parse_string_prefix4(name: &str, fragment: &yaml::Yaml) -> Result<Option<Prefix4>, Error> {
    parse_string(name, fragment).and_then(str_prefix4)
}

pub fn parse_string_prefix6(name: &str, fragment: &yaml::Yaml) -> Result<Option<Prefix6>, Error> {
    parse_string(name, fragment).and_then(str_prefix6)
}

pub fn parse_duration(
    name: &str,
    fragment: &yaml::Yaml,
) -> Result<Option<std::time::Duration>, Error> {
    if let yaml::Yaml::Integer(i) = fragment {
        Ok(Some(std::time::Duration::from_secs(*i as u64)))
    } else {
        parse_string(name, fragment).and_then(str_duration)
    }
}

#[derive(Debug)]
pub struct Prefix4 {
    pub addr: std::net::Ipv4Addr,
    pub prefixlen: u8,
}

#[derive(Debug)]
pub struct Prefix6 {
    pub addr: std::net::Ipv6Addr,
    pub prefixlen: u8,
}

#[derive(Debug)]
pub enum Prefix {
    V4(Prefix4),
    V6(Prefix6),
}

#[derive(Debug, Default)]
pub struct Config {
    pub dhcp: crate::dhcp::config::Config,
    pub ra: crate::radv::config::Config,
    pub dns_servers: Vec<std::net::IpAddr>,
    pub dns_search: Vec<String>,
    pub captive_portal: Option<String>,
    pub addresses: Vec<Prefix>,
}

pub type SharedConfig = std::sync::Arc<tokio::sync::Mutex<Config>>;

fn load_config_from_string(cfg: &str) -> Result<SharedConfig, Error> {
    let y = yaml::YamlLoader::load_from_str(cfg).map_err(Error::YamlError)?;
    match y.len() {
        0 => return Err(Error::MissingConfig),
        1 => (),
        _ => return Err(Error::MultipleConfigs),
    }
    if let Some(fragment) = y[0].as_hash() {
        let mut ra = None;
        let mut dhcp = None;
        let mut dns_servers = vec![];
        let mut dns_search = vec![];
        let mut captive_portal = None;
        let mut addresses = None;
        for (k, v) in fragment {
            match (k.as_str(), v) {
                (Some("dhcp"), d) => dhcp = crate::dhcp::config::Config::new(d)?,
                (Some("router-advertisements"), r) => ra = crate::radv::config::parse(r)?,
                (Some("dns-servers"), s) => {
                    dns_servers = parse_array("dns-servers", s, parse_string_ip)?
                        .ok_or_else(|| Error::InvalidConfig("dns-servers cannot be null".into()))?
                }
                (Some("dns-search"), s) => {
                    dns_search = parse_array("dns-search", s, parse_string)?
                        .ok_or_else(|| Error::InvalidConfig("dns-search cannot be null".into()))?
                }
                (Some("captive-portal"), s) => {
                    captive_portal = parse_string("captive-portal", s)?;
                }
                (Some("addresses"), s) => {
                    addresses = parse_array("addresses", s, parse_string_prefix)?;
                }
                (Some(x), _) => {
                    return Err(Error::InvalidConfig(format!(
                        "Unknown configuration option {}",
                        x
                    )))
                }
                (None, _) => {
                    return Err(Error::InvalidConfig(format!(
                        "Config should be keyed by String, not {}",
                        type_to_name(k)
                    )))
                }
            }
        }
        let conf = Config {
            dhcp: dhcp.unwrap_or_else(crate::dhcp::config::Config::default),
            ra: ra.unwrap_or_else(crate::radv::config::Config::default),
            dns_servers,
            dns_search,
            captive_portal,
            addresses: addresses.unwrap_or_else(Vec::new),
        };
        Ok(std::sync::Arc::new(tokio::sync::Mutex::new(conf)))
    } else {
        Err(Error::InvalidConfig(
            "Top level configuration should be a Hash".into(),
        ))
    }
}

#[cfg(test)]
pub fn load_config_from_string_for_test(cfg: &str) -> Result<SharedConfig, Error> {
    load_config_from_string(cfg)
}

/* We support reading configs from a yaml file, _or_ a program (eg a shell script?) that outputs
 * yaml on stdout.
 *
 * TODO: Implement reading a directory of configs.
 */
pub async fn load_config_from_path(path: &std::path::Path) -> Result<SharedConfig, Error> {
    let metadata = std::fs::metadata(path).map_err(Error::IoError)?;
    let configdata = if metadata.permissions().mode() & 0o111 != 0 {
        let output = tokio::process::Command::new(path)
            .output()
            .await
            .map_err(Error::IoError)?;
        if !output.status.success() {
            return Err(Error::ConfigProcessFailed);
        }
        String::from_utf8(output.stdout).map_err(Error::Utf8Error)?
    } else {
        let mut contents = vec![];
        tokio::fs::File::open(path)
            .await
            .map_err(Error::IoError)?
            .read_to_end(&mut contents)
            .await
            .map_err(Error::IoError)?;

        String::from_utf8(contents).map_err(Error::Utf8Error)?
    };

    load_config_from_string(&configdata)
}

#[test]
fn test_config_parse() -> Result<(), Error> {
    load_config_from_string(
        "---
dhcp:
    policies:
      - match-interface: eth0
        apply-dns-servers: ['8.8.8.8', '8.8.4.4']
        apply-subnet: 192.168.0.0/24
        apply-time-offset: 3600
        apply-domain-name: erbium.dev
        apply-forward: false
        apply-mtu: 1500
        apply-broadcast: 192.168.255.255
        apply-rebind-time: 120
        apply-renewal-time: 90s
        apply-arp-timeout: 1w
        apply-routes:
         - prefix: 192.0.2.0/24
           next-hop: 192.0.2.254


        policies:
           - { match-host-name: myhost, apply-address: 192.168.0.1 }


      - match-interface: dmz
        apply-dns-servers: ['8.8.8.8']
        apply-subnet: 192.0.2.0/24

        # Reserve some space from the pool for servers
        policies:
          - apply-range: {start: 192.0.2.10, end: 192.0.2.20}

            # From the reserved pool, assign a static address.
            policies:
              - { match-hardware-address: 00:01:02:03:04:05, apply-address: 192.168.0.2 }

          # Reserve space for VPN endpoints
          - match-user-class: VPN
            apply-subnet: 192.0.2.128/25

router-advertisements:
    - interface: eth0
",
    )?;
    Ok(())
}

#[test]
fn test_simple_config_parse() -> Result<(), Error> {
    load_config_from_string(
        "---
dns-servers: [$self4, $self6]
dns-search: ['example.com']
addresses: [192.0.2.0/24, 2001:db8::/64]

router-advertisements:
    - interface: eth0
      lifetime: 1d
",
    )?;
    Ok(())
}

#[test]
fn test_duration() {
    assert_eq!(
        parse_duration("test", &yaml::Yaml::String("5s".into())).unwrap(),
        Some(std::time::Duration::from_secs(5))
    );
    assert_eq!(
        parse_duration("test", &yaml::Yaml::String("1w2d3h4m5s".into())).unwrap(),
        Some(std::time::Duration::from_secs(
            7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5
        ))
    );
}
