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

pub fn parse_string_as<T, F>(
    name: &str,
    fragment: &yaml::Yaml,
    str_parser: F,
) -> Result<Option<T>, Error>
where
    F: Fn(&str) -> Result<T, Error>,
{
    match parse_string(name, fragment) {
        Ok(Some(s)) => Ok(Some(str_parser(&s)?)),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn str_parse_ip(st: &str) -> Result<std::net::IpAddr, Error> {
    st.parse()
        .map_err(|e| Error::InvalidConfig(format!("{}", e)))
}

pub fn parse_duration(value: &yaml::Yaml) -> Result<Option<std::time::Duration>, Error> {
    match value {
        yaml::Yaml::Null => Ok(None),
        yaml::Yaml::String(v) => {
            let mut num = None;
            let mut ret = Default::default();
            for c in v.chars() {
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
            Ok(Some(ret))
        }
        yaml::Yaml::Integer(s) => Ok(Some(std::time::Duration::from_secs(
            u64::try_from(*s)
                .map_err(|_| Error::InvalidConfig("Durations cannot be negative".into()))?,
        ))),
        e => Err(Error::InvalidConfig(format!(
            "Expected duration, got {:?}",
            e,
        ))),
    }
}

#[derive(Debug, Default)]
pub struct Config {
    pub dhcp: crate::dhcp::config::Config,
    pub ra: crate::radv::config::Config,
    pub dns_servers: Vec<std::net::IpAddr>,
    pub dns_search: Vec<String>,
    pub captive_portal: Option<String>,
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
        for (k, v) in fragment {
            match (k.as_str(), v) {
                (Some("dhcp"), d) => dhcp = crate::dhcp::config::Config::new(d)?,
                (Some("router-advertisements"), r) => ra = crate::radv::config::parse(r)?,
                (Some("dns-servers"), s) => {
                    dns_servers = parse_array("dns-servers", s, |name, yaml| {
                        parse_string_as(name, yaml, str_parse_ip)
                    })?
                    .ok_or_else(|| Error::InvalidConfig("dns-servers cannot be null".into()))?
                }
                (Some("dns-search"), s) => {
                    dns_search = parse_array("dns-search", s, parse_string)?
                        .ok_or_else(|| Error::InvalidConfig("dns-search cannot be null".into()))?
                }
                (Some("captive-portal"), s) => {
                    captive_portal = parse_string("captive-portal", s)?;
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
fn test_duration() {
    assert_eq!(
        parse_duration(&yaml::Yaml::String("5s".into())).unwrap(),
        Some(std::time::Duration::from_secs(5))
    );
    assert_eq!(
        parse_duration(&yaml::Yaml::String("1w2d3h4m5s".into())).unwrap(),
        Some(std::time::Duration::from_secs(
            7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5
        ))
    );
}
