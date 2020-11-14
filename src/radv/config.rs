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
 *  IPv6 Router Advertisement Configuration
 */

pub use crate::config::*;
use yaml_rust::yaml;

#[derive(Debug)]
pub struct Prefix {
    pub addr: std::net::Ipv6Addr,
    pub prefixlen: u8,
    pub onlink: bool,
    pub autonomous: bool,
    pub valid: std::time::Duration,
    pub preferred: std::time::Duration,
}

#[derive(Debug)]
pub struct Pref64 {
    pub lifetime: std::time::Duration,
    pub prefix: std::net::Ipv6Addr,
    pub prefixlen: u8,
}

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub hoplimit: u8,
    pub managed: bool,
    pub other: bool,
    pub lifetime: std::time::Duration,
    pub reachable: std::time::Duration,
    pub retrans: std::time::Duration,
    pub mtu: ConfigValue<u32>,
    pub prefixes: Vec<Prefix>,
    pub rdnss_lifetime: ConfigValue<std::time::Duration>,
    pub rdnss: ConfigValue<Vec<std::net::Ipv6Addr>>,
    pub dnssl_lifetime: ConfigValue<std::time::Duration>,
    pub dnssl: ConfigValue<Vec<String>>,
    pub captive_portal: ConfigValue<String>,
    pub pref64: Option<Pref64>,
}

#[derive(Debug, Default)]
pub struct Config {
    pub interfaces: Vec<Interface>,
}

fn parse_prefix(name: &str, fragment: &yaml::Yaml) -> Result<Option<Prefix>, Error> {
    match fragment {
        yaml::Yaml::Hash(h) => {
            let mut prefix = None;
            let mut onlink = None;
            let mut autonomous = None;
            let mut valid = None;
            let mut preferred = None;
            for (k, v) in h {
                match (k.as_str(), v) {
                    (Some("prefix"), p) => prefix = parse_string_prefix6("prefix", p)?,
                    (Some("on-link"), b) => onlink = parse_boolean("on-link", b)?,
                    (Some("autonomous"), b) => autonomous = parse_boolean("autonomous", b)?,
                    (Some("valid"), d) => valid = parse_duration("valid", d)?,
                    (Some("preferred"), d) => preferred = parse_duration("preferred", d)?,
                    (Some(m), _) => {
                        return Err(Error::InvalidConfig(format!("Unknown {} key {}", name, m)))
                    }
                    (None, _) => {
                        return Err(Error::InvalidConfig(format!(
                            "{} keys are expected to be strings",
                            name,
                        )))
                    }
                }
            }
            let prefix = prefix.unwrap();
            Ok(Some(Prefix {
                addr: prefix.addr,
                prefixlen: prefix.prefixlen,
                onlink: onlink.unwrap_or(true),
                autonomous: autonomous.unwrap_or(true),
                valid: valid.unwrap_or_else(|| std::time::Duration::from_secs(2592000)),
                preferred: preferred.unwrap_or_else(|| std::time::Duration::from_secs(604800)),
            }))
        }
        e => Err(Error::InvalidConfig(format!(
            "Expected hash for {}, got {}",
            name,
            type_to_name(e)
        ))),
    }
}

fn parse_rdnss(
    name: &str,
    fragment: &yaml::Yaml,
) -> Result<
    (
        ConfigValue<std::time::Duration>,
        ConfigValue<Vec<std::net::Ipv6Addr>>,
    ),
    Error,
> {
    let mut lifetime = Default::default();
    let mut address = Default::default();
    if let Some(h) = fragment.as_hash() {
        for (k, v) in h {
            match (k.as_str(), v) {
                (Some("addresses"), a) => {
                    address =
                        ConfigValue::from_option(parse_array("addresses", a, parse_string_ip6)?)
                }
                (Some("lifetime"), d) => {
                    lifetime = ConfigValue::from_option(parse_duration("lifetime", d)?)
                }
                (Some(m), _) => {
                    return Err(Error::InvalidConfig(format!("Unknown {} key {}", name, m)))
                }
                (None, _) => {
                    return Err(Error::InvalidConfig(format!(
                        "{} key should be string, not {}",
                        name,
                        type_to_name(k)
                    )))
                }
            }
        }
        Ok((lifetime, address))
    } else {
        Err(Error::InvalidConfig(format!(
            "{} should be a hash, not {}",
            name,
            type_to_name(fragment)
        )))
    }
}

fn parse_domain(name: &str, fragment: &yaml::Yaml) -> Result<Option<String>, Error> {
    match fragment {
        yaml::Yaml::Null => Ok(None),
        yaml::Yaml::String(s) => Ok(Some(s.into())),
        e => Err(Error::InvalidConfig(format!(
            "{} expected string, not {}",
            name,
            type_to_name(e),
        ))),
    }
}

fn parse_dnssl(
    name: &str,
    fragment: &yaml::Yaml,
) -> Result<(ConfigValue<std::time::Duration>, ConfigValue<Vec<String>>), Error> {
    let mut lifetime = Default::default();
    let mut domains = Default::default();
    if let Some(h) = fragment.as_hash() {
        for (k, v) in h {
            match (k.as_str(), v) {
                (Some("domains"), a) => {
                    domains = ConfigValue::from_option(parse_array("domains", a, parse_domain)?)
                }
                (Some("lifetime"), d) => {
                    lifetime = ConfigValue::from_option(parse_duration("lifetime", d)?)
                }
                (Some(m), _) => {
                    return Err(Error::InvalidConfig(format!("Unknown {} key {}", name, m)))
                }
                (None, _) => {
                    return Err(Error::InvalidConfig(format!(
                        "{} key should be string, not {}",
                        name,
                        type_to_name(k)
                    )))
                }
            }
        }
        Ok((lifetime, domains))
    } else {
        Err(Error::InvalidConfig(format!(
            "{} should be a hash, not {}",
            name,
            type_to_name(fragment)
        )))
    }
}

fn parse_pref64(name: &str, fragment: &yaml::Yaml) -> Result<Option<Pref64>, Error> {
    if let Some(h) = fragment.as_hash() {
        let mut prefix = None;
        let mut lifetime = None;
        for (k, v) in h {
            match (k.as_str(), v) {
                (Some("prefix"), p) => prefix = parse_string_prefix6("prefix", p)?,
                (Some("lifetime"), d) => lifetime = parse_duration("lifetime", d)?,
                (Some(n), _) => {
                    return Err(Error::InvalidConfig(format!("Unknown {} key: {}", name, n)))
                }
                (None, _) => {
                    return Err(Error::InvalidConfig(format!(
                        "{} keys should be String, not {}",
                        name,
                        type_to_name(fragment)
                    )))
                }
            }
        }
        if let Some(prefix) = prefix {
            Ok(Some(Pref64 {
                prefix: prefix.addr,
                lifetime: lifetime.unwrap_or_else(|| std::time::Duration::from_secs(600)),
                prefixlen: prefix.prefixlen,
            }))
        } else {
            Ok(None)
        }
    } else {
        Err(Error::InvalidConfig(format!(
            "{} should be a hash, not {}",
            name,
            type_to_name(fragment)
        )))
    }
}

fn parse_interface(name: &str, fragment: &yaml::Yaml) -> Result<Option<Interface>, Error> {
    if let Some(h) = fragment.as_hash() {
        let mut intf = None;
        let mut hoplimit: Option<u8> = None;
        let mut managed = None;
        let mut other = None;
        let mut lifetime = None;
        let mut reachable = None;
        let mut retrans = None;
        let mut mtu = ConfigValue::NotSpecified;
        let mut prefixes = vec![];
        let mut rdnss = (ConfigValue::NotSpecified, ConfigValue::NotSpecified);
        let mut dnssl = (Default::default(), Default::default());
        let mut captive_portal = Default::default();
        let mut pref64 = None;
        for (k, v) in h {
            match (k.as_str(), v) {
                (Some("interface"), s) => intf = parse_string("interface", s)?,
                (Some("hop-limit"), i) => hoplimit = parse_num("hop-limit", i)?,
                (Some("managed"), b) => managed = parse_boolean("managed", b)?,
                (Some("other"), o) => other = parse_boolean("other", o)?,
                (Some("lifetime"), d) => lifetime = parse_duration("lifetime", d)?,
                (Some("reachable"), d) => reachable = parse_duration("reachable", d)?,
                (Some("retransmit"), d) => retrans = parse_duration("retransmit", d)?,
                (Some("mtu"), m) => mtu = ConfigValue::from_option(parse_num("mtu", m)?),
                (Some("pref64"), p) => pref64 = parse_pref64("pref64", p)?,
                (Some("prefixes"), p) => {
                    prefixes = parse_array("prefixes", p, parse_prefix)?
                        .ok_or_else(|| Error::InvalidConfig("domains should not be null".into()))?
                }
                (Some("dns-servers"), e) => rdnss = parse_rdnss("dns-servers", e)?,
                (Some("dns-search"), e) => dnssl = parse_dnssl("dns-search", e)?,
                (Some("captive-portal"), e) => {
                    captive_portal = ConfigValue::from_option(parse_string("captive-portal", e)?)
                }
                (Some(key), _) => {
                    return Err(Error::InvalidConfig(format!(
                        "Unknown {} key {}",
                        name, key
                    )))
                }
                (None, _) => {
                    return Err(Error::InvalidConfig(format!(
                        "{} key is {} not String",
                        name,
                        type_to_name(k)
                    )))
                }
            }
        }
        if let Some(ifname) = intf {
            let lifetime = lifetime.unwrap_or_else(|| std::time::Duration::from_secs(0));
            Ok(Some(Interface {
                name: ifname,
                hoplimit: hoplimit.unwrap_or(0),
                managed: managed.unwrap_or(false),
                other: other.unwrap_or(false),
                lifetime,
                reachable: reachable.unwrap_or_else(|| std::time::Duration::from_secs(0)),
                retrans: retrans.unwrap_or_else(|| std::time::Duration::from_secs(0)),
                mtu,
                prefixes,
                rdnss_lifetime: rdnss.0,
                rdnss: rdnss.1,
                dnssl_lifetime: dnssl.0,
                dnssl: dnssl.1,
                captive_portal,
                pref64,
            }))
        } else {
            Err(Error::InvalidConfig(
                "Interface specified without a name".into(),
            ))
        }
    } else {
        Err(Error::InvalidConfig(format!(
            "{} expected hash, got {} instead",
            name,
            type_to_name(fragment)
        )))
    }
}

pub fn parse(fragment: &yaml::Yaml) -> Result<Option<Config>, Error> {
    Ok(Some(Config {
        interfaces: parse_array("router-advertisements", fragment, parse_interface)?
            .unwrap_or_else(Vec::new),
    }))
}

#[test]
fn test_config_parse() -> Result<(), Error> {
    use crate::config;
    config::load_config_from_string_for_test(
        "---
router-advertisements:
    - interface: eth0
      hop-limit: 64
      managed: false
      other: false
      lifetime: 1h 30m
      reachable: 30s
      retransmit: 1s
      mtu: 1480
      prefixes:
       - prefix: 2001:db8::/64
         on-link: true
         autonomous: true
         valid: 7d
         preferred: 24h
      dns-servers:
       addresses: [ 2001:db8::53, 2001:db8::1:53 ]
       lifetime: 6h
      dns-search:
       domains: [ example.com, example.net ]
       lifetime: 6h
      captive-portal: http://portal.example.com/
      pref64:
       prefix: 64:ff9b::/96
       lifetime: 10m
",
    )?;
    Ok(())
}
