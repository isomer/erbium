/*   Copyright 2021 Perry Lorier
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
    pub lifetime: ConfigValue<std::time::Duration>,
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

impl Default for Interface {
    fn default() -> Self {
        use std::time::Duration;
        use ConfigValue::*;
        Self {
            name: "default".into(),
            hoplimit: 0,
            managed: false,
            other: false,
            lifetime: NotSpecified,
            reachable: Duration::from_secs(0), /* Not defined. */
            retrans: Duration::from_secs(0),   /* Not defined. */
            mtu: NotSpecified,
            prefixes: vec![],
            rdnss_lifetime: NotSpecified,
            rdnss: NotSpecified,
            dnssl_lifetime: NotSpecified,
            dnssl: NotSpecified,
            captive_portal: NotSpecified,
            pref64: None,
        }
    }
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
        let mut hoplimit: Option<u8> = None;
        let mut managed = None;
        let mut other = None;
        let mut lifetime = ConfigValue::NotSpecified;
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
                (Some("interface"), _) => {
                    return Err(Error::InvalidConfig(
                        "interface name is no longer specified here".into(),
                    ))
                }
                (Some("hop-limit"), i) => hoplimit = parse_num("hop-limit", i)?,
                (Some("managed"), b) => managed = parse_boolean("managed", b)?,
                (Some("other"), o) => other = parse_boolean("other", o)?,
                (Some("lifetime"), d) => {
                    lifetime = ConfigValue::from_option(parse_duration("lifetime", d)?)
                }
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
        Ok(Some(Interface {
            name: name.into(),
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
        Err(Error::InvalidConfig(format!(
            "{} expected hash, got {} instead",
            name,
            type_to_name(fragment)
        )))
    }
}

pub fn parse(fragment: &yaml::Yaml) -> Result<Option<Config>, Error> {
    let mut conf = Config::default();
    if let Some(h) = fragment.as_hash() {
        for (k, v) in h {
            match (k.as_str(), v) {
                /* You may wish to specify an interface, and accept _all_ the defaults.
                 * So that means the type ends up being null, rewrite it to an empty hash.
                 * This has the side effect that you can't force an interface to _not_ have a
                 * config if you've also specified sufficient config for it at the top level.
                 */
                (Some(interface), yaml::Yaml::Null) => conf.interfaces.push(
                    parse_interface(interface, &yaml::Yaml::Hash(Default::default()))?.unwrap(),
                ),
                (Some(interface), intf) => conf.interfaces.push(
                    parse_interface(interface, intf)
                        .map_err(|e| e.annotate(&format!("while parsing interface {}", interface)))?
                        .unwrap(),
                ),
                (None, _) => {
                    return Err(Error::InvalidConfig(format!(
                        "router-advertisement keys should be names of interfaces, not {}",
                        type_to_name(k)
                    )))
                }
            }
        }
        Ok(Some(conf))
    } else if fragment.is_array() {
        Err(Error::InvalidConfig("router-advertisement is no longer a list of interfaces, but instead a hash indexed by interface name".into()
        ))
    } else {
        Err(Error::InvalidConfig(format!(
            "router-advertisement should be a hash, not {}",
            type_to_name(fragment)
        )))
    }
}

#[test]
fn test_config_parse() -> Result<(), Error> {
    use crate::config;
    config::load_config_from_string_for_test(
        "---
router-advertisements:
    eth0:
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
