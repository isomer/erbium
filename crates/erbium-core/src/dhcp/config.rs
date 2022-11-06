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
 *  DHCP Configuration parsing.
 */
use super::dhcppkt;
use std::convert::TryFrom as _;
use std::ops::Sub;
use yaml_rust::yaml;

pub use crate::config::*;

#[derive(Debug, Default)]
pub struct Policy {
    pub match_all: bool,
    pub match_interface: Option<Option<String>>,
    pub match_chaddr: Option<Vec<u8>>,
    pub match_subnet: Option<erbium_net::Ipv4Subnet>,
    pub match_other:
        std::collections::HashMap<dhcppkt::DhcpOption, Option<dhcppkt::DhcpOptionTypeValue>>,
    pub apply_address: Option<super::pool::PoolAddresses>,
    pub apply_default_lease: Option<std::time::Duration>,
    pub apply_max_lease: Option<std::time::Duration>,
    pub apply_other:
        std::collections::HashMap<dhcppkt::DhcpOption, Option<dhcppkt::DhcpOptionTypeValue>>,
    pub policies: Vec<Policy>,
    pub(super) address_cache:
        std::sync::Mutex<std::cell::RefCell<Option<super::pool::PoolAddresses>>>,
}

impl Clone for Policy {
    fn clone(&self) -> Self {
        Self {
            address_cache: Default::default(),
            match_interface: self.match_interface.clone(),
            match_chaddr: self.match_chaddr.clone(),
            match_other: self.match_other.clone(),
            apply_address: self.apply_address.clone(),
            apply_other: self.apply_other.clone(),
            policies: self.policies.clone(),
            ..*self
        }
    }
}

impl Policy {
    fn get_all_used_addresses(&self) -> std::collections::HashSet<std::net::Ipv4Addr> {
        /* We cache the result of this. */
        if self.address_cache.lock().unwrap().borrow().is_none() {
            /* Cache is cold, heat it. */
            let mut addrset: std::collections::HashSet<std::net::Ipv4Addr> = Default::default();
            if let Some(address) = &self.apply_address {
                addrset.extend(address.iter());
            }
            for p in &self.policies {
                addrset.extend(p.get_all_used_addresses().iter());
            }
            self.address_cache.lock().unwrap().replace(Some(addrset));
        }

        self.address_cache.lock().unwrap().borrow().clone().unwrap()
    }
}

#[derive(Debug, Default)]
pub struct Config {
    pub policies: Vec<Policy>,
}

impl Config {
    pub fn get_all_used_addresses(&self) -> std::collections::HashSet<std::net::Ipv4Addr> {
        self.policies
            .iter()
            .map(Policy::get_all_used_addresses)
            .fold(
                std::collections::HashSet::<std::net::Ipv4Addr>::new(),
                |mut acc, e| {
                    acc.extend(e);
                    acc
                },
            )
    }
    fn parse_routes(fragment: &yaml::Yaml) -> Result<Option<Vec<dhcppkt::Route>>, Error> {
        match fragment {
            yaml::Yaml::Null => Ok(None),
            yaml::Yaml::Array(yroutes) => {
                let mut routes = Vec::new();
                for route in yroutes {
                    let mut prefix = None;
                    let mut nexthop = None;
                    if let Some(h) = route.as_hash() {
                        for (k, v) in h {
                            match k {
                                yaml::Yaml::Null => {
                                    return Err(Error::InvalidConfig(
                                        "Routes cannot have null keys".into(),
                                    ))
                                }
                                yaml::Yaml::String(s) if s == "next-hop" => {
                                    nexthop = Some(parse_string_ip4("next-hop", v)?.ok_or_else(
                                        || Error::InvalidConfig("next-hop cannot be null".into()),
                                    )?);
                                }
                                yaml::Yaml::String(s) if s == "prefix" => match v {
                                    yaml::Yaml::Null => {
                                        return Err(Error::InvalidConfig(
                                            "prefix cannot be null".into(),
                                        ))
                                    }
                                    yaml::Yaml::String(s) => {
                                        let mut it = s.split('/');
                                        let ip =
                                            it.next().unwrap().parse().map_err(|e| {
                                                Error::InvalidConfig(format!("{}", e))
                                            })?; /* TODO: remove unwrap */
                                        let prefixlen = it.next().unwrap().parse().unwrap();
                                        prefix = Some(
                                            erbium_net::Ipv4Subnet::new(ip, prefixlen).map_err(
                                                |e| Error::InvalidConfig(format!("{}", e)),
                                            )?,
                                        );
                                    }
                                    e => {
                                        return Err(Error::InvalidConfig(format!(
                                            "prefix has unexpected type {:?}",
                                            e,
                                        )))
                                    }
                                },
                                yaml::Yaml::String(s) => {
                                    return Err(Error::InvalidConfig(format!(
                                        "Unexpected key in route: {:?}",
                                        s
                                    )));
                                }
                                e => {
                                    return Err(Error::InvalidConfig(format!(
                                        "Key has unexpected type: {:?}",
                                        e
                                    )))
                                }
                            }
                        }
                        if let Some(prefix) = prefix {
                            if let Some(nexthop) = nexthop {
                                routes.push(dhcppkt::Route { prefix, nexthop });
                            } else {
                                return Err(Error::InvalidConfig(
                                    "Missing next-hop: in route".into(),
                                ));
                            }
                        } else {
                            return Err(Error::InvalidConfig("Missing prefix: in route".into()));
                        }
                    } else {
                        return Err(Error::InvalidConfig(format!(
                            "Expected hash, got '{:?}'",
                            route
                        )));
                    }
                }
                Ok(Some(routes))
            }
            e => Err(Error::InvalidConfig(format!(
                "Expected routes, got {:?}",
                e
            ))),
        }
    }

    fn parse_subnet(fragment: &yaml::Yaml) -> Result<Option<erbium_net::Ipv4Subnet>, Error> {
        match fragment {
            yaml::Yaml::Null => Ok(None),
            yaml::Yaml::String(s) => {
                let sections: Vec<&str> = s.split('/').collect();
                if sections.len() != 2 {
                    Err(Error::InvalidConfig(format!(
                        "Expected IP prefix, but '{}'",
                        s
                    )))
                } else {
                    Ok(Some(
                        erbium_net::Ipv4Subnet::new(
                            sections[0]
                                .parse()
                                .map_err(|x| Error::InvalidConfig(format!("{}", x)))?,
                            sections[1]
                                .parse()
                                .map_err(|x| Error::InvalidConfig(format!("{}", x)))?,
                        )
                        .map_err(|_| {
                            Error::InvalidConfig(format!("Prefix length too short {:?}", sections))
                        })?,
                    ))
                }
            }
            e => Err(Error::InvalidConfig(format!(
                "Expected IP prefix as string, got {:?}",
                e
            ))),
        }
    }

    fn parse_number(value: &yaml::Yaml) -> Result<Option<i64>, Error> {
        match value {
            yaml::Yaml::Null => Ok(None),
            yaml::Yaml::Integer(i) => Ok(Some(*i)),
            e => Err(Error::InvalidConfig(format!(
                "Expected Number, got '{:?}'",
                e
            ))),
        }
    }

    fn parse_generic(
        name: &str,
        value: &yaml::Yaml,
    ) -> Result<(dhcppkt::DhcpOption, Option<dhcppkt::DhcpOptionTypeValue>), Error> {
        let maybe_opt = dhcppkt::name_to_option(name);
        if let Some(opt) = maybe_opt {
            use dhcppkt::*;
            Ok((
                opt,
                match opt.get_type() {
                    Some(DhcpOptionType::String) => {
                        parse_string(name, value)?.map(DhcpOptionTypeValue::String)
                    }
                    Some(DhcpOptionType::IpList) => {
                        parse_array(name, value, parse_string_ip4)?.map(DhcpOptionTypeValue::IpList)
                    }
                    Some(DhcpOptionType::Routes) => {
                        Config::parse_routes(value)?.map(DhcpOptionTypeValue::Routes)
                    }
                    Some(DhcpOptionType::Ip) => {
                        parse_string_ip4(name, value)?.map(DhcpOptionTypeValue::Ip)
                    }
                    Some(DhcpOptionType::I32) => Config::parse_number(value)?
                        .map(|i| {
                            i32::try_from(i).map_err(|_| {
                                Error::InvalidConfig(format!("Integer {} out of range", i))
                            })
                        })
                        .transpose()?
                        .map(DhcpOptionTypeValue::I32),
                    Some(DhcpOptionType::U8) => Config::parse_number(value)?
                        .map(|i| {
                            u8::try_from(i).map_err(|_| {
                                Error::InvalidConfig(format!("Integer {} out of range", i))
                            })
                        })
                        .transpose()?
                        .map(DhcpOptionTypeValue::U8),
                    Some(DhcpOptionType::U16) => Config::parse_number(value)?
                        .map(|i| {
                            u16::try_from(i).map_err(|_| {
                                Error::InvalidConfig(format!("Integer {} out of range", i))
                            })
                        })
                        .transpose()?
                        .map(DhcpOptionTypeValue::U16),
                    Some(DhcpOptionType::U32) => Config::parse_number(value)?
                        .map(|i| {
                            u32::try_from(i).map_err(|_| {
                                Error::InvalidConfig(format!("Integer {} out of range", i))
                            })
                        })
                        .transpose()?
                        .map(DhcpOptionTypeValue::U32),
                    Some(DhcpOptionType::Seconds16) => parse_duration(name, value)?
                        .map(|i| {
                            u16::try_from(i.as_secs()).map_err(|_| {
                                Error::InvalidConfig(format!(
                                    "Duration {}s out of range",
                                    i.as_secs()
                                ))
                            })
                        })
                        .transpose()?
                        .map(DhcpOptionTypeValue::U16),
                    Some(DhcpOptionType::Seconds32) => parse_duration(name, value)?
                        .map(|i| {
                            u32::try_from(i.as_secs()).map_err(|_| {
                                Error::InvalidConfig(format!(
                                    "Duration {}s out of range",
                                    i.as_secs()
                                ))
                            })
                        })
                        .transpose()?
                        .map(DhcpOptionTypeValue::U32),
                    Some(DhcpOptionType::Bool) => {
                        parse_boolean(name, value)?.map(|b| DhcpOptionTypeValue::U8(b as u8))
                    }
                    Some(DhcpOptionType::HwAddr) => {
                        parse_string_hwaddr(name, value)?.map(DhcpOptionTypeValue::HwAddr)
                    }
                    Some(DhcpOptionType::DomainList) => {
                        crate::config::parse_array(name, value, parse_string)?
                            .map(DhcpOptionTypeValue::DomainList)
                    }
                    Some(DhcpOptionType::Unknown) => {
                        return Err(Error::InvalidConfig(format!(
                            "Option {} not supported",
                            name
                        )))
                    }
                    None => {
                        return Err(Error::InvalidConfig(format!(
                            "Missing type information for {}",
                            name
                        )))
                    }
                },
            ))
        } else {
            Err(Error::InvalidConfig(format!("Unknown option {}", name)))
        }
    }

    fn parse_policy(fragment: &yaml::Yaml) -> Result<Policy, Error> {
        if let Some(h) = fragment.as_hash() {
            let mut policy: Policy = Default::default();
            let mut addresses: Option<Vec<std::net::Ipv4Addr>> = None;
            for (k, v) in h {
                match k.as_str() {
                    Some("match-interface") => {
                        policy.match_interface = Some(
                            parse_string(k.as_str().unwrap(), v)
                                .map_err(|x| x.annotate("Failed to parse match-interface"))?,
                        );
                    }
                    Some("match-hardware-address") => {
                        if policy.match_chaddr.is_some() {
                            return Err(Error::InvalidConfig(
                                "match-hardware-address specified twice".into(),
                            ));
                        }
                        policy.match_chaddr = parse_string_hwaddr("match-hardware-address", v)
                            .map_err(|x| x.annotate("Failed to parse match-hardware-address"))?;
                    }
                    Some("match-subnet") => {
                        if policy.match_subnet.is_some() {
                            return Err(Error::InvalidConfig(
                                "match-subnet specified twice".into(),
                            ));
                        }
                        policy.match_subnet = Some(
                            Config::parse_subnet(v)
                                .map_err(|x| x.annotate("Failed to parse match-subnet"))?
                                .ok_or_else(|| {
                                    Error::InvalidConfig("match-subnet cannot be nil".into())
                                })?,
                        );
                    }
                    Some(x) if x.starts_with("match-") => {
                        let name = &x[6..];
                        let (opt, value) = Config::parse_generic(name, v)
                            .map_err(|e| e.annotate(&format!("Failed to parse {}", x)))?;
                        policy.match_other.insert(opt, value);
                    }
                    Some("apply-address") => {
                        let addresses = addresses.get_or_insert_with(Vec::new);
                        addresses.push(
                            parse_string_ip4("apply-address", v)
                                .map_err(|x| x.annotate("Failed to parse apply-address"))?
                                .ok_or_else(|| {
                                    Error::InvalidConfig("apply-address cannot be nil".into())
                                })?,
                        );
                    }
                    Some("apply-default-lease") => {
                        policy.apply_default_lease = Some(
                            parse_duration("apply-default-lease", v)
                                .map_err(|x| x.annotate("Failed to parse apply-default-lease"))?
                                .ok_or_else(|| {
                                    Error::InvalidConfig("apply-default-lease cannot be nil".into())
                                })?,
                        );
                    }
                    Some("apply-max-lease") => {
                        policy.apply_default_lease = Some(
                            parse_duration("apply-max-lease", v)
                                .map_err(|x| x.annotate("Failed to parse apply-max-lease"))?
                                .ok_or_else(|| {
                                    Error::InvalidConfig("apply-max-lease cannot be nil".into())
                                })?,
                        );
                    }
                    Some("apply-range") => {
                        if let Some(range) = v.as_hash() {
                            let mut start: Option<std::net::Ipv4Addr> = None;
                            let mut end: Option<std::net::Ipv4Addr> = None;
                            for (rangek, rangev) in range {
                                match rangek.as_str() {
                                    Some("start") => {
                                        start = Some(
                                            parse_string_ip4("start", rangev)
                                                .map_err(|x| {
                                                    x.annotate("Failed to parse range start")
                                                })?
                                                .ok_or_else(|| {
                                                    Error::InvalidConfig(
                                                        "range start cannot be nil".into(),
                                                    )
                                                })?,
                                        )
                                    }
                                    Some("end") => {
                                        end = Some(
                                            parse_string_ip4("end", rangev)
                                                .map_err(|x| {
                                                    x.annotate("Failed to parse range end")
                                                })?
                                                .ok_or_else(|| {
                                                    Error::InvalidConfig(
                                                        "range end cannot be nil".into(),
                                                    )
                                                })?,
                                        )
                                    }
                                    Some(e) => {
                                        return Err(Error::InvalidConfig(format!(
                                            "Unexpected key in range: {}",
                                            e
                                        )))
                                    }
                                    None => {
                                        return Err(Error::InvalidConfig(format!(
                                            "range key is not a string, instead: '{:?}'",
                                            rangek
                                        )))
                                    }
                                }
                            }
                            let start = start.ok_or_else(|| {
                                Error::InvalidConfig("Missing start in range".into())
                            })?;
                            let end = end.ok_or_else(|| {
                                Error::InvalidConfig("Missing end in range".into())
                            })?;
                            let addresses = addresses.get_or_insert_with(Vec::new);
                            for i in u32::from(start)..=u32::from(end) {
                                addresses.push(i.into());
                            }
                        } else {
                            return Err(Error::InvalidConfig(format!(
                                "Range should be a hash, not '{:?}'",
                                v
                            )));
                        }
                    }
                    Some("apply-subnet") => {
                        let subnet = Config::parse_subnet(v)
                            .map_err(|x| x.annotate("Failed to parse apply-subnet"))?
                            .ok_or_else(|| {
                                Error::InvalidConfig("apply-subnet cannot be nil".into())
                            })?;
                        let base: u32 = subnet.network().into();
                        let addresses = addresses.get_or_insert_with(Vec::new);
                        for i in 1..(((1 << (32 - subnet.prefixlen)) - 1) - 1) {
                            addresses.push((base + i).into())
                        }
                    }
                    Some(x) if x.starts_with("apply-") => {
                        let name = &x[6..];
                        let (opt, value) = Config::parse_generic(name, v)
                            .map_err(|e| e.annotate(&format!("Failed to parse {}", x)))?;
                        if policy.apply_other.insert(opt, value).is_some() {
                            return Err(Error::InvalidConfig(format!(
                                "Duplicate specification of {}",
                                x
                            )));
                        }
                    }
                    Some("policies") => {
                        if !policy.policies.is_empty() {
                            return Err(Error::InvalidConfig(
                                "Can't specify policies twice in one policy".into(),
                            ));
                        }
                        policy.policies = Config::parse_policies(v)?;
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
            /* If this Policy overrides addresses, then remove any addresses that are reserved for
             * sub policies */
            if let Some(mut addrvec) = addresses {
                let mut addrset: std::collections::HashSet<std::net::Ipv4Addr> = Default::default();
                addrset.extend(addrvec.drain(..));
                for p in &policy.policies {
                    addrset = addrset.sub(&p.get_all_used_addresses());
                }
                policy.apply_address = Some(addrset);
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
                "policies should be a list of policies".into(),
            ))
        }
    }

    pub fn new(y: &yaml::Yaml) -> Result<Option<Self>, Error> {
        Ok(Some(Config {
            policies: Config::parse_policies(y)?,
        }))
    }
}
