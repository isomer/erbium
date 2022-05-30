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
 *  DNS Configuration parsing.
 */

use crate::config::*;
use yaml_rust::yaml;

#[derive(Debug)]
pub enum Handler {
    Forward(Vec<std::net::SocketAddr>),
    ForgeNxDomain,
}

enum HandlerType {
    Forward,
    ForgeNxDomain,
}

#[derive(Debug)]
pub struct Route {
    pub suffixes: Vec<super::dnspkt::Domain>,
    pub dest: Handler,
}

pub fn parse_dns_route(name: &str, fragment: &yaml::Yaml) -> Result<Option<Route>, Error> {
    if let Some(h) = fragment.as_hash() {
        let mut suffixes = None;
        let mut servers = None;
        let mut handler = None;
        for (k, v) in h {
            match k.as_str() {
                Some("domain-suffixes") => {
                    suffixes = parse_array("domain-suffixes", v, parse_string)?
                }
                Some("dns-servers") => servers = parse_array("domain-servers", v, parse_string_ip)?,
                Some("type") => match parse_string("type", v)? {
                    Some(t) if t == "forward" => handler = Some(HandlerType::Forward),
                    Some(t) if t == "forge-nxdomain" => handler = Some(HandlerType::ForgeNxDomain),
                    Some(kw) => {
                        return Err(Error::InvalidConfig(format!(
                            "{} type {} not supported",
                            name, kw,
                        )))
                    }
                    None => return Err(Error::InvalidConfig(format!("{} cannot be null", name))),
                },
                Some(opt) => {
                    return Err(Error::InvalidConfig(format!(
                        "Unknown {} keyword {}",
                        name, opt
                    )))
                }
                None => {
                    return Err(Error::InvalidConfig(format!(
                        "Expected string in {}, not {:?}",
                        name, k
                    )))
                }
            }
        }
        let suffix_domains: Vec<super::dnspkt::Domain> = suffixes
            .unwrap_or_default()
            .iter()
            .map(|d| d.parse())
            .collect::<Result<_, &'static str>>()
            .map_err(|m| Error::InvalidConfig(m.into()))?;
        let servers = servers.unwrap_or_default();
        if servers.len() > 1 {
            return Err(Error::InvalidConfig(
                "Multiple DNS servers for a prefix not yet implemented.".into(), // TODO
            ));
        }
        match handler {
            Some(HandlerType::Forward) | None => {
                return Ok(Some(Route {
                    suffixes: suffix_domains,
                    dest: Handler::Forward(
                        servers
                            .iter()
                            .map(|ip| std::net::SocketAddr::new(*ip, 53))
                            .collect(),
                    ),
                }));
            }
            Some(HandlerType::ForgeNxDomain) => {
                return Ok(Some(Route {
                    suffixes: suffix_domains,
                    dest: Handler::ForgeNxDomain,
                }))
            }
        }
    }
    Ok(None)
}

pub fn parse_dns_routes(name: &str, fragment: &yaml::Yaml) -> Result<Option<Vec<Route>>, Error> {
    parse_array(name, fragment, parse_dns_route)
}

#[test]
fn test_dns_config() -> Result<(), Error> {
    use crate::config;
    config::load_config_from_string_for_test(
        "---
dns-routes:
  - domain-suffixes: ['invalid']
    type: forge-nxdomain
  - domain-suffixes: ['']
    type: forward
    dns-servers: [2001:4860:4860::8888]
",
    )?;
    Ok(())
}
