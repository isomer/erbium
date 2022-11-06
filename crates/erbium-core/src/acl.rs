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
 *  ACL configuration
 *
 *  ACL checks undergo two phases, the first phase checks if you are "authenticated", which means
 *  "does this client match _any_ of the rules." If you do not match _any_ acl rules you are denied
 *  with a NotAuthenticated error.
 *
 *  The second phase is checking if the _first_ rule you matched contains the permission the client
 *  is being checked against.  If the client does not have this permission then they get a
 *  NotAuthorised error, if they do have this permission then they are permitted.
 */

use crate::config::*;
use erbium_net::addr::{NetAddr, NetAddrExt as _, WithPort as _, UNSPECIFIED6};
use yaml_rust::yaml;

#[derive(Debug)]
pub struct Permission {
    pub allow_dns_recursion: bool,
    pub allow_http: bool,
    pub allow_http_metrics: bool,
    pub allow_http_leases: bool,
}

pub struct Attributes {
    pub addr: NetAddr,
}

impl std::fmt::Display for Attributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

// We implement Default so that when people define an Attributes, they can ..default() all the
// parameters they don't care about.
impl Default for Attributes {
    fn default() -> Self {
        Self {
            addr: UNSPECIFIED6.with_port(0),
        }
    }
}

#[derive(Debug)]
pub struct Acl {
    pub subnet: Option<Vec<Prefix>>,
    pub unix: Option<bool>,
    pub permission: Permission,
}

fn check_subnet(attr: &Attributes, prefix: &Prefix) -> bool {
    match attr.addr.ip() {
        Some(sockaddr) => prefix.contains(sockaddr),
        _ => false,
    }
}

impl Acl {
    fn check(&self, attr: &Attributes) -> Option<&'_ Permission> {
        let mut ok = true;
        /* Check that the addr is contained within any of the subnets */
        ok = ok
            && self
                .subnet
                .as_ref()
                .map(|ss| ss.iter().any(|s| check_subnet(attr, s)))
                .unwrap_or(true);
        /* Check that the addr is unix */
        if let Some(unix) = self.unix {
            use erbium_net::addr::NetAddrExt as _;
            ok = ok && attr.addr.to_unix_addr().is_some() == unix;
        }

        if ok {
            Some(&self.permission)
        } else {
            None
        }
    }
}

pub enum PermissionType {
    DnsRecursion,
    Http,
    HttpLeases,
    HttpMetrics,
}

impl std::fmt::Display for PermissionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use PermissionType::*;
        match self {
            DnsRecursion => write!(f, "DNS Recursion"),
            Http => write!(f, "HTTP"),
            HttpLeases => write!(f, "HTTP Leases"),
            HttpMetrics => write!(f, "HTTP Metrics"),
        }
    }
}

#[cfg_attr(test, derive(Debug))]
#[derive(Eq, PartialEq)]
pub enum AclError {
    NotAuthenticated,
    NotAuthorised(String),
}

impl std::fmt::Display for AclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AclError::*;
        match self {
            NotAuthenticated => write!(f, "Failed to match any ACLs"),
            NotAuthorised(perm) => write!(f, "Matched ACL does not have permission {}", perm),
        }
    }
}

/* This finds the first permission that matches, if no permissions match it returns
 * AclError::NotAuthenticated.
 */
fn check_authenticated<'v>(acl: &'v [Acl], attr: &Attributes) -> Result<&'v Permission, AclError> {
    acl.iter()
        .find_map(|a| a.check(attr))
        .ok_or(AclError::NotAuthenticated)
}

/* This checks that the client matches an ACL ("NotAuthenticated"), and that the ACL has the
 * required permission ("NotAuthorised").
 */
pub fn require_permission(
    acl: &[Acl],
    client: &Attributes,
    perm: PermissionType,
) -> Result<(), AclError> {
    fn check_permission(perm: bool, name: &str) -> Result<(), AclError> {
        if perm {
            Ok(())
        } else {
            Err(AclError::NotAuthorised(name.into()))
        }
    }
    use PermissionType::*;
    match (check_authenticated(acl, client), perm) {
        (Ok(perms), DnsRecursion) => check_permission(perms.allow_dns_recursion, "dns-recursion"),
        (Ok(perms), Http) => check_permission(perms.allow_http, "http"),
        (Ok(perms), HttpLeases) => check_permission(perms.allow_http_leases, "http-leases"),
        (Ok(perms), HttpMetrics) => check_permission(perms.allow_http_metrics, "http-metrics"),
        (Err(err), perm) => {
            log::warn!("{}: {}: {}", client, perm, err);
            Err(err)
        }
    }
}

pub fn default_acls(addresses: &[Prefix]) -> Vec<Acl> {
    vec![
        Acl {
            /* Any address we hand out by DHCP we should also accept DNS requests from */
            subnet: Some(addresses.to_vec()),
            unix: None,
            permission: Permission {
                allow_dns_recursion: true,
                allow_http_leases: true,
                allow_http_metrics: true,
                allow_http: true,
            },
        },
        Acl {
            /* Any v4/v6 localhost should also be able to accept DNS requests. */
            subnet: Some(vec![
                Prefix::V4(Prefix4 {
                    addr: "127.0.0.0".parse().unwrap(),
                    prefixlen: 8,
                }),
                Prefix::V6(Prefix6 {
                    addr: "::1".parse().unwrap(),
                    prefixlen: 128,
                }),
            ]),
            unix: None,
            permission: Permission {
                allow_dns_recursion: true,
                allow_http_leases: true,
                allow_http_metrics: true,
                allow_http: true,
            },
        },
        Acl {
            /* Allow API access over the unix domain socket */
            subnet: None,
            unix: Some(true),
            permission: Permission {
                allow_dns_recursion: false,
                allow_http_leases: true,
                allow_http_metrics: true,
                allow_http: true,
            },
        },
    ]
}

pub(crate) fn parse_acl(name: &str, fragment: &yaml::Yaml) -> Result<Option<Acl>, Error> {
    match fragment {
        yaml::Yaml::Hash(h) => {
            let mut subnet = None;
            let mut unix = None;
            let mut accesses = vec![];
            for (k, v) in h {
                match (k.as_str(), v) {
                    (Some("match-subnets"), s) => {
                        subnet = parse_array("match-subnets", s, parse_string_prefix)?;
                    }
                    (Some("match-unix"), s) => {
                        unix = parse_boolean("match-unix", s)?;
                    }
                    (Some("apply-access"), a) => {
                        accesses =
                            parse_array("apply-access", a, parse_string)?.ok_or_else(|| {
                                Error::InvalidConfig("apply-access cannot be null".into())
                            })?;
                    }
                    (Some(m), _) => {
                        return Err(Error::InvalidConfig(format!("Unknown {} key {}", name, m)))
                    }
                    (None, _) => {
                        return Err(Error::InvalidConfig(format!(
                            "{} keys are expected to be strings",
                            name
                        )))
                    }
                }
            }
            let mut allow_dns_recursion = false;
            let mut allow_http = false;
            let mut allow_http_metrics = false;
            let mut allow_http_leases = false;
            for access in accesses {
                match access.as_str() {
                    "dhcp-client" => {
                        allow_dns_recursion = true;
                    }
                    "dns-recursion" => allow_dns_recursion = true,
                    "http" => allow_http = true,
                    "http-metrics" => allow_http_metrics = true,
                    "http-leases" => allow_http_leases = true,
                    "http-ro" => {
                        allow_http = true;
                        allow_http_metrics = true;
                        allow_http_leases = true;
                    }
                    e => return Err(Error::InvalidConfig(format!("Unknown access {}", e))),
                }
            }
            Ok(Some(Acl {
                subnet,
                unix,
                permission: Permission {
                    allow_dns_recursion,
                    allow_http,
                    allow_http_metrics,
                    allow_http_leases,
                },
            }))
        }
        e => Err(Error::InvalidConfig(format!(
            "Expected hash for {}, got {}",
            name,
            type_to_name(e)
        ))),
    }
}

#[test]
fn acl_not_authenticated() {
    use erbium_net::addr::{Ipv4Addr, ToNetAddr as _, WithPort as _};
    let test_acls = vec![Acl {
        subnet: Some(vec![Prefix::V4(Prefix4 {
            addr: "192.0.2.0".parse().unwrap(),
            prefixlen: 24,
        })]),
        unix: None,
        permission: Permission {
            allow_dns_recursion: true,
            allow_http: false,
            allow_http_leases: false,
            allow_http_metrics: false,
        },
    }];

    let ip = "192.168.0.1".parse::<Ipv4Addr>().unwrap().with_port(0);

    let client = Attributes {
        addr: ip.to_net_addr(),
    };

    assert_eq!(
        require_permission(&test_acls, &client, PermissionType::DnsRecursion)
            .expect_err("Unexpected succeeded")
            .to_string(),
        "Failed to match any ACLs"
    );
}

#[test]
fn acl_not_authorized() {
    use erbium_net::addr::{Ipv4Addr, ToNetAddr as _, WithPort as _};
    let test_acls = vec![Acl {
        subnet: Some(vec![Prefix::V4(Prefix4 {
            addr: "192.0.2.0".parse().unwrap(),
            prefixlen: 24,
        })]),
        unix: None,
        permission: Permission {
            allow_dns_recursion: false,
            allow_http: false,
            allow_http_leases: false,
            allow_http_metrics: false,
        },
    }];

    let ip = "192.0.2.1".parse::<Ipv4Addr>().unwrap().with_port(0);

    let client = Attributes {
        addr: ip.to_net_addr(),
    };

    assert_eq!(
        require_permission(&test_acls, &client, PermissionType::DnsRecursion)
            .expect_err("Unexpected success")
            .to_string(),
        "Matched ACL does not have permission dns-recursion"
    );
}

#[test]
fn acl_allowed() {
    use erbium_net::addr::{Ipv4Addr, ToNetAddr as _, WithPort as _};
    let test_acls = vec![Acl {
        subnet: Some(vec![Prefix::V4(Prefix4 {
            addr: "192.0.2.0".parse().unwrap(),
            prefixlen: 24,
        })]),
        unix: None,
        permission: Permission {
            allow_dns_recursion: true,
            allow_http: false,
            allow_http_leases: false,
            allow_http_metrics: false,
        },
    }];

    let ip = "192.0.2.1".parse::<Ipv4Addr>().unwrap().with_port(0);

    let client = Attributes {
        addr: ip.to_net_addr(),
    };

    assert_eq!(
        require_permission(&test_acls, &client, PermissionType::DnsRecursion),
        Ok(())
    );
}

#[test]
fn acl_parse() {
    load_config_from_string_for_test(
        "---
      acls:
       - match-subnets: [192.0.2.0/24]
         apply-access: ['dns-recursion']
    ",
    )
    .expect("Failed to parse ACL configuration");
}

#[test]
fn acl_parse_fail() {
    assert_eq!(
        load_config_from_string_for_test(
            "---
      acls:
       - match-subnets: [192.0.2.0/24]
         apply-access: ['not-a-permission']
    ",
        )
        .expect_err("Bad config unexpectedly successfully parsed")
        .to_string(),
        "Invalid Configuration: Unknown access not-a-permission"
    );

    assert_eq!(
        load_config_from_string_for_test(
            "---
      acls:
       - not-a-valid-key: 192.0.2.0/24
    ",
        )
        .expect_err("Bad config unexpectedly successfully parsed")
        .to_string(),
        "Invalid Configuration: Unknown acls key not-a-valid-key"
    );

    assert_eq!(
        load_config_from_string_for_test(
            "---
      acls:
       - match-subnets: [192.0.2.0/24]
         apply-access: null
    ",
        )
        .expect_err("Bad config unexpectedly successfully parsed")
        .to_string(),
        "Invalid Configuration: apply-access cannot be null"
    );
}
