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
 *  IPv6 Router Advertisement Code
 */

use rand::Rng;
use std::convert::TryInto;

pub(crate) mod config;
mod icmppkt;

#[cfg(test)]
mod test {
    mod rfc4861;
}

// RFC4861 Section 6.2.1
const DEFAULT_MAX_RTR_ADV_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
const DEFAULT_MIN_RTR_ADV_INTERVAL: std::time::Duration =
    std::time::Duration::from_micros((DEFAULT_MAX_RTR_ADV_INTERVAL.as_micros() / 3) as u64);

const ALL_NODES: std::net::Ipv6Addr = std::net::Ipv6Addr::new(
    0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
);
// Ipv6Addr::new() isn't const (at 0.18)
const ALL_ROUTERS: nix::sys::socket::Ipv6Addr = nix::sys::socket::Ipv6Addr(nix::libc::in6_addr {
    s6_addr: [
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ],
});

pub enum Error {
    Io(std::io::Error),
    Message(String),
    UnconfiguredInterface(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O Error: {:?}", e),
            Error::Message(e) => write!(f, "{}", e),
            Error::UnconfiguredInterface(int) => write!(
                f,
                "No router advertisement configuration for interface {}, ignoring.",
                int
            ),
        }
    }
}

/* An uninhabitable type to be clear that this cannot happen */
enum Void {}

impl std::fmt::Debug for Void {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result {
        unreachable!()
    }
}

pub struct RaAdvService {
    netinfo: crate::net::netinfo::SharedNetInfo,
    conf: crate::config::SharedConfig,
    rawsock: std::sync::Arc<crate::net::raw::Raw6Socket>,
}

impl RaAdvService {
    pub fn new(
        netinfo: crate::net::netinfo::SharedNetInfo,
        conf: super::config::SharedConfig,
    ) -> Result<Self, Error> {
        let rawsock = std::sync::Arc::new(
            crate::net::raw::Raw6Socket::new(crate::net::raw::IpProto::ICMP6).map_err(Error::Io)?,
        );

        rawsock
            .set_socket_option(crate::net::Ipv6RecvPacketInfo, &true)
            .map_err(Error::Io)?;
        //TODO
        //rawsock
        //    .set_socket_option(crate::net::Ipv6UnicastHops, &255)
        //    .map_err(Error::Io)?;
        use std::os::unix::io::AsRawFd;
        crate::net::socket::set_ipv6_unicast_hoplimit(rawsock.as_raw_fd(), 255)
            .map_err(crate::net::socket::nix_to_io_error)
            .map_err(Error::Io)?;
        //rawsock
        //    .set_socket_option(crate::net::Ipv6MulticastHops, &255)
        //    .map_err(Error::Io)?;
        crate::net::socket::set_ipv6_multicast_hoplimit(rawsock.as_raw_fd(), 255)
            .map_err(crate::net::socket::nix_to_io_error)
            .map_err(Error::Io)?;
        //rawsock
        //    .set_socket_option(crate::net::Ipv6RecvHopLimit, &true)
        //    .map_err(Error::Io)?;
        //rawsock
        //    .set_socket_option(crate::net::Ipv6ImcpFilter, ...)?;
        //    .map_err(Error::Io)?;
        rawsock
            .set_socket_option(
                crate::net::Ipv6AddMembership,
                &nix::sys::socket::Ipv6MembershipRequest::new(ALL_ROUTERS),
            )
            .map_err(Error::Io)?;

        Ok(Self {
            netinfo,
            conf,
            rawsock,
        })
    }

    fn build_announcement_pure(
        config: &crate::config::Config,
        intf: &config::Interface,
        ll: Option<[u8; 6]>, /* TODO: This only works for ethernet */
        mtu: Option<u32>,
    ) -> icmppkt::RtrAdvertisement {
        let mut options = icmppkt::NDOptions::default();
        /* Add the LL address of the interface, if it exists. */
        if let Some(lladdr) = ll {
            options.add_option(icmppkt::NDOptionValue::SourceLLAddr(lladdr.to_vec()));
        }

        if let Some(mtu) = mtu {
            options.add_option(icmppkt::NDOptionValue::MTU(mtu));
        }

        for prefix in &intf.prefixes {
            options.add_option(icmppkt::NDOptionValue::Prefix(icmppkt::AdvPrefix {
                prefixlen: prefix.prefixlen,
                onlink: prefix.onlink,
                autonomous: prefix.autonomous,
                valid: prefix.valid,
                preferred: prefix.preferred,
                prefix: prefix.addr,
            }));
        }

        if let Some(v) = &intf.rdnss.unwrap_or(
            config
                .dns_servers
                .iter()
                .filter_map(|ip| {
                    if let std::net::IpAddr::V6(v6) = ip {
                        Some(v6)
                    } else {
                        None
                    }
                })
                .copied()
                .collect(),
        ) {
            options.add_option(icmppkt::NDOptionValue::RDNSS((
                intf.rdnss_lifetime.always_unwrap_or(intf.lifetime),
                v.clone(),
            )))
        }

        if let Some(v) = &intf.dnssl.unwrap_or(config.dns_search.clone()) {
            options.add_option(icmppkt::NDOptionValue::DNSSL((
                intf.dnssl_lifetime.always_unwrap_or(intf.lifetime),
                v.clone(),
            )))
        }

        if let Some(pref64) = &intf.pref64 {
            options.add_option(icmppkt::NDOptionValue::Pref64((
                pref64.lifetime,
                pref64.prefixlen,
                pref64.prefix,
            )))
        }

        if let Some(url) = intf
            .captive_portal
            .as_ref()
            .or(config.captive_portal.as_ref())
        {
            options.add_option(icmppkt::NDOptionValue::CaptivePortal(url.into()))
        }

        icmppkt::RtrAdvertisement {
            hop_limit: intf.hoplimit,
            flag_managed: intf.managed,
            flag_other: intf.other,
            lifetime: intf.lifetime,
            reachable: intf.reachable,
            retrans: intf.retrans,
            options,
        }
    }

    async fn build_announcement(
        &self,
        ifidx: u32,
        intf: &config::Interface,
    ) -> icmppkt::RtrAdvertisement {
        /* Add the LL address of the interface, if it exists. */
        let ll = match self.netinfo.get_linkaddr_by_ifidx(ifidx).await {
            Some(crate::net::netinfo::LinkLayer::Ethernet(lladdr)) => Some(lladdr),
            _ => None,
        };

        /* Let them know the MTU of the interface */
        /* We use the value from the config, but if they don't specify one, we just read the MTU
         * from the interface and use that.  If they don't want erbium to specify one, then they
         * can set the value to "null" in the config.
         */
        use config::ConfigValue::*;
        let mtu = match intf.mtu {
            NotSpecified => self.netinfo.get_mtu_by_ifidx(ifidx).await,
            Value(v) => Some(v),
            DontSet => None,
        };

        Self::build_announcement_pure(&*self.conf.read().await, intf, ll, mtu)
    }

    async fn build_announcement_by_ifidx(
        &self,
        ifidx: u32,
    ) -> Result<icmppkt::RtrAdvertisement, Error> {
        let ifname = self.netinfo.get_safe_name_by_ifidx(ifidx).await;
        if let Some(intf) = self
            .conf
            .read()
            .await
            .ra
            .interfaces
            .iter()
            .find(|intf| intf.name == ifname)
        {
            Ok(self.build_announcement(ifidx, &intf).await)
        } else if let Some(prefixes) = self.netinfo.get_prefixes_by_ifidx(ifidx).await {
            let addresses = &self.conf.read().await.addresses;
            let prefixes = prefixes
                .iter()
                .filter_map(|(addr, prefixlen)| {
                    if let std::net::IpAddr::V6(ip6) = addr {
                        if addresses.contains(&crate::config::Prefix::new(*addr, *prefixlen)) {
                            Some(config::Prefix {
                                addr: *ip6,
                                prefixlen: *prefixlen,
                                onlink: true,
                                autonomous: true,
                                valid: std::time::Duration::from_secs(2592000),
                                preferred: std::time::Duration::from_secs(604800),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect::<Vec<config::Prefix>>();
            if prefixes.is_empty() {
                Err(Error::UnconfiguredInterface(ifname))
            } else {
                let intf = config::Interface {
                    // TODO: should we fill in the interface name correctly here?
                    prefixes: prefixes,
                    ..Default::default()
                };
                Ok(self.build_announcement(ifidx, &intf).await)
            }
        } else {
            Err(Error::UnconfiguredInterface(ifname))
        }
    }

    async fn send_announcement(
        &self,
        msg: icmppkt::RtrAdvertisement,
        dst: nix::sys::socket::SockAddr,
        intf: u32,
    ) -> Result<(), Error> {
        let smsg = icmppkt::Icmp6::RtrAdvert(msg);
        let s = icmppkt::serialise(&smsg);
        use crate::net::socket;
        let cmsg = if intf != 0 {
            socket::ControlMessage::new().set_src6_intf(intf)
        } else {
            socket::ControlMessage::new()
        };
        if let Err(e) = self
            .rawsock
            .send_msg(&s, &cmsg, socket::MsgFlags::empty(), Some(&dst))
            .await
        {
            println!(
                "Failed to send router advertisement for {}(if#{}) ({}): {}",
                self.netinfo.get_safe_name_by_ifidx(intf).await,
                intf,
                dst,
                e
            );
        }
        Ok(())
    }

    async fn handle_solicit(
        &self,
        rm: crate::net::socket::RecvMsg,
        _in_opt: &icmppkt::NDOptions,
    ) -> Result<(), Error> {
        if let Some(ifidx) = rm.local_intf() {
            let reply = self
                .build_announcement_by_ifidx(ifidx.try_into().expect("Interface with ifidx"))
                .await?;
            if let Some(dst) = rm
                .address
                .as_ref()
                .map(crate::net::socket::std_to_nix_sockaddr)
            {
                self.send_announcement(reply, dst, 0).await
            } else {
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Missing destination address",
                )))
            }
        } else {
            Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Packet missing interface information",
            )))
        }
    }

    async fn send_unsolicited(&self, ifidx: u32) -> Result<(), Error> {
        let msg = self.build_announcement_by_ifidx(ifidx).await?;
        let dst = nix::sys::socket::SockAddr::Inet(nix::sys::socket::InetAddr::from_std(
            &std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                ALL_NODES,
                crate::net::raw::IpProto::ICMP6.into(), /* port */
                0,                                      /* flowid */
                ifidx,                                  /* scope_id */
            )),
        ));

        self.send_announcement(msg, dst, ifidx).await
    }

    async fn run_unsolicited(&self) -> Result<Void, Error> {
        loop {
            /* Update the time with jitter */
            let timeout = std::time::Duration::from_secs(rand::thread_rng().gen_range(
                DEFAULT_MIN_RTR_ADV_INTERVAL.as_secs(),
                DEFAULT_MAX_RTR_ADV_INTERVAL.as_secs(),
            ));
            tokio::time::sleep(timeout).await;
            for idx in self.netinfo.get_ifindexes().await {
                if let Some(ifflags) = self.netinfo.get_flags_by_ifidx(idx).await {
                    if ifflags.has_multicast() {
                        match self.send_unsolicited(idx).await {
                            Ok(_) => (),
                            Err(Error::UnconfiguredInterface(_)) => (), // Ignore unconfigured interfaces.
                            e => e?,
                        }
                    }
                }
            }
        }
    }

    async fn run_solicited(&self) -> Result<Void, Error> {
        loop {
            let rm;
            match self
                .rawsock
                .recv_msg(65536, crate::net::raw::MsgFlags::empty())
                .await
            {
                Ok(m) => rm = m,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
            let msg = icmppkt::parse(&rm.buffer);
            match msg {
                Ok(icmppkt::Icmp6::Unknown) => (),
                Err(_) => (),
                Ok(icmppkt::Icmp6::RtrSolicit(opt)) => {
                    if let Err(e) = self.handle_solicit(rm, &opt).await {
                        println!("Failed to handle router solicitation: {}", e);
                    }
                }
                Ok(icmppkt::Icmp6::RtrAdvert(_)) => (),
            }
        }
    }

    pub async fn run(self: std::sync::Arc<Self>) -> Result<(), String> {
        use tokio::stream::StreamExt;
        println!("Starting Router Advertisement service");
        let mut services = futures::stream::FuturesUnordered::new();
        let sol_self = self.clone();
        let unsol_self = self.clone();
        let sol = async move { sol_self.run_solicited().await };
        let unsol = async move { unsol_self.run_unsolicited().await };
        services.push(tokio::spawn(sol));
        services.push(tokio::spawn(unsol));
        while !services.is_empty() {
            let ret = match services.next().await {
                None => "No router advertisement services found".into(),
                Some(Ok(Ok(v))) => format!(
                    "Router advertisement service unexpectedly exited successfully: {:?}",
                    v
                ),
                Some(Ok(Err(e))) => e.to_string(), /* If the service failed */
                Some(Err(e)) => e.to_string(),     /* If the spawn failed */
            };
            println!("Router advertisement service shutdown: {}", ret);
        }
        Err("Router advertisement service shutdown".into())
    }
}

#[test]
fn test_build_announcement() {
    let conf = crate::config::Config::default();
    let msg = RaAdvService::build_announcement_pure(
        &conf,
        &config::Interface {
            name: "eth0".into(),
            hoplimit: 64,
            managed: false,
            other: false,
            lifetime: std::time::Duration::from_secs(3600),
            reachable: std::time::Duration::from_secs(1800),
            retrans: std::time::Duration::from_secs(10),
            mtu: config::ConfigValue::NotSpecified,
            prefixes: vec![config::Prefix {
                addr: "2001:db8::".parse().unwrap(),
                prefixlen: 64,
                onlink: true,
                autonomous: true,
                valid: std::time::Duration::from_secs(3600),
                preferred: std::time::Duration::from_secs(1800),
            }],
            rdnss_lifetime: config::ConfigValue::Value(std::time::Duration::from_secs(3600)),
            rdnss: config::ConfigValue::Value(vec!["2001:db8::53".parse().unwrap()]),
            dnssl_lifetime: config::ConfigValue::Value(std::time::Duration::from_secs(3600)),
            dnssl: config::ConfigValue::Value(vec![]),
            captive_portal: config::ConfigValue::Value("http://example.com/".into()),
            pref64: Some(config::Pref64 {
                lifetime: std::time::Duration::from_secs(600),
                prefix: "64:ff9b::".parse().unwrap(),
                prefixlen: 96,
            }),
        },
        Some([1, 2, 3, 4, 5, 6]),
        Some(1480),
    );
    icmppkt::serialise(&icmppkt::Icmp6::RtrAdvert(msg));
}

#[test]
fn test_default_values() {
    let conf = crate::config::Config {
        dns_servers: vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ],
        dns_search: vec!["example.com".into()],
        captive_portal: Some("example.com".into()),
        ..Default::default()
    };
    let msg = RaAdvService::build_announcement_pure(
        &conf,
        &config::Interface {
            dnssl: config::ConfigValue::NotSpecified,
            rdnss: config::ConfigValue::NotSpecified,
            captive_portal: config::ConfigValue::NotSpecified,
            ..Default::default()
        },
        Some([1, 2, 3, 4, 5, 6]),
        Some(1480),
    );
    assert_eq!(
        msg.options
            .find_option(icmppkt::RDNSS)
            .iter()
            .map(|x| if let icmppkt::NDOptionValue::RDNSS((_, servers)) = x {
                servers
            } else {
                panic!("bad")
            })
            .cloned()
            .collect::<Vec<Vec<_>>>(),
        vec![vec!["2001:db8::53".parse::<std::net::Ipv6Addr>().unwrap()]]
    );
    assert_eq!(
        msg.options
            .find_option(icmppkt::DNSSL)
            .iter()
            .map(|x| if let icmppkt::NDOptionValue::DNSSL((_, domains)) = x {
                domains
            } else {
                panic!("bad")
            })
            .cloned()
            .collect::<Vec<Vec<_>>>(),
        vec![vec![String::from("example.com")]]
    );
    assert_eq!(
        msg.options
            .find_option(icmppkt::CAPTIVE_PORTAL)
            .iter()
            .map(
                |x| if let icmppkt::NDOptionValue::CaptivePortal(domain) = x {
                    domain
                } else {
                    panic!("bad")
                }
            )
            .cloned()
            .collect::<Vec<_>>(),
        vec![String::from("example.com")]
    );
}

#[test]
fn test_dontset_values() {
    let conf = crate::config::Config {
        dns_servers: vec![
            "192.0.2.53".parse().unwrap(),
            "2001:db8::53".parse().unwrap(),
        ],
        dns_search: vec!["example.com".into()],
        captive_portal: Some("example.com".into()),
        ..Default::default()
    };
    let msg = RaAdvService::build_announcement_pure(
        &conf,
        &config::Interface {
            dnssl: config::ConfigValue::DontSet,
            rdnss: config::ConfigValue::DontSet,
            captive_portal: config::ConfigValue::DontSet,
            ..Default::default()
        },
        Some([1, 2, 3, 4, 5, 6]),
        Some(1480),
    );
    assert!(msg.options.find_option(icmppkt::RDNSS).is_empty());
    assert!(msg.options.find_option(icmppkt::DNSSL).is_empty());
    assert!(msg.options.find_option(icmppkt::CAPTIVE_PORTAL).is_empty());
}
