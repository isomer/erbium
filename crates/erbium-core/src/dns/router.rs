/*   Copyright 2023 Perry Lorier
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
 *  Deciders how to route queries.
 *  This should be where decisions about which nameservers to forward to, or if to respond locally
 *  etc are taken.
 */

use super::dnspkt;
use super::Error;

pub struct DnsRouteHandler {
    conf: crate::config::SharedConfig,
    next: super::cache::CacheHandler,
}

impl DnsRouteHandler {
    pub async fn new(conf: crate::config::SharedConfig) -> Self {
        DnsRouteHandler {
            conf,
            next: super::cache::CacheHandler::new().await,
        }
    }

    pub async fn handle_query(&self, msg: &super::DnsMessage) -> Result<dnspkt::DNSPkt, Error> {
        let conf = self.conf.clone();
        let locked_conf = conf.read().await;

        let mut best_route = None;
        let mut best_suffix: Option<&super::dnspkt::Domain> = None;
        for route in 0..locked_conf.dns_routes.len() {
            for suffix in &locked_conf.dns_routes[route].suffixes {
                if msg.in_query.question.qdomain.ends_with(suffix) {
                    if let Some(ref best) = best_suffix {
                        log::trace!("Comparing {} with {}", best, suffix);
                        if super::dnspkt::compare_longest_suffix(best, suffix)
                            == std::cmp::Ordering::Greater
                        {
                            best_route = Some(route);
                            best_suffix = Some(suffix);
                        }
                    } else {
                        best_route = Some(route);
                        best_suffix = Some(suffix);
                    }
                }
            }
        }

        if let Some(route_num) = best_route {
            let route = &locked_conf.dns_routes[route_num];
            log::trace!(
                "[{:x}] \"{}\" is the best route",
                msg.in_query.qid,
                best_suffix.unwrap()
            );
            use super::config::Handler;
            match route.dest {
                Handler::Forward(ref dest) => {
                    if !msg.in_query.rd {
                        // We will only forward queries when requested to do so.
                        Err(Error::NotAuthoritative)
                    } else {
                        self.next.handle_query(msg, dest[0]).await
                    }
                }
                Handler::ForgeNxDomain => Err(Error::Blocked),
            }
        } else {
            Err(Error::NoRouteConfigured)
        }
    }
}
