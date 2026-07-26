/*   Copyright 2024 Perry Lorier
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
 *  mDNS / DNS-SD advertiser.
 *
 *  This announces the erbium HTTP API as a `_erbium._tcp.local` DNS-SD service
 *  so that tools like Home Assistant can discover erbium on the local network.
 *  The heavy lifting (multicast sockets, probing, conflict resolution, keeping
 *  the advertised addresses in sync with the host) is done by the mdns-sd crate.
 */

use erbium_net::addr::NetAddrExt as _;
use mdns_sd::{ServiceDaemon, ServiceInfo};

pub(crate) mod config;

/// The DNS-SD service type we advertise the API under.
const SERVICE_TYPE: &str = "_erbium._tcp.local.";

#[derive(Debug)]
pub enum Error {
    Mdns(mdns_sd::Error),
    NoApiPort,
    Disabled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Mdns(e) => write!(f, "mDNS error: {}", e),
            Error::NoApiPort => write!(
                f,
                "No TCP api-listener to advertise over mDNS, not starting advertiser"
            ),
            Error::Disabled => write!(f, "mDNS advertiser disabled by configuration"),
        }
    }
}

impl std::error::Error for Error {}

pub struct MdnsService {
    daemon: ServiceDaemon,
    instance: String,
}

/// Finds the port of the first TCP (IPv4 or IPv6) api-listener; unix-socket
/// listeners have no port and are skipped.
async fn find_api_port(conf: &crate::config::SharedConfig) -> Option<u16> {
    conf.read()
        .await
        .listeners
        .iter()
        .find_map(|addr| addr.port())
}

/// Returns the system host name reduced to a single mDNS label.
fn hostname() -> String {
    erbium_net::hostname()
        .and_then(|h| h.split('.').next().map(str::to_string))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "erbium".into())
}

impl MdnsService {
    pub async fn new(conf: crate::config::SharedConfig) -> Result<Self, Error> {
        let mdns_conf = conf.read().await.mdns.clone();
        // Default to enabled, but respect an explicit enable: false.
        if mdns_conf.enabled == Some(false) {
            return Err(Error::Disabled);
        }

        let port = find_api_port(&conf).await.ok_or(Error::NoApiPort)?;
        let host = hostname();
        let instance = mdns_conf.instance_name.unwrap_or_else(|| host.clone());

        let daemon = ServiceDaemon::new().map_err(Error::Mdns)?;

        let properties = [
            ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("path".to_string(), "/".to_string()),
        ];

        // enable_addr_auto lets the daemon fill in and keep updated the host's
        // IP addresses, so we don't have to enumerate them ourselves.  An empty
        // address list is fine here because of that.
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &format!("{}.local.", host),
            (),
            port,
            &properties[..],
        )
        .map_err(Error::Mdns)?
        .enable_addr_auto();

        daemon.register(service).map_err(Error::Mdns)?;

        Ok(MdnsService { daemon, instance })
    }

    pub async fn run(self) -> Result<(), String> {
        log::info!(
            "Advertising API over mDNS as {}.{}",
            self.instance,
            SERVICE_TYPE
        );

        // Log daemon events (announcements, address changes, conflicts) for
        // observability.  The daemon keeps running on its own thread regardless.
        let monitor = self
            .daemon
            .monitor()
            .map_err(|e| format!("failed to monitor mDNS daemon: {}", e))?;

        loop {
            match monitor.recv_async().await {
                Ok(event) => log::debug!("mDNS: {:?}", event),
                Err(e) => {
                    return Err(format!("mDNS daemon stopped: {}", e));
                }
            }
        }
    }
}

#[cfg(test)]
mod test;
