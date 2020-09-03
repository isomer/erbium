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

pub enum Error {
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O Error: {:?}", e),
        }
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
        Ok(Self {
            netinfo,
            conf,
            rawsock: std::sync::Arc::new(
                crate::net::raw::Raw6Socket::new(crate::net::raw::IpProto::ICMP6)
                    .map_err(Error::Io)?,
            ),
        })
    }

    async fn run_internal(&self) -> Result<(), Error> {
        println!("Starting Router Advertisement service");

        loop {
            let rm = self
                .rawsock
                .recv_msg(65536, crate::net::udp::MsgFlags::empty())
                .await
                .map_err(Error::Io)?;
            println!("Got packet: {:?}", rm);
        }
    }

    pub async fn run(&self) -> Result<(), String> {
        match self.run_internal().await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}
