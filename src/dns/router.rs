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
 *  Deciders how to route queries.
 *  This should be where decisions about which nameservers to forward to, or if to respond locally
 *  etc are taken.
 */

use super::dnspkt;
use super::Error;

pub struct DnsRouteHandler {
    next: super::cache::CacheHandler,
}

impl DnsRouteHandler {
    pub async fn new() -> Self {
        DnsRouteHandler {
            next: super::cache::CacheHandler::new().await,
        }
    }

    pub async fn handle_query(&self, msg: &super::DnsMessage) -> Result<dnspkt::DNSPkt, Error> {
        /* This is a stub, currently we just route all queries to 8.8.8.8 */
        if !msg.in_query.rd {
            Err(Error::NotAuthoritative)
        } else {
            self.next.handle_query(msg).await
        }
    }
}
