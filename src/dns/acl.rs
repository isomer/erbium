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
 *  ACL processing for incoming DNS packets.
 */

use super::dnspkt;
use super::router;
use crate::acl;
use crate::config;

use super::DnsMessage;
use super::Error;

pub(super) struct DnsAclHandler {
    config: config::SharedConfig,
    next: router::DnsRouteHandler,
}

impl DnsAclHandler {
    pub async fn new(config: config::SharedConfig) -> Self {
        Self {
            config: config.clone(),
            next: router::DnsRouteHandler::new(config).await,
        }
    }

    pub async fn handle_query(&self, msg: &DnsMessage) -> Result<dnspkt::DNSPkt, Error> {
        acl::require_permission(
            &self.config.read().await.acls,
            &acl::Attributes {
                addr: msg.remote_addr.into(),
            },
            acl::PermissionType::DnsRecursion,
        )
        .map_err(Error::RefusedByAcl)?;
        if msg.in_query.question.qtype == dnspkt::RR_ANY {
            return Err(Error::Denied("ANY queries are not allowed".into()));
        } else if msg.remote_addr.port() == 53 {
            return Err(Error::Denied("Invalid Source Port".into()));
        }
        self.next.handle_query(msg).await
    }
}
