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
 *  Simple DNS cache.
 *  Caching in Erbium is applied on the "out" side, not on the "in" side as might be more common.
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::dns::dnspkt;
use crate::dns::outquery;

#[derive(Eq, PartialEq, Hash)]
struct CacheKey {
    qname: dnspkt::Domain,
    qtype: dnspkt::Type,
}

struct CacheValue {
    reply: dnspkt::DNSPkt,
    birth: Instant,
    lifetime: Duration,
}

type Cache = HashMap<CacheKey, CacheValue>;

#[derive(Clone)]
pub struct CacheHandler {
    next: outquery::OutQuery,
    cache: Arc<RwLock<Cache>>,
}

impl CacheHandler {
    pub fn new() -> Self {
        CacheHandler {
            next: outquery::OutQuery::new(),
            cache: Arc::new(RwLock::new(Cache::new())),
        }
    }

    pub async fn handle_query(
        &self,
        q: &dnspkt::Question,
    ) -> Result<dnspkt::DNSPkt, std::io::Error> {
        let ck = CacheKey {
            qname: q.qdomain.clone(),
            qtype: q.qtype,
        };
        if q.qclass == dnspkt::CLASS_IN {
            if let Some(entry) = self.cache.read().await.get(&ck) {
                let now = Instant::now();
                if entry.birth + entry.lifetime > now {
                    return Ok(entry
                        .reply
                        .clone_with_ttl_decrement((now - entry.birth).as_secs() as u32));
                }
            }
        }

        let outreply = self.next.handle_query(q).await?;

        if q.qclass == dnspkt::CLASS_IN {
            self.cache.write().await.insert(
                ck,
                CacheValue {
                    reply: outreply.clone(),
                    birth: Instant::now(),
                    lifetime: outreply.get_expiry(),
                },
            );
        }

        println!("OutReply: {:?}", outreply);

        Ok(outreply)
    }
}
