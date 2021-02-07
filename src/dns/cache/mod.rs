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

use super::Error;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

use crate::dns::dnspkt;
use crate::dns::outquery;

#[cfg(test)]
mod test;

lazy_static::lazy_static! {
    static ref DNS_CACHE: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_cache",
            "Cache statistics",
            &["result"])
            .unwrap();

    static ref DNS_CACHE_SIZE: prometheus::IntGauge =
        prometheus::register_int_gauge!("dns_cache_size",
            "Number of entries in the cache")
        .unwrap();
}

#[derive(Eq, PartialEq, Hash)]
#[cfg_attr(test, derive(Clone))]
struct CacheKey {
    qname: dnspkt::Domain,
    qtype: dnspkt::Type,
}

struct CacheValue {
    reply: Result<dnspkt::DNSPkt, Error>,
    birth: Instant,
    lifetime: Duration,
}

impl CacheValue {
    fn expiry(&self) -> Instant {
        self.birth + self.lifetime
    }
}

type Cache = HashMap<CacheKey, CacheValue>;

#[derive(Clone)]
pub struct CacheHandler {
    next: outquery::OutQuery,
    cache: Arc<RwLock<Cache>>,
}

/* std::io::Error is not clonable (for good reason), but we want to clone it.
 * So instead, we do some mappings to remove the std::io::Error
 */
fn clone_out_reply(reply: &Result<dnspkt::DNSPkt, Error>) -> Result<dnspkt::DNSPkt, Error> {
    use outquery::Error as OutReplyError;
    use Error::*;
    match reply {
        Ok(out_reply) => Ok(out_reply.clone()),
        Err(NotAuthoritative) => Err(NotAuthoritative),
        Err(OutReply(OutReplyError::Timeout)) => Err(OutReply(OutReplyError::Timeout)),
        Err(OutReply(OutReplyError::FailedToSend(io))) => {
            Err(OutReply(OutReplyError::FailedToSendMsg(format!("{}", io))))
        }
        Err(OutReply(OutReplyError::FailedToSendMsg(msg))) => {
            Err(OutReply(OutReplyError::FailedToSendMsg(msg.clone())))
        }
        Err(OutReply(OutReplyError::FailedToRecv(io))) => {
            Err(OutReply(OutReplyError::FailedToRecvMsg(format!("{}", io))))
        }
        Err(OutReply(OutReplyError::FailedToRecvMsg(msg))) => {
            Err(OutReply(OutReplyError::FailedToRecvMsg(msg.clone())))
        }
        Err(OutReply(OutReplyError::TcpConnectionError(msg))) => {
            Err(OutReply(OutReplyError::TcpConnectionError(msg.clone())))
        }
        Err(OutReply(OutReplyError::ParseError(msg))) => {
            Err(OutReply(OutReplyError::ParseError(msg.clone())))
        }
        Err(OutReply(OutReplyError::InternalError(msg))) => {
            Err(OutReply(OutReplyError::InternalError(msg.clone())))
        }
        /* These errors cannot occur */
        Err(ListenError(_)) => unreachable!(),
        Err(RecvError(_)) => unreachable!(),
        Err(ParseError(_)) => unreachable!(),
        Err(RefusedByAcl(_)) => unreachable!(),
    }
}

/* std::io::Error is not clonable (for good reason), but we want to clone it.
 * So instead, we do some mappings to remove the std::io::Error
 */
fn clone_with_ttl_decrement_out_reply(
    reply: &Result<dnspkt::DNSPkt, Error>,
    decrement: std::time::Duration,
) -> Result<dnspkt::DNSPkt, Error> {
    match reply {
        Ok(out_reply) => Ok(out_reply.clone_with_ttl_decrement(decrement.as_secs() as u32)),
        err => clone_out_reply(err),
    }
}

impl CacheHandler {
    pub async fn new() -> Self {
        let cache = Arc::new(RwLock::new(Cache::new()));
        let cache_copy = cache.clone();
        tokio::spawn(async move {
            Self::expire_thread(cache_copy).await;
        });
        CacheHandler {
            next: outquery::OutQuery::new(),
            cache,
        }
    }

    /* Expires entries, returns the time for the next expiration run. */
    fn expire(cache: &mut Cache, now: Instant) -> Instant {
        use std::convert::TryInto as _;

        /* We don't have any notification from the resolvers if this time needs to go down.
         * So if we get a spike of resolutions we might have to start doing expiries, so poll
         * at least every this time.
         */
        let mut next_cycle = now + Duration::from_secs(1800);
        cache.retain(|_k, v| {
            if v.expiry() >= now {
                next_cycle = std::cmp::min(next_cycle, v.expiry());
                true
            } else {
                false
            }
        });

        /* Update the new cache size. */
        DNS_CACHE_SIZE.set(cache.len().try_into().unwrap_or(i64::MAX));

        /* Don't waste cpu cycling too often.  If we have a lot of entries expiring at about
         * the same time, cap this to poll a bit more infrequently, it's more efficient to do
         * one run that collects multiple entries.
         * Again, we don't need to be too precise.
         */
        std::cmp::max(next_cycle, Instant::now() + Duration::from_secs(30))
    }

    async fn expire_thread(cache: Arc<RwLock<Cache>>) {
        loop {
            let next_cycle;

            /* Expire all the old entries */
            {
                let mut rwcache = cache.write().await;
                next_cycle = Self::expire(&mut rwcache, Instant::now());
            }

            /* Now wait until then. */
            log::trace!(
                "Next cache expiry in {} seconds",
                (next_cycle - Instant::now()).as_secs(),
            );
            tokio::time::sleep_until(next_cycle.into()).await;
        }
    }

    fn get_entry(
        cache: &Cache,
        ck: &CacheKey,
        now: Instant,
    ) -> Option<Result<dnspkt::DNSPkt, Error>> {
        /* Check to see if we have a cache hit that is still valid, if so, return it */
        if let Some(entry) = cache.get(&ck) {
            if entry.expiry() >= now {
                let remaining = (entry.birth + entry.lifetime) - now;
                log::trace!("Cache hit ({:?} remaining)", remaining);
                DNS_CACHE.with_label_values(&[&"HIT"]).inc();
                Some(clone_with_ttl_decrement_out_reply(
                    &entry.reply,
                    now - entry.birth,
                ))
            } else {
                log::trace!("Cache miss: Cache expired");
                DNS_CACHE.with_label_values(&[&"EXPIRED"]).inc();
                None
            }
        } else {
            log::trace!("Cache miss: Entry not present");
            DNS_CACHE.with_label_values(&[&"MISS"]).inc();
            None
        }
    }

    fn calculate_expiry(&self, out_result: &Result<crate::dns::dnspkt::DNSPkt, Error>) -> Duration {
        match &out_result {
            /* If we got a packet, then use the expiry from the packet. */
            Ok(out_reply) => out_reply.get_expiry(),
            /* If there was a problem sending the reply, then wait for at least as long
             * as exponential backoff would allow.
             */
            Err(Error::OutReply(outquery::Error::Timeout))
            | Err(Error::OutReply(outquery::Error::FailedToSend(_)))
            | Err(Error::OutReply(outquery::Error::FailedToRecv(_)))
            | Err(Error::OutReply(outquery::Error::TcpConnectionError(_)))
            | Err(Error::OutReply(outquery::Error::ParseError(_))) => {
                std::time::Duration::from_secs(8)
            }
            /* Otherwise do not cache the error */
            _ => std::time::Duration::from_secs(0),
        }
    }

    fn insert_cache_entry(
        &self,
        cache: &mut Cache,
        ck: CacheKey,
        out_result: &Result<dnspkt::DNSPkt, Error>,
        expiry: Duration,
    ) {
        use std::convert::TryInto as _;

        cache.insert(
            ck,
            CacheValue {
                reply: clone_out_reply(&out_result),
                birth: Instant::now(),
                lifetime: expiry,
            },
        );

        DNS_CACHE_SIZE.set(cache.len().try_into().unwrap_or(i64::MAX));
    }

    pub async fn handle_query(&self, msg: &super::DnsMessage) -> Result<dnspkt::DNSPkt, Error> {
        let q = &msg.in_query.question;
        /* Only do caching for IN queries */
        if q.qclass != dnspkt::CLASS_IN {
            log::trace!("Not caching non-IN query");
            DNS_CACHE.with_label_values(&[&"UNCACHABLE_CLASS"]).inc();
            return self.next.handle_query(msg).await;
        }

        let ck = CacheKey {
            qname: q.qdomain.clone(),
            qtype: q.qtype,
        };

        {
            let rocache = self.cache.read().await;
            if let Some(result) = Self::get_entry(&rocache, &ck, Instant::now()) {
                return result;
            }
        }

        /* Cache miss: Go attempt the resolve, and return the result */
        let out_result = self.next.handle_query(msg).await;

        let expiry = self.calculate_expiry(&out_result);

        /* Only insert into the cache if the duration is reasonable */
        if expiry > Duration::from_secs(0) {
            let mut rwcache = self.cache.write().await;
            self.insert_cache_entry(&mut rwcache, ck, &out_result, expiry);
        }

        match &out_result {
            Ok(x) => log::trace!("OutReply: {:?}", x),
            Err(e) => log::trace!("OutReply: {}", e),
        };

        out_result
    }
}
