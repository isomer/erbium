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
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::dns::dnspkt;
use crate::dns::outquery;

lazy_static::lazy_static! {
    static ref DNS_CACHE: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_cache",
            "Cache statistics",
            &["result"])
            .unwrap();
}

#[derive(Eq, PartialEq, Hash)]
struct CacheKey {
    qname: dnspkt::Domain,
    qtype: dnspkt::Type,
}

struct CacheValue {
    reply: Result<dnspkt::DNSPkt, Error>,
    birth: Instant,
    lifetime: Duration,
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
    pub fn new() -> Self {
        CacheHandler {
            next: outquery::OutQuery::new(),
            cache: Arc::new(RwLock::new(Cache::new())),
        }
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

        /* Check to see if we have a cache hit that is still valid, if so, return it */
        if let Some(entry) = self.cache.read().await.get(&ck) {
            let now = Instant::now();
            if entry.birth + entry.lifetime > now {
                let remaining = (entry.birth + entry.lifetime) - now;
                log::trace!("Cache hit ({:?} remaining)", remaining);
                DNS_CACHE.with_label_values(&[&"HIT"]).inc();
                return clone_with_ttl_decrement_out_reply(&entry.reply, now - entry.birth);
            } else {
                log::trace!("Cache miss: Cache expired");
                DNS_CACHE.with_label_values(&[&"EXPIRED"]).inc();
            }
        } else {
            log::trace!("Cache miss: Entry not present");
            DNS_CACHE.with_label_values(&[&"MISS"]).inc();
        }

        /* Cache miss: Go attempt the resolve, and return the result */
        let out_result = self.next.handle_query(msg).await;

        let expiry = match &out_result {
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
            /* Otherwise propagate the error, and do not cache it */
            e => return clone_out_reply(e),
        };

        self.cache.write().await.insert(
            ck,
            CacheValue {
                reply: clone_out_reply(&out_result),
                birth: Instant::now(),
                lifetime: expiry,
            },
        );

        match &out_result {
            Ok(x) => log::trace!("OutReply: {:?}", x),
            Err(e) => log::trace!("OutReply: {}", e),
        };

        out_result
    }
}
