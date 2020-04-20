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
            qtype: q.qtype.clone(),
        };
        if q.qclass == dnspkt::CLASS_IN {
            match self.cache.read().await.get(&ck) {
                Some(entry) => {
                    let now = Instant::now();
                    if entry.birth + entry.lifetime > now {
                        return Ok(entry
                            .reply
                            .clone_with_ttl_decrement((now - entry.birth).as_secs() as u32));
                    }
                }
                _ => (),
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
