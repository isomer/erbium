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
 *  Tests for caching.
 */

use super::*;
use crate::dns::dnspkt::*;

#[tokio::test]
async fn test_expiry() {
    let handler = CacheHandler {
        next: outquery::OutQuery::new(),
        cache: Arc::new(RwLock::new(Cache::new())),
    };

    let example_net: dnspkt::Domain = "example.net".parse().unwrap();

    let ck = CacheKey {
        qname: example_net.clone(),
        qtype: RR_A,
    };

    let mut now = Instant::now();

    /* First verify the entry doesn't exist in an empty cache */
    {
        let rocache = handler.cache.read().await;
        assert!(CacheHandler::get_entry(&rocache, &ck, now).is_none());
    }

    let out_result = Ok(dnspkt::DNSPkt {
        qid: 1,
        rd: true,
        tc: false,
        aa: false,
        qr: true,
        opcode: dnspkt::OPCODE_QUERY,
        cd: false,
        ad: false,
        ra: false,
        rcode: dnspkt::NOERROR,
        bufsize: 512,
        edns_ver: Some(0),
        edns_do: false,
        question: dnspkt::Question {
            qdomain: example_net.clone(),
            qtype: RR_A,
            qclass: CLASS_IN,
        },
        answer: vec![dnspkt::RR {
            domain: example_net.clone(),
            class: CLASS_IN,
            rrtype: RR_A,
            ttl: 600,
            rdata: dnspkt::RData::Other(vec![192, 0, 2, 1]),
        }],
        nameserver: vec![],
        additional: vec![],
        edns: None,
    });

    let expiry = handler.calculate_expiry(&out_result);
    assert_eq!(expiry, Duration::from_secs(600));

    /* Insert an entry */
    {
        let mut rwcache = handler.cache.write().await;
        handler.insert_cache_entry(&mut rwcache, ck.clone(), &out_result, expiry);
        assert_eq!(rwcache.len(), 1);
    }

    /* Now test that it comes back 5s later */
    now += Duration::from_secs(5);
    {
        let rocache = handler.cache.read().await;
        assert!(CacheHandler::get_entry(&rocache, &ck, now).is_some());
    }

    /* Now run a GC after 60s and check the entry isn't removed */
    now += Duration::from_secs(60);
    {
        let mut rwcache = handler.cache.write().await;
        let next = CacheHandler::expire(&mut rwcache, now);
        assert_eq!(rwcache.len(), 1);
        assert!(CacheHandler::get_entry(&rwcache, &ck, now).is_some());
        assert!(next < now + Duration::from_secs(1800)); // We have an entry that is newer than that.
        assert!(next > now + Duration::from_secs(30)); // But not too frequently!
    }

    /* Test that it is expired after 15 minutes */
    now += Duration::from_secs(900);
    {
        let rocache = handler.cache.read().await;
        assert!(CacheHandler::get_entry(&rocache, &ck, now).is_none());
    }

    /* Test that after an hour, the expiry garbage collection removes the entry */
    now += Duration::from_secs(3600);
    {
        let mut rwcache = handler.cache.write().await;
        let next = CacheHandler::expire(&mut rwcache, now);
        assert!(CacheHandler::get_entry(&rwcache, &ck, now).is_none());
        assert_eq!(rwcache.len(), 0);
        assert!(next >= now + Duration::from_secs(1800)); // There are no entries left, so re-run infrequently.
    }
}
