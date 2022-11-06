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
 *  Infrastructure for DNS services.
 */
use erbium_net::addr::NetAddr;
use erbium_net::udp;

type UdpSocket = udp::UdpSocket;

extern crate crypto;
extern crate nix;
extern crate rand;

mod acl;
mod bucket;
mod cache;
pub(crate) mod config;
pub mod dnspkt;
mod outquery;
#[cfg(fuzzing)]
pub mod parse;
#[cfg(not(fuzzing))]
mod parse;
mod router;

use bytes::BytesMut;
use tokio_util::codec::Decoder;

type Key = [u8; 8];

struct CookieKeys {
    next_refresh: tokio::time::Instant,
    current: Key,
    previous: Key,
}

impl CookieKeys {
    fn new() -> Self {
        use rand::distributions::Distribution as _;
        use rand::Rng as _;
        use tokio::time::{Duration, Instant};
        let mut rng = rand::rngs::OsRng::default();
        Self {
            next_refresh: Instant::now()
                + rand::distributions::Uniform::new(
                    Duration::from_secs(86400 / 2),
                    Duration::from_secs(86400 + 86400 / 2),
                )
                .sample(&mut rng),
            current: rng.gen(),
            previous: rng.gen(),
        }
    }

    fn needs_rotation(&self) -> bool {
        self.next_refresh < tokio::time::Instant::now()
    }

    // Gets the current and previous cookie keys, rotating them if they've expired.
    async fn get_keys(s: &tokio::sync::RwLock<Self>) -> (Key, Key) {
        use rand::distributions::Distribution as _;
        use rand::Rng as _;
        use tokio::time::{Duration, Instant};
        if s.read().await.needs_rotation() {
            // TODO: This only does one rotation, it's possibly both keys have expired, in which
            // case we should rotate both.
            let mut cookies = s.write().await;
            let mut rng = rand::rngs::OsRng::default();
            *cookies = Self {
                next_refresh: Instant::now()
                    + rand::distributions::Uniform::new(
                        Duration::from_secs(86400 / 2),
                        Duration::from_secs(86400 + 86400 / 2),
                    )
                    .sample(&mut rng),
                current: rng.gen(),
                previous: cookies.current,
            }
        }

        let cookies = s.read().await;
        (cookies.current, cookies.previous)
    }

    async fn get_current_key(s: &tokio::sync::RwLock<Self>) -> Key {
        Self::get_keys(s).await.0
    }
}

impl Default for CookieKeys {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    static ref IN_QUERY_LATENCY: prometheus::HistogramVec =
        prometheus::register_histogram_vec!("dns_in_query_latency",
            "DNS latency for in queries",
            &["protocol"])
        .unwrap();

    /* Result is "RCode" or "RCode (EdeCode)" */
    static ref IN_QUERY_RESULT: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_in_query_result",
            "DNS response codes for in queries",
            &["protocol", "result"])
        .unwrap();

    static ref IN_QUERY_DROPPED: prometheus::IntCounter =
        prometheus::register_int_counter!("dns_in_query_dropped",
            "DNS queries dropped")
        .unwrap();

    static ref COOKIE_KEYS: tokio::sync::RwLock<CookieKeys> = Default::default();
}

#[cfg_attr(test, derive(Debug))]
pub enum Error {
    ListenError(std::io::Error, Box<erbium_net::addr::NetAddr>),
    AcceptError(std::io::Error),
    RecvError(std::io::Error),
    ParseError(String),
    RefusedByAcl(crate::acl::AclError),
    Denied(String),
    Blocked,
    NoRouteConfigured,
    NotAuthoritative,
    OutReply(outquery::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            ListenError(io, addr) => write!(f, "Failed to listen for DNS on {}: {}", addr, io),
            AcceptError(io) => write!(f, "Failed to accept new TCP connection for DNS: {}", io),
            RecvError(io) => write!(f, "Failed to receive DNS in query: {}", io),
            ParseError(msg) => write!(f, "Failed to parse DNS in query: {}", msg),
            RefusedByAcl(why) => write!(f, "Query refused by policy: {}", why),
            NotAuthoritative => write!(f, "Not Authoritative"),
            Blocked => write!(f, "Blocked by configuration"),
            NoRouteConfigured => write!(f, "No route configured"),
            Denied(msg) => write!(f, "Denied: {}", msg),
            OutReply(err) => write!(f, "{}", err),
        }
    }
}

// We want to rate limit some error codes (like REFUSED) to prevent being used in reflection
// attacks.  We don't want to keep track of a whole bunch of IP addresses tho, so we do a variation
// on a bloom filter.  We have N token buckets, we hash the IP into *two* of those buckets, and
// then we try and take some tokens from which ever has more tokens available.  If neither bucket
// has sufficient tokens available, then we fail.  This means for small amounts of fixed memory
// we can have a pretty low false positive rate.
type Bucket = tokio::sync::RwLock<bucket::GenericTokenBucket>;
struct IpRateLimiter([Bucket; 256]);

impl IpRateLimiter {
    fn new() -> Self {
        let new = Bucket::default;
        Self([
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
            new(),
        ])
    }

    fn hash_ip(seed: u64, ip: std::net::IpAddr) -> usize {
        use std::hash::Hash as _;
        use std::hash::Hasher as _;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        seed.hash(&mut hasher);
        ip.hash(&mut hasher);
        hasher.finish() as usize
    }

    async fn check(&self, ip: std::net::IpAddr, bytes: usize) -> bool {
        // TODO: Base seeds on time, rotating every 60s or something.
        // They probably should also be unique per process.
        // Maybe each seed should be staggered in time.
        const SEED1: u64 = 0x1234_5678_9ABC_DEF0;
        const SEED2: u64 = 0x2345_6789_ABCD_EF01;

        let hash1 = Self::hash_ip(SEED1, ip);
        let hash2 = Self::hash_ip(SEED2, ip);

        let bucket1 = hash1 % self.0.len();

        /* Normally a read() lock like this, when converted to a write() should be tested again,
         * however since the writes are commutative, and we're more worried about speed than exact
         * precision this should be fine.
         */
        if self.0[bucket1]
            .read()
            .await
            .check::<bucket::RealTimeClock>(bytes as u32)
        {
            self.0[bucket1]
                .write()
                .await
                .deplete::<bucket::RealTimeClock>(bytes as u32);
            true
        } else {
            let mut bucket2 = hash2 % (self.0.len() - 1);
            if bucket2 == bucket1 {
                bucket2 = self.0.len() - 1;
            }

            if self.0[bucket2]
                .read()
                .await
                .check::<bucket::RealTimeClock>(bytes as u32)
            {
                self.0[bucket2]
                    .write()
                    .await
                    .deplete::<bucket::RealTimeClock>(bytes as u32);
                true
            } else {
                false
            }
        }
    }
}

struct DnsCodec {}

impl Decoder for DnsCodec {
    type Item = dnspkt::DNSPkt;
    type Error = std::io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let in_query = parse::PktParser::new(&src[..]).get_dns();
        match in_query {
            Ok(p) => Ok(Some(p)),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        }
    }
}

pub enum Protocol {
    Udp,
    Tcp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Tcp => write!(f, "TCP"),
        }
    }
}

#[derive(Eq, PartialEq)]
enum CookieStatus {
    Missing,
    Bad,
    Good,
}

pub struct DnsMessage {
    pub in_query: dnspkt::DNSPkt,
    pub in_size: usize,
    pub local_ip: std::net::IpAddr,
    pub remote_addr: NetAddr,
    pub protocol: Protocol,
}

impl DnsMessage {
    // Calculate the value of the cookie based on a key.
    // This uses the client cookie, the source and dest ip addresses for generating the cookie.
    fn calculate_cookie(&self, client: &[u8], key: &[u8]) -> crypto::mac::MacResult {
        use crypto::mac::Mac;
        // I'm not a crypto expert, but I am to understand that Hmac is the safest way to use a
        // hash function to avoid length extension attacks.
        let mut hasher = crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), key);
        hasher.input(client);
        match self.local_ip {
            std::net::IpAddr::V4(v4) => hasher.input(&v4.octets()),
            std::net::IpAddr::V6(v6) => hasher.input(&v6.octets()),
        }
        use erbium_net::addr::NetAddrExt as _;
        match self.remote_addr.ip() {
            Some(std::net::IpAddr::V4(v4)) => hasher.input(&v4.octets()),
            Some(std::net::IpAddr::V6(v6)) => hasher.input(&v6.octets()),
            _ => unreachable!(),
        };
        hasher.result()
    }

    fn validate_cookie_key(&self, key: &[u8]) -> CookieStatus {
        if let Some((client, Some(server))) = self
            .in_query
            .edns
            .as_ref()
            .and_then(|edns| edns.get_cookie())
        {
            let myserver = self.calculate_cookie(client, key);
            if myserver == crypto::mac::MacResult::new(server) {
                CookieStatus::Good
            } else {
                CookieStatus::Bad
            }
        } else {
            CookieStatus::Missing
        }
    }

    // To support key rotation, we provide a new key, and an old key, we first
    // check if they match using the new key, if so we accept it, if not, then
    // we try again with the older key.
    fn validate_cookie_keys(&self, key: &[u8], oldkey: &[u8]) -> CookieStatus {
        match self.validate_cookie_key(key) {
            CookieStatus::Bad => self.validate_cookie_key(oldkey),
            status => status,
        }
    }

    async fn calculate_current_cookie(&self, client: &[u8]) -> crypto::mac::MacResult {
        let key = CookieKeys::get_current_key(&COOKIE_KEYS).await;
        self.calculate_cookie(client, &key)
    }

    async fn validate_cookie(&self) -> CookieStatus {
        let keys = CookieKeys::get_keys(&COOKIE_KEYS).await;
        self.validate_cookie_keys(&keys.0, &keys.1)
    }
}

struct DnsListenerHandler {
    next: acl::DnsAclHandler,
    udp_listeners: Vec<UdpSocket>,
    tcp_listeners: Vec<tokio::net::TcpListener>,
    rate_limiter: std::sync::Arc<IpRateLimiter>,
}

impl DnsListenerHandler {
    async fn listen_udp(
        _conf: &crate::config::SharedConfig,
        addr: &erbium_net::addr::NetAddr,
    ) -> Result<UdpSocket, Error> {
        let mut count: i32 = 0;
        let udp = loop {
            match UdpSocket::bind(&[*addr]).await {
                Ok(sock) => break sock,
                Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                    // Due to duplicate address detection, the IPv6 address we're binding to might
                    // still be in the "tentative" state, which prevents binding.  Retry a few
                    // times with exponential backoff to see if it will become ready.
                    //
                    // Ideally we would just not bind to it, and get a signal later from netinfo
                    // when it becomes ready and bind to it then, but that would require a massive
                    // restructuring of netinfo.
                    if count > 2 {
                        return Err(Error::ListenError(e, Box::new(*addr)));
                    }
                    log::warn!(
                        "Failed to bind DNS UDP to {} ({}): Retrying after {}s",
                        addr,
                        e,
                        1 << count
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(1 << count)).await;
                    count += 1;
                    continue;
                }
                Err(e) => return Err(Error::ListenError(e, Box::new(*addr))),
            }
        };

        if addr.as_sockaddr_in6().is_some() {
            udp.set_opt_ipv6_packet_info(true)
                .map_err(|e| Error::ListenError(e, Box::new(*addr)))?
        } else {
            udp.set_opt_ipv4_packet_info(true)
                .map_err(|e| Error::ListenError(e, Box::new(*addr)))?
        }

        log::info!(
            "Listening for DNS on UDP {}",
            udp.local_addr()
                .map(|name| format!("{}", name))
                .unwrap_or_else(|_| "Unknown".into())
        );

        Ok(udp)
    }

    async fn listen_tcp(
        _conf: &crate::config::SharedConfig,
        addr: &erbium_net::addr::NetAddr,
    ) -> Result<tokio::net::TcpListener, Error> {
        use erbium_net::addr::NetAddrExt as _;
        let tcp = tokio::net::TcpListener::bind(addr.to_std_socket_addr().ok_or_else(|| {
            Error::ListenError(std::io::ErrorKind::Unsupported.into(), Box::new(*addr))
        })?)
        .await
        .map_err(|e| Error::ListenError(e, Box::new(*addr)))?;

        log::info!(
            "Listening for DNS on TCP {}",
            tcp.local_addr()
                .map(|name| format!("{}", name))
                .unwrap_or_else(|_| "Unknown".into())
        );

        Ok(tcp)
    }

    async fn new(
        conf: crate::config::SharedConfig,
        netinfo: &erbium_net::netinfo::SharedNetInfo,
    ) -> Result<Self, Error> {
        let mut udp_listeners = vec![];
        let mut tcp_listeners = vec![];
        {
            let roconf = conf.read().await;
            for addr in &roconf
                .dns_listeners
                .as_sockaddrs(&roconf.addresses, netinfo, 53)
                .await
            {
                udp_listeners.push(Self::listen_udp(&conf, addr).await?);
                tcp_listeners.push(Self::listen_tcp(&conf, addr).await?);
            }
        }
        let rate_limiter = IpRateLimiter::new().into();

        Ok(Self {
            next: acl::DnsAclHandler::new(conf).await,
            udp_listeners,
            tcp_listeners,
            rate_limiter,
        })
    }

    async fn add_edns(edns: &mut dnspkt::EdnsData, msg: &DnsMessage) {
        // If they requested NSID, then return it.
        if msg
            .in_query
            .edns
            .as_ref()
            .map(|edns| edns.get_nsid().is_some())
            .unwrap_or(false)
        {
            // We fill in NSID with the receiving interface IP.
            // TODO: This might not be particularly interesting if this is a VIP.  We might want to
            // find some more useful information to put in here.
            edns.set_nsid(format!("{}", msg.local_ip).as_bytes());
        }

        // Handle DNS COOKIE (RFC7873)
        if let Some((client, _server)) = msg
            .in_query
            .edns
            .as_ref()
            .and_then(|edns| edns.get_cookie())
        {
            let server = msg.calculate_current_cookie(client).await;
            edns.set_cookie(client, &server.code()[..32]);
        }
    }

    async fn create_in_reply(msg: &DnsMessage, outr: &dnspkt::DNSPkt) -> dnspkt::DNSPkt {
        let mut edns: dnspkt::EdnsData = Default::default();
        Self::add_edns(&mut edns, msg).await;
        dnspkt::DNSPkt {
            qid: msg.in_query.qid,
            rd: false,
            tc: outr.tc,
            aa: outr.aa,
            qr: true,
            opcode: dnspkt::OPCODE_QUERY,

            cd: outr.cd,
            ad: outr.ad,
            ra: outr.ra,

            rcode: outr.rcode,

            bufsize: 4096,

            edns_ver: msg.in_query.edns_ver.map(|_| 0),
            edns_do: false,

            question: msg.in_query.question.clone(),
            answer: outr.answer.clone(),
            nameserver: outr.answer.clone(),
            additional: outr.additional.clone(),
            edns: Some(edns),
        }
    }

    async fn create_in_error(msg: &DnsMessage, err: Error) -> dnspkt::DNSPkt {
        use dnspkt::*;
        use Error::*;
        let mut edns: EdnsData = Default::default();
        Self::add_edns(&mut edns, msg).await;
        let rcode;
        match err {
            /* These errors mean we never get a packet to reply to. */
            ListenError(..) => unreachable!(),
            AcceptError(..) => unreachable!(),
            RecvError(_) => unreachable!(),
            ParseError(_) => unreachable!(),
            RefusedByAcl(why) => {
                rcode = REFUSED;
                edns.set_extended_dns_error(EDE_PROHIBITED, &why.to_string());
            }
            Denied(why) => {
                rcode = REFUSED;
                edns.set_extended_dns_error(EDE_PROHIBITED, &why);
            }
            Blocked => {
                rcode = NXDOMAIN;
                edns.set_extended_dns_error(
                    EDE_BLOCKED,
                    "Server is configured to block these queries",
                );
            }
            NotAuthoritative => {
                rcode = REFUSED;
                edns.set_extended_dns_error(EDE_NOT_AUTHORITATIVE, "Not Authoritative");
            }
            NoRouteConfigured => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NOT_SUPPORTED, "No route configured for suffix");
            }
            OutReply(outquery::Error::Timeout) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(
                    EDE_NO_REACHABLE_AUTHORITY,
                    "Timed out talking to upstream server",
                );
            }
            OutReply(outquery::Error::FailedToSend(io)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &io.to_string());
            }
            OutReply(outquery::Error::FailedToSendMsg(msg)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &msg);
            }
            OutReply(outquery::Error::FailedToRecv(io)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &io.to_string());
            }
            OutReply(outquery::Error::FailedToRecvMsg(msg)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &msg);
            }
            OutReply(outquery::Error::TcpConnection(msg)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &msg);
            }
            OutReply(outquery::Error::Parse(msg)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &msg);
            }
            OutReply(outquery::Error::Internal(_)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_OTHER, "Internal Error");
            }
        }
        dnspkt::DNSPkt {
            qid: msg.in_query.qid,
            rd: false,
            tc: false,
            aa: false,
            qr: true,
            opcode: dnspkt::OPCODE_QUERY,
            cd: false,
            ad: false,
            ra: true,
            rcode,
            bufsize: 4096,
            edns_ver: msg.in_query.edns_ver.map(|_| 0),
            edns_do: false,

            question: msg.in_query.question.clone(),
            answer: vec![],
            additional: vec![],
            nameserver: vec![],
            edns: Some(edns),
        }
    }

    fn build_dns_message(
        pkt: &[u8],
        local_ip: std::net::IpAddr,
        remote_addr: NetAddr,
        protocol: Protocol,
    ) -> Result<DnsMessage, Error> {
        let in_query = parse::PktParser::new(pkt)
            .get_dns()
            .map_err(Error::ParseError)?;
        Ok(DnsMessage {
            in_query,
            local_ip,
            remote_addr,
            protocol,
            in_size: pkt.len(),
        })
    }

    async fn recv_in_query(
        s: &std::sync::Arc<tokio::sync::RwLock<Self>>,
        msg: &DnsMessage,
    ) -> Result<dnspkt::DNSPkt, std::convert::Infallible> {
        log::trace!(
            "[{:x}] In Query {}: {} ⇐ {}: {:?}",
            msg.in_query.qid,
            msg.protocol,
            msg.local_ip,
            msg.remote_addr,
            msg.in_query
        );
        let next = &s.read().await.next;
        let in_reply;
        match next.handle_query(msg).await {
            Ok(out_reply) => {
                in_reply = Self::create_in_reply(msg, &out_reply).await;
                IN_QUERY_RESULT
                    .with_label_values(&[&msg.protocol.to_string(), &in_reply.status()])
                    .inc();
            }
            Err(err) => {
                in_reply = Self::create_in_error(msg, err).await;
                IN_QUERY_RESULT
                    .with_label_values(&[&msg.protocol.to_string(), &in_reply.status()])
                    .inc();
            }
        }
        log::trace!("[{:x}] In Reply: {:?}", msg.in_query.qid, in_reply);
        Ok(in_reply)
    }

    async fn should_ratelimit(
        msg: &DnsMessage,
        in_reply: &dnspkt::DNSPkt,
        in_reply_serialised: &[u8],
        rate_limiter: &IpRateLimiter,
    ) -> bool {
        // Currently we only ratelimit REFUSEDs.
        if in_reply.rcode != dnspkt::REFUSED {
            return false;
        }

        match msg.validate_cookie().await {
            CookieStatus::Good => {
                // If we can tell it's not spoofed, don't ratelimit.
                log::trace!("[{:x}] Cookie status: Good", msg.in_query.qid);
                return false;
            }
            CookieStatus::Bad => {
                log::trace!("[{:x}] Cookie status: Bad", msg.in_query.qid);
            }
            CookieStatus::Missing => {
                log::trace!("[{:x}] Cookie status: Missing", msg.in_query.qid);
            }
        }

        // For each byte larger than the incoming request, we charge it at 2× the cost.
        // For each byte smaller or equal than the incoming request, we charge it at 1× the cost.
        // But always charge at least 200.
        let cost = std::cmp::max(
            (in_reply_serialised.len() * 2).saturating_sub(msg.in_size),
            200,
        );

        use erbium_net::addr::NetAddrExt as _;

        // We bill this to the remote address.
        // TODO: Should we bill this to the subnet?  Eg, /56 for v6 and /24 for v4?
        !rate_limiter
            .check(msg.remote_addr.ip().unwrap(), cost)
            .await
    }

    async fn run_udp(
        listener: &std::sync::Arc<UdpSocket>,
        s: &std::sync::Arc<tokio::sync::RwLock<Self>>,
    ) -> Result<(), Error> {
        let local_rate_limiter;
        {
            let local_self = s.read().await;
            local_rate_limiter = local_self.rate_limiter.clone();
        }
        let rm = match listener.recv_msg(4096, udp::MsgFlags::empty()).await {
            Ok(rm) => rm,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => return Ok(()),
            Err(err) => return Err(Error::RecvError(err)),
        };
        let timer = IN_QUERY_LATENCY.with_label_values(&["UDP"]).start_timer();

        let q = s.clone();
        let local_listener = listener.clone();

        log::trace!(
            "Received UDP {:?} ⇒ {:?} ({})",
            rm.address,
            rm.local_ip(),
            rm.buffer.len()
        );

        tokio::spawn(async move {
            match Self::build_dns_message(
                &rm.buffer,
                rm.local_ip().unwrap(), /* TODO: Error? */
                rm.address.unwrap(),    /* TODO: Error? */
                Protocol::Udp,
            ) {
                Ok(msg) => {
                    let in_reply = Self::recv_in_query(&q, &msg).await.unwrap();
                    let in_reply_bytes = in_reply.serialise();
                    if !Self::should_ratelimit(
                        &msg,
                        &in_reply,
                        &in_reply_bytes,
                        &local_rate_limiter,
                    )
                    .await
                    {
                        let cmsg = udp::ControlMessage::new().set_send_from(rm.local_ip());
                        local_listener
                            .send_msg(
                                in_reply_bytes.as_slice(),
                                &cmsg,
                                udp::MsgFlags::empty(),
                                Some(&rm.address.unwrap()), /* TODO: Error? */
                            )
                            .await
                            .expect("Failed to send reply"); // TODO: Better error handling
                    } else {
                        IN_QUERY_DROPPED.inc();
                        log::warn!("[{:x}] Not Sending Reply: Rate Limit", msg.in_query.qid);
                    }
                }
                Err(err) => {
                    log::warn!("Failed to handle request: {}", err);
                    IN_QUERY_RESULT
                        .with_label_values(&["UDP", "parse fail"])
                        .inc();
                }
            }
            drop(timer);
        });
        Ok(())
    }

    fn prepare_to_send(pkt: &dnspkt::DNSPkt, size: usize) -> Vec<u8> {
        let size = std::cmp::max(size, 512);
        pkt.serialise_with_size(size)
    }

    async fn run_tcp(
        s: &std::sync::Arc<tokio::sync::RwLock<Self>>,
        mut sock: tokio::net::TcpStream,
        sock_addr: NetAddr,
    ) -> Result<(), Error> {
        use tokio::io::AsyncReadExt as _;

        log::trace!(
            "Received TCP connection {:?} ⇒ {:?}",
            sock_addr,
            sock.local_addr().unwrap(), /* TODO: Error? */
        );

        let mut lbytes = [0u8; 2];

        if sock.read(&mut lbytes).await.map_err(Error::RecvError)? != lbytes.len() {
            return Err(Error::ParseError("Failed to read length".into()));
        }

        let l = u16::from_be_bytes(lbytes) as usize;
        let mut buffer = vec![0u8; l];

        sock.read_exact(&mut buffer[..])
            .await
            .map_err(Error::RecvError)?;
        let timer = IN_QUERY_LATENCY.with_label_values(&["TCP"]).start_timer();

        let q = s.clone();

        log::trace!(
            "Received TCP {:?} ⇒ {:?} ({})",
            sock_addr,
            sock.local_addr(),
            buffer.len()
        );

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            match Self::build_dns_message(
                &buffer,
                sock.local_addr().ok().map(|addr| addr.ip()).unwrap(), /* TODO: Error? */
                sock_addr,
                Protocol::Tcp,
            ) {
                Ok(msg) => {
                    let in_reply = Self::recv_in_query(&q, &msg).await.unwrap();
                    let serialised =
                        Self::prepare_to_send(&in_reply, msg.in_query.bufsize as usize);
                    let mut in_reply_bytes = vec![];
                    in_reply_bytes.reserve(2 + serialised.len());
                    in_reply_bytes.extend((serialised.len() as u16).to_be_bytes().iter());
                    in_reply_bytes.extend(serialised);
                    if let Err(io) = sock.write(&in_reply_bytes).await {
                        log::warn!("[{:x}] Failed to send DNS reply: {}", msg.in_query.qid, io);
                        IN_QUERY_RESULT
                            .with_label_values(&["TCP", "send fail"])
                            .inc();
                    }
                    drop(timer);
                }
                Err(err) => {
                    IN_QUERY_RESULT
                        .with_label_values(&["TCP", "parse fail"])
                        .inc();
                    log::warn!("Failed to handle request: {}", err);
                }
            }
        });

        Ok(())
    }

    async fn run_tcp_listener(
        tcp: &tokio::net::TcpListener,
        s: &std::sync::Arc<tokio::sync::RwLock<Self>>,
    ) -> Result<(), Error> {
        let (sock, sock_addr) = tcp.accept().await.map_err(Error::AcceptError)?;
        let local_s = s.clone();

        tokio::spawn(async move { Self::run_tcp(&local_s, sock, sock_addr.into()).await });

        Ok(())
    }

    async fn run(s: &std::sync::Arc<tokio::sync::RwLock<Self>>) -> Result<(), Error> {
        use futures::StreamExt as _;
        let mut services = futures::stream::FuturesUnordered::new();
        let mut my_self = s.write().await;
        for listener in my_self.udp_listeners.drain(..) {
            let s_clone = s.clone();
            services.push(tokio::spawn(async move {
                let shared_listener = listener.into();
                loop {
                    match Self::run_udp(&shared_listener, &s_clone).await {
                        Ok(()) => (),
                        Err(err) => {
                            log::warn!(
                                "{}: {}",
                                shared_listener
                                    .local_addr()
                                    .map(|a| format!("{}", a))
                                    .unwrap_or_else(|e| format!("<unknown: {}>", e)),
                                err
                            )
                        }
                    }
                }
            }));
        }
        for listener in my_self.tcp_listeners.drain(..) {
            let s_clone = s.clone();
            services.push(tokio::spawn(async move {
                loop {
                    match Self::run_tcp_listener(&listener, &s_clone).await {
                        Ok(()) => (),
                        Err(err) => {
                            log::warn!(
                                "{}: {}",
                                listener
                                    .local_addr()
                                    .map(|a| format!("{}", a))
                                    .unwrap_or_else(|e| format!("<unknown: {}>", e)),
                                err
                            )
                        }
                    }
                }
            }));
        }

        drop(my_self);

        services.next().await.unwrap().unwrap()
    }
}

pub struct DnsService {
    next: std::sync::Arc<tokio::sync::RwLock<DnsListenerHandler>>,
}

impl DnsService {
    pub async fn run(self) -> Result<(), Error> {
        loop {
            DnsListenerHandler::run(&self.next).await?;
        }
    }

    pub async fn new(
        conf: crate::config::SharedConfig,
        netinfo: &erbium_net::netinfo::SharedNetInfo,
    ) -> Result<Self, Error> {
        Ok(Self {
            next: tokio::sync::RwLock::new(DnsListenerHandler::new(conf, netinfo).await?).into(),
        })
    }
}
