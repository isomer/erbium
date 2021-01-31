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
 *  Send queries "out" to the next server.
 */

use crate::dns::rand::RngCore;
use std::cell::Cell;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::dns::dnspkt;
use crate::dns::parse;

/* Wow, this is a surprising amount of code for handling outbound TCP queries.
 * We only want to create one TCP connection, and send all queries over that, handling the fact
 * that they can come back out of order.  We also don't want to hold open the TCP socket
 * needlessly.
 *
 * So we spawn a separate task per nameserver, with a channel to send queries
 * (TcpNameserverMessage) on.  This message contains a oneshot reply channel that gets the reply
 * (and possibly any errors that occurred).
 */
type TcpNameserverChannel = tokio::sync::mpsc::Sender<TcpNameserverMessage>;

lazy_static::lazy_static! {
    static ref NAMESERVER_INFO: tokio::sync::Mutex<std::collections::HashMap<std::net::SocketAddr,TcpNameserverChannel>> = Default::default();

    static ref DNS_SENT_QUERIES: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_out_queries_packets_sent",
            "Number of DNS out queries packets sent",
            &["dns_server", "protocol"]
            )
            .unwrap();

    static ref KAMINSKY_MITIGATIONS: prometheus::IntCounter =
        prometheus::register_int_counter!("dns_kaminsky_mitigations",
                                            "Number of times kaminsky mitigations were triggered")
            .unwrap();

    static ref TRUNCATED_RETRY: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_out_query_truncated_retry",
            "Number of times a UDP out query was upgraded to a TCP out query due to truncation",
            &["dns_server"]
            )
            .unwrap();

    static ref OUT_QUERY_LATENCY: prometheus::HistogramVec =
        prometheus::register_histogram_vec!("dns_out_query_latency",
            "DNS latency for out queries",
            &["dns_server", "protocol"])
        .unwrap();

    static ref OUT_QUERY_RESULT: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_out_query_result",
            "DNS out query results",
            &["dns_server", "result"])
        .unwrap();

    static ref OUT_QUERY_OUTSTANDING: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!("dns_out_query_outstanding",
            "Number of out queries currently outstanding",
            &["dns_server"])
        .unwrap();
}

#[derive(Debug)]
pub enum Error {
    Timeout,
    FailedToSend(std::io::Error),
    FailedToSendMsg(String),
    FailedToRecv(std::io::Error),
    FailedToRecvMsg(String),
    TcpConnectionError(String),
    ParseError(String),
    InternalError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            Timeout => write!(f, "Timeout"),
            FailedToSend(err) => write!(f, "Failed to send out query: {}", err),
            FailedToSendMsg(msg) => write!(f, "Failed to send out query: {}", msg),
            FailedToRecv(err) => write!(f, "Failed to receive out query: {}", err),
            FailedToRecvMsg(msg) => write!(f, "Failed to receive out query: {}", msg),
            TcpConnectionError(err) => {
                write!(f, "TCP connection error while waiting for result: {}", err)
            }
            ParseError(err) => write!(f, "Failed to parse out reply: {}", err),
            InternalError(err) => write!(f, "Internal error in out query handling: {}", err),
        }
    }
}

type Protocol = super::Protocol;

fn increment_result(dns_server: &str, result: &Result<dnspkt::DNSPkt, Error>) {
    OUT_QUERY_RESULT
        .with_label_values(&[
            dns_server,
            &match result {
                Ok(pkt) => match pkt
                    .edns
                    .as_ref()
                    .and_then(|edns| edns.get_extended_dns_error())
                {
                    Some((code, _msg)) => format!("{} ({})", pkt.rcode.to_string(), code),
                    _ => pkt.rcode.to_string(),
                },
                Err(Error::Timeout) => "TIMEOUT".into(),
                Err(Error::FailedToSend(io)) => format!("SEND: {}", io),
                Err(Error::FailedToRecv(io)) => format!("RECV: {}", io),
                Err(Error::FailedToSendMsg(msg)) => format!("SEND: {}", msg),
                Err(Error::FailedToRecvMsg(msg)) => format!("RECV: {}", msg),
                Err(Error::ParseError(msg)) => format!("PARSE_ERROR: {}", msg),
                Err(Error::InternalError(msg)) => format!("INTERNAL: {}", msg),
                Err(Error::TcpConnectionError(msg)) => format!("TCP: {}", msg),
            },
        ])
        .inc()
}

type Responder<T> = tokio::sync::oneshot::Sender<Result<T, Error>>;

struct TcpNameserverMessage {
    out_query: super::dnspkt::DNSPkt,
    out_reply: Responder<super::dnspkt::DNSPkt>,
}

struct TcpNameserver {
    addr: std::net::SocketAddr,
    tcp: Option<tokio::net::TcpStream>,
    tcp_last_send_activity: Instant,
    tcp_last_recv_activity: Instant,
    qid2reply: std::collections::HashMap<u16, Responder<super::dnspkt::DNSPkt>>,
}

impl TcpNameserver {
    fn start(addr: std::net::SocketAddr) -> TcpNameserverChannel {
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let ret = Box::new(Self {
            addr,
            tcp: None,
            tcp_last_send_activity: Instant::now(),
            tcp_last_recv_activity: Instant::now(),
            qid2reply: Default::default(),
        });

        tokio::task::spawn(ret.run(rx));

        tx
    }

    async fn send_query_to(
        addr: &std::net::SocketAddr,
        out_query: super::dnspkt::DNSPkt,
    ) -> Result<super::dnspkt::DNSPkt, Error> {
        let chan = NAMESERVER_INFO
            .lock()
            .await
            .entry(*addr)
            .or_insert_with(|| TcpNameserver::start(*addr))
            .clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _timer = OUT_QUERY_LATENCY
            .with_label_values(&[&addr.to_string(), "TCP"])
            .start_timer();
        chan.send(TcpNameserverMessage {
            out_query,
            out_reply: tx,
        })
        .await
        .map_err(|err| Error::InternalError(format!("Channel send failed: {}", err)))?;
        match rx.await {
            Ok(ret) => ret,
            Err(err) => Err(Error::InternalError(format!(
                "Channel recv failed: {}",
                err
            ))),
        }
    }

    async fn send_tcp_reply(&mut self, qid: u16, reply: Result<super::dnspkt::DNSPkt, Error>) {
        if let Some(resp) = self.qid2reply.remove(&qid) {
            resp.send(reply).unwrap();
        } else {
            log::error!("Sending reply to unknown request: {:?}", reply);
        }
    }

    async fn send_tcp_query(&mut self, msg: TcpNameserverMessage) -> Result<(), Error> {
        assert!(self
            .qid2reply
            .insert(msg.out_query.qid, msg.out_reply)
            .is_none()); // TODO: Collisions!
        if let Some(ref mut tcp_sock) = self.tcp {
            use tokio::io::AsyncWriteExt as _;
            let bytes = msg.out_query.serialise();
            /* There should be a write_all_vectored trait somewhere, but I cannot find it.
             * Bodge it.
             */
            let mut buf: Vec<u8> = vec![];
            buf.reserve_exact(2 + bytes.len());
            buf.extend((bytes.len() as u16).to_be_bytes().iter());
            buf.extend(bytes);
            DNS_SENT_QUERIES
                .with_label_values(&[&self.addr.to_string(), "TCP"])
                .inc();
            let ret = tcp_sock.write_all(&buf).await.map_err(Error::FailedToSend);
            self.tcp_last_send_activity = Instant::now();
            ret
        } else {
            panic!("Write on non-existant tcp socket");
        }
    }

    async fn read_reply(&mut self) -> Result<Vec<u8>, Error> {
        if let Some(ref mut tcp_sock) = self.tcp {
            use tokio::io::AsyncReadExt as _;
            let mut lbuf = [0u8; 2];
            tcp_sock
                .read_exact(&mut lbuf)
                .await
                .map_err(Error::FailedToRecv)?;
            let l = u16::from_be_bytes(lbuf);
            let mut msg_buf = vec![0u8; l as usize];
            log::trace!("Reading {} bytes from TCP socket", l);
            tcp_sock
                .read_exact(&mut msg_buf[..])
                .await
                .map_err(Error::FailedToRecv)?;
            self.tcp_last_recv_activity = Instant::now();
            Ok(msg_buf)
        } else {
            panic!("Read from non existant tcp socket");
        }
    }

    async fn handle_reply(&mut self, buf: &[u8]) {
        let pkt = match parse::PktParser::new(&buf)
            .get_dns()
            .map_err(Error::ParseError)
        {
            Ok(pkt) => pkt,
            Err(err) => {
                /* TODO: Drop the TCP connection */
                log::error!("{}", err);
                return;
            }
        };
        self.send_tcp_reply(pkt.qid, Ok(pkt)).await
    }

    fn tcp_teardown(&mut self, err: Error) {
        self.tcp = None;
        log::trace!("Tearing down {} TCP channel: {}", self.addr, err);
        for (_qid, chan) in self.qid2reply.drain() {
            chan.send(Err(Error::TcpConnectionError(format!(
                "TCP channel closed before reply: {}",
                err
            ))))
            .unwrap();
        }
    }

    async fn run(mut self, mut chan: tokio::sync::mpsc::Receiver<TcpNameserverMessage>) {
        loop {
            let last_send_activity = self.tcp_last_send_activity;
            let last_recv_activity = self.tcp_last_recv_activity;
            if self.tcp.is_some() {
                /* We have an open TCP connection, so listen on both the TCP connection and the request
                 * channel. (TODO: Also timeout the TCP channel)
                 */
                use futures::FutureExt as _;
                futures::select! {
                    msg = chan.recv().fuse() => if let Some(msg) = msg {
                        if let Err(e) = self.send_tcp_query(msg).await {
                            // Shutdown the TCP channel, report the error back to all clients
                            // waiting on this channel, including the one we're handling now.
                            self.tcp_teardown(e);
                        }
                    } else {
                        /* No more clients, clean up. */
                        return;
                    },
                    ret = self.read_reply().fuse() => match ret {
                            Ok(msg) => self.handle_reply(&msg[..]).await,
                            Err(e) => {
                                /* We failed to perform the correct read on the channel,
                                 * something's gone wrong, no more responses on this channel are
                                 * sensible, close the channel and report the failure to all
                                 * clients.
                                 */
                                self.tcp_teardown(e);
                            },
                        },
                    /* If we have stopped sending queries, then close down the idle channel to
                     * spare resources on the server side.
                     */
                    () = tokio::time::sleep_until(last_send_activity + std::time::Duration::from_secs(120)).fuse() => {
                            self.tcp_teardown(Error::TcpConnectionError("TCP Connection idle".into()));
                    },
                    /* If the other end isn't replying to us at all, then close down the
                     * connection.
                     */
                    () = tokio::time::sleep_until(last_recv_activity + std::time::Duration::from_secs(120)).fuse() => {
                            self.tcp_teardown(Error::TcpConnectionError("Timed out waiting for TCP replies".into()));
                    },
                }
            } else if let Some(msg) = chan.recv().await {
                /* We've not already opened the tcp connection, so open it now. */
                log::trace!("Opening new TCP channel to {}", self.addr);
                match tokio::net::TcpStream::connect(self.addr).await {
                    Ok(sock) => self.tcp = Some(sock),
                    /* If we can't open the channel, report the error, and continue */
                    Err(err) => {
                        msg.out_reply.send(Err(Error::FailedToSend(err))).unwrap();
                        continue;
                    }
                }
                self.tcp_last_recv_activity = Instant::now();
                self.tcp_last_send_activity = Instant::now();
                if let Err(e) = self.send_tcp_query(msg).await {
                    // Shutdown the TCP connection, report the error back to all clients
                    // (including the client that we're currently handling)
                    self.tcp_teardown(e);
                }
            } else {
                /* No more incoming queries, exit cleanly. */
                return;
            }
        }
    }
}

fn create_outquery(id: u16, q: &dnspkt::Question) -> dnspkt::DNSPkt {
    dnspkt::DNSPkt {
        qid: id,
        rd: true,
        tc: false,
        aa: false,
        qr: false,
        opcode: dnspkt::OPCODE_QUERY,

        cd: false,
        ad: false,
        ra: false,
        rcode: dnspkt::NOERROR,

        bufsize: 4096,

        edns_ver: Some(0),
        edns_do: false,

        question: q.clone(),
        answer: vec![],
        nameserver: vec![],
        additional: vec![],
        edns: Some(dnspkt::EdnsData::new()),
    }
}

#[derive(Clone)]
pub struct OutQuery {
    rng: Arc<Mutex<Cell<rand::rngs::OsRng>>>,
}

impl OutQuery {
    pub fn new() -> Self {
        OutQuery {
            rng: Arc::new(Mutex::new(Cell::new(rand::rngs::OsRng::default()))),
        }
    }

    async fn send_udp(
        &self,
        addr: std::net::SocketAddr,
        oq: &super::dnspkt::DNSPkt,
    ) -> Result<dnspkt::DNSPkt, Error> {
        let outsock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(Error::FailedToSend)?;
        outsock.connect(addr).await.map_err(Error::FailedToSend)?;

        log::trace!("OutQuery: {:?}", oq);
        let mut timeout = std::time::Duration::from_millis(1000);
        let mut buf = [0; 65536];
        let mut attempts = 0i32; // Forcing i32 as the type checker can't choose a type.  i32 is perhaps cheapest?
        let _timer = OUT_QUERY_LATENCY
            .with_label_values(&[&addr.to_string(), "UDP"])
            .start_timer();
        let l = loop {
            DNS_SENT_QUERIES
                .with_label_values(&[&addr.to_string(), "UDP"])
                .inc();
            outsock
                .send(oq.serialise().as_slice())
                .await
                .map_err(Error::FailedToSend)?;

            attempts += 1;

            match tokio::time::timeout(timeout, outsock.recv(&mut buf)).await {
                /* Success */
                Ok(Ok(l)) => break l,
                /* recv failed */
                Ok(Err(io)) => return Err(Error::FailedToRecv(io)),
                /* timeout */
                Err(_) => {
                    use rand::distributions::Distribution;
                    if attempts > 3 {
                        return Err(Error::Timeout);
                    }
                    // We want to retry, with exponential backoff and jitter.
                    // This gives us the fastest possible retry behaviour, but still avoids
                    // overloading the nameserver.
                    // This is not part of the security, thus we can use a cheap, fast random
                    // number generator.
                    let mut rng = rand::thread_rng();
                    let jitter = rand::distributions::Uniform::new(
                        std::time::Duration::from_secs(0),
                        timeout,
                    )
                    .sample(&mut rng);
                    // This should increase by x1.5 to x2.5
                    timeout += (timeout / 2) + jitter;
                }
            }
        };

        let pkt = parse::PktParser::new(&buf[0..l])
            .get_dns()
            .map_err(Error::ParseError)?;

        Ok(pkt)
    }

    async fn handle_query_internal(
        &self,
        msg: &super::DnsMessage,
        addr: std::net::SocketAddr,
    ) -> Result<dnspkt::DNSPkt, Error> {
        let q = &msg.in_query.question;
        let id = self.rng.lock().await.get().next_u32() as u16;
        let oq = create_outquery(id, q);

        let out_reply;
        match msg.protocol {
            Protocol::UDP => {
                /* TODO: If we have a warm TCP connection already open, _and_ we have stats that
                 * say TCP is faster than UDP (which is likely if packet loss is high), then we
                 * should skip UDP and just use the existing TCP connection.
                 */
                let reply = self.send_udp(addr, &oq).await?;
                if reply.qid != id {
                    /* This smells dangerously like a kaminisky attack.  Disregard the message, and immediately
                     * retry over TCP.
                     */
                    KAMINSKY_MITIGATIONS.inc();
                    out_reply = TcpNameserver::send_query_to(&addr, oq).await?;
                } else if reply.tc {
                    /* If it's a truncated reply, then retry again over TCP, so we can get the full
                     * reply.  Truncated replies are also used by servers that suspect that we are
                     * spoofing to get us to prove that we can perform a 3 way handshake.
                     */
                    TRUNCATED_RETRY
                        .with_label_values(&[&addr.to_string()])
                        .inc();
                    out_reply = TcpNameserver::send_query_to(&addr, oq).await?;
                } else {
                    out_reply = reply;
                }
            }
            /* If the original request came in on TCP, then we're going to assume that they had a
             * good reason for it (eg, a previous reply was truncated, or due to kaminsky attacks
             * or whatever), so we're going to follow suit.
             */
            Protocol::TCP => {
                out_reply = TcpNameserver::send_query_to(&addr, oq).await?;
            }
        }

        if out_reply.qid != id {
            log::warn!("Mismatched ID: {} != {}", out_reply.qid, id);
        }

        Ok(out_reply)
    }

    pub async fn handle_query(
        &self,
        msg: &super::DnsMessage,
    ) -> Result<dnspkt::DNSPkt, super::Error> {
        let addr: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();
        OUT_QUERY_OUTSTANDING
            .with_label_values(&[&addr.to_string()])
            .inc();
        let ret = self.handle_query_internal(msg, addr).await;
        OUT_QUERY_OUTSTANDING
            .with_label_values(&[&addr.to_string()])
            .dec();
        increment_result(&addr.to_string(), &ret);
        ret.map_err(super::Error::OutReply)
    }
}
