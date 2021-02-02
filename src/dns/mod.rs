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
use crate::net::udp;

type UdpSocket = udp::UdpSocket;

extern crate nix;
extern crate rand;

mod acl;
mod cache;
#[cfg(fuzzing)]
pub mod dnspkt;
#[cfg(not(fuzzing))]
pub mod dnspkt;
mod outquery;
#[cfg(fuzzing)]
pub mod parse;
#[cfg(not(fuzzing))]
mod parse;
mod router;

use bytes::BytesMut;
use tokio_util::codec::Decoder;

lazy_static::lazy_static! {
    static ref IN_QUERY_LATENCY: prometheus::HistogramVec =
        prometheus::register_histogram_vec!("dns_in_query_latency",
            "DNS latency for in queries",
            &["protocol"])
        .unwrap();

    /* Result is "RCode" or "RCode (EdeCode)" */
    static ref IN_QUERY_RESULT: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!("dns_in_query_latency",
            "DNS latency for in queries",
            &["protocol", "result"])
        .unwrap();

}

#[cfg_attr(test, derive(Debug))]
pub enum Error {
    ListenError(std::io::Error),
    RecvError(std::io::Error),
    ParseError(String),
    RefusedByAcl(crate::acl::AclError),
    NotAuthoritative,
    OutReply(outquery::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            ListenError(io) => write!(f, "Failed to listen for DNS: {}", io),
            RecvError(io) => write!(f, "Failed to receive DNS in query: {}", io),
            ParseError(msg) => write!(f, "Failed to parse DNS in query: {}", msg),
            RefusedByAcl(why) => write!(f, "Query refused by policy: {}", why),
            NotAuthoritative => write!(f, "Not Authoritative"),
            OutReply(err) => write!(f, "{}", err),
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
    UDP,
    TCP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Protocol::UDP => write!(f, "UDP"),
            Protocol::TCP => write!(f, "TCP"),
        }
    }
}

pub struct DnsMessage {
    pub in_query: dnspkt::DNSPkt,
    pub local_ip: std::net::IpAddr,
    pub remote_addr: std::net::SocketAddr,
    pub protocol: Protocol,
}

struct DnsListenerHandler {
    _conf: crate::config::SharedConfig,
    next: acl::DnsAclHandler,
    udp_listener: std::sync::Arc<UdpSocket>,
    tcp_listener: tokio::net::TcpListener,
}

impl DnsListenerHandler {
    async fn listen_udp(_conf: &crate::config::SharedConfig) -> Result<UdpSocket, Error> {
        let udp = UdpSocket::bind(
            &tokio::net::lookup_host("[::]:53")
                .await
                .map_err(Error::ListenError)?
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(Error::ListenError)?;

        udp.set_opt_ipv4_packet_info(true)
            .map_err(Error::ListenError)?;
        udp.set_opt_ipv6_packet_info(true)
            .map_err(Error::ListenError)?;

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
    ) -> Result<tokio::net::TcpListener, Error> {
        let tcp = tokio::net::TcpListener::bind("[::]:53")
            .await
            .map_err(Error::ListenError)?;

        log::info!(
            "Listening for DNS on TCP {}",
            tcp.local_addr()
                .map(|name| format!("{}", name))
                .unwrap_or_else(|_| "Unknown".into())
        );

        Ok(tcp)
    }

    async fn new(conf: crate::config::SharedConfig) -> Result<Self, Error> {
        let udp_listener = Self::listen_udp(&conf).await?.into();
        let tcp_listener = Self::listen_tcp(&conf).await?;

        Ok(Self {
            _conf: conf.clone(),
            next: acl::DnsAclHandler::new(conf).await,
            udp_listener,
            tcp_listener,
        })
    }

    fn create_in_reply(inq: &dnspkt::DNSPkt, outr: &dnspkt::DNSPkt) -> dnspkt::DNSPkt {
        dnspkt::DNSPkt {
            qid: inq.qid,
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

            edns_ver: Some(0),
            edns_do: false,

            question: inq.question.clone(),
            answer: outr.answer.clone(),
            nameserver: outr.answer.clone(),
            additional: outr.additional.clone(),
            edns: Some(dnspkt::EdnsData::new()), // We should do more here.
        }
    }

    fn create_in_error(inq: &dnspkt::DNSPkt, err: Error) -> dnspkt::DNSPkt {
        let mut edns: EdnsData = Default::default();
        let rcode;
        use dnspkt::*;
        use Error::*;
        match err {
            /* These errors mean we never get a packet to reply to. */
            ListenError(_) => unreachable!(),
            RecvError(_) => unreachable!(),
            ParseError(_) => unreachable!(),
            RefusedByAcl(why) => {
                rcode = REFUSED;
                edns.set_extended_dns_error(EDE_PROHIBITED, &why.to_string());
            }
            NotAuthoritative => {
                rcode = REFUSED;
                edns.set_extended_dns_error(EDE_NOT_AUTHORITATIVE, "Not Authoritative");
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
            OutReply(outquery::Error::TcpConnectionError(msg)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &msg);
            }
            OutReply(outquery::Error::ParseError(msg)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_NETWORK_ERROR, &msg);
            }
            OutReply(outquery::Error::InternalError(_)) => {
                rcode = SERVFAIL;
                edns.set_extended_dns_error(EDE_OTHER, "Internal Error");
            }
        }
        dnspkt::DNSPkt {
            qid: inq.qid,
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
            edns_ver: Some(0),
            edns_do: false,

            question: inq.question.clone(),
            answer: vec![],
            additional: vec![],
            nameserver: vec![],
            edns: Some(edns),
        }
    }

    fn build_dns_message(
        pkt: &[u8],
        local_ip: std::net::IpAddr,
        remote_addr: std::net::SocketAddr,
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
        })
    }

    async fn recv_in_query(
        s: &std::sync::Arc<tokio::sync::RwLock<Self>>,
        msg: &DnsMessage,
    ) -> Result<dnspkt::DNSPkt, Error> {
        log::trace!(
            "[{:x}] In Query {}: {} ⇐ {}",
            msg.in_query.qid,
            msg.protocol,
            msg.local_ip,
            msg.remote_addr
        );
        let next = &s.read().await.next;
        let in_reply;
        match next.handle_query(&msg).await {
            Ok(out_reply) => {
                in_reply = Self::create_in_reply(&msg.in_query, &out_reply);
            }
            Err(err) => {
                in_reply = Self::create_in_error(&msg.in_query, err);
            }
        }
        log::trace!("[{:x}] In Reply: {:?}", msg.in_query.qid, in_reply);
        Ok(in_reply)
    }

    async fn run_udp(s: &std::sync::Arc<tokio::sync::RwLock<Self>>) -> Result<(), Error> {
        let local_listener = s.read().await.udp_listener.clone();
        let rm = match local_listener.recv_msg(4096, udp::MsgFlags::empty()).await {
            Ok(rm) => rm,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => return Ok(()),
            Err(err) => return Err(Error::RecvError(err)),
        };
        let timer = IN_QUERY_LATENCY.with_label_values(&["UDP"]).start_timer();

        let q = s.clone();

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
                Protocol::UDP,
            ) {
                Ok(msg) => {
                    match Self::recv_in_query(&q, &msg).await {
                        Ok(in_reply) => {
                            let cmsg = udp::ControlMessage::new().set_send_from(rm.local_ip());
                            // TODO: Add EDE
                            IN_QUERY_RESULT
                                .with_label_values(&[&"UDP", &in_reply.rcode.to_string()])
                                .inc();
                            local_listener
                                .send_msg(
                                    in_reply.serialise().as_slice(),
                                    &cmsg,
                                    udp::MsgFlags::empty(),
                                    Some(&rm.address.unwrap()), /* TODO: Error? */
                                )
                                .await
                                .expect("Failed to send reply"); // TODO: Better error handling
                        }
                        Err(err) => {
                            log::warn!("Failed to handle query: {}", err);
                            IN_QUERY_RESULT
                                .with_label_values(&[&"UDP", &"failed"])
                                .inc();
                        }
                    }
                }
                Err(err) => {
                    log::warn!("Failed to handle request: {}", err);
                    IN_QUERY_RESULT
                        .with_label_values(&[&"UDP", &"parse fail"])
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
        sock_addr: std::net::SocketAddr,
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
                Protocol::TCP,
            ) {
                Ok(msg) => {
                    let in_reply = match Self::recv_in_query(&q, &msg).await {
                        Ok(in_reply) => in_reply,
                        Err(msg) => {
                            log::warn!("Failed to handle DNS query: {}", msg);
                            IN_QUERY_RESULT
                                .with_label_values(&[&"TCP", &"failed"])
                                .inc();
                            return;
                        }
                    };
                    IN_QUERY_RESULT
                        .with_label_values(&[
                            &"TCP",
                            &format!(
                                "{}{}",
                                in_reply.rcode.to_string(),
                                in_reply
                                    .edns
                                    .as_ref()
                                    .and_then(|edns| edns.get_extended_dns_error())
                                    .map(|ede| format!(" ({})", ede.0.to_string()))
                                    .unwrap_or_else(|| "".into())
                            ),
                        ])
                        .inc();
                    let serialised =
                        Self::prepare_to_send(&in_reply, msg.in_query.bufsize as usize);
                    let mut in_reply_bytes = vec![];
                    in_reply_bytes.reserve(2 + serialised.len());
                    in_reply_bytes.extend((serialised.len() as u16).to_be_bytes().iter());
                    in_reply_bytes.extend(serialised);
                    if let Err(msg) = sock.write(&in_reply_bytes).await {
                        log::warn!("Failed to send DNS reply: {}", msg);
                        IN_QUERY_RESULT
                            .with_label_values(&[&"TCP", &"send fail"])
                            .inc();
                    }
                    drop(timer);
                }
                Err(err) => {
                    IN_QUERY_RESULT
                        .with_label_values(&[&"TCP", &"parse fail"])
                        .inc();
                    log::warn!("Failed to handle request: {}", err);
                }
            }
        });

        Ok(())
    }

    async fn run_tcp_listener(s: &std::sync::Arc<tokio::sync::RwLock<Self>>) -> Result<(), Error> {
        let (sock, sock_addr) = s
            .read()
            .await
            .tcp_listener
            .accept()
            .await
            .map_err(Error::ListenError)?;
        let local_s = s.clone();

        tokio::spawn(async move { Self::run_tcp(&local_s, sock, sock_addr).await });

        Ok(())
    }

    async fn run(s: &std::sync::Arc<tokio::sync::RwLock<Self>>) -> Result<(), Error> {
        use futures::future::FutureExt as _;
        use futures::pin_mut;
        let udp_fut = Self::run_udp(s).fuse();
        let tcp_listener_fut = Self::run_tcp_listener(s).fuse();

        pin_mut!(udp_fut, tcp_listener_fut);

        futures::select! {
            udp = udp_fut => udp,
            tcp_listener = tcp_listener_fut => tcp_listener,
        }
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

    pub async fn new(conf: crate::config::SharedConfig) -> Result<Self, Error> {
        Ok(Self {
            next: tokio::sync::RwLock::new(DnsListenerHandler::new(conf).await?).into(),
        })
    }
}
