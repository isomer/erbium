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
 *  Infrastructure for DNS services.
 */
use crate::net::udp;
use std::error::Error;
use std::sync::Arc;
use tokio::io;

type UdpSocket = udp::UdpSocket;

extern crate nix;
extern crate rand;

mod cache;
mod dnspkt;
mod outquery;
mod parse;

use bytes::BytesMut;
use tokio_util::codec::Decoder;
struct DnsCodec {}

impl Decoder for DnsCodec {
    type Item = dnspkt::DNSPkt;
    type Error = std::io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let inquery = parse::PktParser::new(&src[..]).get_dns();
        match inquery {
            Ok(p) => Ok(Some(p)),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        }
    }
}

#[derive(Clone)]
struct DnsServer {
    next: cache::CacheHandler,
}

impl DnsServer {
    fn create_inreply(&self, inq: &dnspkt::DNSPkt, outr: &dnspkt::DNSPkt) -> dnspkt::DNSPkt {
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
            edns: Some(dnspkt::EdnsData { other: vec![] }), // We should do more here.
        }
    }

    async fn recvinquery(
        &mut self,
        responder: Arc<UdpSocket>,
        pkt: &[u8],
        from: std::net::SocketAddr,
        to: Option<std::net::IpAddr>,
    ) {
        let inquery = parse::PktParser::new(pkt)
            .get_dns()
            .expect("Failed to parse InQuery"); // TODO
        println!("InQuery {:?} {:?}", from, inquery);

        match self.next.handle_query(&inquery.question).await {
            Ok(outreply) => {
                let inreply = self.create_inreply(&inquery, &outreply);
                println!("InReply: {:?} <- {:?}", from, inreply);
                let cmsg = udp::ControlMessage::new().set_send_from(to);
                responder
                    .send_msg(
                        inreply.serialise().as_slice(),
                        &cmsg,
                        udp::MsgFlags::empty(),
                        Some(&from),
                    )
                    .await
                    .expect("Failed to send reply"); // TODO: Better error handling
                println!("Reply sent");
            }
            Err(e) => println!("Error: {:?}", e),
        };
    }

    async fn run(self, sock: UdpSocket) -> Result<(), io::Error> {
        let shared_sock = Arc::new(sock);
        loop {
            match shared_sock.recv_msg(4096, udp::MsgFlags::empty()).await {
                Ok(rm) => {
                    let mut q = self.clone();
                    let shared_responder2 = shared_sock.clone();
                    println!(
                        "Received {:?} => {:?} ({})",
                        rm.address,
                        rm.local_addr(),
                        rm.buffer.len()
                    );
                    tokio::spawn(async move {
                        q.recvinquery(
                            shared_responder2,
                            &rm.buffer,
                            rm.address.unwrap(),
                            rm.local_addr(),
                        )
                        .await
                    });
                }
                Err(e) => {
                    println!("Error {}", e);
                }
            }
        }
    }
}

async fn run_internal() -> Result<(), Box<dyn Error>> {
    let listener = UdpSocket::bind(
        &tokio::net::lookup_host("[::]:1053")
            .await?
            .collect::<Vec<_>>(),
    )
    .await?;

    listener.set_opt_ipv4_packet_info(true)?;
    listener.set_opt_ipv6_packet_info(true)?;

    println!("Listening for DNS on {}", listener.local_addr()?);

    let server = DnsServer {
        next: cache::CacheHandler::new(),
    };

    server.run(listener).await?;

    Ok(())
}

pub async fn run() -> Result<(), String> {
    match run_internal().await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
