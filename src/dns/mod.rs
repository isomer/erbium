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
    ) {
        println!("Received {}", pkt.len());
        let inquery = parse::PktParser::new(pkt)
            .get_dns()
            .expect("Failed to parse InQuery"); // TODO
        println!("InQuery {:?} {:?}", from, inquery);

        match self.next.handle_query(&inquery.question).await {
            Ok(outreply) => {
                let inreply = self.create_inreply(&inquery, &outreply);
                println!("InReply: {:?} <- {:?}", from, inreply);
                responder
                    .send_msg(
                        inreply.serialise().as_slice(),
                        &udp::ControlMessage {},
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
            let mut cmsg = Vec::new(); /* TODO: Calculate better size */
            match shared_sock
                .recv_msg(4096, &mut cmsg, udp::MsgFlags::empty())
                .await
            {
                Ok(rm) => {
                    let mut q = self.clone();
                    let shared_responder2 = shared_sock.clone();
                    tokio::spawn(async move {
                        q.recvinquery(shared_responder2, &rm.buffer, rm.address.unwrap())
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
    let listener = UdpSocket::bind("[::]:1053").await?;

    listener.set_opt_ipv4_packet_info(true)?;

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
