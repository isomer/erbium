use crate::rand::RngCore;
use std::cell::Cell;
use std::collections::HashMap;
use std::error::Error;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::RwLock;

extern crate nix;
extern crate rand;

mod dnspkt;
mod net;
mod parse;

mod dhcp;

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
struct DnsServer {
    cache: Arc<RwLock<Cache>>,
    rng: Arc<Mutex<Cell<rand::rngs::OsRng>>>,
}

impl DnsServer {
    async fn get_random_id(&self) -> u16 {
        self.rng.lock().await.get().next_u32() as u16
    }
    async fn create_outquery(&self, q: &dnspkt::Question) -> dnspkt::DNSPkt {
        return dnspkt::DNSPkt {
            qid: self.get_random_id().await,
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
            edns: Some(dnspkt::EdnsData { other: vec![] }),
        };
    }

    fn create_inreply(&self, inq: &dnspkt::DNSPkt, outr: &dnspkt::DNSPkt) -> dnspkt::DNSPkt {
        return dnspkt::DNSPkt {
            qid: inq.qid,
            rd: false,
            tc: outr.tc,
            aa: outr.aa,
            qr: true,
            opcode: dnspkt::OPCODE_QUERY,

            cd: outr.cd,
            ad: outr.ad,
            ra: outr.ra,

            rcode: outr.rcode.clone(),

            bufsize: 4096,

            edns_ver: Some(0),
            edns_do: false,

            question: inq.question.clone(),
            answer: outr.answer.clone(),
            nameserver: outr.answer.clone(),
            additional: outr.additional.clone(),
            edns: Some(dnspkt::EdnsData { other: vec![] }), // We should do more here.
        };
    }

    async fn send_outquery(&self, q: &dnspkt::Question) -> Result<dnspkt::DNSPkt, std::io::Error> {
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
        let oq = self.create_outquery(q).await;

        let mut outsock = UdpSocket::bind("0.0.0.0:0").await?;
        outsock.connect("8.8.8.8:53").await?;

        println!("OutQuery: {:?}", oq);
        println!(
            "OutQuery (parsed): {:?}",
            parse::PktParser::new(&oq.serialise()).get_dns()
        );
        outsock.send(oq.serialise().as_slice()).await?;

        let mut buf = [0; 65536];
        let l = outsock.recv(&mut buf).await?;
        let outreply = parse::PktParser::new(&buf[0..l])
            .get_dns()
            .expect("Failed to parse OutReply"); // TODO: Better error handling than panic!

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

    async fn recvinquery(
        &mut self,
        responder: Arc<Mutex<tokio::net::udp::SendHalf>>,
        pkt: &[u8],
        from: std::net::SocketAddr,
    ) {
        println!("Received {}", pkt.len());
        let inquery = parse::PktParser::new(pkt)
            .get_dns()
            .expect("Failed to parse InQuery"); // TODO
        println!("InQuery {:?} {:?}", from, inquery);

        match self.send_outquery(&inquery.question).await {
            Ok(outreply) => {
                let inreply = self.create_inreply(&inquery, &outreply);
                println!("InReply: {:?} <- {:?}", from, inreply);
                responder
                    .lock()
                    .await
                    .send_to(inreply.serialise().as_slice(), &from)
                    .await
                    .expect("Failed to send reply"); // TODO
                println!("Reply sent");
            }
            Err(e) => println!("Error: {:?}", e),
        };
    }

    async fn run(self, sock: tokio::net::UdpSocket) -> Result<(), io::Error> {
        let (mut listener, responder) = sock.split();
        let shared_responder = Arc::new(Mutex::new(responder));
        loop {
            let mut buf = [0; 65536];
            match listener.recv_from(&mut buf).await {
                Ok((n, sa)) => {
                    let mut q = self.clone();
                    let shared_responder = shared_responder.clone();
                    tokio::spawn(
                        async move { q.recvinquery(shared_responder, &buf[0..n], sa).await },
                    );
                }
                Err(e) => {
                    println!("Error {}", e);
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = UdpSocket::bind("[::]:1053").await?;

    nix::sys::socket::setsockopt(
        listener.as_raw_fd(),
        nix::sys::socket::sockopt::Ipv4PacketInfo,
        &true,
    )?;

    println!("Listening for DNS on {}", listener.local_addr()?);
    let cache = Arc::new(RwLock::new(Cache::new()));

    let rng = rand::rngs::OsRng::default();

    let server = DnsServer {
        cache: cache,
        rng: Arc::new(Mutex::new(Cell::new(rng))),
    };

    tokio::spawn(dhcp::run());

    server.run(listener).await?;

    Ok(())
}
