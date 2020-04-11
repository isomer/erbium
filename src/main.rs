use crate::rand::RngCore;
use std::cell::Cell;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::io;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use std::os::unix::io::AsRawFd;

extern crate rand;
extern crate nix;

mod dnspkt;
mod parse;
mod net;

#[derive(Eq, PartialEq, Hash)]
struct CacheKey {
    qname: dnspkt::Domain,
    qtype: dnspkt::Type,
}

struct Cache {
    cache: HashMap<CacheKey, ()>,
}

impl Cache {
    fn new() -> Self {
        return Cache {
            cache: HashMap::new(),
        };
    }

    fn lookup(&self, key: &CacheKey) -> Option<()> {
        match self.cache.get(key) {
            Some(_) => Some(()),
            None => None,
        }
    }
}

struct DnsServer {
    listener: UdpSocket,
    cache: Arc<RwLock<Cache>>,
    rng: Cell<rand::rngs::OsRng>,
}

impl DnsServer {
    fn get_random_id(&self) -> u16 {
        self.rng.get().next_u32() as u16
    }
    fn create_outquery(&self, q: &dnspkt::Question) -> dnspkt::DNSPkt {
        return dnspkt::DNSPkt {
            qid: self.get_random_id(),
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
        let oq = self.create_outquery(q).serialise();

        let mut outsock = UdpSocket::bind("0.0.0.0:0").await?;
        outsock.connect("8.8.8.8:53").await?;

        println!("OutQuery: {:?}", oq);
        outsock.send(oq.as_slice()).await?;

        let mut buf = [0; 65536];
        let l = outsock.recv(&mut buf).await?;
        let outreply = parse::PktParser::new(&buf[0..l])
            .get_dns()
            .expect("Failed to parse OutReply"); // TODO

        println!("OutReply: {:?}", outreply);

        Ok(outreply)
    }

    async fn recvinquery(&mut self, pkt: &[u8], from : std::net::SocketAddr) {
        println!("Received {}", pkt.len());
        let inquery = parse::PktParser::new(pkt)
            .get_dns()
            .expect("Failed to parse InQuery"); // TODO
        println!("InQuery {:?} {:?}", from, inquery);
        let key = CacheKey {
            qname: inquery.question.qdomain.clone(),
            qtype: inquery.question.qtype.clone(),
        };
        self.cache.read().await.lookup(&key);

        match self.send_outquery(&inquery.question).await {
            Ok(outreply) => {
                let inreply = self.create_inreply(&inquery, &outreply);
                println!("InReply: {:?}", inreply);
                self.listener
                    .send_to(inreply.serialise().as_slice(), from)
                    .await
                    .expect("Failed to send reply"); // TODO
            }
            Err(e) => println!("Error: {:?}", e),
        };
    }

    async fn run(mut self) -> Result<(), io::Error> {
        loop {
            let mut buf = [0; 65536];
            let mut cmsg = nix::cmsg_space!(nix::sys::socket::sockopt::Ipv4PacketInfo);
            match self.listener.recv_from(&mut buf).await {
                Ok((n, sa)) => self.recvinquery(&buf[0..n], sa).await,
                Err(e) => println!("Error {}", e),
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
        &true)?;

    println!("Listening on {}", listener.local_addr()?);
    let cache = Arc::new(RwLock::new(Cache::new()));

    let rng = rand::rngs::OsRng::default();

    let server = DnsServer {
        listener: listener,
        cache: cache,
        rng: Cell::new(rng),
    };

    server.run().await?;

    Ok(())
}
