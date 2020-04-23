use std::error::Error;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

extern crate nix;
extern crate rand;

mod cache;
mod dnspkt;
mod outquery;
mod parse;

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
        responder: Arc<Mutex<tokio::net::udp::SendHalf>>,
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

async fn run_internal() -> Result<(), Box<dyn Error>> {
    let listener = UdpSocket::bind("[::]:1053").await?;

    nix::sys::socket::setsockopt(
        listener.as_raw_fd(),
        nix::sys::socket::sockopt::Ipv4PacketInfo,
        &true,
    )?;

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
