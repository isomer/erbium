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
 *  Send queries "out" to the next server.
 */

use crate::dns::rand::RngCore;
use std::cell::Cell;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::dns::dnspkt;
use crate::dns::parse;

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
        edns: Some(dnspkt::EdnsData { other: vec![] }),
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

    pub async fn handle_query(
        &self,
        q: &dnspkt::Question,
    ) -> Result<dnspkt::DNSPkt, std::io::Error> {
        let oq = create_outquery(self.rng.lock().await.get().next_u32() as u16, q);

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

        Ok(outreply)
    }
}
