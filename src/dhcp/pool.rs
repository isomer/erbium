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
 *  DHCP Pool Management.
 */
use rusqlite;

pub struct Lease {
    pub ip: std::net::Ipv4Addr,
    pub lease: std::time::Duration,
}

pub struct Pools {
    conn: rusqlite::Connection,
}

#[derive(Debug)]
pub enum Error {
    DbError(rusqlite::Error),
}

impl ToString for Error {
    fn to_string(&self) -> String {
        match self {
            Error::DbError(e) => e.to_string(),
        }
    }
}

impl Pools {
    pub fn new() -> Result<Pools, Error> {
        Ok(Pools {
            conn: rusqlite::Connection::open("inmemory:").map_err(Error::DbError)?,
        })
    }

    pub fn allocate_address(&self, _name: &str) -> Option<Lease> {
        Some(Lease {
            ip: "192.168.0.100".parse().unwrap(),
            lease: std::time::Duration::from_secs(600),
        })
    }
}
