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

#[derive(Debug)]
pub struct Lease {
    pub ip: std::net::Ipv4Addr,
    pub expire: std::time::Duration,
}

pub struct PoolInfo {
    addresses: Vec<std::net::Ipv4Addr>,
}

pub struct Pools {
    conn: rusqlite::Connection,
    poolinfo: std::collections::HashMap<String, PoolInfo>,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    DbError(String, rusqlite::Error),
    NoSuchPool(String),
    DuplicatePool(String),
    CorruptDatabase(String),
    InternalError(String),
    NoAssignableAddress,
}

impl ToString for Error {
    fn to_string(&self) -> String {
        match self {
            Error::DbError(reason, e) => format!("{}: {}", reason, e.to_string()),
            Error::NoSuchPool(s) => format!("No Such Pool: {}", s),
            Error::DuplicatePool(s) => format!("Duplicate Pool: {}", s),
            Error::CorruptDatabase(s) => format!("Corrupt Database: {}", s),
            Error::InternalError(s) => format!("Internal Error: {}", s),
            Error::NoAssignableAddress => "No Assignable Address".into(),
        }
    }
}

impl Error {
    fn emit(reason: String, e: rusqlite::Error) -> Error {
        Error::DbError(reason, e)
    }
}

impl Pools {
    fn setup_db(self) -> Result<Self, Error> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS leases (
              pool  TEXT NOT NULL,
              address TEXT NOT NULL,
              clientid BLOB NOT NULL,
              start INTEGER NOT NULL,
              expiry INTEGER NOT NULL,
              PRIMARY KEY (pool, address)
            )",
                rusqlite::params![],
            )
            .map_err(|e| Error::emit("Creating table leases".into(), e))?;

        Ok(self)
    }

    fn new_with_conn(conn: rusqlite::Connection) -> Result<Self, Error> {
        Pools {
            conn,
            poolinfo: std::collections::HashMap::new(),
        }
        .setup_db()
    }

    #[cfg(test)]
    pub fn new_in_memory() -> Result<Pools, Error> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| Error::emit("Creating database in memory database".into(), e))?;

        Self::new_with_conn(conn)
    }

    pub fn new() -> Result<Pools, Error> {
        let conn = rusqlite::Connection::open("erbium-leases.sqlite")
            .map_err(|e| Error::emit("Creating database erbium-leases.sqlite".into(), e))?;

        Self::new_with_conn(conn)
    }

    pub fn add_addr(&mut self, name: &str, addr: std::net::Ipv4Addr) -> Result<(), Error> {
        self.poolinfo
            .get_mut(name)
            .ok_or_else(|| Error::NoSuchPool(name.into()))?
            .addresses
            .push(addr);
        Ok(())
    }

    pub fn add_subnet(&mut self, name: &str, netblock: Netblock) -> Result<(), Error> {
        self.poolinfo
            .get_mut(name)
            .ok_or_else(|| Error::NoSuchPool(name.into()))?
            .addresses
            .reserve(1 << (32 - netblock.prefixlen));
        let base: u32 = netblock.netmask().into();
        for i in 1..((1 << (32 - netblock.prefixlen)) - 1) {
            self.add_addr(name, (base + i).into())?;
        }
        Ok(())
    }

    pub fn add_pool(&mut self, name: &str) -> Result<(), Error> {
        if self.poolinfo.contains_key(name) {
            Err(Error::DuplicatePool(name.into()))
        } else {
            self.poolinfo
                .insert(name.into(), PoolInfo { addresses: vec![] });
            Ok(())
        }
    }

    fn select_requested_address(
        &mut self,
        name: &str,
        requested: std::net::Ipv4Addr,
        ts: u32,
    ) -> Result<Lease, Error> {
        if !self
            .poolinfo
            .get(name)
            .ok_or_else(|| Error::NoSuchPool(name.into()))?
            .addresses
            .contains(&requested)
        {
            println!("Requested address {:?} does not exist in pool", requested);
            println!("{:?}", self.poolinfo.get(name).unwrap().addresses);
            Err(Error::NoAssignableAddress)
        } else if self
            .conn
            .query_row(
                "SELECT
                      true
                     FROM
                      leases
                     WHERE pool = ?1
                     AND expiry >= ?2
                     AND address = ?3",
                rusqlite::params![name, ts, requested.to_string()],
                |_row| Ok(Some(())),
            )
            .or_else(map_no_row_to_none)?
            == None
        {
            println!("Using requested {:?}", requested);
            return Ok(Lease {
                ip: requested,
                expire: std::time::Duration::from_secs(0), /* We rely on the min_lease_time below */
            });
        } else {
            println!("Requested address is already in use in pool");
            Err(Error::NoAssignableAddress)
        }
    }

    fn select_address(
        &mut self,
        name: &str,
        clientid: &[u8],
        requested: std::net::Ipv4Addr,
    ) -> Result<Lease, Error> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("clock failure")
            .as_secs();
        /* RFC2131 Section 4.3.1:
         * If an address is available, the new address SHOULD be chosen as follows:
         *
         * o The client's current address as recorded in the client's current
         *   binding, ELSE */
        if let Some(lease) = self
            .conn
            .query_row(
                "SELECT
               address,
               expiry
             FROM
               leases
             WHERE pool = ?1
             AND clientid = ?2
             AND expiry > ?3",
                rusqlite::params![name, clientid, ts as u32],
                |row| {
                    Ok(Some((
                        row.get::<usize, String>(0)?,
                        row.get::<usize, u32>(1)?,
                    )))
                },
            )
            .or_else(map_no_row_to_none)?
        {
            println!("Reusing existing lease: {:?}", lease);
            return Ok(Lease {
                ip: lease.0.parse::<std::net::Ipv4Addr>().map_err(|e| {
                    Error::CorruptDatabase(format!(
                        "Failed to parse IP: {} ({:?})",
                        e.to_string(),
                        lease.0
                    ))
                })?,
                expire: std::time::Duration::from_secs((lease.1 - (ts as u32)).into()),
            });
        }

        /* o The client's previous address as recorded in the client's (now
         * expired or released) binding, if that address is in the server's
         * pool of available addresses and not already allocated, ELSE */

        if let Some(lease) = self
            .conn
            .query_row(
                "SELECT
               address,
               start,
               max(expiry)
             FROM
               leases
             WHERE pool = ?1
             AND clientid = ?2
             GROUP BY 1",
                rusqlite::params![name, clientid],
                |row| {
                    Ok(Some((
                        row.get::<usize, String>(0)?,
                        row.get::<usize, u32>(1)?,
                        row.get::<usize, u32>(2)?,
                    )))
                },
            )
            .or_else(map_no_row_to_none)?
        {
            println!("Reviving old lease: {:?}", lease);
            return Ok(Lease {
                ip: lease.0.parse::<std::net::Ipv4Addr>().map_err(|e| {
                    Error::CorruptDatabase(format!(
                        "Failed to parse IP: {:?} ({:?})",
                        e.to_string(),
                        lease.0,
                    ))
                })?,
                /* If a device is constantly asking for the same lease, we should double
                 * the lease time.  This means transient devices get short leases, and
                 * devices that are more permanent get longer leases.
                 */
                expire: std::time::Duration::from_secs(2 * (lease.2 - lease.1) as u64),
            });
        }

        /* o The address requested in the 'Requested IP Address' option, if that
         * address is valid and not already allocated, ELSE
         */
        match self.select_requested_address(name, requested, ts as u32) {
            Err(Error::NoAssignableAddress) => (),
            x => return x,
        }

        /* o A new address allocated from the server's pool of available
         *   addresses; the address is selected based on the subnet from which
         *   the message was received (if 'giaddr' is 0) or on the address of
         *   the relay agent that forwarded the message ('giaddr' when not 0).
         */
        println!("Assigning new lease");
        Ok(Lease {
            ip: *self
                .poolinfo
                .get(name)
                .ok_or_else(|| Error::NoSuchPool(name.into()))?
                .addresses
                .first()
                .ok_or_else(|| Error::NoAssignableAddress)?,
            expire: std::time::Duration::from_secs(0), /* We rely on the min_lease_time below */
        })
    }

    /* TODO: This function should return a Result, not an Option, to handle error cases better
     */
    pub fn allocate_address(&mut self, name: &str, clientid: &[u8]) -> Result<Lease, Error> {
        println!("Allocating lease for {:?}", clientid);
        let lease = self.select_address(name, clientid, "192.168.0.100".parse().unwrap())?;

        let min_expire_time = std::time::Duration::from_secs(300);
        let max_expire_time = std::time::Duration::from_secs(86400);

        let lease = Lease {
            expire: std::cmp::min(
                std::cmp::max(lease.expire, min_expire_time),
                max_expire_time,
            ),
            ..lease
        };

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("clock failure")
            .as_secs();

        self.conn
            .execute(
                "INSERT INTO leases (pool, address, clientid, start, expiry)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (pool, address) DO
             UPDATE SET clientid=?3, start=?4, expiry=?5",
                rusqlite::params![
                    name,
                    lease.ip.to_string(),
                    clientid,
                    ts as u32,
                    (ts + lease.expire.as_secs()) as u32
                ],
            )
            .expect("Updating lease database failed"); /* Better error handling */

        Ok(lease)
    }

    #[cfg(test)]
    fn reserve_address(&mut self, pool_name: &str, client_id: &[u8], addr: std::net::Ipv4Addr) {
        self.conn
            .execute(
                "INSERT INTO leases (pool, address, clientid, start, expiry)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    pool_name,
                    addr.to_string(),
                    client_id,
                    0,             /* Reserved from the beginning of time */
                    0xFFFFFFFFu32  /* Until the end of time */
                ],
            )
            .expect("Failed to add existing lease to pool");
    }
}

fn map_no_row_to_none<T>(e: rusqlite::Error) -> Result<Option<T>, Error> {
    if e == rusqlite::Error::QueryReturnedNoRows {
        Ok(None)
    } else {
        Err(Error::emit("Database query Error".into(), e))
    }
}

pub struct Netblock {
    pub addr: std::net::Ipv4Addr,
    pub prefixlen: u8,
}

impl Netblock {
    fn netmask(&self) -> std::net::Ipv4Addr {
        (u32::from(self.addr) & (((1 << self.prefixlen) - 1) as u32).to_be()).into()
    }
}

#[test]
fn smoke_test() {
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    p.add_subnet(
        "default",
        Netblock {
            addr: "192.168.0.0".parse().unwrap(),
            prefixlen: 24,
        },
    )
    .expect("Failed to add netblock");
    p.allocate_address("default", b"client")
        .expect("Didn't get allocated an address?!");
}

#[test]
fn empty_pool() {
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    /* Deliberately don't add any addresses, so we'll fail when we try and allocate something */
    assert_eq!(
        p.allocate_address("default", b"client")
            .expect_err("Got allocated an address from an empty pool!"),
        Error::NoAssignableAddress
    );
}

#[test]
fn reacquire_lease() {
    /* o The client's current address as recorded in the client's current binding */
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    p.conn
        .execute(
            "INSERT INTO leases (pool, address, clientid, start, expiry)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "default",
                "192.168.0.100",
                b"client" as &[u8],
                0,
                0xFFFFFFFFu32
            ],
        )
        .expect("Failed to add existing lease to pool");
    let lease = p
        .allocate_address("default", b"client")
        .expect("Failed to allocate address");

    assert_eq!(
        lease.ip,
        "192.168.0.100".parse::<std::net::Ipv4Addr>().unwrap(),
    );
    assert!(lease.expire > std::time::Duration::from_secs(0));
}

#[test]
fn reacquire_expired_lease() {
    /* o The client's previous address as recorded in the client's (now expired or released)
     * binding, if that address is in the server's pool of available addresses and not already
     * allocated */
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    p.conn
        .execute(
            "INSERT INTO leases (pool, address, clientid, start, expiry)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "default",
                "192.168.0.100",
                b"client" as &[u8],
                0,
                0, /* Address has already expired. */
            ],
        )
        .expect("Failed to add existing lease to pool");
    let lease = p
        .allocate_address("default", b"client")
        .expect("Failed to allocate address");

    assert_eq!(
        lease.ip,
        "192.168.0.100".parse::<std::net::Ipv4Addr>().unwrap(),
    );
    assert!(lease.expire > std::time::Duration::from_secs(0));
}

#[test]
fn acquire_requested_address_success() {
    /* o The address requested in the 'Requested IP Address' option, if that address is valid and
     * not already allocated, ELSE
     */
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    p.add_subnet(
        "default",
        Netblock {
            addr: "192.168.0.0".parse().unwrap(),
            prefixlen: 24,
        },
    )
    .expect("Failed to add subnet to default pool");

    let lease = p
        .select_address("default", b"client", "192.168.0.101".parse().unwrap())
        .expect("Failed to allocate address");

    assert_eq!(
        lease.ip,
        "192.168.0.101".parse::<std::net::Ipv4Addr>().unwrap(),
    );
}

#[test]
fn acquire_requested_address_in_use() {
    /* o The address requested in the 'Requested IP Address' option, if that address is valid and
     * not already allocated, ELSE
     */
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    p.add_subnet(
        "default",
        Netblock {
            addr: "192.168.0.0".parse().unwrap(),
            prefixlen: 24,
        },
    )
    .expect("Failed to add subnet to default pool");
    p.reserve_address("default", b"other-client", "192.168.0.101".parse().unwrap());

    let lease = p
        .select_address("default", b"client", "192.168.0.101".parse().unwrap())
        .expect("Failed to allocate address");

    /* Do not assigned the reserved address! */
    assert_ne!(
        lease.ip,
        "192.168.0.101".parse::<std::net::Ipv4Addr>().unwrap(),
    );
}

#[test]
fn acquire_requested_address_invalid() {
    /* o The address requested in the 'Requested IP Address' option, if that address is valid and
     * not already allocated, ELSE
     */
    let mut p = Pools::new_in_memory().expect("Failed to create in memory pools");
    p.add_pool("default")
        .expect("Failed to create default pool");
    p.add_subnet(
        "default",
        Netblock {
            addr: "192.168.0.0".parse().unwrap(),
            prefixlen: 24,
        },
    )
    .expect("Failed to add subnet to default pool");

    let lease = p
        .select_address("default", b"client", "10.0.0.1".parse().unwrap())
        .expect("Failed to allocate address");

    /* Do not assigned the reserved address! */
    assert_ne!(lease.ip, "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap(),);
}
