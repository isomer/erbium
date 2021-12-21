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
 *  DHCP Pool Management.
 */

use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;

pub const DEFAULT_MIN_LEASE: std::time::Duration = std::time::Duration::from_secs(300);
pub const DEFAULT_MAX_LEASE: std::time::Duration = std::time::Duration::from_secs(86400);

pub type PoolAddresses = std::collections::HashSet<std::net::Ipv4Addr>;

#[derive(Debug)]
pub enum LeaseType {
    NewAddress,
    ReusingLease,
    Requested,
    Revived,
}

#[derive(Debug)]
pub struct Lease {
    pub ip: std::net::Ipv4Addr,
    pub expire: std::time::Duration,
    pub lease_type: LeaseType,
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct LeaseInfo {
    pub ip: std::net::Ipv4Addr,
    pub client_id: Vec<u8>,
    pub start: u32,
    pub expire: u32,
}

pub struct Pool {
    conn: rusqlite::Connection,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    DbError(String),
    CorruptDatabase(String),
    NoAssignableAddress,
    RequestedAddressInUse,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DbError(reason) => write!(f, "{}", reason),
            Error::CorruptDatabase(s) => write!(f, "Corrupt Database: {}", s),
            Error::NoAssignableAddress => write!(f, "No Assignable Address"),
            Error::RequestedAddressInUse => write!(f, "Requested address is in use"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    fn emit(reason: &str, e: &rusqlite::Error) -> Error {
        Error::DbError(format!("{} ({})", reason, e))
    }
}

fn calculate_hash<S: Hash, T: Hash>(s: &S, t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    t.hash(&mut h);
    h.finish()
}

impl Pool {
    fn setup_db(self) -> Result<Self, Error> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS leases (
              address TEXT NOT NULL,
              chaddr BLOB,
              clientid BLOB,
              start INTEGER NOT NULL,
              expiry INTEGER NOT NULL,
              PRIMARY KEY (address)
            )",
                rusqlite::params![],
            )
            .map_err(|e| Error::emit("Creating table leases", &e))?;

        Ok(self)
    }

    fn new_with_conn(conn: rusqlite::Connection) -> Result<Self, Error> {
        Pool { conn }.setup_db()
    }

    //#[cfg(any(test, fuzzing))]
    pub fn new_in_memory() -> Result<Pool, Error> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| Error::emit("Creating database in memory database", &e))?;

        Self::new_with_conn(conn)
    }

    pub fn new() -> Result<Pool, Error> {
        let conn = rusqlite::Connection::open("/var/lib/erbium/leases.sqlite")
            .map_err(|e| Error::emit("Creating database /var/lib/erbium/leases.sqlite", &e))?;

        Self::new_with_conn(conn)
    }

    pub fn get_pool_metrics(&mut self) -> Result<(u32, u32), Error> {
        let ts: u32 = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("clock failure")
            .as_secs() as u32;
        self.conn
            .query_row(
                "SELECT
             SUM(CASE WHEN expiry < ?1 THEN 1 ELSE 0 END) as active,
             SUM(CASE WHEN expiry >= ?1 THEN 1 ELSE 0 END) as expired
             FROM leases",
                rusqlite::params![ts],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| Error::DbError(e.to_string()))
    }

    pub fn get_leases(&mut self) -> Result<Vec<LeaseInfo>, Error> {
        self.conn
            .prepare_cached(
                "SELECT
                  address,
                  clientid,
                  start,
                  expiry
                 FROM
                  leases",
            )
            .map_err(|e| Error::DbError(e.to_string()))?
            .query_map([], |row| {
                Ok(LeaseInfo {
                    ip: row
                        .get::<_, String>(0)?
                        .parse::<std::net::Ipv4Addr>()
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                    client_id: row.get(1)?,
                    start: row.get(2)?,
                    expire: row.get(3)?,
                })
            })
            .map_err(|e| Error::DbError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::DbError(e.to_string()))
    }

    fn select_requested_address(
        &mut self,
        requested: std::net::Ipv4Addr,
        ts: u32,
        addresses: &PoolAddresses,
    ) -> Result<Lease, Error> {
        if !addresses.contains(&requested) {
            Err(Error::NoAssignableAddress)
        } else if self
            .conn
            .query_row(
                "SELECT
                      true
                     FROM
                      leases
                     WHERE expiry >= ?1
                     AND address = ?2",
                rusqlite::params![ts, requested.to_string()],
                |_row| Ok(Some(())),
            )
            .or_else(map_no_row_to_none)?
            == None
        {
            Ok(Lease {
                ip: requested,
                expire: std::time::Duration::from_secs(0), /* We rely on the min_lease_time below */
                lease_type: LeaseType::Requested,
            })
        } else {
            Err(Error::RequestedAddressInUse)
        }
    }

    fn select_new_address(
        &mut self,
        ts: u32,
        addresses: &PoolAddresses,
        clientid: &[u8],
    ) -> Result<Lease, Error> {
        /* This performs a consistent hash of the clientid and the IP addresses
         * then orders by the distance from the hash of the clientid
         */
        let clienthash = calculate_hash(&0, &clientid);
        let mut addresses = addresses
            .iter()
            .map(|ip| (calculate_hash(&clienthash, ip), ip))
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        let addresses = addresses
            .iter()
            .map(|(_dist, ip)| ip)
            .copied()
            .collect::<Vec<_>>();
        /* Now for each address, see if it's in use, and if so, return it */
        for i in addresses {
            if self
                .conn
                .query_row(
                    "SELECT
                      true
                     FROM
                      leases
                     WHERE expiry >= ?1
                     AND address = ?2",
                    rusqlite::params![ts, i.to_string()],
                    |_row| Ok(Some(())),
                )
                .or_else(map_no_row_to_none)?
                == None
            {
                return Ok(Lease {
                    ip: *i,
                    expire: std::time::Duration::from_secs(0), /* We rely on the min_lease_time below */
                    lease_type: LeaseType::NewAddress,
                });
            }
        }
        Err(Error::NoAssignableAddress)
    }

    fn select_address(
        &mut self,
        clientid: &[u8],
        requested: Option<std::net::Ipv4Addr>,
        addresses: &PoolAddresses,
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
               expiry,
               start
             FROM
               leases
             WHERE clientid = ?1
             AND expiry > ?2
             ORDER BY
              address=?3 DESC,
              expiry DESC
             LIMIT 1",
                rusqlite::params![
                    clientid,
                    ts as u32,
                    requested.map(|ip| ip.to_string()).unwrap_or("".into())
                ],
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
            if let Ok(ip) = lease.0.parse::<std::net::Ipv4Addr>() {
                if addresses.contains(&ip) {
                    // We want leases to double in size.  But normally you renew your
                    // lease at ½ the duration.  We don't want to always just double
                    // the lease, because you can accidentally end up with a ridiculously
                    // long lease if you renew rapidly.
                    // So instead we just use 3*renew.
                    let expiry = (ts as u32).saturating_sub(lease.2).saturating_mul(3);
                    return Ok(Lease {
                        ip,
                        expire: std::time::Duration::from_secs(expiry.into()),
                        lease_type: LeaseType::ReusingLease,
                    });
                }
            }
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
               max(expiry) as expire_time
             FROM
               leases
             WHERE clientid = ?1
             GROUP BY 1
             ORDER BY
               address=?2 DESC,
               expire_time DESC
             LIMIT 1
             ",
                rusqlite::params![
                    clientid,
                    requested.map(|ip| ip.to_string()).unwrap_or("".into())
                ],
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
            if let Ok(ip) = lease.0.parse::<std::net::Ipv4Addr>() {
                if addresses.contains(&ip) {
                    return Ok(Lease {
                        ip,
                        /* If a device is constantly asking for the same lease, we should double
                         * the lease time.  This means transient devices get short leases, and
                         * devices that are more permanent get longer leases.
                         */
                        expire: std::time::Duration::from_secs(2 * (lease.2 - lease.1) as u64),
                        lease_type: LeaseType::Revived,
                    });
                }
            }
        }

        /* o The address requested in the 'Requested IP Address' option, if that
         * address is valid and not already allocated, ELSE
         */
        if let Some(addr) = requested {
            match self.select_requested_address(addr, ts as u32, addresses) {
                Err(Error::NoAssignableAddress) => (),
                Err(Error::RequestedAddressInUse) => (),
                x => return x,
            }
        }

        /* o A new address allocated from the server's pool of available
         *   addresses; the address is selected based on the subnet from which
         *   the message was received (if 'giaddr' is 0) or on the address of
         *   the relay agent that forwarded the message ('giaddr' when not 0).
         */
        self.select_new_address(ts as u32, addresses, clientid)
    }

    pub fn allocate_address(
        &mut self,
        clientid: &[u8],
        requested: Option<std::net::Ipv4Addr>,
        addresses: &PoolAddresses,
        min_expire_time: std::time::Duration,
        max_expire_time: std::time::Duration,
    ) -> Result<Lease, Error> {
        let lease = self.select_address(clientid, requested, addresses)?;

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
                "INSERT OR REPLACE
                 INTO leases (address, clientid, start, expiry)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
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
    fn reserve_address_internal(
        &mut self,
        client_id: &[u8],
        addr: std::net::Ipv4Addr,
        expired: bool,
    ) {
        self.conn
            .execute(
                "INSERT INTO leases (address, clientid, start, expiry)
             VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    addr.to_string(),
                    client_id,
                    0, /* Reserved from the beginning of time */
                    if expired {
                        0
                    } else {
                        0xFFFFFFFFu32 /* Until the end of time */
                    }
                ],
            )
            .expect("Failed to add existing lease to pool");
    }

    #[cfg(test)]
    fn reserve_address(&mut self, client_id: &[u8], addr: std::net::Ipv4Addr) {
        self.reserve_address_internal(client_id, addr, false);
    }

    #[cfg(test)]
    fn reserve_expired_address(&mut self, client_id: &[u8], addr: std::net::Ipv4Addr) {
        self.reserve_address_internal(client_id, addr, true);
    }
}

fn map_no_row_to_none<T>(e: rusqlite::Error) -> Result<Option<T>, Error> {
    if e == rusqlite::Error::QueryReturnedNoRows {
        Ok(None)
    } else {
        Err(Error::emit("Database query Error", &e))
    }
}

#[test]
fn smoke_test() {
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");
    let mut addrpool: PoolAddresses = Default::default();
    addrpool.insert("192.168.0.100".parse().unwrap());
    addrpool.insert("192.168.0.101".parse().unwrap());
    addrpool.insert("192.168.0.102".parse().unwrap());
    p.allocate_address(
        b"client",
        None,
        &addrpool,
        DEFAULT_MIN_LEASE,
        DEFAULT_MAX_LEASE,
    )
    .expect("Didn't get allocated an address?!");
}

#[test]
fn empty_pool() {
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");
    /* Deliberately don't add any addresses, so we'll fail when we try and allocate something */
    let addrpool: PoolAddresses = Default::default();
    assert_eq!(
        p.allocate_address(
            b"client",
            None,
            &addrpool,
            DEFAULT_MIN_LEASE,
            DEFAULT_MAX_LEASE,
        )
        .expect_err("Got allocated an address from an empty pool!"),
        Error::NoAssignableAddress
    );
}

#[test]
fn reacquire_lease() {
    /* o The client's current address as recorded in the client's current binding */
    let requested = "192.168.0.100".parse().unwrap();
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");
    p.reserve_address(b"client", requested);
    let mut addrpool: PoolAddresses = Default::default();
    addrpool.insert("192.168.0.100".parse().unwrap());
    addrpool.insert("192.168.0.101".parse().unwrap());
    addrpool.insert("192.168.0.102".parse().unwrap());
    let lease = p
        .allocate_address(
            b"client",
            Some(requested),
            &addrpool,
            DEFAULT_MIN_LEASE,
            DEFAULT_MAX_LEASE,
        )
        .expect("Failed to allocate address");

    assert_eq!(lease.ip, requested);
    assert!(lease.expire > std::time::Duration::from_secs(0));
}

#[test]
fn reacquire_expired_lease() {
    /* o The client's previous address as recorded in the client's (now expired or released)
     * binding, if that address is in the server's pool of available addresses and not already
     * allocated */
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");
    let requested = "192.168.0.100".parse().unwrap();

    let mut addrpool: PoolAddresses = Default::default();
    addrpool.insert("192.168.0.100".parse().unwrap());
    addrpool.insert("192.168.0.101".parse().unwrap());
    addrpool.insert("192.168.0.102".parse().unwrap());
    p.reserve_expired_address(b"client", requested);
    let lease = p
        .allocate_address(
            b"client",
            Some(requested),
            &addrpool,
            DEFAULT_MIN_LEASE,
            DEFAULT_MAX_LEASE,
        )
        .expect("Failed to allocate address");

    assert_eq!(lease.ip, requested);
    assert!(lease.expire > std::time::Duration::from_secs(0));
}

#[test]
fn acquire_requested_address_success() {
    /* o The address requested in the 'Requested IP Address' option, if that address is valid and
     * not already allocated, ELSE
     */
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");
    let requested = "192.168.0.101".parse().unwrap();

    let mut addrpool: PoolAddresses = Default::default();
    addrpool.insert("192.168.0.100".parse().unwrap());
    addrpool.insert("192.168.0.101".parse().unwrap());
    addrpool.insert("192.168.0.102".parse().unwrap());

    let lease = p
        .allocate_address(
            b"client",
            Some(requested),
            &addrpool,
            DEFAULT_MIN_LEASE,
            DEFAULT_MAX_LEASE,
        )
        .expect("Failed to allocate address");

    assert_eq!(lease.ip, requested);
}

#[test]
fn acquire_requested_address_in_use() {
    /* o The address requested in the 'Requested IP Address' option, if that address is valid and
     * not already allocated, ELSE
     */
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");
    let requested = "192.168.0.101".parse().unwrap();
    p.reserve_address(b"other-client", requested);

    let mut addrpool: PoolAddresses = Default::default();
    addrpool.insert("192.168.0.1".parse().unwrap());

    let lease = p
        .allocate_address(
            b"client",
            Some(requested),
            &addrpool,
            DEFAULT_MIN_LEASE,
            DEFAULT_MAX_LEASE,
        )
        .expect("Failed to allocate address");

    /* Do not assigned the reserved address! */
    assert_ne!(lease.ip, requested);
}

#[test]
fn acquire_requested_address_invalid() {
    /* o The address requested in the 'Requested IP Address' option, if that address is valid and
     * not already allocated, ELSE
     */
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");

    let mut addrpool: PoolAddresses = Default::default();
    addrpool.insert("192.168.0.1".parse().unwrap());

    let requested = "10.0.0.1".parse().unwrap();
    let lease = p
        .select_address(b"client", Some(requested), &addrpool)
        .expect("Failed to allocate address");

    /* Do not assigned the reserved address! */
    assert_ne!(lease.ip, requested);
}

#[test]
fn dont_hand_out_old_stale_lease() {
    /* If this client previously had an address that is no longer in the pool,
     * don't hand out the old address! Give them a new one!
     */
    let mut p = Pool::new_in_memory().expect("Failed to create in memory pools");

    let mut addrpool: PoolAddresses = Default::default();
    let old_reserved = "192.168.0.101".parse().unwrap();
    p.reserve_address(b"client", old_reserved);

    addrpool.insert("192.168.0.100".parse().unwrap());

    let lease = p
        .select_address(b"client", Some(old_reserved), &addrpool)
        .expect("Failed to allocate address");

    /* Do not assigned the old_reserved address! */
    assert_ne!(lease.ip, old_reserved);
}
