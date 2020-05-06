use rusqlite;

pub struct Lease {
    pub ip: std::net::Ipv4Addr,
    pub lease: std::time::Duration,
}

pub struct Pools {
    conn: rusqlite::Connection,
}

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
