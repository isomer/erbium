use rusqlite;

pub struct Pools {
    conn: rusqlite::Connection,
}

impl Pools {
    pub fn new() -> Result<Pools, Box<dyn std::error::Error>> {
        Ok(Pools {
            conn: rusqlite::Connection::open("inmemory:")?,
        })
    }

    pub fn allocate_address(&self, _name: &str) -> std::net::IpAddr {
        "192.168.0.100".parse().unwrap()
    }
}
