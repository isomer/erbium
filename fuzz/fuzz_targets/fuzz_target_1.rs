#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate erbium;

fuzz_target!(|data: &[u8]| {
    let mut pools = erbium::dhcp::pool::Pool::new_in_memory().expect("failed to create pool");
    let dst = "192.168.0.1".parse().unwrap();
    let serverids = std::collections::HashSet::new();

    let cfg = erbium::config::Config {
        dhcp: erbium::dhcp::config::Config {
            policies: vec![erbium::dhcp::config::Policy {
                match_subnet: Some(
                    erbium::net::Ipv4Subnet::new("192.0.2.0".parse().unwrap(), 24).unwrap(),
                ),
                ..Default::default()
            }],
        },
    };

    erbium::dhcp::handle_pkt(&mut pools, data, dst, serverids, 1, &cfg);
});
