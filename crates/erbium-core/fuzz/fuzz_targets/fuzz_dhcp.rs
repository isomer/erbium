#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut pools = erbium::dhcp::pool::Pool::new_in_memory().expect("failed to create pool");
    let serverids = std::collections::HashSet::new();

    let cfg = erbium::config::Config {
        dhcp: erbium::dhcp::config::Config {
            policies: vec![erbium::dhcp::config::Policy {
                match_subnet: Some(
                    erbium_net::Ipv4Subnet::new("192.0.2.0".parse().unwrap(), 24).unwrap(),
                ),
                ..Default::default()
            }],
        },
        ..Default::default()
    };

    if let Ok(pkt) = erbium::dhcp::dhcppkt::parse(data) {
        let request = erbium::dhcp::DHCPRequest {
            pkt,
            serverip: "192.168.0.1".parse().unwrap(),
            ifindex: 1,
            if_mtu: Some(1500),
            if_router: None,
        };

        if let Ok(reply) = erbium::dhcp::handle_pkt(&mut pools, &request, serverids, &cfg).await {
            let _ = reply.serialise();
        }
    }
});
