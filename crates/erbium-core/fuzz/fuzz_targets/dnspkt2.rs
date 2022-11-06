#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate erbium;
use libfuzzer_sys::arbitrary::Arbitrary as _;

fuzz_target!(|pkt: erbium::dns::dnspkt::DNSPkt| {
    let d1 = pkt.serialise();
    let pkt2 = match erbium::dns::parse::PktParser::new(&d1).get_dns() {
        Ok(pkt) => pkt,
        Err(e) => panic!("First: {}: {:?} {:?}", e, d1, pkt),
    };
    let d2 = pkt2.serialise();
    let pkt3 = match erbium::dns::parse::PktParser::new(&d2).get_dns() {
        Ok(pkt) => pkt,
        Err(e) => panic!("Second: {}: {:?} {:?}", e, d1, pkt),
    };
    assert_eq!(pkt2, pkt3);
});
