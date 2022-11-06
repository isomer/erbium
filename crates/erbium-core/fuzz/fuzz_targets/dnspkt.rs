#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate erbium;

fuzz_target!(|data: &[u8]| {
    if let Ok(pkt) = erbium::dns::parse::PktParser::new(data).get_dns() {
        // Check we can serialise this back out.
        let d1 = pkt.serialise();
        // Check we can parse what we serialised.
        let pkt2 = match erbium::dns::parse::PktParser::new(&d1).get_dns() {
            Ok(pkt) => pkt,
            Err(e) => panic!("{}: {:?} {:?}", e, d1, pkt),
        };
        let d2 = pkt2.serialise();
        let pkt3 = match erbium::dns::parse::PktParser::new(&d2).get_dns() {
            Ok(pkt) => pkt,
            Err(e) => panic!("{}: {:?} {:?}", e, d2, pkt2),
        };
        assert_eq!(pkt2, pkt3);
    }
});
