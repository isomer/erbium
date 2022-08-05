#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate erbium;
use erbium::radv::icmppkt::*;

fuzz_target!(|data: &[u8]| {
    if let Ok(radv @ Icmp6::RtrAdvert(_)) = parse(data) {
        let data = serialise(&radv);
        let radv2 = parse(&data).unwrap();
        /* radv2 is unlikely to match radv because it wasnt serialised by us */
        let data2 = serialise(&radv);
        assert_eq!(data, data2);
        let radv3 = parse(&data).unwrap();
        assert_eq!(radv2, radv3);
    }
});
