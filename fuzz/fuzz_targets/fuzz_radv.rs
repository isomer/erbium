#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate erbium;
use erbium::radv::icmppkt::*;

fuzz_target!(|radv: Icmp6| {
    if let Icmp6::RtrAdvert(_) = radv {
        let data = serialise(&radv);
        let radv2 = parse(&data).unwrap();
        assert_eq!(radv, radv2)
    }
});
