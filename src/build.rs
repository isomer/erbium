extern crate vergen;

use vergen::{gen, ConstantsFlags};

fn main() {
    let flags = ConstantsFlags::all();

    // Generate the 'cargo:' key output
    gen(flags).expect("Unable to generate the cargo keys!");
}
