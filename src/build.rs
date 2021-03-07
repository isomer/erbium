extern crate vergen;

fn main() {
    vergen::vergen(vergen::Config::default()).expect("Unable to generate the cargo keys!");
}
