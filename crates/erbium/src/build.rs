extern crate vergen;

fn main() {
    let mut conf = vergen::Config::default();
    *conf.git_mut().semver_dirty_mut() = Some("-dirty");
    *conf.cargo_mut().features_mut() = true;
    match vergen::vergen(conf.clone()) {
        Ok(()) => {}
        Err(_) => {
            /* Try again but this time disabling git, in case this is being built from outside git
             */
            *conf.git_mut().enabled_mut() = false;
            vergen::vergen(conf).expect("Unable to get vergen build information");
        }
    }
}
