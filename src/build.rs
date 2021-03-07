extern crate vergen;

fn main() {
    let mut conf = vergen::Config::default();
    match vergen::vergen(conf) {
        Ok(()) => {}
        Err(vergen::Error::Git2(_)) => {
            /* If this is not from a git repository, ignore trying to get the git info */
            *conf.git_mut().branch_mut() = false;
            *conf.git_mut().commit_timestamp_mut() = false;
            *conf.git_mut().rerun_on_head_change_mut() = false;
            *conf.git_mut().semver_mut() = false;
            *conf.git_mut().sha_mut() = false;
            vergen::vergen(conf).expect("Unable to get vergen build information");
        }
        Err(e) => {
            panic!("Unable to get vergen build information: {}", e);
        }
    }
}
