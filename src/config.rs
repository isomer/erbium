use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncReadExt;
use yaml_rust::yaml::YamlLoader;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
    DhcpError(crate::dhcp::config::Error),
    YamlError(yaml_rust::scanner::ScanError),
    MissingConfig,
    MultipleConfigs,
    ConfigProcessFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "I/O Error reading configuration file: {}", e),
            Error::Utf8Error(e) => {
                write!(f, "UTF8 Decoding error reading configuration file: {}", e)
            }
            Error::DhcpError(e) => write!(f, "DHCP Config loading error: {}", e),
            Error::YamlError(e) => write!(f, "Yaml parse erorr while reading configuration: {}", e),
            Error::MissingConfig => write!(f, "Configuration is empty/missing"),
            Error::MultipleConfigs => {
                write!(f, "Configuration file contains multiple configurations")
            }
            Error::ConfigProcessFailed => write!(f, "Configuration process failed"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
pub struct Config {
    pub dhcp: crate::dhcp::config::Config,
}

pub type SharedConfig = std::sync::Arc<tokio::sync::Mutex<Config>>;

fn load_config_from_string(cfg: &str) -> Result<SharedConfig, Error> {
    let mut y = YamlLoader::load_from_str(cfg).map_err(Error::YamlError)?;
    match y.len() {
        0 => return Err(Error::MissingConfig),
        1 => (),
        _ => return Err(Error::MultipleConfigs),
    }
    let conf = Config {
        dhcp: crate::dhcp::config::Config::new(&mut y[0]).map_err(Error::DhcpError)?,
    };
    Ok(std::sync::Arc::new(tokio::sync::Mutex::new(conf)))
}

/* We support reading configs from a yaml file, _or_ a program (eg a shell script?) that outputs
 * yaml on stdout.
 *
 * TODO: Implement reading a directory of configs.
 */
pub async fn load_config_from_path(path: &std::path::Path) -> Result<SharedConfig, Error> {
    let metadata = std::fs::metadata(path).map_err(Error::IoError)?;
    let configdata = if metadata.permissions().mode() & 0o111 != 0 {
        let output = tokio::process::Command::new(path)
            .output()
            .await
            .map_err(Error::IoError)?;
        if !output.status.success() {
            return Err(Error::ConfigProcessFailed);
        }
        String::from_utf8(output.stdout).map_err(Error::Utf8Error)?
    } else {
        let mut contents = vec![];
        tokio::fs::File::open(path)
            .await
            .map_err(Error::IoError)?
            .read_to_end(&mut contents)
            .await
            .map_err(Error::IoError)?;

        String::from_utf8(contents).map_err(Error::Utf8Error)?
    };

    load_config_from_string(&configdata)
}

#[test]
fn test_config_parse() -> Result<(), Error> {
    load_config_from_string(
        "---
dhcp:
    Policies:
      - match-interface: eth0
        apply-dns-server: ['8.8.8.8', '8.8.4.4']
        apply-subnet: 192.168.0.0/24

        Policies:
           - { match-hostname: myhost, apply-address: [192.168.0.1] }


      - match-interface: dmz
        apply-dns-server: ['8.8.8.8']
        apply-subnet: 192.0.2.0/24

        # Reserve some space from the pool for servers
        Policies:
          - apply-range: {start: 192.0.2.10, end: 192.0.2.20}

            # From the reserved pool, assign a static address.
            Policies:
              - { match-hardware-address: 00:01:02:03:04:05, apply-address: [192.168.0.2] }

          # Reserve space for VPN endpoints
          - match-user-class: VPN
            apply-subnet: 192.0.2.128/25
        ",
    )?;
    Ok(())
}
