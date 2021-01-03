/*   Copyright 2020 Perry Lorier
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Thin wrapper to start all services.
 */

use lazy_static::*;
use log::{error, info};
use prometheus::register_int_counter;

lazy_static! {
    static ref HIGH_FIVE_COUNTER: prometheus::IntCounter =
        register_int_counter!("highfives", "Number of high fives received").unwrap();
}

use tokio::stream::StreamExt;

use erbium::*;

enum Error {
    ConfigError(std::path::PathBuf, erbium::config::Error),
    ServiceError(String),
    CommandLineError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConfigError(path, e) => write!(
                f,
                "Failed to load config from {}: {}",
                path.to_string_lossy(),
                e
            ),
            Error::ServiceError(msg) => write!(f, "{}", msg),
            Error::CommandLineError(msg) => write!(f, "{}", msg),
        }
    }
}

async fn go() -> Result<(), Error> {
    /* Process the command line options.
     * Currently we don't do anything smart with the command line.
     */
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() > 2 || args[1].to_string_lossy().starts_with("-") {
        return Err(Error::CommandLineError(format!(
            "Usage: {} <configfile>",
            args[0].to_string_lossy()
        )));
    }
    let config_file = if args.len() == 1 {
        std::path::Path::new("erbium.conf")
    } else {
        std::path::Path::new(&args[1])
    };
    let conf = erbium::config::load_config_from_path(config_file)
        .await
        .map_err(|e| Error::ConfigError(config_file.to_path_buf(), e))?;

    /* Build the shared network information database that various systems depend on */
    let netinfo = net::netinfo::SharedNetInfo::new().await;

    /* Initialise each of the services, and record them */
    let mut services = futures::stream::FuturesUnordered::new();
    #[cfg(feature = "dns")]
    services.push(tokio::spawn(dns::run()));

    let dhcp;
    #[cfg(feature = "dhcp")]
    {
        dhcp = std::sync::Arc::new(
            dhcp::DhcpService::new(netinfo.clone(), conf.clone())
                .await
                .map_err(Error::ServiceError)?,
        );
        let dhcp_copy = dhcp.clone();
        services.push(tokio::spawn(async move { dhcp_copy.run().await }));
    }
    #[cfg(feature = "radv")]
    {
        let radv = std::sync::Arc::new(
            radv::RaAdvService::new(netinfo.clone(), conf.clone())
                .map_err(|x| Error::ServiceError(x.to_string()))?,
        );

        services.push(tokio::spawn(async move { radv.run().await }));
    }
    #[cfg(feature = "http")]
    http::run(dhcp, conf.clone())
        .await
        .map_err(|x| Error::ServiceError(x.to_string()))?;

    /* TODO: Perhaps drop some of the capabilities we don't need? */

    /* Now start running them */
    let x = services.next().await.unwrap();
    error!("Service complete: {:?}", x);

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!(
        "erbium {} ({})",
        env!("CARGO_PKG_VERSION"),
        env!("VERGEN_SHA_SHORT")
    );
    match go().await {
        Ok(()) => (),
        Err(x) => {
            error!("Error: {}", x);
            std::process::exit(1);
        }
    }
}
