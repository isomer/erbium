/*   Copyright 2021 Perry Lorier
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
 *  Thin wrapper to start DHCP services only.
 */

use futures::StreamExt as _;

extern crate erbium;

use erbium::dhcp;

enum Error {
    ConfigError(std::path::PathBuf, erbium::config::Error),
    ServiceError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Error::ConfigError(ref path, ref e) => write!(
                f,
                "Failed to load config from {}: {}",
                path.to_string_lossy(),
                e
            ),
            Error::ServiceError(ref e) => write!(f, "{}", e),
        }
    }
}

async fn go() -> Result<(), Error> {
    let args: Vec<_> = std::env::args_os().collect();
    let config_file = match args.len() {
        1 => std::path::Path::new("erbium.conf"),
        2 => std::path::Path::new(&args[1]),
        _ => {
            println!("Usage: {} <configfile>", args[0].to_string_lossy());
            return Ok(());
        }
    };
    let netinfo = erbium_net::netinfo::SharedNetInfo::new().await;
    let conf = erbium::config::load_config_from_path(config_file)
        .await
        .map_err(|e| Error::ConfigError(config_file.to_path_buf(), e))?;
    let mut services = futures::stream::FuturesUnordered::new();

    let dhcp = std::sync::Arc::new(
        dhcp::DhcpService::new(netinfo.clone(), conf.clone())
            .await
            .map_err(Error::ServiceError)?,
    );
    services.push(tokio::spawn(async move { dhcp.run().await }));

    while let Some(x) = services.next().await {
        println!("Service complete: {:?}", x)
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    match go().await {
        Ok(()) => (),
        Err(x) => {
            println!("Error: {}", x);
            std::process::exit(1);
        }
    }
}
