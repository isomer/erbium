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
 *  Thin wrapper to start DNS services only.
 */
use futures::StreamExt as _;

extern crate erbium;

use erbium::dns;

enum Error {
    Config(erbium::config::Error),
    Dns(dns::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            Config(e) => write!(f, "Failed to load config: {}", e),
            Dns(e) => write!(f, "Dns Error: {}", e),
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
    let conf = erbium::config::load_config_from_path(config_file)
        .await
        .map_err(Error::Config)?;
    let mut services = futures::stream::FuturesUnordered::new();

    let dns = dns::DnsService::new(conf.clone())
        .await
        .map_err(Error::Dns)?;

    services.push(tokio::spawn(async move {
        dns.run().await.map_err(|err| err.to_string())
    }));

    while let Some(x) = services.next().await {
        println!("Service complete: {:?}", x)
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!(
        "erbium-dns {}{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("VERGEN_GIT_SHA")
            .map(|sha| format!(" ({})", sha))
            .unwrap_or_else(|| "".into())
    );
    match go().await {
        Ok(()) => (),
        Err(x) => {
            println!("Error: {}", x);
            std::process::exit(1);
        }
    }
}
