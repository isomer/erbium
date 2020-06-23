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

use std::error::Error;
use tokio::stream::StreamExt;

use erbium::*;

async fn go() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() > 2 {
        println!("Usage: {} <configfile>", args[0].to_string_lossy());
        return Ok(());
    }
    let netinfo = net::netinfo::SharedNetInfo::new().await;
    let config_file = if args.len() == 1 {
        std::path::Path::new("erbium.conf")
    } else {
        std::path::Path::new(&args[1])
    };
    let conf = erbium::config::load_config_from_path(config_file).await?;
    let mut services = futures::stream::FuturesUnordered::new();

    println!("Configuration: {:?}", *conf.lock().await);

    services.push(tokio::spawn(dhcp::run(netinfo, conf)));
    services.push(tokio::spawn(dns::run()));

    let x = services.next().await.unwrap();
    println!("Service complete: {:?}", x);

    Ok(())
}

#[tokio::main]
async fn main() {
    match go().await {
        Ok(()) => (),
        Err(x) => println!("Error: {}", x),
    }
}
