/*   Copyright 2024 Perry Lorier
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
 *  Configuration for the mDNS advertiser.
 */

use crate::config::{Error, parse_boolean, parse_string, type_to_name};
use yaml_rust::yaml;

#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Whether to advertise the API over mDNS.  Defaults to enabled whenever
    /// there is a TCP api-listener to advertise.
    pub enabled: Option<bool>,
    /// The DNS-SD instance name to advertise.  Defaults to the system hostname.
    pub instance_name: Option<String>,
}

pub fn parse(fragment: &yaml::Yaml) -> Result<Config, Error> {
    let mut conf = Config::default();
    match fragment {
        yaml::Yaml::Null => Ok(conf),
        yaml::Yaml::Hash(h) => {
            for (k, v) in h {
                match k.as_str() {
                    Some("enable") => {
                        conf.enabled = parse_boolean("mdns enable", v)?;
                    }
                    Some("instance-name") => {
                        conf.instance_name = parse_string("mdns instance-name", v)?;
                    }
                    Some(o) => {
                        return Err(Error::InvalidConfig(format!(
                            "Unknown mdns configuration option {}",
                            o
                        )));
                    }
                    None => {
                        return Err(Error::InvalidConfig(format!(
                            "mdns configuration should be keyed by String, not {}",
                            type_to_name(k)
                        )));
                    }
                }
            }
            Ok(conf)
        }
        e => Err(Error::InvalidConfig(format!(
            "mdns should be a Hash, not {}",
            type_to_name(e)
        ))),
    }
}
