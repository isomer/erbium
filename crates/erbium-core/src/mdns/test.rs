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
 */

use super::*;

#[test]
fn hostname_is_a_single_label() {
    let h = hostname();
    assert!(
        !h.contains('.'),
        "hostname {:?} should be a single label",
        h
    );
    assert!(!h.is_empty());
}

#[tokio::test]
async fn find_api_port_returns_tcp_listener_port() {
    let conf = crate::config::load_config_from_string_for_test(
        "---
api-listeners: ['[::1]:9999']
",
    )
    .unwrap();
    assert_eq!(find_api_port(&conf).await, Some(9999));
}

#[tokio::test]
async fn find_api_port_skips_unix_listeners() {
    // A unix-socket listener has no port; there is no TCP listener to advertise.
    let conf = crate::config::load_config_from_string_for_test(
        "---
api-listeners: ['/var/lib/erbium/control']
",
    )
    .unwrap();
    assert_eq!(find_api_port(&conf).await, None);
}

#[tokio::test]
async fn find_api_port_picks_tcp_among_mixed_listeners() {
    let conf = crate::config::load_config_from_string_for_test(
        "---
api-listeners: ['/var/lib/erbium/control', '0.0.0.0:8080']
",
    )
    .unwrap();
    assert_eq!(find_api_port(&conf).await, Some(8080));
}

#[test]
fn config_disable_is_parsed() {
    let conf = config::parse(&yaml_fragment("enable: false")).unwrap();
    assert_eq!(conf.enabled, Some(false));
}

#[test]
fn config_instance_name_is_parsed() {
    let conf = config::parse(&yaml_fragment("instance-name: my-router")).unwrap();
    assert_eq!(conf.instance_name.as_deref(), Some("my-router"));
}

#[test]
fn config_unknown_option_is_rejected() {
    assert!(config::parse(&yaml_fragment("bogus: 1")).is_err());
}

#[test]
fn config_empty_defaults_to_enabled_and_default_instance() {
    let conf = config::Config::default();
    assert_eq!(conf.enabled, None);
    assert_eq!(conf.instance_name, None);
}

fn yaml_fragment(s: &str) -> yaml_rust::Yaml {
    yaml_rust::YamlLoader::load_from_str(s)
        .unwrap()
        .into_iter()
        .next()
        .unwrap()
}
