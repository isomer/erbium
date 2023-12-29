/*   Copyright 2023 Perry Lorier
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
 *  Tests to verify requirements of RFC4861: Neighbor Discovery for IP version 6
 */

use crate::radv;
use radv::config;
use radv::icmppkt;
use radv::ADV_DEFAULT_LIFETIME;

impl Default for config::Pref64 {
    fn default() -> Self {
        config::Pref64 {
            lifetime: std::time::Duration::from_secs(600),
            prefix: "2001:db8::".parse().unwrap(),
            prefixlen: 64,
        }
    }
}

impl Default for config::Prefix {
    fn default() -> Self {
        config::Prefix {
            addr: "2001:db8::".parse().unwrap(),
            prefixlen: 64,
            onlink: true,
            autonomous: true,
            valid: std::time::Duration::from_secs(2592000),
            preferred: std::time::Duration::from_secs(604800),
        }
    }
}

/* Section 2.3: All interfaces on routers MUST have a link-local address.
 * Justification: Kernels responsibility.
 */

/* Section 4.1: [Reserved field] MUST be initialized to zero by the sender and MUST be ignored by
 * the receiver.
 */
#[test]
fn test_router_solitication_reserved_must_be_ignored() {
    let pkt = [
        133u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 253, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];
    assert!(icmppkt::parse(&pkt).is_ok());
}

/* Section 4.1: The link-layer address of the sender, if known.  MUST NOT be included if the Source
 * Address is the unspecified address.  Otherwise, it SHOULD be included on link layers that have
 * addresses.
 * Justification: erbium doesn't send router solicitations.
 */

/* Section 4.1: Future versions of this protocol may define new option types.  Receivers MUST
 * silently ignore any options they do not recognize and continue processing the message.
 */
#[test]
fn test_solicitations_may_contain_unknown_options() {
    let pkt = [
        133u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 253, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    ];
    assert!(icmppkt::parse(&pkt).is_ok());
}

/* Section 4.2: Source Address MUST be the link-local address assigned to the interface from which
 * this message is sent.
 * TODO
 */

/* Section 4.2: Reserved: A 6-bit unused field.  It MUST be initialized to zero by the sender
 * and MUST be ignored by the receiver.
 */
#[test]
fn test_reserved_is_zero() {
    let conf = crate::config::Config::default();
    let intf = config::Interface::default();
    let msg = radv::RaAdvService::build_announcement_pure(
        &conf,
        &intf,
        Some([1, 2, 3, 4, 5, 6]),
        Some(1500),
        std::net::Ipv6Addr::UNSPECIFIED,
        ADV_DEFAULT_LIFETIME,
    );
    let pkt = icmppkt::serialise(&radv::icmppkt::Icmp6::RtrAdvert(msg));
    assert_eq!(pkt[5] & 0b00111111, 0b0);
}

/* Section 4.2: Receivers MUST silently ignore any options they do not recognize and continue
 * processing the message.
 *
 * Justification: We send, not receive router announcements.
 */

/* Section 4.3:  Reserved.  It MUST be initialized to zero by the sender and MUST be ignored by the receiver.
 *
 * Target Address The IP address of the target of the solicitation.  It MUST NOT be a multicast address.
 *
 * Source link-layer address MUST NOT be included when the source IP address is the
 *   unspecified address.  Otherwise, on link layers that have addresses this option MUST be
 *   included in multicast solicitations and SHOULD be included in unicast solicitations.
 *
 * Receivers MUST silently ignore any options they do not recognize and continue processing the message.
 *
 * Justification: Neighbour solitications are handled by the kernel, not erbium.
 */

/* Section 4.4
 * Justification: Neighbour advertisements are handled by the kernel, not erbium.
 */

/* Section 4.5
 * Justification: Redirects are handled by the kernel, not erbium.
 */

/* Section 4.6: Nodes MUST silently discard an ND packet that contains an option with length zero.
 */
#[test]
fn test_zero_length_option() {
    let pkt = [133u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 253, 0x0];
    assert!(icmppkt::parse(&pkt).is_err());
}

/* Section 4.6.1:
 * [Source Link Layer address MUST be ignored for neighbour discovery, except for ... Router
 * Solicitation.]
 *
 * The Target Link-Layer Address option contains the link-layer address of the target, it must be
 * ignored in ... router solicitations]
 *
 */
#[test]
fn target_lladdr_ignored_in_router_solicitations() {
    let pkt = [
        133u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 2, 1, 1, 2, 3, 4, 5, 6,
    ];
    assert!(icmppkt::parse(&pkt).is_ok());
}

/* Section 4.6.2
 *  In other words, if the L flag is not set a host MUST NOT conclude that an address derived from
 *  the prefix is off-link.  That is, it MUST NOT update a previous indication that the address is
 *  on-link.
 *
 * Justification: onlink determination is performed by the kernel.
 */

/* Section 4.6.2
 *       Reserved1 MUST be initialized to zero by the sender and MUST be ignored by the receiver.
 */
#[test]
fn prefix_reserved1_is_zero() {
    let conf = crate::config::Config::default();
    let intf = config::Interface::default();
    let msg = radv::RaAdvService::build_announcement_pure(
        &conf,
        &intf,
        Some([1, 2, 3, 4, 5, 6]),
        Some(1500),
        std::net::Ipv6Addr::UNSPECIFIED,
        ADV_DEFAULT_LIFETIME,
    );
    let pkt = icmppkt::serialise(&radv::icmppkt::Icmp6::RtrAdvert(msg));
    assert_eq!(pkt[8 + 4] & 0b00111111, 0b0);
}

/* Section 4.6.2
 *   Reserved2 [..] MUST be initialized to zero by the sender and MUST be ignored by the receiver.
 */
#[test]
fn prefix_reserved2_is_zero() {
    let conf = crate::config::Config::default();
    let intf = config::Interface::default();
    let msg = radv::RaAdvService::build_announcement_pure(
        &conf,
        &intf,
        Some([1, 2, 3, 4, 5, 6]),
        Some(1500),
        std::net::Ipv6Addr::UNSPECIFIED,
        ADV_DEFAULT_LIFETIME,
    );
    let pkt = icmppkt::serialise(&radv::icmppkt::Icmp6::RtrAdvert(msg));
    assert_eq!(&pkt[12..16], &[0, 0, 0, 0]);
}

/* Section 4.6.2
 *      The Prefix Length field contains the number of valid leading bits in the prefix.  The bits
 *      in the prefix after the prefix length are reserved and MUST be initialized to zero by the
 *      sender and ignored by the receiver.  A router SHOULD NOT send a prefix option for the
 *      link-local prefix and a host SHOULD ignore such a prefix option.
 */
#[test]
fn prefix_length_must_have_zero_suffix() {
    let conf = crate::config::Config::default();
    let intf = config::Interface::default();
    let msg = radv::RaAdvService::build_announcement_pure(
        &conf,
        &intf,
        Some([1, 2, 3, 4, 5, 6]),
        Some(1500),
        std::net::Ipv6Addr::UNSPECIFIED,
        ADV_DEFAULT_LIFETIME,
    );
    let pkt = icmppkt::serialise(&radv::icmppkt::Icmp6::RtrAdvert(msg));
    assert_eq!(&pkt[12..16], &[0, 0, 0, 0]);
}

/* Section 4.6.2
 *   The Prefix Information option appears in Router Advertisement packets and MUST be silently
 *   ignored for other messages.
 */
#[test]
fn prefix_ignored_for_solicitation() {
    let pkt = [
        133u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x4, 64, 0b11000000, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(icmppkt::parse(&pkt).is_ok());
}

/* Section 4.6.3
 *   These fields are unused.  They MUST be initialized to zero by the sender and MUST be ignored
 *   by the receiver.
 *
 *   This option MUST be silently ignored for other Neighbor Discovery messages.
 *
 * Justification: redirection and it's options are the kernel's responsibility.
 */

/* Section 4.6.4 MTU
 *   Reserved [..] MUST be initialized to zero by the sender and MUST be ignored by the receiver.
 */
#[test]
fn mtu_reserved_must_be_zero() {
    let conf = crate::config::Config::default();
    let intf = config::Interface::default();
    let msg = radv::RaAdvService::build_announcement_pure(
        &conf,
        &intf,
        Some([1, 2, 3, 4, 5, 6]),
        Some(1500),
        std::net::Ipv6Addr::UNSPECIFIED,
        ADV_DEFAULT_LIFETIME,
    );
    let pkt = icmppkt::serialise(&radv::icmppkt::Icmp6::RtrAdvert(msg));
    assert_eq!(&pkt[26..=27], &[0, 0]);
}

#[test]
fn mtu_reserved_must_be_ignored() {
    let pkt = [
        134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 3, 4, 5, 6, 5, 1, 0xff,
        0xff, 0, 0, 5, 220,
    ];
    assert!(icmppkt::parse(&pkt).is_ok());
}

/* Section 4.6.4
 *   This option MUST be silently ignored for other Neighbor Discovery messages.
 *
 * TODO
 */

/* Section 6.1.1
 *   Hosts MUST silently discard any received Router Solicitation Messages.
 *
 * Justification: We're not a host, but a router.
 */

/* Section 6.1.1
 *  A router MUST silently discard any received Router Solicitation
 * messages that do not satisfy all of the following validity checks:
 *
 *    - The IP Hop Limit field has a value of 255, i.e., the packet
 *      could not possibly have been forwarded by a router.
 *  TODO: nix-rust does not provide this information (yet).
 *
 *    - ICMP Checksum is valid.
 *  TODO: This is hopefully checked by the kernel?
 *
 *    - ICMP Code is 0.
 *  TODO: write test.
 *
 *    - ICMP length (derived from the IP length) is 8 or more octets.
 *  TODO: write test
 *
 *    - All included options have a length that is greater than zero.
 *  Justification: tested above.
 *
 *    - If the IP source address is the unspecified address, there is no
 *      source link-layer address option in the message.
 *  TODO: Write code, then write test.
 */

/* Section 6.1.1
 *   The contents of the Reserved field, and of any unrecognized options, MUST be ignored.
 * Justification: tested above.
 */

/* Section 6.1.1.
 *   The contents of any defined options that are not specified to be used with Router Solicitation
 *   messages MUST be ignored and the packet processed as normal.
 * Justification: tested above.
 */

/* Section 6.1.2.
 *  A node MUST silently discard any received Router Advertisement
 *  messages that do not satisfy all of the following validity checks:
 *
 *    - IP Source Address is a link-local address.  Routers must use
 *      their link-local address as the source for Router Advertisement
 *      and Redirect messages so that hosts can uniquely identify
 *      routers.
 *  TODO: Check
 *
 *    - The IP Hop Limit field has a value of 255, i.e., the packet
 *      could not possibly have been forwarded by a router.
 *  Justification: We set the hop limit to 255.
 *
 *    - ICMP Checksum is valid.
 *  Justification: The checksum is set by the kernel.
 *
 *    - ICMP Code is 0.
 *  TODO: Test?
 *
 *    - ICMP length (derived from the IP length) is 16 or more octets.
 *  TODO: Test?
 *
 *    - All included options have a length that is greater than zero.
 *  TODO: Test?
 */

/* Section 6.1.2
 *   The contents of the Reserved field, and of any unrecognized options, MUST be ignored.
 * Justification: Tested above.
 */

/* Section 6.1.2
 *   The contents of any defined options that are not specified to be used with Router
 *   Advertisement messages MUST be ignored and the packet processed as normal.
 * Justification: Duplicate requirement, tested above.
 */

/* Section 6.2.1
 *   A router MUST allow for the following conceptual variables to be configured by system management.
 *
 *   - IsRouter (default: FALSE)
 *   - AdvSendAdvertisements (default: FALSE)
 *     Note that AdvSendAdvertisements MUST be FALSE by default so that a node will not
 *     accidentally start acting as a router unless it is explicitly configured by system
 *     management to send Router Advertisements.
 *   - MaxRtrAdvertisements (default: 600)
 *     MUST be no less than 4 seconds and no greater than 1800 seconds.
 *   - MinRtrAdvInterval (default: 0.33 * MaxRtrAdvInterval If MaxRtrAdvInterval >= 9 seconds;
 *     otherwise, the Default is MaxRtrAdvInterval.)
 *     MUST be no less than 3 seconds and no greater than .75 * MaxRtrAdvInterval.
 *   - AdvManagedFlag (default: FALSE)
 *   - AdvOtherConfigFlag (default: FALSE)
 *   - AdvLinkMTU (default: 0)
 *   - AdvReachableTime (default: 0)
 *     MUST be no greater than 3,600,000 milliseconds (1 hour).
 *   - AdvRetransTimer (default: 0)
 *   - AdvCurHopLimit (default: The value specified in the "Assigned Numbers" [ASSIGNED] that was in effect at the time of implementation.)
 *   - AdvDefaultLifetime (default: 3 * MaxRtrAdvInterval)
 *     MUST be either zero or between MaxRtrAdvInterval and 9000 seconds.
 *   - AdvPrefixList:
 *     - AdvValidLifetime (default: 30 days)
 *     - AdvOnLinkFlag (default: TRUE)
 *     - AdvPreferredLifetime (default: 7 days)
 *     - AdvAutonomousFlag (default: TRUE)
 */

/* Section 6.2.1
 *   However, external router behavior MUST be the same as host behavior with respect to these
 *   variables.  In particular, this includes the occasional randomization of the ReachableTime
 *   value as described in Section 6.3.2.
 */

/* Section 6.2.2
 *   A router MUST NOT send Router Advertisements out any interface that is not an advertising interface.
 */

/* Section 6.2.2
 *   A router MUST join the all-routers multicast address on an advertising interface.
 */

/* Section 6.2.4
 *   A host MUST NOT send Router Advertisement messages at any time.
 *
 * Justification: We only send RA's when we're a router.
 */

/* Section 6.2.5
 *   In addition, the host MUST ensure that subsequent Neighbor Advertisement messages sent from
 *   the interface have the Router flag set to zero.
 *
 * TODO
 */

/* Section 6.2.5
 *   Note that system management may disable a router's IP forwarding capability [..], subsequent
 *   Router Advertisements MUST set the Router Lifetime field to zero.
 * TODO: Implement check, add test.
 */

/* Section 6.2.6
 *   A host MUST silently discard any received Router Solicitation messages.
 *
 * Justification: We're a router.
 */

/* Section 6.2.6
 *  In all cases, Router Advertisements sent in response to a Router Solicitation MUST be delayed
 *  by a random time between 0 and MAX_RA_DELAY_TIME seconds.
 *
 *  In addition, consecutive Router Advertisements sent to the all-nodes multicast address MUST be
 *  rate limited to no more than one advertisement every MIN_DELAY_BETWEEN_RAS seconds.
 *
 *  In all cases, however, unsolicited multicast advertisements MUST NOT be sent more frequently
 *  than indicated by MinRtrAdvInterval.
 *
 *  Router Solicitations in which the Source Address is the unspecified address MUST NOT update the
 *  router's Neighbor Cache;
 *
 *  If the router already has a Neighbor Cache entry for the solicitation's sender, the
 *  solicitation contains a Source Link-Layer Address option, and the received link-layer address
 *  differs from that already in the cache, then the link-layer address SHOULD be updated in the
 *  appropriate Neighbor Cache entry, and its reachability state MUST also be set to STALE.
 *
 *  Whether or not a Source Link-Layer Address option is provided, if a Neighbor Cache entry for
 *  the solicitation's sender exists (or is created) the entry's IsRouter flag MUST be set to
 *  FALSE.
 */

/* Section 6.3.4
 *   Hosts accept the union of all received information; the receipt of a Router Advertisement MUST
 *   NOT invalidate all information received in a previous advertisement or from another source.
 */

/* Section 6.3.4
 *   [..] a host MUST NOT interpret the unspecified value as meaning change back to the default
 *   value that was in use before the first Router Advertisement was received.
 */

/* Section 6.3.4
 *   [..] a host MUST retain at least two router addresses and SHOULD retain more.
 */

/* Section 6.3.4
 *   If the [router] advertisement contains a Source Link-Layer Address option, the link-layer
 *   address SHOULD be recorded in the Neighbor Cache entry for the router (creating an entry if
 *   necessary) and the IsRouter flag in the Neighbor Cache entry MUST be set to TRUE.
 *
 *   If no Source Link-Layer Address is included, but a corresponding Neighbor Cache entry exists,
 *   its IsRouter flag MUST be set to TRUE.
 *
 *   If a Neighbor Cache entry is created for the router, its reachability state MUST be set to STALE [..].
 *
 *   If a cache entry already exists and is updated with a different link-layer address, the
 *   reachability state MUST also be set to STALE.
 */

/* Section 6.3.4
 *   [..] a Prefix Information option with the on-link flag set to zero conveys no information
 *   concerning on-link determination and MUST NOT be interpreted to mean that addresses covered by
 *   the prefix are off-link.
 */

/* Section 6.3.4
 *   When removing a router from the Default Router list, the node MUST update the Destination
 *   Cache in such a way that all entries using the router perform next-hop determination again
 *   rather than continue sending traffic to the (deleted) router.
 */

/* Section 6.3.7
 *   Once the host sends a Router Solicitation, and receives a valid Router Advertisement with a
 *   non-zero Router Lifetime, the host MUST desist from sending additional solicitations on that
 *   interface, until the next time one of the above events occurs.
 */

/* Section 7.1.1.  Validation of Neighbor Solicitations
 * Section 7.1.2.  Validation of Neighbor Advertisements
 *   Justification: Erbium doesn't handle Neighbor solicitations/advertisements, they're processed by the kernel.
 */

/* Section 7.2.  Address Resolution.
 *  Justification: Erbium doesn't participate in address resolution, they're handled by the kernel.
 * Section 7.1.2.  Validation of Neighbor Advertisements
 *   Justification: Erbium doesn't handle Neighbor solicitations/advertisements, they're processed by the kernel.
 */

/* Section 8.2.  Router Specification
 */
