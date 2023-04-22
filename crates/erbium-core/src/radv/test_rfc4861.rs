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

/* Section 2.3: All interfaces on routers MUST have a link-local address.
 * Justification: Kernels responsibility.
 */

/* Section 4.1: [Reserved field] MUST be initialized to zero by the sender and MUST be ignored by
 * the receiver.
 */
#[test]
fn test_reserved_is_zero() {
    let conf = config::Interface {};
    let adv = build_announcement_pure(&conf, Some([1, 2, 3, 4, 5, 6]), Some(1500));
    let pkt = icmppkt::serialise(&icmppkt::Icmp6::RtrAdvert(adv));
    assert_eq!(pkt[4..9], [0, 0, 0, 0]);
}
