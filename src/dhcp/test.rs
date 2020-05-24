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
 *  Sections quoted from RFCs are covered by the terms specified in RFC3978.
 *
 *  Tests for DHCP functionality.
 */

use crate::dhcp;
use crate::dhcp::dhcppkt;
use crate::dhcp::pool;
use std::collections;
use std::net;
use tokio::sync;

const EXAMPLE_IP1: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 1); /* Documentation prefix 1 */
const EXAMPLE_IP2: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 2); /* Documentation prefix 2 */
const EXAMPLE_IP3: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 3); /* Documentation prefix 3 */
const EXAMPLE_IP4: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 4); /* Documentation prefix 4 */

const SERVER_IP: net::Ipv4Addr = EXAMPLE_IP1;
const SERVER_IP2: net::Ipv4Addr = EXAMPLE_IP2;
const NOT_SERVER_IP: net::Ipv4Addr = EXAMPLE_IP3;

fn mk_dhcp_request() -> dhcppkt::DHCP {
    dhcppkt::DHCP {
        op: dhcppkt::OP_BOOTREQUEST,
        htype: dhcppkt::HWTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid: 0,
        secs: 0,
        flags: 0,
        ciaddr: net::Ipv4Addr::UNSPECIFIED,
        yiaddr: net::Ipv4Addr::UNSPECIFIED,
        siaddr: net::Ipv4Addr::UNSPECIFIED,
        giaddr: net::Ipv4Addr::UNSPECIFIED,
        chaddr: vec![
            0x00, 0x00, 0x5E, 0x00, 0x53, 0x00, /* Reserved for documentation, per RFC7042 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        sname: vec![],
        file: vec![],
        options: dhcppkt::DhcpOptions {
            messagetype: dhcppkt::DHCPREQUEST,
            hostname: Some("example.org".to_string()),
            parameterlist: None,
            leasetime: None,
            serveridentifier: None,
            clientidentifier: None,
            other: collections::HashMap::new(),
        },
    }
}

fn mk_default_pools() -> pool::Pools {
    let mut pool = pool::Pools::new_in_memory().expect("Failed to create pool");
    pool.add_pool("default")
        .expect("Failed to create default pool");
    pool
}

#[test]
fn test_parsing_inverse_serialising() {
    let mut orig_pkt = mk_dhcp_request();
    let bytes = orig_pkt.serialise();
    let new_pkt = dhcppkt::parse(bytes.as_slice()).expect("Failed to parse DHCP packet");
    assert!(
        orig_pkt.sname.len() <= 64,
        "sname={:?} ({} <= 64 is false",
        orig_pkt.sname,
        orig_pkt.sname.len()
    );
    assert!(
        orig_pkt.chaddr.len() <= 16,
        "chaddr={:?} ({} <= 16 is false",
        orig_pkt.chaddr,
        orig_pkt.chaddr.len()
    );
    assert_eq!(orig_pkt, new_pkt);
}

/* rfc2131 Section 2: The 'client identifier' chosen by a DHCP client MUST be unique to that client
 * within the subnet to which the client is attached.
 *
 * Commentary: Only required by the client, not the server.
 */

/* rfc2131 Section 2: If the client uses a 'client identifier' in
 * one message, it MUST use that same identifier in all subsequent messages, to ensure that all
 * servers correctly identify the client.
 *
 * Commentary: Only required by the client, not the server.
 */

/* rfc2131 Section 2: A DHCP client must be prepared to receive DHCP messages with an 'options'
 * field of at least length 312 octets.
 *
 * Commentary: TODO: Check what happens when the server needs to send a huge reply to a client.
 * This is also not a requirement, as must is in lower case.
 */

/* rfc2131 Section 2: The remaining bits of the flags field are reserved for future use.  They MUST
 * be set to zero by clients and ignored by servers and relay agents.
 *
 * Commentary: Check the bits are ignord by servers.
 */
#[tokio::test]
async fn ignore_unused_flag_bits() {
    let mut p = mk_default_pools();
    let pkt = dhcppkt::DHCP {
        flags: 0x7FFF,
        ..mk_dhcp_request()
    };
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    dhcp::handle_discover(
        &mut p,
        &pkt,
        net::SocketAddr::new(net::IpAddr::V4(SERVER_IP), 68),
        serverids,
    )
    .expect("Failed to handle request");
}

/* rfc2131 Section 3.1 Step 3: The client broadcasts a DHCPREQUEST message that MUST include the
 * 'server identifier' option to indicate which server it has selected, and that MAY include other
 * options specifying desired configuration values.
 *
 * Commentary: Client side behaviour.
 */

/* rfc2131 Section 3.1 Step 3: The 'requested IP address' option MUST be set to the value of
 * 'yiaddr' in the DHCPOFFER message from the server.
 *
 * Commentary: Client side behaviour, but we should check we set the yiaddr correctly.
 */
#[tokio::test]
async fn confirm_yiaddr_set() {
    let mut p = mk_default_pools();
    let pkt = mk_dhcp_request();
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let reply = dhcp::handle_discover(
        &mut p,
        &pkt,
        net::SocketAddr::new(net::IpAddr::V4(SERVER_IP), 68),
        serverids,
    )
    .expect("Failed to handle request");
    assert_ne!(
        reply.yiaddr,
        net::Ipv4Addr::UNSPECIFIED,
        "yiaddr is not set on replies"
    );
}

/* rfc2131 Section 3.1 Step 3: To help ensure that any BOOTP relay agents forward the DHCPREQUEST
 * message to the same set of DHCP servers that received the original DHCPDISCOVER message, the
 * DHCPREQUEST message MUST use the same value in the DHCP message header's 'secs' field and be
 * sent to the same IP broadcast address as the original DHCPDISCOVER message.
 *
 * Commentary: Client side behaviour.
 */

/* rfc2131 Section 3.1 Step 5: If the client detects that the address is already in use (e.g.,
 * through the use of ARP), the client MUST send a DHCPDECLINE message to the server and restarts
 * the configuration process.
 *
 * Commentary: Client side behaviour.
 */

/* rfc2131 Section 3.1 Step 6: If the client used a 'client identifier' when it obtained the lease,
 * it MUST use the same 'client identifier' in the DHCPRELEASE message.
 *
 * Commentary: Client side behaviour.
 */

/* rfc2131 Section 3.2 Step 1: The server MUST broadcast the DHCPNAK message to the 0xffffffff broadcast address because the client may not have a correct network address or subnet mask, and the client may not be answering ARP requests.  Otherwise, the server MUST send the DHCPNAK message to the IP address of the BOOTP relay agent, as recorded in 'giaddr'.
 */
fn broadcast_failed_renew() {
    /* TODO */
}

/* rfc2131 Section 3.2 Step 3: If the client detects that the IP address in the DHCPACK message is
 * already in use, the client MUST send a DHCPDECLINE message to the server and restarts the
 * configuration process by requesting a new network address.
 *
 * Commentary: Client side behaviour.
 */

/* rfc2131 Section 3.4: The server SHOULD check the network address in a DHCPINFORM message for
 * consistency, but MUST NOT check for an existing lease.
 */
fn dhcpinform_dont_check_existing_lease() {
    /* TODO */
}

/* rfc2131 Section 3.5: If the client includes a list of parameters in a DHCPDISCOVER message, it
 * MUST include that list in any subsequent DHCPREQUEST messages.
 *
 * Commentary: Client side behaviour.
 */

/* rfc2131 Section 4.1: A server with multiple network addresses MUST be prepared to to accept any
 * of its network addresses as identifying that server in a DHCP message.  To accommodate
 * potentially incomplete network connectivity, a server MUST choose an address as a 'server
 * identifier' that, to the best of the server's knowledge, is reachable from the client.
 *
 * Commentary: The Server Identifier is set to the IP address of the interface the packet was
 * received on.  We remember all ServerIdentifiers we've ever handed out, and if it's not for one
 * of them, we ignore the packet as being for a different server.
 */
#[tokio::test]
async fn server_address_set() {
    let mut p = mk_default_pools();
    let pkt = mk_dhcp_request();
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let reply = dhcp::handle_discover(
        &mut p,
        &pkt,
        net::SocketAddr::new(net::IpAddr::V4(SERVER_IP), 68),
        serverids,
    )
    .expect("Failed to handle request");
    assert_ne!(
        reply
            .options
            .serveridentifier
            .expect("server identifier not set on repliy"),
        net::Ipv4Addr::UNSPECIFIED,
        "server identifier is not set on replies"
    );
}

#[tokio::test]
async fn ignore_other_request() {
    let pools = std::sync::Arc::new(sync::Mutex::new(
        pool::Pools::new_in_memory().expect("Failed to create pool"),
    ));
    let mut p = pools.lock().await;
    let mut pkt = mk_dhcp_request();
    pkt.options.serveridentifier = Some(NOT_SERVER_IP);
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    serverids.insert(SERVER_IP);
    serverids.insert(SERVER_IP2);
    let reply = dhcp::handle_request(
        &mut p,
        &pkt,
        net::SocketAddr::new(net::IpAddr::V4(SERVER_IP), 68),
        serverids,
    )
    .expect_err("Handled request not to me");
    assert_eq!(
        reply,
        dhcp::DhcpError::OtherServer,
        "Packet to not-a-server-ip should be ignored."
    );
}

/* RFC2131 Section 4.1: DHCP clients MUST use the IP address provided in the 'server identifier'
 * option for any unicast requests to the DHCP server.
 *
 * Commentary: Client side behaviour.
 */

/* RFC2131 Section 4.1: If the options in a DHCP message extend into the 'sname' and 'file' fields,
 * the 'option overload' option MUST appear in the 'options' field, with value 1, 2 or 3, as
 * specified in RFC 1533.
 *
 * Commentary: We don't yet support options in the sname or file fields.
 */

/* RFC2131 Section 4.1: If the 'option overload' option is present in the 'options' field, the
 * options in the 'options' field MUST be terminated by an 'end' option, and MAY contain one or
 * more 'pad' options to fill the options field.
 *
 * Commentary: We don't yet support the "option overload" option.
 */

/* RFC2131 Section 4.1: The options in the 'sname' and 'file' fields (if in use as indicated by the
 * 'options overload' option) MUST begin with the first octet of the field, MUST be terminated by
 * an 'end' option, and MUST be followed by 'pad' options to fill the remainder of the field.
 *
 * Commentary: We don't yet support the "option overload" option to have options in sname or file
 * fields.
 */

/* RFC2131 Section 4.1: Any individual option in the 'options', 'sname' and 'file' fields MUST be
 * entirely contained in that field.
 *
 * Commentary: We don't yet support the "option overload" option to have options in sname or file
 * fields.
 */

/* RFC2131 Section 4.1: The options in the 'options' field MUST be interpreted first, so that any
 * 'option overload' options may be interpreted.  The 'file' field MUST be interpreted next (if the
 * 'option overload' option indicates that the 'file' field contains DHCP options), followed by the
 * 'sname' field.
 *
 * Commentary: We don't yet support the "option overload" option to have options in sname or file
 * fields.
 */

/* RFC2131 Section 4.1: The client MUST adopt a retransmission strategy that incorporates a
 * randomized exponential backoff algorithm to determine the delay between retransmissions.
 *
 * Commentary: Client side behaviour.
 */

/* RFC2131 Section 4.1: A DHCP client MUST choose 'xid's in such a way as to minimize the chance of
 * using an 'xid' identical to one used by another client.
 *
 * Commentary: Client side behaviour.
 */

/* RFC2131 Section 4.1: If the client supplies a 'client identifier', the client MUST use the same
 * 'client identifier' in all subsequent messages, and the server MUST use that identifier to
 * identify the client.
 *
 * Commentary: Client side behaviour.
 */

/* RFC2131 Section 4.1: If the client does not provide a 'client identifier' option, the server
 * MUST use the contents of the 'chaddr' field to identify the client.
 */
#[test]
fn client_identifier_or_chaddr() {
    let mut ci = mk_dhcp_request();
    ci.options.clientidentifier = Some(vec![1, 2, 3]);
    assert_eq!(
        ci.get_client_id(),
        vec![1, 2, 3],
        "Did not use client identifier option!"
    );

    let mut ch = mk_dhcp_request();
    ch.options.clientidentifier = None;
    assert_eq!(
        ch.get_client_id(),
        vec![
            0x00, 0x00, 0x5E, 0x00, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        "Did not use chaddr"
    );
}

/* RFC2131 Section 4.3.1:
 * Option                    DHCPOFFER    DHCPACK            DHCPNAK
 * ------                    ---------    -------            -------
 * Requested IP address      MUST NOT     MUST NOT           MUST NOT
 * IP address lease time     MUST         MUST (DHCPREQUEST) MUST NOT
 *                                        MUST NOT (DHCPINFORM)
 * Use 'file'/'sname' fields MAY          MAY                MUST NOT
 * DHCP message type         DHCPOFFER    DHCPACK            DHCPNAK
 * Parameter request list    MUST NOT     MUST NOT           MUST NOT
 * Message                   SHOULD       SHOULD             SHOULD
 * Client identifier         MUST NOT     MUST NOT           MAY
 * Vendor class identifier   MAY          MAY                MAY
 * Server identifier         MUST         MUST               MUST
 * Maximum message size      MUST NOT     MUST NOT           MUST NOT
 * All others                MAY          MAY                MUST NOT
 *
 * TODO: Implement tests for all of these.
 */
