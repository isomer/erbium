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
use rand::Rng;
use std::net;
use tokio::sync;

const EXAMPLE_IP1: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 1); /* Documentation prefix 1 */
const EXAMPLE_IP2: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 2); /* Documentation prefix 2 */
const EXAMPLE_IP3: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 3); /* Documentation prefix 3 */
const EXAMPLE_IP4: net::Ipv4Addr = net::Ipv4Addr::new(192, 0, 2, 4); /* Documentation prefix 4 */

const SERVER_IP: net::Ipv4Addr = EXAMPLE_IP1;
const SERVER_IP2: net::Ipv4Addr = EXAMPLE_IP2;
const NOT_SERVER_IP: net::Ipv4Addr = EXAMPLE_IP3;

const CLIENTID: &[u8] = b"Client Identifier";

fn mk_dhcp_request_pkt() -> dhcppkt::DHCP {
    dhcppkt::DHCP {
        op: dhcppkt::OP_BOOTREQUEST,
        htype: dhcppkt::HWTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid: rand::thread_rng().gen(),
        secs: 0,
        flags: 0,
        ciaddr: net::Ipv4Addr::UNSPECIFIED,
        yiaddr: net::Ipv4Addr::UNSPECIFIED,
        siaddr: net::Ipv4Addr::UNSPECIFIED,
        giaddr: net::Ipv4Addr::UNSPECIFIED,
        chaddr: vec![
            0x00, 0x00, 0x5E, 0x00, 0x53, 0x00, /* Reserved for documentation, per RFC7042 */
        ],
        sname: vec![],
        file: vec![],
        options: dhcppkt::DhcpOptions {
            ..Default::default()
        }
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPREQUEST)
        .set_option(&dhcppkt::OPTION_HOSTNAME, &vec![dhcppkt::OPTION_HOSTNAME]) // TODO: is this correct?
        .set_option(
            &dhcppkt::OPTION_PARAMLIST,
            &vec![1u8, 3u8, 6u8, 15, 26, 28, 51, 58, 59, 43],
        ),
    }
}

fn mk_dhcp_request() -> dhcp::DHCPRequest {
    dhcp::DHCPRequest {
        pkt: mk_dhcp_request_pkt(),
        serverip: SERVER_IP,
        ifindex: 1,
    }
}

fn mk_default_config() -> crate::config::Config {
    let mut apply_address: pool::PoolAddresses = Default::default();
    for i in 1..255 {
        apply_address
            .insert((u32::from("192.0.2.0".parse::<std::net::Ipv4Addr>().unwrap()) + i).into());
    }
    crate::config::Config {
        dhcp: dhcp::config::Config {
            policies: vec![dhcp::config::Policy {
                match_subnet: Some(
                    crate::net::Ipv4Subnet::new("192.0.2.0".parse().unwrap(), 24).unwrap(),
                ),
                apply_address: Some(apply_address),
                ..Default::default()
            }],
        },
    }
}

#[test]
fn test_parsing_inverse_serialising() {
    let mut orig_pkt = mk_dhcp_request();
    orig_pkt.pkt.options = orig_pkt
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_LEASETIME, &(321 as u32))
        .set_option(&dhcppkt::OPTION_SERVERID, &SERVER_IP)
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_NTPSERVERS, &EXAMPLE_IP4);
    let bytes = orig_pkt.pkt.serialise();
    let new_pkt = dhcppkt::parse(bytes.as_slice()).expect("Failed to parse DHCP packet");
    assert!(
        orig_pkt.pkt.sname.len() <= 64,
        "sname={:?} ({} <= 64 is false",
        orig_pkt.pkt.sname,
        orig_pkt.pkt.sname.len()
    );
    assert!(
        orig_pkt.pkt.chaddr.len() <= 16,
        "chaddr={:?} ({} <= 16 is false",
        orig_pkt.pkt.chaddr,
        orig_pkt.pkt.chaddr.len()
    );
    assert_eq!(orig_pkt.pkt, new_pkt);
}

#[test]
fn test_handle_pkt() {
    let mut request = mk_dhcp_request();
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_LEASETIME, &321u32)
        .set_option(&dhcppkt::OPTION_SERVERID, &SERVER_IP);

    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    serverids.insert(SERVER_IP);
    let conf = mk_default_config();
    dhcp::handle_pkt(&mut p, &request, serverids, &conf).expect("Failed to handle request");
}

#[test]
fn truncated_pkt() {
    /* Check that truncated packets don't cause panics or other problems */
    let mut orig_pkt = mk_dhcp_request();
    orig_pkt.pkt.options = orig_pkt
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_LEASETIME, &(321u32))
        .set_option(&dhcppkt::OPTION_SERVERID, &SERVER_IP);
    let bytes = orig_pkt.pkt.serialise();
    for i in 0..(bytes.len() - 1) {
        match dhcppkt::parse(&bytes[0..i]) {
            Err(dhcppkt::ParseError::UnexpectedEndOfInput) => (),
            x => panic!("Unexpected response: {:?}", x),
        }
    }
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
    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut pkt = mk_dhcp_request();
    pkt.pkt.flags = 0x7FFF;
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let conf = mk_default_config();
    dhcp::handle_discover(&mut p, &pkt, serverids, &conf).expect("Failed to handle request");
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
    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let pkt = mk_dhcp_request();
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let conf = mk_default_config();
    let reply =
        dhcp::handle_discover(&mut p, &pkt, serverids, &conf).expect("Failed to handle request");
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
    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let pkt = mk_dhcp_request();
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let conf = mk_default_config();
    let reply =
        dhcp::handle_discover(&mut p, &pkt, serverids, &conf).expect("Failed to handle request");
    assert_ne!(
        reply
            .options
            .get_serverid()
            .expect("server identifier not set on repliy"),
        net::Ipv4Addr::UNSPECIFIED,
        "server identifier is not set on replies"
    );
}

#[tokio::test]
async fn ignore_other_request() {
    let pools = std::sync::Arc::new(sync::Mutex::new(
        pool::Pool::new_in_memory().expect("Failed to create pool"),
    ));
    let mut p = pools.lock().await;
    let mut pkt = mk_dhcp_request();
    pkt.pkt.options = pkt
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_SERVERID, &NOT_SERVER_IP);
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    serverids.insert(SERVER_IP);
    serverids.insert(SERVER_IP2);
    let cfg = mk_default_config();
    let reply =
        dhcp::handle_request(&mut p, &pkt, serverids, &cfg).expect_err("Handled request not to me");
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
    ci.pkt.options = ci
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &vec![1u8, 2, 3]);
    println!("{:?}", ci.pkt.options);
    assert_eq!(
        ci.pkt.get_client_id(),
        vec![1, 2, 3],
        "Did not use client identifier option!"
    );

    let mut ch = mk_dhcp_request();
    ch.pkt.options = ch.pkt.options.remove_option(&dhcppkt::OPTION_CLIENTID);
    assert_eq!(
        ch.pkt.get_client_id(),
        vec![0x00, 0x00, 0x5E, 0x00, 0x53, 0x00,],
        "Did not use chaddr"
    );
}

/* RFC2131 Section 4.3.1:
 * Option                    DHCPOFFER    DHCPACK            DHCPNAK
 * ------                    ---------    -------            -------
 * 'op'       BOOTREPLY            BOOTREPLY           BOOTREPLY
 * 'htype'    (From "Assigned Numbers" RFC)
 * 'hlen'     (Hardware address length in octets)
 * 'hops'     0                    0                   0
 * 'xid'      'xid' from client    'xid' from client   'xid' from client
 *            DHCPDISCOVER         DHCPREQUEST         DHCPREQUEST
 *            message              message             message
 * 'secs'     0                    0                   0
 * 'ciaddr'   0                    'ciaddr' from       0
 *                                 DHCPREQUEST or 0
 * 'yiaddr'   IP address offered   IP address          0
 *            to client            assigned to client
 * 'siaddr'   IP address of next   IP address of next  0
 *            bootstrap server     bootstrap server
 * 'flags'    'flags' from         'flags' from        'flags' from
 *            client DHCPDISCOVER  client DHCPREQUEST  client DHCPREQUEST
 *            message              message             message
 * 'giaddr'   'giaddr' from        'giaddr' from       'giaddr' from
 *            client DHCPDISCOVER  client DHCPREQUEST  client DHCPREQUEST
 *            message              message             message
 * 'chaddr'   'chaddr' from        'chaddr' from       'chaddr' from
 *            client DHCPDISCOVER  client DHCPREQUEST  client DHCPREQUEST
 *            message              message             message
 * 'sname'    Server host name     Server host name    (unused)
 *            or options           or options
 * 'file'     Client boot file     Client boot file    (unused)
 *            name or options      name or options
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
 */

#[test]
fn offer_required() {
    let mut request = mk_dhcp_request();
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_LEASETIME, &321u32)
        .set_option(&dhcppkt::OPTION_SERVERID, &SERVER_IP)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPDISCOVER);

    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    serverids.insert(SERVER_IP);
    let conf = mk_default_config();
    let reply =
        dhcp::handle_pkt(&mut p, &request, serverids, &conf).expect("Failed to handle request");
    assert_eq!(reply.op, dhcppkt::OP_BOOTREPLY);
    assert_eq!(reply.htype, dhcppkt::HWTYPE_ETHERNET);
    assert_eq!(reply.hlen, 6);
    assert_eq!(reply.hops, 0);
    assert_eq!(reply.xid, request.pkt.xid);
    assert_eq!(reply.secs, 0);
    assert_eq!(reply.ciaddr, std::net::Ipv4Addr::UNSPECIFIED);
    assert_ne!(reply.yiaddr, std::net::Ipv4Addr::UNSPECIFIED);
    assert_eq!(reply.siaddr, std::net::Ipv4Addr::UNSPECIFIED);
    assert_eq!(reply.flags, request.pkt.flags);
    assert_eq!(reply.giaddr, request.pkt.giaddr);
    assert_eq!(reply.chaddr, request.pkt.chaddr);
    assert_eq!(reply.options.get_messagetype().unwrap(), dhcppkt::DHCPOFFER);
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_ADDRESSREQUEST)
        .is_none());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_PARAMLIST)
        .is_none());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_SERVERID)
        .is_some());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_MAXMSGSIZE)
        .is_none());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_CLIENTID)
        .is_none());
}

#[test]
fn ack_required() {
    let mut request = mk_dhcp_request();
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_LEASETIME, &321u32)
        .set_option(&dhcppkt::OPTION_SERVERID, &SERVER_IP)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPREQUEST);

    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    serverids.insert(SERVER_IP);
    let conf = mk_default_config();
    let reply =
        dhcp::handle_pkt(&mut p, &request, serverids, &conf).expect("Failed to handle request");
    assert_eq!(reply.op, dhcppkt::OP_BOOTREPLY);
    assert_eq!(reply.htype, dhcppkt::HWTYPE_ETHERNET);
    assert_eq!(reply.hlen, 6);
    assert_eq!(reply.hops, 0);
    assert_eq!(reply.xid, request.pkt.xid);
    assert_eq!(reply.secs, 0);
    assert!(
        (reply.ciaddr == std::net::Ipv4Addr::UNSPECIFIED) || (reply.ciaddr == request.pkt.ciaddr)
    );
    assert_ne!(reply.yiaddr, std::net::Ipv4Addr::UNSPECIFIED);
    assert_eq!(reply.siaddr, std::net::Ipv4Addr::UNSPECIFIED);
    assert_eq!(reply.flags, request.pkt.flags);
    assert_eq!(reply.giaddr, request.pkt.giaddr);
    assert_eq!(reply.chaddr, request.pkt.chaddr);
    assert_eq!(reply.options.get_messagetype().unwrap(), dhcppkt::DHCPACK);
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_ADDRESSREQUEST)
        .is_none());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_PARAMLIST)
        .is_none());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_SERVERID)
        .is_some());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_MAXMSGSIZE)
        .is_none());
    assert!(reply
        .options
        .get_option::<Vec<u8>>(&dhcppkt::OPTION_CLIENTID)
        .is_none());
}

#[test]
fn test_renew_unknown() {
    /* If the server is started and there is a client that tries to renew a lease we've not heard
     * about.  If the lease is available, we should update our database and give it to them!
     */
    let mut request = mk_dhcp_request();
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPREQUEST);
    request.pkt.ciaddr = EXAMPLE_IP2;

    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    serverids.insert(SERVER_IP);
    let conf = mk_default_config();
    let reply =
        dhcp::handle_pkt(&mut p, &request, serverids, &conf).expect("Failed to handle request");
    assert_eq!(reply.yiaddr, EXAMPLE_IP2);
}

#[test]
fn test_full() {
    /* This is an end to end test, testing a sequence of packets that a client should send and
     * making sure that we handle them correctly.
     */
    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let mut serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let conf = mk_default_config();
    let xid = rand::thread_rng().gen();
    let secs = 0;

    /* Send DISCOVER */
    let mut request = mk_dhcp_request();
    request.pkt.xid = xid;
    request.pkt.secs = secs;
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPDISCOVER);

    let offer = dhcp::handle_pkt(&mut p, &request, serverids.clone(), &conf)
        .expect("Failed to handle request");

    serverids.insert(offer.options.get_serverid().unwrap());

    assert_eq!(offer.options.get_messagetype(), Some(dhcppkt::DHCPOFFER));

    /* Send REQUEST */
    let mut request = mk_dhcp_request();
    request.pkt.xid = xid;
    request.pkt.secs = secs;
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPREQUEST)
        .set_option(&dhcppkt::OPTION_ADDRESSREQUEST, &offer.yiaddr);

    let ack = dhcp::handle_pkt(&mut p, &request, serverids.clone(), &conf)
        .expect("Failed to handle request");

    assert_eq!(ack.options.get_messagetype(), Some(dhcppkt::DHCPACK));
    assert_eq!(ack.yiaddr, offer.yiaddr); /* make sure we don't needlessly change our mind */

    /* Time passes and now we want to renew */
    let mut request = mk_dhcp_request();
    /* xid and seconds are not copied from the previous requests */
    request.pkt.secs = 0;
    request.pkt.ciaddr = offer.yiaddr;
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPREQUEST);
    /* no server id */
    let ack = dhcp::handle_pkt(&mut p, &request, serverids.clone(), &conf)
        .expect("Failed to handle request");
    assert_eq!(ack.options.get_messagetype(), Some(dhcppkt::DHCPACK));
    assert_eq!(ack.yiaddr, offer.yiaddr); /* Did we get back the same address? */

    /* Okay, now it's time to RELEASE the address */
    let mut request = mk_dhcp_request();
    /* xid and seconds are not copied from the previous requests */
    request.pkt.secs = 0;
    request.pkt.options = request
        .pkt
        .options
        .set_option(&dhcppkt::OPTION_CLIENTID, &CLIENTID)
        .set_option(&dhcppkt::OPTION_MSGTYPE, &dhcppkt::DHCPRELEASE);
    /* no server id */
    /* release is not supported, so we expect an error here.  But we shouldn't crash */
    let _ack =
        dhcp::handle_pkt(&mut p, &request, serverids, &conf).expect_err("Failed to handle request");
}

#[tokio::test]
async fn test_defaults() {
    let mut p = pool::Pool::new_in_memory().expect("Failed to create pool");
    let pkt = mk_dhcp_request();
    let conf = crate::config::load_config_from_string_for_test(
        "
dhcp:
 policies:
  - match-subnet: 192.0.2.0/24
    apply-address: 192.0.2.1
    apply-netmask: null
",
    )
    .expect("Failed to parse test config");
    let lockedconf = conf.lock().await;
    let serverids: dhcp::ServerIds = dhcp::ServerIds::new();
    let reply = dhcp::handle_discover(&mut p, &pkt, serverids, &lockedconf)
        .expect("Failed to handle request");
    /* We've asked that netmask doesn't get set, so check it's not set */
    assert_eq!(
        reply
            .options
            .get_option::<std::net::Ipv4Addr>(&dhcppkt::OPTION_NETMASK),
        None
    );
    /* We've not specified what happens to the broadcast, so check it was defaulted correctly. */
    assert_eq!(
        reply
            .options
            .get_option::<std::net::Ipv4Addr>(&dhcppkt::OPTION_BROADCAST),
        Some("192.0.2.255".parse().expect("Failed to parse IP"))
    );
}

/* TODO:
 * 4. The servers receive the DHCPREQUEST broadcast from the client.  Those servers not selected by
 *    the DHCPREQUEST message use the message as notification that the client has declined that
 *    server's offer.
*/
