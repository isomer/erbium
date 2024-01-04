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
 *  Common Socket Traits
 */

use crate::addr::NetAddr;
use std::os::unix::io::{OwnedFd, RawFd};

pub fn std_to_libc_in_addr(addr: std::net::Ipv4Addr) -> libc::in_addr {
    libc::in_addr {
        s_addr: addr
            .octets()
            .iter()
            .fold(0, |acc, x| ((acc << 8) | (*x as u32))),
    }
}

pub const fn std_to_libc_in6_addr(addr: std::net::Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: addr.octets(),
    }
}

pub type MsgFlags = nix::sys::socket::MsgFlags;
pub use std::io::{IoSlice, IoSliceMut};

use nix::libc;

#[derive(Debug)]
pub struct ControlMessage {
    pub send_from: Option<std::net::IpAddr>,
    /* private, used to hold memory after conversions */
    pktinfo4: libc::in_pktinfo,
    pktinfo6: libc::in6_pktinfo,
}

impl ControlMessage {
    pub fn new() -> Self {
        Self {
            send_from: None,
            pktinfo4: libc::in_pktinfo {
                ipi_ifindex: 0, /* Unspecified interface */
                ipi_addr: std_to_libc_in_addr(std::net::Ipv4Addr::UNSPECIFIED),
                ipi_spec_dst: std_to_libc_in_addr(std::net::Ipv4Addr::UNSPECIFIED),
            },
            pktinfo6: libc::in6_pktinfo {
                ipi6_ifindex: 0, /* Unspecified interface */
                ipi6_addr: std_to_libc_in6_addr(std::net::Ipv6Addr::UNSPECIFIED),
            },
        }
    }
    #[must_use]
    pub const fn set_send_from(mut self, send_from: Option<std::net::IpAddr>) -> Self {
        self.send_from = send_from;
        self
    }
    #[must_use]
    pub const fn set_src4_intf(mut self, intf: u32) -> Self {
        self.pktinfo4.ipi_ifindex = intf as i32;
        self
    }
    #[must_use]
    pub const fn set_src6_intf(mut self, intf: u32) -> Self {
        self.pktinfo6.ipi6_ifindex = intf;
        self
    }
    pub fn convert_to_cmsg(&mut self) -> Vec<nix::sys::socket::ControlMessage> {
        let mut cmsgs: Vec<nix::sys::socket::ControlMessage> = vec![];

        if let Some(addr) = self.send_from {
            match addr {
                std::net::IpAddr::V4(ip) => {
                    self.pktinfo4.ipi_spec_dst = std_to_libc_in_addr(ip);
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                        &self.pktinfo4,
                    ))
                }
                std::net::IpAddr::V6(ip) => {
                    self.pktinfo6.ipi6_addr = std_to_libc_in6_addr(ip);
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv6PacketInfo(
                        &self.pktinfo6,
                    ))
                }
            }
        }

        cmsgs
    }
}

impl Default for ControlMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct RecvMsg {
    pub buffer: Vec<u8>,
    pub address: Option<NetAddr>,
    /* TODO: These should probably return std types */
    /* Or possibly have accessors that convert them for you */
    /* either way, we shouldn't be exporting nix types here */
    timestamp: Option<nix::sys::time::TimeVal>,
    ipv4pktinfo: Option<libc::in_pktinfo>,
    ipv6pktinfo: Option<libc::in6_pktinfo>,
}

impl RecvMsg {
    fn new(m: nix::sys::socket::RecvMsg<NetAddr>, buffer: Vec<u8>) -> RecvMsg {
        let mut r = RecvMsg {
            buffer,
            address: m.address,
            timestamp: None,
            ipv4pktinfo: None,
            ipv6pktinfo: None,
        };

        for cmsg in m.cmsgs() {
            use nix::sys::socket::ControlMessageOwned;
            match cmsg {
                ControlMessageOwned::ScmTimestamp(rtime) => {
                    r.timestamp = Some(rtime);
                }
                ControlMessageOwned::Ipv4PacketInfo(pi) => {
                    r.ipv4pktinfo = Some(pi);
                }
                ControlMessageOwned::Ipv6PacketInfo(pi) => {
                    r.ipv6pktinfo = Some(pi);
                }
                x => log::warn!("Unknown control message {:?}", x),
            }
        }

        r
    }

    /// Returns the local address of the packet.
    ///
    /// This is primarily used by UDP sockets to tell you which address a packet arrived on when
    /// the UDP socket is bound to INADDR_ANY or IN6ADDR_ANY.
    pub const fn local_ip(&self) -> Option<std::net::IpAddr> {
        // This function can be overridden to provide different implementations for different
        // platforms.
        //
        if let Some(pi) = self.ipv6pktinfo {
            // Oh come on, this conversion is even more ridiculous than the last one!
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                (pi.ipi6_addr.s6_addr[0] as u16) << 8 | (pi.ipi6_addr.s6_addr[1] as u16),
                (pi.ipi6_addr.s6_addr[2] as u16) << 8 | (pi.ipi6_addr.s6_addr[3] as u16),
                (pi.ipi6_addr.s6_addr[4] as u16) << 8 | (pi.ipi6_addr.s6_addr[5] as u16),
                (pi.ipi6_addr.s6_addr[6] as u16) << 8 | (pi.ipi6_addr.s6_addr[7] as u16),
                (pi.ipi6_addr.s6_addr[8] as u16) << 8 | (pi.ipi6_addr.s6_addr[9] as u16),
                (pi.ipi6_addr.s6_addr[10] as u16) << 8 | (pi.ipi6_addr.s6_addr[11] as u16),
                (pi.ipi6_addr.s6_addr[12] as u16) << 8 | (pi.ipi6_addr.s6_addr[13] as u16),
                (pi.ipi6_addr.s6_addr[14] as u16) << 8 | (pi.ipi6_addr.s6_addr[15] as u16),
            )))
        } else if let Some(pi) = self.ipv4pktinfo {
            let ip = pi.ipi_addr.s_addr.to_ne_bytes(); // This is already in big endian form, don't try and perform a conversion.
                                                       // It is a pity I haven't found a nicer way to do this conversion.
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                ip[0], ip[1], ip[2], ip[3],
            )))
        } else {
            None
        }
    }

    pub fn local_intf(&self) -> Option<i32> {
        if let Some(pi) = self.ipv6pktinfo {
            Some(pi.ipi6_ifindex as i32)
        } else {
            self.ipv4pktinfo.map(|pi| pi.ipi_ifindex)
        }
    }
}

#[derive(Debug)]
pub struct SocketFd {
    fd: OwnedFd,
}

impl std::os::unix::io::AsRawFd for SocketFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

pub fn new_socket(
    domain: libc::c_int,
    ty: libc::c_int,
    protocol: libc::c_int,
) -> Result<SocketFd, std::io::Error> {
    // I would love to use the nix socket() wrapper, except, uh, it has a closed enum.
    // See https://github.com/nix-rust/nix/issues/854
    //
    // So I have to use the libc version directly.
    unsafe {
        use std::os::unix::io::FromRawFd as _;
        let fd = libc::socket(
            domain,
            ty | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            protocol,
        );
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(SocketFd {
            fd: OwnedFd::from_raw_fd(fd as RawFd),
        })
    }
}

pub async fn recv_msg<F: std::os::unix::io::AsRawFd>(
    sock: &tokio::io::unix::AsyncFd<F>,
    bufsize: usize,
    flags: MsgFlags,
) -> Result<RecvMsg, std::io::Error> {
    let mut ev = sock.readable().await?;

    let mut buf = Vec::new();
    buf.resize_with(bufsize, Default::default);
    let iov = &mut [IoSliceMut::new(buf.as_mut_slice())];

    let mut cmsg = Vec::new();
    cmsg.resize_with(65536, Default::default); /* TODO: Calculate a more reasonable size */

    let mut flags = flags;
    flags.set(MsgFlags::MSG_DONTWAIT, true);

    match nix::sys::socket::recvmsg(sock.get_ref().as_raw_fd(), iov, Some(&mut cmsg), flags) {
        Ok(rm) => {
            if let Some(buf) = rm.iovs().next() {
                ev.retain_ready();
                Ok(RecvMsg::new(rm, buf.into()))
            } else {
                // Zero length datagram
                ev.retain_ready();
                Ok(RecvMsg::new(rm, vec![]))
            }
        }
        Err(e) if e == nix::errno::Errno::EAGAIN => {
            ev.clear_ready();
            Err(e.into())
        }
        Err(e) => {
            ev.retain_ready();
            Err(e.into())
        }
    }
}

/// This function makes an async stream out of calling recv_msg repeatedly.
pub fn recv_msg_stream<F>(
    sock: &tokio::io::unix::AsyncFd<F>,
    bufsize: usize,
    flags: MsgFlags,
) -> impl futures::stream::Stream<Item = Result<RecvMsg, std::io::Error>> + '_
where
    F: std::os::unix::io::AsRawFd,
{
    futures::stream::unfold((), move |()| async move {
        Some((recv_msg::<F>(sock, bufsize, flags).await, ()))
    })
}

pub async fn send_msg<F: std::os::unix::io::AsRawFd>(
    sock: &tokio::io::unix::AsyncFd<F>,
    buffer: &[u8],
    cmsg: &ControlMessage,
    flags: MsgFlags,
    from: Option<&NetAddr>,
) -> std::io::Result<()> {
    let mut ev = sock.writable().await?;

    let iov = &[IoSlice::new(buffer)];
    let mut cmsgs: Vec<nix::sys::socket::ControlMessage> = vec![];
    let mut in_pktinfo = cmsg.pktinfo4;
    let mut in6_pktinfo = cmsg.pktinfo6;

    if let Some(addr) = cmsg.send_from {
        match addr {
            std::net::IpAddr::V4(ip) => {
                in_pktinfo.ipi_spec_dst = std_to_libc_in_addr(ip);
                cmsgs.push(nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                    &in_pktinfo,
                ))
            }
            std::net::IpAddr::V6(ip) => {
                in6_pktinfo.ipi6_addr = std_to_libc_in6_addr(ip);
                cmsgs.push(nix::sys::socket::ControlMessage::Ipv6PacketInfo(
                    &in6_pktinfo,
                ))
            }
        }
    } else if in6_pktinfo.ipi6_ifindex != 0 {
        cmsgs.push(nix::sys::socket::ControlMessage::Ipv6PacketInfo(
            &in6_pktinfo,
        ));
    } else if in_pktinfo.ipi_ifindex != 0 {
        cmsgs.push(nix::sys::socket::ControlMessage::Ipv4PacketInfo(
            &in_pktinfo,
        ));
    }

    match nix::sys::socket::sendmsg(sock.get_ref().as_raw_fd(), iov, &cmsgs, flags, from) {
        Ok(_) => {
            ev.retain_ready();
            Ok(())
        }
        Err(nix::errno::Errno::EAGAIN) => {
            ev.clear_ready();
            Err(nix::errno::Errno::EAGAIN.into())
        }
        Err(e) => {
            ev.retain_ready();
            Err(e.into())
        }
    }
}

pub fn set_ipv6_unicast_hoplimit(fd: RawFd, val: i32) -> Result<(), nix::Error> {
    unsafe {
        let res = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        nix::errno::Errno::result(res).map(drop)
    }
}

pub fn set_ipv6_multicast_hoplimit(fd: RawFd, val: i32) -> Result<(), nix::Error> {
    unsafe {
        let res = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MULTICAST_HOPS,
            &val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        nix::errno::Errno::result(res).map(drop)
    }
}
