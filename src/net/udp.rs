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
 *  An async UdpSocket type with recvmsg / sendmsg support.
 */

// We desperately need recvmsg / sendmsg support, and rust doesn't support it, so we need *yet
// another* udp socket type.
//
// This should not export libc::, nix:: or tokio:: types, only std:: and it's own types to insulate
// the rest of the program of the horrors of portability.

use futures::ready;
use std::convert::TryFrom;
use std::io;
use std::net;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::task::{Context, Poll};
use tokio::future::poll_fn;
use tokio::io::PollEvented;
use tokio::net::ToSocketAddrs;

use nix::libc;

pub struct UdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
}

pub type MsgFlags = nix::sys::socket::MsgFlags;
pub type IoVec<A> = nix::sys::uio::IoVec<A>;

#[derive(Debug)]
pub struct ControlMessage {
    pub send_from: Option<net::IpAddr>,
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
                ipi_addr: std_to_libc_in_addr(net::Ipv4Addr::UNSPECIFIED),
                ipi_spec_dst: std_to_libc_in_addr(net::Ipv4Addr::UNSPECIFIED),
            },
            pktinfo6: libc::in6_pktinfo {
                ipi6_ifindex: 0, /* Unspecified interface */
                ipi6_addr: std_to_libc_in6_addr(net::Ipv6Addr::UNSPECIFIED),
            },
        }
    }
    pub fn set_send_from(mut self, send_from: Option<net::IpAddr>) -> Self {
        self.send_from = send_from;
        self
    }
    pub fn convert_to_cmsg(&mut self) -> Vec<nix::sys::socket::ControlMessage> {
        let mut cmsgs: Vec<nix::sys::socket::ControlMessage> = vec![];

        if let Some(addr) = self.send_from {
            match addr {
                net::IpAddr::V4(ip) => {
                    self.pktinfo4.ipi_spec_dst = std_to_libc_in_addr(ip);
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                        &self.pktinfo4,
                    ))
                }
                net::IpAddr::V6(ip) => {
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
    pub address: Option<SocketAddr>,
    /* TODO: These should probably return std types */
    /* Or possibly have accessors that convert them for you */
    /* either way, we shouldn't be exporting nix types here */
    timestamp: Option<nix::sys::time::TimeVal>,
    ipv4pktinfo: Option<libc::in_pktinfo>,
    ipv6pktinfo: Option<libc::in6_pktinfo>,
}

impl RecvMsg {
    fn new(m: nix::sys::socket::RecvMsg, buffer: Vec<u8>) -> RecvMsg {
        let mut r = RecvMsg {
            buffer,
            address: m.address.map(nix_to_std_sockaddr),
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
                x => println!("Unknown control message {:?}", x),
            }
        }

        r
    }

    /// Returns the local address of the packet.
    ///
    /// This is primarily used by UDP sockets to tell you which address a packet arrived on when
    /// the UDP socket is bound to INADDR_ANY or IN6ADDR_ANY.
    pub fn local_addr(&self) -> Option<net::IpAddr> {
        // This function can be overridden to provide different implementations for different
        // platforms.
        //
        if let Some(pi) = self.ipv6pktinfo {
            // Oh come on, this conversion is even more ridiculous than the last one!
            Some(net::IpAddr::V6(net::Ipv6Addr::new(
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
            Some(net::IpAddr::V4(net::Ipv4Addr::new(
                ip[0], ip[1], ip[2], ip[3],
            )))
        } else {
            None
        }
    }

    pub fn local_intf(&self) -> Option<i32> {
        if let Some(pi) = self.ipv6pktinfo {
            Some(pi.ipi6_ifindex as i32)
        } else if let Some(pi) = self.ipv4pktinfo {
            Some(pi.ipi_ifindex as i32)
        } else {
            None
        }
    }
}

pub fn nix_to_io_error(n: nix::Error) -> io::Error {
    match n {
        nix::Error::Sys(_) => io::Error::new(io::ErrorKind::Other, n),
        nix::Error::InvalidPath => io::Error::new(io::ErrorKind::InvalidData, n),
        nix::Error::InvalidUtf8 => io::Error::new(io::ErrorKind::InvalidData, n),
        nix::Error::UnsupportedOperation => io::Error::new(io::ErrorKind::InvalidData, n),
    }
}

pub fn nix_to_std_sockaddr(n: nix::sys::socket::SockAddr) -> SocketAddr {
    match n {
        nix::sys::socket::SockAddr::Inet(ia) => ia.to_std(),
        _ => unimplemented!(),
    }
}

pub fn std_to_libc_in_addr(addr: net::Ipv4Addr) -> libc::in_addr {
    libc::in_addr {
        s_addr: addr
            .octets()
            .iter()
            .fold(0, |acc, x| ((acc << 8) | (*x as u32))),
    }
}

pub const fn std_to_libc_in6_addr(addr: net::Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: addr.octets(),
    }
}

impl TryFrom<mio::net::UdpSocket> for UdpSocket {
    type Error = io::Error;
    fn try_from(s: mio::net::UdpSocket) -> Result<Self, Self::Error> {
        Ok(UdpSocket {
            io: PollEvented::new(s)?,
        })
    }
}

impl UdpSocket {
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self, io::Error> {
        let addrs = addr.to_socket_addrs().await?;

        let mut last_err = None;

        for addr in addrs {
            match mio::net::UdpSocket::bind(&addr) {
                Ok(socket) => return Self::try_from(socket),
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )
        }))
    }

    pub async fn recv_msg(&self, bufsize: usize, flags: MsgFlags) -> io::Result<RecvMsg> {
        poll_fn(|cx| self.poll_recv_msg(cx, bufsize, flags)).await
    }

    fn poll_recv_msg(
        &self,
        cx: &mut Context<'_>,
        bufsize: usize,
        flags: MsgFlags,
    ) -> Poll<Result<RecvMsg, io::Error>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;

        let mut buf = Vec::new();
        buf.resize_with(bufsize, Default::default);
        let iov = &[IoVec::from_mut_slice(buf.as_mut_slice())];

        let mut cmsg = Vec::new();
        cmsg.resize_with(65536, Default::default); /* TODO: Calculate a more reasonable size */

        let mut flags = flags;
        flags.set(MsgFlags::MSG_DONTWAIT, true);

        match nix::sys::socket::recvmsg(self.io.get_ref().as_raw_fd(), iov, Some(&mut cmsg), flags)
        {
            Ok(rm) => {
                buf.truncate(rm.bytes);
                Poll::Ready(Ok(RecvMsg::new(rm, buf)))
            }
            Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => Poll::Pending,
            Err(nix::Error::Sys(nix::errno::Errno::EAGAIN)) => {
                self.io.clear_read_ready(cx, mio::Ready::readable())?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(nix_to_io_error(e))),
        }
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&SocketAddr>,
    ) -> io::Result<()> {
        poll_fn(|cx| self.poll_send_msg(cx, buffer, cmsg, flags, addr)).await
    }

    fn poll_send_msg(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&SocketAddr>,
    ) -> Poll<io::Result<()>> {
        ready!(self.io.poll_write_ready(cx))?;

        let iov = &[IoVec::from_slice(buffer)];
        let mut cmsgs: Vec<nix::sys::socket::ControlMessage> = vec![];
        let from =
            addr.map(|x| nix::sys::socket::SockAddr::Inet(nix::sys::socket::InetAddr::from_std(x)));
        let mut in_pktinfo = libc::in_pktinfo {
            ipi_ifindex: 0, /* Unspecified interface */
            ipi_addr: std_to_libc_in_addr(net::Ipv4Addr::UNSPECIFIED),
            ipi_spec_dst: std_to_libc_in_addr(net::Ipv4Addr::UNSPECIFIED),
        };
        let mut in6_pktinfo = libc::in6_pktinfo {
            ipi6_ifindex: 0, /* Unspecified interface */
            ipi6_addr: std_to_libc_in6_addr(net::Ipv6Addr::UNSPECIFIED),
        };

        if let Some(addr) = cmsg.send_from {
            match addr {
                net::IpAddr::V4(ip) => {
                    in_pktinfo.ipi_spec_dst = std_to_libc_in_addr(ip);
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv4PacketInfo(
                        &in_pktinfo,
                    ))
                }
                net::IpAddr::V6(ip) => {
                    in6_pktinfo.ipi6_addr = std_to_libc_in6_addr(ip);
                    cmsgs.push(nix::sys::socket::ControlMessage::Ipv6PacketInfo(
                        &in6_pktinfo,
                    ))
                }
            }
        }

        println!("Send cmsg: {:?}", cmsgs);

        match nix::sys::socket::sendmsg(
            self.io.get_ref().as_raw_fd(),
            iov,
            &cmsgs,
            flags,
            from.as_ref(),
        ) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => Poll::Pending,
            Err(nix::Error::Sys(nix::errno::Errno::EAGAIN)) => {
                self.io.clear_write_ready(cx)?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(nix_to_io_error(e))),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.io.get_ref().local_addr()
    }

    pub fn set_opt_ipv4_packet_info(&self, b: bool) -> Result<(), io::Error> {
        nix::sys::socket::setsockopt(
            self.io.get_ref().as_raw_fd(),
            nix::sys::socket::sockopt::Ipv4PacketInfo,
            &b,
        )
        .map_err(nix_to_io_error)
    }

    pub fn set_opt_ipv6_packet_info(&self, b: bool) -> Result<(), io::Error> {
        nix::sys::socket::setsockopt(
            self.io.get_ref().as_raw_fd(),
            nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
            &b,
        )
        .map_err(nix_to_io_error)
    }
}
