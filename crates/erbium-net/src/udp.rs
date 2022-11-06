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
 *  An async UdpSocket type with recvmsg / sendmsg support.
 */

// We desperately need recvmsg / sendmsg support, and rust doesn't support it, so we need *yet
// another* udp socket type.
//
// This should not export libc::, nix:: or tokio:: types, only std:: and it's own types to insulate
// the rest of the program of the horrors of portability.

use crate::addr::NetAddr;
use std::convert::TryFrom;
use std::io;
use std::net;
use std::os::unix::io::AsRawFd as _;
use tokio::io::unix::AsyncFd;

use nix::libc;

pub struct UdpSocket {
    fd: AsyncFd<mio::net::UdpSocket>,
}

pub type MsgFlags = crate::socket::MsgFlags;
pub type ControlMessage = crate::socket::ControlMessage;
pub type RecvMsg = crate::socket::RecvMsg;

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
            fd: AsyncFd::new(s)?,
        })
    }
}

impl UdpSocket {
    pub async fn bind(addrs: &[NetAddr]) -> Result<Self, io::Error> {
        use crate::addr::NetAddrExt as _;
        let mut last_err = None;

        for addr in addrs {
            match mio::net::UdpSocket::bind(addr.to_std_socket_addr().unwrap()) {
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
        crate::socket::recv_msg(&self.fd, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&NetAddr>,
    ) -> io::Result<()> {
        crate::socket::send_msg(&self.fd, buffer, cmsg, flags, addr).await
    }

    pub fn local_addr(&self) -> Result<NetAddr, io::Error> {
        self.fd.get_ref().local_addr().map(|x| x.into())
    }

    pub fn set_opt_ipv4_packet_info(&self, b: bool) -> Result<(), io::Error> {
        nix::sys::socket::setsockopt(
            self.fd.get_ref().as_raw_fd(),
            nix::sys::socket::sockopt::Ipv4PacketInfo,
            &b,
        )
        .map_err(|e| e.into())
    }

    pub fn set_opt_ipv6_packet_info(&self, b: bool) -> Result<(), io::Error> {
        nix::sys::socket::setsockopt(
            self.fd.get_ref().as_raw_fd(),
            nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
            &b,
        )
        .map_err(|e| e.into())
    }

    pub fn set_opt_reuse_port(&self, b: bool) -> Result<(), io::Error> {
        nix::sys::socket::setsockopt(
            self.fd.get_ref().as_raw_fd(),
            nix::sys::socket::sockopt::ReusePort,
            &b,
        )
        .map_err(|e| e.into())
    }
}
