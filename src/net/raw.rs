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
 *  Low level functions to create/use an async raw socket.
 */

use mio::event::Evented;
use mio::unix::EventedFd;
use mio::{Poll, PollOpt, Ready, Token};
use nix::sys::socket;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use tokio::io::PollEvented;

use crate::net::udp;
use nix::libc;

pub type SockAddr = crate::net::socket::SockAddr;
pub type Error = std::io::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub type MsgFlags = socket::MsgFlags;
pub type IoVec<A> = nix::sys::uio::IoVec<A>;

/* These should be refactored out somewhere */
pub type ControlMessage = udp::ControlMessage;

pub struct IpProto(u8);
impl IpProto {
    pub const ICMP: IpProto = IpProto(1);
    pub const TCP: IpProto = IpProto(6);
    pub const UDP: IpProto = IpProto(17);
    pub const ICMP6: IpProto = IpProto(58);
}

pub struct EthProto(u16);
impl EthProto {
    pub const IP4: EthProto = EthProto(0x0800);
    pub const ALL: EthProto = EthProto(0x0003);
}

#[derive(Debug)]
pub struct RawSocketEvented {
    fd: RawFd,
}

impl RawSocketEvented {
    pub fn new(fd: RawFd) -> RawSocketEvented {
        RawSocketEvented { fd }
    }
}

impl Evented for RawSocketEvented {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> Result<()> {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> Result<()> {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}

impl AsRawFd for RawSocketEvented {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[derive(Debug)]
pub struct RawSocket {
    io: PollEvented<RawSocketEvented>,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl RawSocket {
    pub fn new(protocol: EthProto) -> Result<Self> {
        Ok(Self {
            io: crate::net::socket::new_socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(udp::nix_to_io_error)
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.io, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&SockAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.io, buffer, cmsg, flags, addr).await
    }
}

#[derive(Debug)]
pub struct CookedRawSocket {
    io: PollEvented<RawSocketEvented>,
}

impl AsRawFd for CookedRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl CookedRawSocket {
    pub fn new(protocol: EthProto) -> Result<Self> {
        Ok(Self {
            io: crate::net::socket::new_socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(udp::nix_to_io_error)
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.io, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&SockAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.io, buffer, cmsg, flags, addr).await
    }
}

#[derive(Debug)]
pub struct Raw6Socket {
    io: PollEvented<RawSocketEvented>,
}

impl AsRawFd for Raw6Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl Raw6Socket {
    pub fn new(protocol: IpProto) -> Result<Self> {
        Ok(Self {
            io: crate::net::socket::new_socket(
                libc::AF_INET6,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(udp::nix_to_io_error)
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.io, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&SockAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.io, buffer, cmsg, flags, addr).await
    }
}

#[derive(Debug)]
pub struct Raw4Socket {
    io: PollEvented<RawSocketEvented>,
}

impl AsRawFd for Raw4Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.io.get_ref().as_raw_fd()
    }
}

impl Raw4Socket {
    pub fn new(protocol: IpProto) -> Result<Self> {
        Ok(Self {
            io: crate::net::socket::new_socket(
                libc::AF_INET,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(udp::nix_to_io_error)
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.io, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&SockAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.io, buffer, cmsg, flags, addr).await
    }
}
