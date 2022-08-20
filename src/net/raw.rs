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
 *  Low level functions to create/use an async raw socket.
 */

use nix::sys::socket;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use tokio::io::unix::AsyncFd;

use crate::net::{addr::NetAddr, udp};
use nix::libc;

pub type Error = std::io::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub type MsgFlags = socket::MsgFlags;
pub use std::io::{IoSlice, IoSliceMut};

/* These should be refactored out somewhere */
pub type ControlMessage = udp::ControlMessage;

#[derive(Copy, Clone)]
pub struct IpProto(u8);
impl IpProto {
    pub const ICMP: IpProto = IpProto(1);
    pub const TCP: IpProto = IpProto(6);
    pub const UDP: IpProto = IpProto(17);
    pub const ICMP6: IpProto = IpProto(58);
}

impl From<IpProto> for u8 {
    fn from(ipp: IpProto) -> Self {
        ipp.0
    }
}

impl From<IpProto> for u16 {
    fn from(ipp: IpProto) -> Self {
        ipp.0 as u16
    }
}

#[derive(Copy, Clone)]
pub struct EthProto(u16);
impl EthProto {
    pub const IP4: EthProto = EthProto(0x0800);
    pub const ALL: EthProto = EthProto(0x0003);
}

#[derive(Debug)]
pub struct RawSocket {
    fd: AsyncFd<crate::net::socket::SocketFd>,
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl RawSocket {
    pub fn new(protocol: EthProto) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(crate::net::socket::new_socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?)?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(|e| e.into())
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.fd, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&NetAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.fd, buffer, cmsg, flags, addr).await
    }

    pub fn set_socket_option<O: nix::sys::socket::SetSockOpt>(
        &self,
        opt: O,
        val: &O::Val,
    ) -> Result<()> {
        nix::sys::socket::setsockopt(self.as_raw_fd(), opt, val).map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub struct CookedRawSocket {
    fd: AsyncFd<crate::net::socket::SocketFd>,
}

impl AsRawFd for CookedRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl CookedRawSocket {
    pub fn new(protocol: EthProto) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(crate::net::socket::new_socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?)?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(|e| e.into())
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.fd, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&NetAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.fd, buffer, cmsg, flags, addr).await
    }

    pub fn set_socket_option<O: nix::sys::socket::SetSockOpt>(
        &self,
        opt: O,
        val: &O::Val,
    ) -> Result<()> {
        nix::sys::socket::setsockopt(self.as_raw_fd(), opt, val).map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub struct Raw6Socket {
    fd: AsyncFd<crate::net::socket::SocketFd>,
}

impl AsRawFd for Raw6Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Raw6Socket {
    pub fn new(protocol: IpProto) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(crate::net::socket::new_socket(
                libc::AF_INET6,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?)?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(|e| e.into())
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.fd, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&NetAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.fd, buffer, cmsg, flags, addr).await
    }

    pub fn set_socket_option<O: nix::sys::socket::SetSockOpt>(
        &self,
        opt: O,
        val: &O::Val,
    ) -> Result<()> {
        nix::sys::socket::setsockopt(self.as_raw_fd(), opt, val).map_err(|e| e.into())
    }
}

#[derive(Debug)]
pub struct Raw4Socket {
    fd: AsyncFd<crate::net::socket::SocketFd>,
}

impl AsRawFd for Raw4Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Raw4Socket {
    pub fn new(protocol: IpProto) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(crate::net::socket::new_socket(
                libc::AF_INET,
                libc::SOCK_RAW,
                protocol.0 as libc::c_int,
            )?)?,
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(|e| e.into())
    }

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        flags: MsgFlags,
    ) -> io::Result<crate::net::socket::RecvMsg> {
        crate::net::socket::recv_msg(&self.fd, bufsize, flags).await
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &ControlMessage,
        flags: MsgFlags,
        addr: Option<&NetAddr>,
    ) -> io::Result<()> {
        crate::net::socket::send_msg(&self.fd, buffer, cmsg, flags, addr).await
    }

    pub fn set_socket_option<O: nix::sys::socket::SetSockOpt>(
        fd: RawFd,
        opt: O,
        val: &O::Val,
    ) -> Result<()> {
        nix::sys::socket::setsockopt(fd, opt, val).map_err(|e| e.into())
    }
}
