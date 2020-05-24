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

use futures::ready;
use mio::event::Evented;
use mio::unix::EventedFd;
use mio::{Poll, PollOpt, Ready, Token};
use nix::sys::socket;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::task::Context;
use tokio::future::poll_fn;
use tokio::io::PollEvented;

use crate::net::udp;
use nix::libc;

pub type Error = std::io::Error;
pub type Result<T> = std::result::Result<T, Error>;
pub type MsgFlags = socket::MsgFlags;
pub type IoVec<A> = nix::sys::uio::IoVec<A>;

/* These should be refactored out somewhere */
pub type ControlMessage = udp::ControlMessage;

#[derive(Debug)]
struct RawSocketEvented {
    fd: RawFd,
}

impl RawSocketEvented {
    fn new(fd: RawFd) -> RawSocketEvented {
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
    pub fn new() -> Result<Self> {
        // I would love to use the nix socket() wrapper, except, uh, it has a closed enum.
        // See https://github.com/nix-rust/nix/issues/854
        //
        // So I have to use the libc version directly.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from(
                    ((libc::ETH_P_ALL | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u16).to_be(),
                ),
            )
        };
        if fd == -1 {
            return Err(Error::last_os_error());
        }
        Ok(Self {
            io: PollEvented::new(RawSocketEvented::new(fd as RawFd)).unwrap(),
        })
    }

    #[allow(dead_code)]
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize> {
        socket::send(self.as_raw_fd(), buf, flags).map_err(udp::nix_to_io_error)
    }

    pub async fn send_msg(
        &self,
        buffer: &[u8],
        cmsg: &mut ControlMessage,
        flags: MsgFlags,
        addr: Option<&nix::sys::socket::SockAddr>,
    ) -> io::Result<()> {
        poll_fn(|cx| self.poll_send_msg(cx, buffer, cmsg, flags, addr)).await
    }

    fn poll_send_msg(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        cmsg: &mut ControlMessage,
        flags: MsgFlags,
        from: Option<&nix::sys::socket::SockAddr>,
    ) -> std::task::Poll<io::Result<()>> {
        ready!(self.io.poll_write_ready(cx))?;

        let iov = &[IoVec::from_slice(buffer)];

        let cmsgs = cmsg.convert_to_cmsg();

        match nix::sys::socket::sendmsg(self.io.get_ref().as_raw_fd(), iov, &cmsgs, flags, from) {
            Ok(_) => std::task::Poll::Ready(Ok(())),
            Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => std::task::Poll::Pending,
            Err(nix::Error::Sys(nix::errno::Errno::EAGAIN)) => {
                self.io.clear_write_ready(cx)?;
                std::task::Poll::Pending
            }
            Err(e) => std::task::Poll::Ready(Err(udp::nix_to_io_error(e))),
        }
    }
}
