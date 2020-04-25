// We desperately need recvmsg / sendmsg support, and rust doesn't support it, so we need *yet
// another* udp socket type.

use futures::ready;
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::task::{Context, Poll};
use tokio::future::poll_fn;
use tokio::io::PollEvented;
use tokio::net::ToSocketAddrs;

pub struct UdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
}

pub type MsgFlags = nix::sys::socket::MsgFlags;
pub type IoVec<A> = nix::sys::uio::IoVec<A>;

#[derive(Debug)]
pub struct ControlMessage {}

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
                _ => (),
            }
        }

        r
    }
}

fn nix_to_io_error(n: nix::Error) -> io::Error {
    match n {
        nix::Error::Sys(_) => io::Error::new(io::ErrorKind::Other, n),
        nix::Error::InvalidPath => io::Error::new(io::ErrorKind::InvalidData, n),
        nix::Error::InvalidUtf8 => io::Error::new(io::ErrorKind::InvalidData, n),
        nix::Error::UnsupportedOperation => io::Error::new(io::ErrorKind::InvalidData, n),
    }
}

fn nix_to_std_sockaddr(n: nix::sys::socket::SockAddr) -> SocketAddr {
    match n {
        nix::sys::socket::SockAddr::Inet(ia) => ia.to_std(),
        _ => unimplemented!(),
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

    pub async fn recv_msg(
        &self,
        bufsize: usize,
        cmsg: &mut Vec<u8>,
        flags: MsgFlags,
    ) -> io::Result<RecvMsg> {
        poll_fn(|cx| self.poll_recv_msg(cx, bufsize, cmsg, flags)).await
    }

    fn poll_recv_msg(
        &self,
        cx: &mut Context<'_>,
        bufsize: usize,
        cmsg: &mut Vec<u8>,
        flags: MsgFlags,
    ) -> Poll<Result<RecvMsg, io::Error>> {
        ready!(self.io.poll_read_ready(cx, mio::Ready::readable()))?;

        let mut buf = Vec::new();
        buf.resize_with(bufsize, Default::default);
        let iov = &[IoVec::from_mut_slice(buf.as_mut_slice())];

        let mut flags = flags;
        flags.set(MsgFlags::MSG_DONTWAIT, true);

        match nix::sys::socket::recvmsg(self.io.get_ref().as_raw_fd(), iov, Some(cmsg), flags) {
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
        let cmsgs: Vec<nix::sys::socket::ControlMessage> = vec![];
        let from =
            addr.map(|x| nix::sys::socket::SockAddr::Inet(nix::sys::socket::InetAddr::from_std(x)));

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
}
