use futures::ready;
use mio::Ready;
use std::future::Future;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::PollEvented;
use libc;
use std::convert::TryFrom;


struct UdpMsg {
    poll_evented: PollEvented<mio::net::UdpSocket>,
}

struct RecvMsgFuture<'l> {
    poll_evented: &'l PollEvented<mio::net::UdpSocket>,
    iov: &'l[nix::sys::uio::IoVec<&'l mut [u8]>],
    cmsg_buffer: std::cell::Cell<&'l mut Vec<u8>>,
    flags: nix::sys::socket::MsgFlags,
}

impl<'l> RecvMsgFuture<'l> {
    pub fn new(
        poll_evented: &'l PollEvented<mio::net::UdpSocket>,
        iov: &'l [nix::sys::uio::IoVec<&'l mut [u8]>],
        cmsg_buffer: &'l mut Vec<u8>,
        flags: nix::sys::socket::MsgFlags,
    ) -> RecvMsgFuture<'l> {
        RecvMsgFuture {
            poll_evented: &poll_evented,
            iov: iov,
            cmsg_buffer: std::cell::Cell::new(cmsg_buffer),
            flags: flags,
        }
    }
}


#[derive(Debug)]
struct RecvMsg {
    pub bytes: usize,
    pub address: Option<nix::sys::socket::SockAddr>,
    /* TODO: These should probably return std types */
    /* Or possibly have accessors that convert them for you */
    pub timestamp : Option<nix::sys::time::TimeVal>,
    pub ipv4pktinfo : Option<libc::in_pktinfo>,
    pub ipv6pktinfo : Option<libc::in6_pktinfo>,
}

impl RecvMsg {
    fn new(m : nix::sys::socket::RecvMsg) -> RecvMsg {
        let mut r = RecvMsg {
            bytes: m.bytes,
            address: m.address,
            timestamp: None,
            ipv4pktinfo: None,
            ipv6pktinfo: None,
        };

        for cmsg in m.cmsgs() {
            use nix::sys::socket::ControlMessageOwned;
            match cmsg {
                ControlMessageOwned::ScmTimestamp(rtime) => { r.timestamp = Some(rtime); },
                ControlMessageOwned::Ipv4PacketInfo(pi) => { r.ipv4pktinfo = Some(pi); },
                ControlMessageOwned::Ipv6PacketInfo(pi) => { r.ipv6pktinfo = Some(pi); },
                _ => (),
            }
        }

        r
    }
}


impl<'l> Future for RecvMsgFuture<'l> {
    type Output = Result<RecvMsg, Box<dyn std::error::Error>>;
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let ready = Ready::readable();

        ready!(self.poll_evented.poll_read_ready(cx, ready))?;

        let mut flags2 = self.flags.clone();
        flags2.set(nix::sys::socket::MsgFlags::MSG_DONTWAIT, true);

        let received = nix::sys::socket::recvmsg(
            (self.poll_evented.get_ref()).as_raw_fd(),
            self.iov,
            Some(self.cmsg_buffer.get_mut()),
            flags2,
        );

        match received {
            Ok(msg) => Poll::Ready(Ok(RecvMsg::new(msg))),
            Err(nix::Error::Sys(nix::errno::Errno::EINTR)) => return Poll::Pending,
            Err(nix::Error::Sys(nix::errno::Errno::EAGAIN)) => {
                self.poll_evented.clear_read_ready(cx, ready)?;
                return Poll::Pending
            }
            Err(e) => return Poll::Ready(Err(Box::new(e))),
        }
    }
}

impl UdpMsg {
    pub fn recvmsg<'l>(
        &'l mut self,
        iov: &'l [nix::sys::uio::IoVec<&'l mut [u8]>],
        cmsg_buffer: &'l mut Vec<u8>,
        flags: nix::sys::socket::MsgFlags,
    ) -> RecvMsgFuture<'l> {
        RecvMsgFuture::new(&self.poll_evented, iov, cmsg_buffer, flags)
    }
}

impl TryFrom<std::net::UdpSocket> for UdpMsg {
    type Error = std::io::Error;
    fn try_from(socket: std::net::UdpSocket) -> Result<Self, Self::Error> {
        let io = mio::net::UdpSocket::from_socket(socket)?;
        let io = PollEvented::new(io)?;
        Ok(UdpMsg { poll_evented: io })
    }
}

#[cfg(test)]
async fn example(m : &mut UdpMsg) {
    let mut buffer = [0; 4096];
    let iov = [ nix::sys::uio::IoVec::from_mut_slice(&mut buffer[..]) ];
    let mut cmsg_buffer = nix::cmsg_space!([ std::os::unix::io::RawFd; 2]);
    m.recvmsg(&iov, &mut cmsg_buffer, nix::sys::socket::MsgFlags::empty()).await.expect("recvmsg");
    println!("buffer: {:?}", cmsg_buffer);
}


#[tokio::test]
async fn recvmsgtest() {
    use std::convert::TryInto;
    let listener = std::net::UdpSocket::bind("[::]:1053").expect("bind");
    nix::sys::socket::setsockopt(
        listener.as_raw_fd(),
        nix::sys::socket::sockopt::Ipv4PacketInfo,
        &true).expect("setsockopt(ipv4packetinfo, true)");

    example(&mut listener.try_into().expect("try_into UdpMsg")).await;
}
