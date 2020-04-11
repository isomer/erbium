use tokio::io::PollEvented;

use futures::ready;
use mio::Ready;
use nix::sys;
use std::io;
use std::task::{Context, Poll};
use tokio::future::poll_fn;
use tokio::net::UdpSocket;

extern crate futures;

struct MMsg {
    poll_evented: PollEvented<UdpSocket>,
}

impl MMSg {
    pub fn poll_recvmmsg(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, io::Error>> {
        let ready = Ready::readable();

        ready!(self.poll_evented.poll_read_ready(cx, ready))?;

        match socket::recvmsg(
            self.poll_evented.get_ref().as_raw_fd(),
            &iov,
            Some(&mut cmsg),
            socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Poll::Pending,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.poll_evented.clear_read_ready(cx, ready)?;
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
