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
 *  Unfortunately, the std library address types are often woefully lacking, causing everyone to
 *  create their own types, often missing conversions.  This leads to leaking internal details
 *  everywhere.  Instead, we alias the types here, so we have one consistent set of types.
 */

mod link;

pub use link::*;
pub use nix::sys::socket::{
    SockaddrIn as Inet4Addr, SockaddrIn6 as Inet6Addr, SockaddrStorage as NetAddr, UnixAddr,
};
pub use std::net::{Ipv4Addr, Ipv6Addr};
pub const UNSPECIFIED6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;
pub const UNSPECIFIED4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(
    0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
);
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(
    0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002,
);

/// Converts the socket address to a NetAddr.
pub trait ToNetAddr {
    fn to_net_addr(&self) -> NetAddr;
}

impl<X: nix::sys::socket::SockaddrLike> ToNetAddr for X {
    fn to_net_addr(&self) -> NetAddr {
        use nix::sys::socket::SockaddrLike;
        unsafe {
            NetAddr::from_raw(<Self as SockaddrLike>::as_ptr(self), Some(Self::size())).unwrap()
        }
    }
}

pub fn tokio_to_unixaddr(src: &tokio::net::unix::SocketAddr) -> UnixAddr {
    if let Some(path) = src.as_pathname() {
        UnixAddr::new(path).unwrap()
    } else {
        unimplemented!()
    }
}

// convenience function for .map()
pub fn to_net_addr<X: ToNetAddr>(x: X) -> NetAddr {
    x.to_net_addr()
}

/// Takes an address, gives it a port, and makes a NetAddr.
pub trait WithPort {
    fn with_port(&self, port: u16) -> NetAddr;
}

impl WithPort for std::net::Ipv4Addr {
    fn with_port(&self, port: u16) -> NetAddr {
        Inet4Addr::from(std::net::SocketAddrV4::new(*self, port)).to_net_addr()
    }
}

impl WithPort for std::net::Ipv6Addr {
    fn with_port(&self, port: u16) -> NetAddr {
        Inet6Addr::from(std::net::SocketAddrV6::new(*self, port, 0, 0)).to_net_addr()
    }
}

impl WithPort for std::net::IpAddr {
    fn with_port(&self, port: u16) -> NetAddr {
        match self {
            Self::V4(ip) => ip.with_port(port),
            Self::V6(ip) => ip.with_port(port),
        }
    }
}

// I can't implement ToSocketAddrs on nix's types directly, but nix doesn't implement them either.
// (https://github.com/nix-rust/nix/issues/1799)
//
// I'm so very much over everyone having their own socket types.  sigh.
//
// So this trait will be used on exactly one type - NetAddr.
pub trait NetAddrExt {
    fn to_std_socket_addr(&self) -> Option<std::net::SocketAddr>;
    fn to_unix_addr(&self) -> Option<UnixAddr>;
    fn ip(&self) -> Option<std::net::IpAddr>;
    fn port(&self) -> Option<u16>;
}

impl NetAddrExt for NetAddr {
    fn to_std_socket_addr(&self) -> Option<std::net::SocketAddr> {
        if let Some(&v4) = self.as_sockaddr_in() {
            Some(std::net::SocketAddrV4::from(v4).into())
        } else if let Some(&v6) = self.as_sockaddr_in6() {
            Some(std::net::SocketAddrV6::from(v6).into())
        } else {
            None
        }
    }
    // unixaddr is difficult to create from just a sockaddr. (https://github.com/nix-rust/nix/issues/1800)
    fn to_unix_addr(&self) -> Option<UnixAddr> {
        use nix::sys::socket::SockaddrLike;
        if self.family() == Some(nix::sys::socket::AddressFamily::Unix) {
            unsafe { UnixAddr::from_raw(<Self as SockaddrLike>::as_ptr(self), Some(Self::size())) }
        } else {
            None
        }
    }
    fn ip(&self) -> Option<std::net::IpAddr> {
        if let Some(&v4) = self.as_sockaddr_in() {
            Some(std::net::Ipv4Addr::from(v4.ip()).into())
        } else if let Some(&v6) = self.as_sockaddr_in6() {
            Some(v6.ip().into())
        } else {
            None
        }
    }
    fn port(&self) -> Option<u16> {
        if let Some(&v4) = self.as_sockaddr_in() {
            Some(v4.port())
        } else if let Some(&v6) = self.as_sockaddr_in6() {
            Some(v6.port())
        } else {
            None
        }
    }
}
