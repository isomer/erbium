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
 *  HTTP services for erbium
 */

use ::prometheus;
use hyper::{Body, Request, Response};
use std::convert::Infallible;

#[derive(Debug)]
pub enum Error {
    InvalidName(String),
    ListenError(String, std::io::Error),
    SocketInUse(String),
    CleanupFailed(String, std::io::Error),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            InvalidName(sock_name) => write!(f, "{} is not a valid socket name", sock_name),
            ListenError(sock_name, err) => write!(f, "Failed to listen on {}: {}", sock_name, err),
            SocketInUse(sock_name) => {
                write!(
                    f,
                    "{} already in use by existing running process",
                    sock_name
                )
            }
            CleanupFailed(sock_name, err) => write!(f, "Failed to cleanup {}: {}", sock_name, err),
        }
    }
}

async fn serve_metrics(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    use prometheus::{Encoder, TextEncoder};

    // Register & measure some metrics.

    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();

    // Gather the metrics.
    let metric_families = prometheus::gather();
    // Encode them to send.
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Ok(Response::builder()
        .status(200)
        .header("Content-type", "text/plain; version=0.0.4")
        .body(buffer.into())
        .unwrap())
}

async fn serve_leases(
    _req: Request<Body>,
    dhcp: &std::sync::Arc<crate::dhcp::DhcpService>,
) -> Result<Response<Body>, Infallible> {
    let mut leases = dhcp.get_leases().await;
    leases.sort();
    let buffer = format!(
        "{{ \"leases\" : [\n{}\n]}}\n",
        leases
            .iter()
            .map(|li| format!(
                " {{ \"ip\": \"{}\", \"client_id\": \"{}\", \"start\": {}, \"expire\": {} }}",
                li.ip,
                li.client_id
                    .iter()
                    .map(|b| format!("{:0>2x}", b))
                    .collect::<Vec<_>>()
                    .join(":"),
                li.start,
                li.expire
            ))
            .collect::<Vec<_>>()
            .join(",\n")
    );

    Ok(Response::builder()
        .status(200)
        .header("Content-type", "application/json")
        .body(buffer.into())
        .unwrap())
}

async fn serve_request(
    req: Request<Body>,
    dhcp: std::sync::Arc<crate::dhcp::DhcpService>,
) -> Result<Response<Body>, Infallible> {
    use hyper::{Method, StatusCode};

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(Response::new(
            format!("Welcome to Erbium {}", env!("CARGO_PKG_VERSION"),).into(),
        )),
        (&Method::GET, "/metrics") => {
            dhcp.update_metrics().await;
            serve_metrics(req).await
        }
        (&Method::GET, "/api/v1/leases.json") => serve_leases(req, &dhcp).await,
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not found".into())
            .unwrap()),
    }
}

async fn run_listener<L, S, E>(
    dhcp: std::sync::Arc<crate::dhcp::DhcpService>,
    mut listener: L,
) -> Result<(), hyper::Error>
where
    L: futures_core::stream::Stream<Item = Result<S, E>> + Unpin,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + std::marker::Send + 'static,
    E: std::fmt::Debug,
{
    use futures::stream::StreamExt as _;
    use hyper::service::service_fn;

    while let Some(stream) = listener.next().await {
        let stream = stream.unwrap(); // TODO: Error handling?
        let dhcp_copy = dhcp.clone();
        let srv = move |req| serve_request(req, dhcp_copy.clone());
        tokio::task::spawn(async move {
            if let Err(http_err) = hyper::server::conn::Http::new()
                .http1_only(true)
                .http1_keep_alive(true)
                .serve_connection(stream, service_fn(srv))
                .await
            {
                log::warn!("Error while serving HTTP connection: {}", http_err);
            }
        });
    }
    Ok(())
}

pub async fn run(
    dhcp: std::sync::Arc<crate::dhcp::DhcpService>,
    conf: crate::config::SharedConfig,
) -> Result<(), Error> {
    // Set up all the listeners and listen on them.
    for addr in &conf.read().await.listeners {
        use nix::sys::socket::SockAddr::*;
        use tokio::net::{TcpListener, UnixListener};
        match addr {
            Inet(s) => {
                let listener = TcpListener::bind((s.ip().to_std(), s.port()))
                    .await
                    .map_err(|e| Error::ListenError(s.to_string(), e))?;
                tokio::task::spawn(run_listener(dhcp.clone(), listener));
            }
            Unix(s) => {
                let listener;
                if let Some(path) = s.path() {
                    loop {
                        use nix::sys::stat::*;
                        let oldmask = umask(Mode::from_bits(0o077).unwrap());
                        let mut newmask = oldmask;
                        // Limit to at least 0o077
                        newmask.insert(Mode::from_bits(0o077).unwrap());
                        let _ = umask(newmask);
                        let listener_status = UnixListener::bind(path);
                        // Now restore it.
                        umask(oldmask);
                        use std::io;
                        listener = match listener_status {
                            Ok(l) => l,
                            Err(listen_err) if listen_err.kind() == io::ErrorKind::AddrInUse => {
                                // This is perhaps a socket left over from a previous encantation of
                                // the program.  Test to see if it's live, if it's not, then remove it
                                // and try again.
                                match tokio::net::UnixStream::connect(path).await {
                                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                                        log::warn!(
                                            "Cleaning up stale socket {}",
                                            path.to_string_lossy()
                                        );
                                        std::fs::remove_file(path).map_err(|e| {
                                            Error::CleanupFailed(path.to_string_lossy().into(), e)
                                        })?;
                                        // Try and rebind this socket again.
                                        continue;
                                    }
                                    Err(_) => {
                                        // We return the top level error ("Address in use")
                                        return Err(Error::ListenError(
                                            path.to_string_lossy().into(),
                                            listen_err,
                                        ));
                                    }
                                    Ok(_) => {
                                        // We were able to connect to the unix domain socket, so
                                        // there must be a process on the other side listening on
                                        // it.  Fail the entire operation.
                                        return Err(Error::SocketInUse(
                                            path.to_string_lossy().into(),
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                // We were unable to listen on the socket for some reason (eg the
                                // containing directory doesn't exist).
                                return Err(Error::ListenError(path.to_string_lossy().into(), e));
                            }
                        };
                        break;
                    }
                } else if let Some(name) = s.as_abstract() {
                    let mut name_bytes = vec![0x00u8];
                    name_bytes.extend(name);
                    let sock_name = String::from_utf8(name_bytes)
                        .map_err(|_| Error::InvalidName(String::from_utf8_lossy(name).into()))?;
                    listener = UnixListener::bind(sock_name)
                        .map_err(|e| Error::ListenError(String::from_utf8_lossy(name).into(), e))?;
                } else {
                    panic!("Unknown unix listener!");
                }
                log::trace!("Starting listener on {:?}", listener);
                tokio::task::spawn(run_listener(dhcp.clone(), listener));
            }
            _ => panic!("Unknown listener type!"),
        }
    }
    Ok(())
}
