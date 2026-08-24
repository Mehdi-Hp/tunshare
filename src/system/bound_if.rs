//! Hickory `RuntimeProvider` that pins sockets to a Darwin iface via `IP_BOUND_IF`.
//!
//! Source-IP `bind(2)` does not pick the WAN uplink when the default route is a
//! VPN tunnel. `IP_BOUND_IF` (ifindex from `if_nametoindex`) is the Darwin lever.

use std::ffi::CString;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;
use std::pin::Pin;
use std::time::Duration;

use hickory_resolver::net::runtime::{
    iocompat::AsyncIoTokioAsStd, RuntimeProvider, TokioHandle, TokioTime,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::error::{Result, TunshareError};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// ifindex for `name`. `0` / missing is an error.
pub fn ifindex(name: &str) -> Result<NonZeroU32> {
    let c_name = CString::new(name)
        .map_err(|_| TunshareError::Resolver(format!("interface name <{name}> contains a NUL")))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    NonZeroU32::new(index)
        .ok_or_else(|| TunshareError::Resolver(format!("unknown interface <{name}>")))
}

/// Hickory provider that sets `IP_BOUND_IF` on every UDP/TCP socket it creates.
#[derive(Clone)]
pub struct BoundIfProvider {
    handle: TokioHandle,
    index: NonZeroU32,
    local_ip: Ipv4Addr,
}

impl BoundIfProvider {
    pub fn new(iface: &str, local_ip: Ipv4Addr) -> Result<Self> {
        Ok(Self {
            handle: TokioHandle::default(),
            index: ifindex(iface)?,
            local_ip,
        })
    }
}

impl RuntimeProvider for BoundIfProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        _bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let index = self.index;
        let local = SocketAddr::from((IpAddr::V4(self.local_ip), 0));
        Box::pin(async move {
            let socket = bound_tcp_socket(index, local, server_addr)?;
            socket.set_nodelay(true)?;
            let wait_for = wait_for.unwrap_or(CONNECT_TIMEOUT);
            match timeout(wait_for, socket.connect(server_addr)).await {
                Ok(Ok(stream)) => Ok(AsyncIoTokioAsStd(stream)),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP connect timed out",
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let index = self.index;
        let local = match local_addr.ip() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED) => SocketAddr::from((IpAddr::V4(self.local_ip), 0)),
            _ => local_addr,
        };
        Box::pin(async move { bound_udp_socket(index, local) })
    }
}

fn bound_udp_socket(index: NonZeroU32, local: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.bind_device_by_index_v4(Some(index))?;
    socket.bind(&local.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn bound_tcp_socket(
    index: NonZeroU32,
    local: SocketAddr,
    server_addr: SocketAddr,
) -> io::Result<TcpSocket> {
    if !server_addr.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WAN DNS is IPv4-only",
        ));
    }
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind_device_by_index_v4(Some(index))?;
    socket.bind(&local.into())?;
    socket.set_nonblocking(true)?;
    Ok(TcpSocket::from_std_stream(socket.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lo0_ifindex_is_nonzero() {
        let index = ifindex("lo0").expect("lo0 exists");
        assert!(index.get() > 0);
    }

    #[test]
    fn unknown_iface_errors() {
        let error = ifindex("tunshare-no-such-if").unwrap_err();
        assert!(error.to_string().contains("unknown interface"));
    }

    #[test]
    fn ip_bound_if_on_lo0_does_not_fail() {
        let index = ifindex("lo0").unwrap();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket
            .bind_device_by_index_v4(Some(index))
            .expect("IP_BOUND_IF on lo0");
        socket
            .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
            .expect("bind after IP_BOUND_IF");
    }
}
