use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use mio::{event::Source, Interest as InterestMio, Registry, Token};
use mio::unix::SourceFd;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Receiver;

/// An ICMP socket used with `tokio` events.
#[derive(Clone)]
pub struct AsyncTokioSocket {
    socket: Arc<AsyncFd<MioTokioSocket>>,
}

impl AsyncTokioSocket {
    /// `new` creates a raw system socket which is non-blocking.
    ///
    /// Calling `new` requires root permission for the
    /// raw network capability `CAP_NET_RAW` to open a raw socket.
    ///
    /// `new` returns a "no permission" error if `CAP_NET_RAW` is unavailable.
    pub fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Self> {
        let mio_sck = MioTokioSocket::new(domain, ty, protocol)?;
        let fd_mio_sck = AsyncFd::new(mio_sck)?;
        Ok(Self {
            socket: Arc::new(fd_mio_sck),
        })
    }

    pub async fn connect(&self, ip: Ipv4Addr) -> io::Result<()> {
        self.socket.get_ref().connect(ip)
    }
    
    pub fn bind(&self, socket_addr: SocketAddr) -> io::Result<()> {
        self.socket.get_ref().bind(socket_addr)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.get_ref().local_addr()?.as_socket().ok_or(io::Error::last_os_error())
    }

    pub async fn send_to(&self, buf: &[u8], socket_addr: SocketAddr) -> io::Result<usize> {
        self.socket
            .async_io(Interest::WRITABLE, |socket| socket.send_to(buf, socket_addr))
            .await
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket
            .async_io(Interest::WRITABLE, |socket| socket.send(buf))
            .await
    }
    
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket
            .async_io(Interest::READABLE, |socket| socket.recv(buf))
            .await
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.get_ref().set_ttl(ttl)
    }

    pub fn set_header_included(&self, flag: bool) -> io::Result<()> {
        self.socket.get_ref().set_header_included(flag)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket.get_ref().shutdown(how)
    }
}

struct MioTokioSocket {
    socket: Socket,
}

impl MioTokioSocket {
    /// `new` creates an IcmpSocketMio.
    ///
    /// `new` creates a raw system socket which is non-blocking.
    ///
    /// Calling `new` requires root permission for the
    /// raw network capability `CAP_NET_RAW` to open a raw socket.
    ///
    /// `new` returns a "no permission" error if `CAP_NET_RAW` is unavailable.
    fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Self> {
        let socket = Socket::new(domain, ty, protocol)?;

        socket.set_nonblocking(true)?;

        Ok(Self { socket })
    }

    /// Connect the ICMP socket with a destination IPv4 address.
    ///
    /// Used by the `send` and `recv` functions.
    fn connect(&self, ip: Ipv4Addr) -> io::Result<()> {
        let address = SocketAddr::new(IpAddr::V4(ip), 0);

        self.socket.connect(&address.into())
    }
    
    fn bind(&self, socket_addr: SocketAddr) -> io::Result<()> {
        self.socket.bind(&socket_addr.into())
    }
    
    fn local_addr(&self) -> io::Result<SockAddr> {
        self.socket.local_addr()
    }

    /// Send data to the socket and remote address.
    ///
    /// Ensure `connect` was called once before calling `send`.
    ///
    /// Returns the number of bytes sent; or, an error.
    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    fn send_to(&self, buf: &[u8], socket_addr: SocketAddr) -> io::Result<usize> {
        let result = self.socket.send_to(buf, &socket_addr.into());
        result
    }

    /// Receive data from the socket and remote address.
    ///
    /// Ensure `connect` was called once before calling `recv`.
    ///
    /// Returns the number of bytes received; or, an error.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let result = (&self.socket).read(buf);
        result
    }

    fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket.set_ttl(ttl)
    }
    
    fn set_header_included(&self, flag: bool) -> io::Result<()> {
        self.socket.set_header_included(flag)
    }
    
    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }
}

// Implement Source for the `mio` crate.
impl Source for MioTokioSocket {
    fn register(&mut self, poll: &Registry, token: Token, interest: InterestMio) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).register(poll, token, interest)
    }

    fn reregister(
        &mut self,
        poll: &Registry,
        token: Token,
        interest: InterestMio,
    ) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).reregister(poll, token, interest)
    }

    fn deregister(&mut self, poll: &Registry) -> io::Result<()> {
        SourceFd(&self.as_raw_fd()).deregister(poll)
    }
}

// Implement AsRawFd for the `mio` crate.
impl AsRawFd for MioTokioSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

pub struct SharedAsyncTokioSocket {
    socket: AsyncTokioSocket,
    rx: Receiver<(Vec<u8>, SocketAddr)>,
}

impl SharedAsyncTokioSocket {
    pub fn new(
        domain: Domain,
        ty: Type,
        protocol: Option<Protocol>,
        rx: Receiver<(Vec<u8>, SocketAddr)>,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: AsyncTokioSocket::new(domain, ty, protocol)?,
            rx
        })
    }

    pub async fn share(&mut self) {
        while let Some((bytes, socket_addr)) = self.rx.recv().await {
            self.socket.send_to(&bytes, socket_addr).await.expect("TODO: panic message");
        }
    }

    pub fn set_header_included(&mut self, value: bool) -> io::Result<()> {
        self.socket.set_header_included(value)
    }
}