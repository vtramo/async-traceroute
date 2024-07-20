use std::io;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Receiver;

#[derive(Clone)]
pub struct AsyncSocket {
    socket_async_fd: Arc<AsyncFd<SocketWrapper>>,
}

impl AsyncSocket {
    pub fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Self> {
        let socket = SocketWrapper::new(domain, ty, protocol)?;
        
        let socket_async_fd = AsyncFd::new(socket)?;
        
        Ok(Self {
            socket_async_fd: Arc::new(socket_async_fd),
        })
    }

    pub async fn connect(&self, ip: Ipv4Addr) -> io::Result<()> {
        self.socket_async_fd.get_ref().connect(ip)
    }
    
    pub fn bind(&self, socket_addr: SocketAddr) -> io::Result<()> {
        self.socket_async_fd.get_ref().bind(socket_addr)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket_async_fd.get_ref().local_addr()?.as_socket().ok_or(io::Error::last_os_error())
    }

    pub async fn send_to(&self, buf: &[u8], socket_addr: SocketAddr) -> io::Result<usize> {
        self.socket_async_fd
            .async_io(Interest::WRITABLE, |socket| socket.send_to(buf, socket_addr))
            .await
    }

    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket_async_fd
            .async_io(Interest::WRITABLE, |socket| socket.send(buf))
            .await
    }
    
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket_async_fd
            .async_io(Interest::READABLE, |socket| socket.recv(buf))
            .await
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.socket_async_fd.get_ref().set_ttl(ttl)
    }

    pub fn set_header_included(&self, flag: bool) -> io::Result<()> {
        self.socket_async_fd.get_ref().set_header_included(flag)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.socket_async_fd.get_ref().shutdown(how)
    }
}

struct SocketWrapper {
    socket: Socket,
}

impl SocketWrapper {
    fn new(domain: Domain, ty: Type, protocol: Option<Protocol>) -> io::Result<Self> {
        let socket = Socket::new(domain, ty, protocol)?;

        socket.set_nonblocking(true)?;

        Ok(Self { socket })
    }

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

    fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    fn send_to(&self, buf: &[u8], socket_addr: SocketAddr) -> io::Result<usize> {
        let result = self.socket.send_to(buf, &socket_addr.into());
        result
    }

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

impl AsRawFd for SocketWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}


pub struct SharedWriteOnlyAsyncSocket {
    socket: AsyncSocket,
    rx: Receiver<(Vec<u8>, SocketAddr)>,
}

impl SharedWriteOnlyAsyncSocket {
    pub fn new(
        domain: Domain,
        ty: Type,
        protocol: Option<Protocol>,
        rx: Receiver<(Vec<u8>, SocketAddr)>,
    ) -> io::Result<Self> {
        Ok(Self {
            socket: AsyncSocket::new(domain, ty, protocol)?,
            rx
        })
    }

    pub async fn share(&mut self) {
        while let Some((bytes, socket_addr)) = self.rx.recv().await {
            match self.socket.send_to(&bytes, socket_addr).await {
                Ok(_) => (),
                Err(_) => {
                    self.rx.close();
                    break;
                }
            };
        }
    }

    pub fn set_header_included(&mut self, value: bool) -> io::Result<()> {
        self.socket.set_header_included(value)
    }
}