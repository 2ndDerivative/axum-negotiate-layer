use std::{
    pin::{pin, Pin},
    task::{Context, Poll},
};

use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use futures_util::FutureExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::NegotiateInfo;

pub trait AddNegotiateInfo: Sized {
    fn add_negotiate_info(self) -> WithNegotiateInfo<Self> {
        WithNegotiateInfo(self)
    }
}
impl<T> AddNegotiateInfo for T {}
pub struct WithNegotiateInfo<L>(pub L);
impl<L> Listener for WithNegotiateInfo<L>
where
    L: Listener,
{
    type Addr = L::Addr;
    type Io = Negotiated<L::Io>;
    fn accept(&mut self) -> impl std::future::Future<Output = (Self::Io, Self::Addr)> + Send {
        self.0.accept().map(|(l, a)| (Negotiated(l, NegotiateInfo::new()), a))
    }
    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}
pub struct Negotiated<T>(T, NegotiateInfo);
impl<L> AsyncRead for Negotiated<L>
where
    L: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl<L> AsyncWrite for Negotiated<L>
where
    L: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        pin!(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self).poll_shutdown(cx)
    }
}
#[cfg(any(feature = "http1", feature = "http2"))]
impl<L> Connected<IncomingStream<'_, WithNegotiateInfo<L>>> for NegotiateInfo
where
    L: Listener,
{
    fn connect_info(target: IncomingStream<'_, WithNegotiateInfo<L>>) -> Self {
        target.io().1.clone()
    }
}
