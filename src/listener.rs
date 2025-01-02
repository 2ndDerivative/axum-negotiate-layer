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

/// [`axum::serve::Listener`] extension for a convenient way to create a [`HasNegotiateInfo`]
pub trait WithNegotiateInfo: Sized + Listener {
    fn with_negotiate_info(self) -> HasNegotiateInfo<Self> {
        HasNegotiateInfo(self)
    }
}
impl<T: Listener> WithNegotiateInfo for T {}
/// [`axum::serve::Listener`] wrapper that provides connection-bound negotiation info.
pub struct HasNegotiateInfo<L>(pub L)
where
    L: Listener;
impl<L> Listener for HasNegotiateInfo<L>
where
    L: Listener,
{
    type Addr = L::Addr;
    type Io = Negotiator<L::Io>;
    fn accept(&mut self) -> impl std::future::Future<Output = (Self::Io, Self::Addr)> + Send {
        self.0
            .accept()
            .map(|(io, addr)| (Negotiator(io, NegotiateInfo::new()), addr))
    }
    fn local_addr(&self) -> tokio::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}
/// Io Wrapper that carries a specific connection's negotiation information
pub struct Negotiator<T>(T, NegotiateInfo);
impl<L> AsyncRead for Negotiator<L>
where
    L: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        pin!(&mut self.0).poll_read(cx, buf)
    }
}
impl<L> AsyncWrite for Negotiator<L>
where
    L: AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        pin!(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        pin!(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        pin!(&mut self.0).poll_shutdown(cx)
    }
}
#[cfg(any(feature = "http1", feature = "http2"))]
impl<L> Connected<IncomingStream<'_, HasNegotiateInfo<L>>> for NegotiateInfo
where
    L: Listener,
{
    fn connect_info(target: IncomingStream<'_, HasNegotiateInfo<L>>) -> Self {
        target.io().1.clone()
    }
}
