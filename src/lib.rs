//! axum-negotiate-layer provides middleware for authenticating connections over the Microsoft "HTTP Negotiate" extension.
//!
//! # Features
//!
//! - [`NegotiateMiddleware`]: A [`tower::Service`] object that uses the [`NegotiateInfo`] attached to the connection to authenticate that connection
//! - [`NegotiateLayer`]: A [`tower::Layer`] for the above mentioned service
//! - A [`Authenticated`] request extension object to get information about authenticated clients (so far only the user identity)
//! - An extension to the standard [`axum::serve::Listener`] (with feature `http1` or `http2`) to add negotiation info to every connection.
//!   As SPNEGO is a non-http standard authentication method authenticating by connection, the negotiation info has to be included in every
//!   connection given to axum, either via this struct or by manually providing it as a `ConnectInfo` extension when driving the routing loop yourself.
//!
//! # Usage
//! The middleware and layer require the Kerberos SPN for the Router in question.
//!
//! ```rust
//! use axum::{routing::get, Extension, Router};
//! use axum_negotiate_layer::{Authenticated, NegotiateInfo, NegotiateLayer, AddNegotiateInfo};
//! use tokio::net::TcpListener;
//!
//! #[tokio::main]
//! async fn main() {
//!     let router = Router::new()
//!         .route("/", get(hello))
//!         .layer(NegotiateLayer::new("HTTP/example.com"))
//!         .into_make_service_with_connect_info::<NegotiateInfo>();
//!     let listener = TcpListener::bind("0.0.0.0:80").await.unwrap().with_negotiate_info();
//!     axum::serve(listener, router).with_graceful_shutdown(std::future::ready(())).await.unwrap();
//! }
//!
//! # async fn hello(Extension(a): Extension<Authenticated>) -> String {
//! #     format!("Hello, {}!", a.client().unwrap_or("whoever".into()))
//! # }
//! ```
//!
//! The most convenient use case shown above will use the layer object to verify all routes above it are authenticated.
//! The [`Router::into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info) call is mandatory for this layer to work
//! on the used Router, otherwise the layer will panic.
//!
//! ## Axum handler usage example
//!
//! ```rust
//! # use axum::Extension;
//! # use axum_negotiate_layer::Authenticated;
//! async fn hello(Extension(a): Extension<Authenticated>) -> String {
//!     format!("Hello, {}!", a.client().unwrap_or("whoever".into()))
//! }
//! ```
//!
//! When getting the [`Authenticated`] object from the request extension, the authentication can be guaranteed for this route, as this object can
//! only be set by a middleware of this crate.
use axum::{
    extract::{ConnectInfo, Request},
    http::{
        header::{AUTHORIZATION, CONNECTION, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
};
use cross_krb5::{AcceptFlags, K5ServerCtx, PendingServerCtx, ServerCtx};
use futures_util::future::BoxFuture;
use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::{Layer, Service};

mod kerberos;
#[cfg(any(feature = "http1", feature = "http2"))]
mod listener;
#[cfg(any(feature = "http1", feature = "http2"))]
pub use listener::{HasNegotiateInfo, Negotiator, WithNegotiateInfo};

#[derive(Default)]
enum NegotiateState {
    #[default]
    Unauthorized,
    Pending(PendingServerCtx),
    Authenticated,
}
impl Debug for NegotiateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticated => f.write_str("Authenticated"),
            Self::Pending(_) => f.write_str("Pending"),
            Self::Unauthorized => f.write_str("Unauthenticated"),
        }
    }
}

fn new_context(spn: &str) -> Result<PendingServerCtx, String> {
    ServerCtx::new(AcceptFlags::NEGOTIATE_TOKEN, Some(spn)).map_err(|x| x.to_string())
}

/// [`Extension`](axum::Extension) type that gets set after successful Authentication
#[derive(Debug, Clone)]
pub struct Authenticated(Option<String>);
impl Authenticated {
    fn from_finished_context(f: &mut ServerCtx) -> Self {
        let client = f.client().ok();
        Self(client)
    }
    #[must_use]
    pub fn client(&self) -> Option<String> {
        self.0.clone()
    }
}

/// Type that must be set via [`Router::into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info).
///
/// Without this, the [`NegotiateLayer`] will not work
#[derive(Clone, Debug, Default)]
pub struct NegotiateInfo {
    auth: Arc<Mutex<NegotiateState>>,
}
impl NegotiateInfo {
    #[must_use]
    /// You should probably only have to use this if you drive the IO loop yourself instead of using [`axum::serve()`]
    pub fn new() -> Self {
        Self::default()
    }
}

/// [`Layer`] which will enforce authentication
///
/// The SPN must be correctly installed in the local realm
///
/// Also a [`ConnectInfo`] extension must have been set on the router.
#[derive(Clone)]
pub struct NegotiateLayer {
    spn: String,
}
impl NegotiateLayer {
    #[must_use]
    pub fn new(spn: &str) -> Self {
        Self { spn: spn.to_owned() }
    }
}
impl<S> Layer<S> for NegotiateLayer {
    type Service = NegotiateMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NegotiateMiddleware::new(inner, &self.spn)
    }
}
#[derive(Clone)]
/// Middleware to enforce authentication
///
/// A layer may be made from this via [`NegotiateLayer::new`]
///
/// This middleware will not work without the [`NegotiateInfo`] [`ConnectInfo`] object.
/// If there is no such connection information set, this middleware will panic.
pub struct NegotiateMiddleware<S> {
    inner: S,
    spn: String,
}
impl<S> NegotiateMiddleware<S> {
    #[must_use]
    pub fn new(service: S, spn: &str) -> NegotiateMiddleware<S> {
        let spn = spn.into();
        NegotiateMiddleware { inner: service, spn }
    }
}
impl<S> Service<Request> for NegotiateMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, req: Request) -> Self::Future {
        let (mut parts, body) = req.into_parts();
        let Some(ConnectInfo(connection)) = parts.extensions.get::<ConnectInfo<NegotiateInfo>>().cloned() else {
            panic!("No NegotiateInfo ConnectInfo was given. you may have forgotten to use into_make_service_with_connect_info")
        };
        let mut lock = connection.auth.lock().unwrap();
        if let NegotiateState::Authenticated = &mut *lock {
            let request = Request::from_parts(parts, body);
            let next_future = self.inner.call(request);
            return Box::pin(next_future);
        }
        let token = match extract_token(&parts.headers) {
            Ok(token) => token,
            Err(response) => return Box::pin(async { Ok(response) }),
        };
        let Ok(context) = (match std::mem::take(&mut *lock) {
            NegotiateState::Authenticated => unreachable!(),
            NegotiateState::Pending(context) => Ok(context),
            NegotiateState::Unauthorized => new_context(&self.spn),
        }) else {
            return Box::pin(async { Ok(failed_to_create_context()) });
        };
        let step_result = kerberos::handle(context, token);
        match step_result {
            StepResult::Finished(mut f) => {
                parts.extensions.insert(Authenticated::from_finished_context(&mut f));
                let request = Request::from_parts(parts, body);
                let next_future = self.inner.call(request);
                *lock = NegotiateState::Authenticated;
                Box::pin(next_future)
            }
            StepResult::ContinueWith(server_context, response) => {
                *lock = NegotiateState::Pending(server_context);
                Box::pin(async move { Ok(response) })
            }
            StepResult::Error(response) => {
                *lock = NegotiateState::Unauthorized;
                Box::pin(async { Ok(response) })
            }
        }
    }
}

enum StepResult {
    Finished(ServerCtx),
    ContinueWith(PendingServerCtx, Response),
    Error(Response),
}

fn extract_token(headers: &HeaderMap) -> Result<&str, Response> {
    let Some(authorization) = headers.get(AUTHORIZATION) else {
        return Err(unauthorized("No Authorization given"));
    };
    let Some(token) = authorization
        .to_str()
        .ok()
        .and_then(|with_prefix| with_prefix.strip_prefix("Negotiate "))
    else {
        return Err(unauthorized("Invalid Authorization Header"));
    };
    Ok(token)
}

fn www_authenticate_map() -> HeaderMap {
    let mut map = HeaderMap::new();
    map.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
    map.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    map
}

fn unauthorized(message: &str) -> Response {
    (StatusCode::UNAUTHORIZED, www_authenticate_map(), message.to_owned()).into_response()
}

fn failed_to_create_context() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
}
