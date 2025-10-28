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
//!     let listener = TcpListener::bind("127.0.0.1:80").await.unwrap();
//! }
//! # async fn hello() {}
//! ```
//!
//! The most convenient use case shown above will use the layer object to verify all routes above it are authenticated.
//! The [`Router::into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info) call is mandatory for this layer to work
//! on the used Router, otherwise the layer will panic.
//!
//! ## Axum handler usage example
//!
//! ```rust
//! # use axum_negotiate_layer::Authenticated;
//! async fn hello(a: Authenticated) -> String {
//!     format!("Hello, {}!", a.client().unwrap_or("whoever".to_owned()))
//! }
//! ```
//!
//! Alternatively, this works:
//! ```rust
//! # use axum::Extension;
//! # use axum_negotiate_layer::Authenticated;
//! async fn hello(Extension(a): Extension<Authenticated>) -> String {
//!     format!("Hello, {}!", a.client().unwrap_or("whoever".to_owned()))
//! }
//! ```
//!
//! When getting the [`Authenticated`] object from the request extension or extracting it directly, the authentication can be guaranteed for this route, as this object can
//! only be set by a middleware of this crate.
use axum::{
    extract::{ConnectInfo, FromRequestParts, Request, connect_info::Connected},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CONNECTION, WWW_AUTHENTICATE},
        request::Parts,
    },
    response::{IntoResponse, Response},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use futures_util::future::BoxFuture;
use kenobi::{ContextBuilder, FinishedContext, PendingContext, SecurityInfo};
use sspi::handle_sspi;
use std::{
    convert::Infallible,
    ffi::OsString,
    fmt::Debug,
    ops::Deref,
    sync::{Arc, RwLock},
    task::Poll,
};
use tower::{Layer, Service};

#[cfg(any(feature = "http1", feature = "http2"))]
mod listener;
mod sspi;
#[cfg(any(feature = "http1", feature = "http2"))]
pub use listener::{HasNegotiateInfo, Negotiator, WithNegotiateInfo};

#[derive(Default)]
enum NegotiateState {
    #[default]
    Unauthorized,
    Pending(PendingContext),
    Authenticated(FinishedContext),
}
impl NegotiateState {
    fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }
}
impl Debug for NegotiateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticated(_) => f.write_str("Authenticated"),
            Self::Pending(_) => f.write_str("Pending"),
            Self::Unauthorized => f.write_str("Unauthenticated"),
        }
    }
}

/// [`Extension`](axum::Extension) or Extractor type that gets set after successful Authentication
// This struct can only be created by the middleware in this crate or cloned from an
// existing one. Extracting it directly panics when the Layer has not been applied yet.
#[derive(Debug, Clone)]
pub struct Authenticated(Arc<RwLock<NegotiateState>>);
impl Authenticated {
    fn call<T>(&self, f: impl Fn(&FinishedContext) -> T) -> T {
        match self.0.read().unwrap().deref() {
            NegotiateState::Authenticated(x) => f(x),
            _ => unreachable!("Authenticated only exists after successful authentication"),
        }
    }
    pub fn client(&self) -> Option<String> {
        self.call(|x| x.client_native_name().ok().map(|os| os.to_string_lossy().into_owned()))
    }
    pub fn access_token(&self) -> Result<OsString, String> {
        self.call(|x| x.access_token())
    }
}
impl<S: Sync> FromRequestParts<S> for Authenticated {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let auth = get_state_from_extension(parts);
        if auth.clone().read().unwrap().is_authenticated() {
            Ok(Authenticated(auth))
        } else {
            tracing::error!(r#"NegotiateINfo not autorized. Probably extracted "Authenticated" outside of layer"#);
            panic!("NegotiateInfo was not authorized. you may have extracted `Authenticated` outside of the layer")
        }
    }
}

fn get_state_from_extension(parts: &Parts) -> Arc<RwLock<NegotiateState>> {
    match parts.extensions.get::<ConnectInfo<NegotiateInfo>>().cloned() {
        Some(ConnectInfo(NegotiateInfo { auth })) => auth,
        None => {
            tracing::error!("Panicking due to no ConnectInfo given");
            panic!(
                "No NegotiateInfo ConnectInfo was given. you may have forgotten to use into_make_service_with_connect_info"
            )
        }
    }
}
/// Type that must be set via [`Router::into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info).
///
/// Without this, the [`NegotiateLayer`] will not work
#[derive(Clone, Debug, Default)]
pub struct NegotiateInfo {
    auth: Arc<RwLock<NegotiateState>>,
}
impl Connected<NegotiateInfo> for NegotiateInfo {
    fn connect_info(value: NegotiateInfo) -> Self {
        value
    }
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
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, req: Request) -> Self::Future {
        let (mut parts, body) = req.into_parts();
        let auth = get_state_from_extension(&parts);
        // If anyone moves this .read() call around remember to not accidentally deadlock
        // with the write() call below
        if auth.read().unwrap().deref().is_authenticated() {
            let request = Request::from_parts(parts, body);
            return Box::pin(self.inner.call(request));
        }
        let token = match extract_token(&parts.headers) {
            Ok(token) => token,
            Err(response) => {
                return Box::pin(async { Ok(response) });
            }
        };
        let mut lock = auth.write().unwrap();
        let step_result = match std::mem::take(&mut *lock) {
            NegotiateState::Authenticated(_) => unreachable!(),
            NegotiateState::Pending(context) => handle_sspi(context, token),
            NegotiateState::Unauthorized => match ContextBuilder::new(Some(&self.spn)) {
                Ok(context) => handle_sspi(context, token),
                Err(_) => return Box::pin(async { Ok(failed_to_create_context()) }),
            },
        };
        match step_result {
            StepResult::Finished(f, maybe_token) => {
                if let Some(token) = maybe_token {
                    parts.headers.append(WWW_AUTHENTICATE, to_negotiate_header(&token));
                }
                parts.extensions.insert(Authenticated(auth.clone()));
                let request = Request::from_parts(parts, body);
                let next_future = self.inner.call(request);
                *lock = NegotiateState::Authenticated(f);
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

fn to_negotiate_header(token_bytes: &[u8]) -> HeaderValue {
    let encoded = BASE64_STANDARD.encode(token_bytes.as_ref());
    HeaderValue::from_str(&format!("Negotiate {encoded}")).expect("Base64-string should be valid header material")
}

enum StepResult {
    Finished(FinishedContext, Option<Box<[u8]>>),
    ContinueWith(PendingContext, Response),
    Error(Response),
}

#[allow(clippy::result_large_err)]
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
