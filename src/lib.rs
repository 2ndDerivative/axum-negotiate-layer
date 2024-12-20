//! axum-negotiate-layer provides middleware for authenticating connections over the Microsoft "HTTP Negotiate" extension.
//!
//! # Features
//!
//! - [`NegotiateMiddleware`]: A [`tower::Service`] object that uses the [`NegotiateInfo`] attached to the connection to authenticate that connection
//! - [`NegotiateLayer`]: A [`tower::Layer`] for the above mentioned service
//! - A [`Authenticated`] request extension object to get information about authenticated clients (so far only the user identity)
//!
//! # Incompleteness
//! NTLM authentication is not available on non-Windows systems. These will have to stop NTLM tokens from reaching this crate's service or it will panic
//!
//! # Usage
//! The middleware and layer require the Kerberos SPN for the Router in question.
//!
//! ```rust,no_run
//! use axum::{routing::get, Extension, Router};
//! use axum_negotiate_layer::{Authenticated, NegotiateInfo, NegotiateLayer};
//! use tokio::net::TcpListener;
//!
//! #[tokio::main]
//! async fn main() {
//!     let router = Router::new()
//!         .route("/", get(hello))
//!         .layer(NegotiateLayer::new("HTTP/example.com"))
//!         .into_make_service_with_connect_info::<NegotiateInfo>();
//!     let listener = TcpListener::bind("0.0.0.0:80").await.unwrap();
//!     axum::serve(listener, router).await.unwrap();
//! }
//! ```
//!
//! The most convenient use case shown above will use the layer object to verify all routes above it are authenticated.
//! The [`Router::into_make_service_with_connect_info`](axum::Router::into_make_service_with_connect_info) call is mandatory for this layer to work
//! on the used Router, otherwise the layer will only return Status code 500. (will probably be changed to a panic in the future).
//!
//! ## Axum handler usage example
//!
//! ```rust,no_run
//! async fn hello(Extension(a): Extension<Authenticated>) -> String {
//!     format!("Hello, {}!", a.client().unwrap_or("whoever"))
//! }
//! ```
//!
//! When getting the [`Authenticated`] object from the request extension, the authentication can be guaranteed for this route, as this object can
//! only be set by a middleware of this crate.
use axum::{
    extract::{connect_info::Connected, ConnectInfo, Request},
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
    ops::DerefMut,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::{Layer, Service};
#[cfg(windows)]
use winauth::windows::{NtlmSspi, NtlmSspiBuilder};

mod kerberos;
#[cfg(windows)]
mod ntlm;

#[derive(Default)]
enum NegotiateState {
    #[default]
    Unauthorized,
    Pending(PendingServerContext),
    Authenticated(FinishedServerContext),
}
impl Debug for NegotiateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authenticated(_) => f.write_str("Authorized"),
            Self::Pending(_) => f.write_str("Pending"),
            Self::Unauthorized => f.write_str("Unauthorized"),
        }
    }
}

enum PendingServerContext {
    Kerberos(PendingServerCtx),
    #[cfg(windows)]
    Ntlm(NtlmSspi),
}
impl PendingServerContext {
    fn new_kerberos(spn: &str) -> Result<Self, String> {
        Ok(PendingServerContext::Kerberos(
            ServerCtx::new(AcceptFlags::NEGOTIATE_TOKEN, Some(spn)).map_err(|x| x.to_string())?,
        ))
    }
    #[cfg(windows)]
    fn new_ntlm(spn: &str) -> Result<Self, String> {
        Ok(PendingServerContext::Ntlm(
            NtlmSspiBuilder::new()
                .inbound()
                .target_spn(spn)
                .build()
                .map_err(|x| x.to_string())?,
        ))
    }
}

/// [`Extension`](axum::Extension) type that gets set after successful Authentication
#[derive(Debug, Clone)]
pub struct Authenticated(Option<String>);
impl Authenticated {
    fn from_finished_context(f: &mut FinishedServerContext) -> Self {
        let client = f.client();
        Self(client)
    }
    pub fn client(&self) -> Option<&str> {
        self.0.as_deref()
    }
}
enum FinishedServerContext {
    Kerberos(ServerCtx),
    #[cfg(windows)]
    Ntlm(NtlmSspi),
}
impl FinishedServerContext {
    fn client(&mut self) -> Option<String> {
        match self {
            Self::Kerberos(k) => k.client().ok(),
            #[cfg(windows)]
            Self::Ntlm(n) => n.client_identity().ok(),
        }
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
    pub fn new() -> Self {
        Self::default()
    }
}
impl<T> Connected<T> for NegotiateInfo {
    fn connect_info(_target: T) -> Self {
        Self::new()
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
/// This middleware will not work without the [`NegotiateInfo`] [`ConnectInfo`] object
pub struct NegotiateMiddleware<S> {
    inner: S,
    spn: String,
}
impl<S> NegotiateMiddleware<S> {
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
        let ConnectInfo(connection) = match parts.extensions.get::<ConnectInfo<NegotiateInfo>>().cloned() {
            Some(negotiate_info) => negotiate_info,
            None => return Box::pin(async { Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()) }),
        };
        let mut lock = connection.auth.lock().unwrap();
        if let NegotiateState::Authenticated(f) = lock.deref_mut() {
            parts.extensions.insert(Authenticated::from_finished_context(f));
            let request = Request::from_parts(parts, body);
            let next_future = self.inner.call(request);
            return Box::pin(next_future);
        }
        let token = match extract_token(&parts.headers) {
            Ok(token) => token,
            Err(response) => return Box::pin(async { Ok(response) }),
        };
        let Ok(context) = (match std::mem::replace(lock.deref_mut(), NegotiateState::Unauthorized) {
            NegotiateState::Authenticated(_) => unreachable!(),
            NegotiateState::Pending(context) => Ok(context),
            #[cfg(windows)]
            NegotiateState::Unauthorized if is_ntlm(token) => PendingServerContext::new_ntlm(&self.spn),
            #[cfg(not(windows))]
            NegotiateState::Unauthorized if is_ntlm(token) => {
                unimplemented!("NTLM is not yet supported on non-windows platforms")
            }
            NegotiateState::Unauthorized => PendingServerContext::new_kerberos(&self.spn),
        }) else {
            return Box::pin(async { Ok(failed_to_create_context()) });
        };
        let step_result = match context {
            #[cfg(windows)]
            PendingServerContext::Ntlm(ntlm) => ntlm::handle_ntlm(ntlm, token),
            PendingServerContext::Kerberos(kerberos) => kerberos::handle_kerberos(kerberos, token),
        };
        match step_result {
            StepResult::Finished(mut f) => {
                parts.extensions.insert(Authenticated::from_finished_context(&mut f));
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

enum StepResult {
    Finished(FinishedServerContext),
    ContinueWith(PendingServerContext, Response),
    Error(Response),
}

fn is_ntlm(token: &str) -> bool {
    token.starts_with("TlR")
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
