use axum::{
    extract::{connect_info::Connected, ConnectInfo, Request},
    http::{
        header::{AUTHORIZATION, CONNECTION, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
};
use cross_krb5::{AcceptFlags, PendingServerCtx, ServerCtx};
use futures_util::future::BoxFuture;
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tower::{Layer, Service};

mod kerberos;

#[derive(Default)]
enum NegotiateState {
    #[default]
    Unauthorized,
    Pending(ServerContext),
    Authorized,
}
impl Debug for NegotiateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authorized => f.write_str("Authorized"),
            Self::Pending(_) => f.write_str("Pending"),
            Self::Unauthorized => f.write_str("Unauthorized"),
        }
    }
}

struct NtlmContext;

enum ServerContext {
    Kerberos(PendingServerCtx),
    Ntlm(NtlmContext),
}
impl ServerContext {
    fn new_kerberos(spn: &str) -> Result<Self, String> {
        Ok(ServerContext::Kerberos(
            ServerCtx::new(AcceptFlags::NEGOTIATE_TOKEN, Some(spn)).map_err(|x| x.to_string())?,
        ))
    }
    fn new_ntlm(_spn: &str) -> Result<Self, String> {
        todo!()
    }
}

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
        let (parts, body) = req.into_parts();
        let ConnectInfo(connection) = match parts.extensions.get::<ConnectInfo<NegotiateInfo>>().cloned() {
            Some(negotiate_info) => negotiate_info,
            None => return Box::pin(async { Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()) }),
        };
        let mut lock = connection.auth.lock().unwrap();
        if let NegotiateState::Authorized = lock.deref() {
            let request = Request::from_parts(parts, body);
            let next_future = self.inner.call(request);
            return Box::pin(next_future);
        }
        let token = match extract_token(&parts.headers) {
            Ok(token) => token,
            Err(response) => return Box::pin(async { Ok(response) }),
        };
        let Ok(context) = (match std::mem::replace(lock.deref_mut(), NegotiateState::Unauthorized) {
            NegotiateState::Authorized => unreachable!(),
            NegotiateState::Pending(context) => Ok(context),
            NegotiateState::Unauthorized if is_ntlm(token) => ServerContext::new_ntlm(&self.spn),
            NegotiateState::Unauthorized => ServerContext::new_kerberos(&self.spn),
        }) else {
            return Box::pin(async { Ok(failed_to_create_context()) });
        };
        let step_result = match context {
            ServerContext::Ntlm(NtlmContext) => unimplemented!(),
            ServerContext::Kerberos(kerberos) => kerberos::handle_kerberos(kerberos, token),
        };
        match step_result {
            StepResult::Finished => {
                let request = Request::from_parts(parts, body);
                let next_future = self.inner.call(request);
                *lock = NegotiateState::Authorized;
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
    Finished,
    ContinueWith(ServerContext, Response),
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