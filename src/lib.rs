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
use winauth::windows::{NtlmSspi, NtlmSspiBuilder};

mod kerberos;
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
    Ntlm(NtlmSspi),
}
impl PendingServerContext {
    fn new_kerberos(spn: &str) -> Result<Self, String> {
        Ok(PendingServerContext::Kerberos(
            ServerCtx::new(AcceptFlags::NEGOTIATE_TOKEN, Some(spn)).map_err(|x| x.to_string())?,
        ))
    }
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
    Ntlm(NtlmSspi),
}
impl FinishedServerContext {
    fn client(&mut self) -> Option<String> {
        match self {
            Self::Kerberos(k) => k.client().ok(),
            Self::Ntlm(n) => n.client_identity().ok(),
        }
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
            NegotiateState::Unauthorized if is_ntlm(token) => PendingServerContext::new_ntlm(&self.spn),
            NegotiateState::Unauthorized => PendingServerContext::new_kerberos(&self.spn),
        }) else {
            return Box::pin(async { Ok(failed_to_create_context()) });
        };
        let step_result = match context {
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
