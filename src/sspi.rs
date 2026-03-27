use crate::{StepResult, to_negotiate_header, unauthorized};
use axum_core::response::IntoResponse;
use base64::{Engine, prelude::BASE64_STANDARD};
use http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{CONNECTION, WWW_AUTHENTICATE},
};
use kenobi::{
    cred::Inbound,
    server::{AcceptError, PendingServerContext, ServerBuilder, StepOut},
};

pub trait Step {
    fn step(self, token: &[u8]) -> Result<StepOut<Inbound>, AcceptError>;
}
impl Step for PendingServerContext<Inbound> {
    fn step(self, token: &[u8]) -> Result<StepOut<Inbound>, AcceptError> {
        self.step(token)
    }
}
impl Step for ServerBuilder<Inbound> {
    fn step(self, token: &[u8]) -> Result<StepOut<Inbound>, AcceptError> {
        self.initialize(token)
    }
}

pub fn handle_sspi(context: impl Step, token: &str) -> StepResult {
    #[cfg(feature = "tracing")]
    tracing::trace!(token_length = token.len());
    let Ok(header_bytes) = BASE64_STANDARD.decode(token) else {
        return StepResult::Error(StatusCode::BAD_REQUEST.into_response());
    };
    match context.step(&header_bytes) {
        Ok(StepOut::Pending(context)) => {
            let response_bytes = context.next_token();
            #[cfg(feature = "tracing")]
            tracing::debug!("SPNEGO Continue, sending {} bytes", response_bytes.len());
            let mut header_map = HeaderMap::new();
            header_map.insert(WWW_AUTHENTICATE, to_negotiate_header(response_bytes));
            header_map.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
            let response = (StatusCode::UNAUTHORIZED, header_map, "continue").into_response();
            StepResult::ContinueWith(context, response)
        }
        #[allow(unused_mut)]
        Ok(StepOut::Finished(mut context)) => {
            let maybe_token = context.last_token().map(|x| x.to_vec().into_boxed_slice());
            #[cfg(feature = "tracing")]
            tracing::info!("SPNEGO Finished: authenticated {}", context.client_name());
            StepResult::Finished(context, maybe_token)
        }
        Err(e) => {
            #[cfg(feature = "tracing")]
            tracing::error!("Authentication failed: {e:?}");
            StepResult::Error(unauthorized("authorization failed"))
        }
    }
}
